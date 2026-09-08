package meshu.gateway.session;

import meshu.core.l2.KeyAgreement;
import meshu.core.l2.L2;
import meshu.core.l3.Envelope;
import meshu.core.l3.Op;
import meshu.core.l3.Ops;
import meshu.gateway.ops.OpDispatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Arrays;

/**
 * The gateway's message pipeline: takes one inbound L1 message body (the sealed
 * L2 bytes, or a bootstrap HELLO) and produces the sealed L2 response bytes.
 *
 * <p>Responsibilities, in order:
 * <ol>
 *   <li><b>Bootstrap</b> (§4.2.1): a {@code 0xFF}-form message is accepted only
 *       if its L3 opcode is HELLO; the wallet's key is pinned (never replaced),
 *       and the response is sealed to it.</li>
 *   <li><b>Open</b> (§4): AEAD-verify the sealed message under the wallet's
 *       pinned key, trying candidate keys on src-hash collision (§2.3). The
 *       verified key — not the src hash — is the identity.</li>
 *   <li><b>Replay</b> (§11.1): exact retry → cached response; msg_id conflict →
 *       MC_MALFORMED; otherwise execute.</li>
 *   <li><b>Dispatch + seal</b>: run the op, seal the response under k_g2w, and
 *       store it in the replay cache before returning.</li>
 * </ol>
 *
 * <p>This class is transport-agnostic: the caller (mesh or HTTPS) supplies the
 * message bytes and the routing hints and gets back the response bytes.
 */
@Service
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);

    private final PairingService pairing;
    private final ReplayCache replayCache;
    private final OpDispatcher dispatcher;

    public SessionService(PairingService pairing, ReplayCache replayCache, OpDispatcher dispatcher) {
        this.pairing = pairing;
        this.replayCache = replayCache;
        this.dispatcher = dispatcher;
    }

    /**
     * Process one inbound L2 message body.
     *
     * @param msgId       the L1 message id (idempotency + nonce input, §3.3/§4.5)
     * @param l2Body      the L2 message: {@code epoch ‖ ciphertext ‖ tag}, or
     *                    bootstrap form {@code 0xFF ‖ L3 plaintext}
     * @param srcHashHint the 1-byte src node hash from the routing prefix (§2.3),
     *                    used only to order candidate keys; may be -1 if unknown
     * @return the sealed L2 response body to send back
     */
    public byte[] handleMessage(int msgId, byte[] l2Body, int srcHashHint) {
        if (L2.isBootstrap(l2Body)) {
            return handleBootstrap(msgId, l2Body);
        }
        return handleSealed(msgId, l2Body, srcHashHint);
    }

    // ------------------------------------------------------------ bootstrap (§4.2.1)

    private byte[] handleBootstrap(int msgId, byte[] l2Body) {
        Envelope req;
        byte[] walletPubkey;
        try {
            byte[] l3 = L2.parseBootstrap(l2Body);
            req = Envelope.decode(l3);
            if (req.opcode() != Op.HELLO) {
                // Bootstrap form is only ever valid for HELLO (§4.2.1).
                log.warn("bootstrap-form message with opcode 0x{} discarded",
                        Integer.toHexString(req.opcode()));
                throw new SessionException("bootstrap form accepted only for HELLO");
            }
            // wallet_pubkey is field index 1 ([l1_version, wallet_pubkey, [ops...]]).
            walletPubkey = ((meshu.core.l3.Cbor.Value.Bytes) req.fields().get(1)).value();
        } catch (RuntimeException e) {
            // Malformed bootstrap → session-level rejection (H3), never a crash.
            log.warn("malformed bootstrap message: {}", e.toString());
            throw new SessionException("malformed bootstrap HELLO");
        }

        KeyAgreement.DirectionalKeys keys;
        try {
            keys = pairing.pinIfNew(walletPubkey);
        } catch (PairingService.PairingException e) {
            throw new SessionException("pairing refused: " + e.getMessage());
        }
        pairing.seen(walletPubkey);

        // Build + seal the HELLO response to the (possibly just-pinned) key.
        Envelope resp = dispatcher.dispatchHello(walletPubkey, pairing.daemonPublicKey());
        return sealForWallet(keys, walletPubkey, msgId, Op.responseOf(Op.HELLO), resp.encode());
    }

    // ------------------------------------------------------------ sealed messages

    private byte[] handleSealed(int msgId, byte[] l2Body, int srcHashHint) {
        int epoch = l2Body[0] & 0xFF;

        // Identify the wallet by finding a pinned key that opens the message.
        // Try the src-hash-consistent candidates first, then all (§2.3).
        byte[] walletPubkey = null;
        KeyAgreement.DirectionalKeys keys = null;
        byte[] l3 = null;

        for (byte[] candidate : pairing.allWallets()) {
            if (srcHashHint >= 0 && (candidate[0] & 0xFF) != srcHashHint) {
                continue; // cheap filter; full scan happens below if nothing matches
            }
            var opened = tryOpen(candidate, msgId, l2Body, epoch);
            if (opened != null) {
                walletPubkey = candidate;
                keys = pairing.keysFor(candidate);
                l3 = opened.l3();
                break;
            }
        }
        if (walletPubkey == null) {
            // src hash was a hint only; try every pinned key.
            for (byte[] candidate : pairing.allWallets()) {
                var opened = tryOpen(candidate, msgId, l2Body, epoch);
                if (opened != null) {
                    walletPubkey = candidate;
                    keys = pairing.keysFor(candidate);
                    l3 = opened.l3();
                    break;
                }
            }
        }
        if (walletPubkey == null) {
            // No pinned key opened it. Could be a lost pairing table (§4.2.1) —
            // the wallet will fall back to bootstrap on NACK DECRYPT_FAILED.
            throw new DecryptFailedException("no pinned key verified the message");
        }

        pairing.seen(walletPubkey);
        byte[] walletKey = walletPubkey;

        // Replay cache (§11.1) — the exact-retry / conflict / execute decision.
        ReplayCache.Lookup lookup = replayCache.lookup(walletKey, epoch, msgId, l3);
        switch (lookup) {
            case ReplayCache.Lookup.Hit h -> {
                log.debug("replay cache hit for msg_id {}", msgId);
                return h.sealedResponse();
            }
            case ReplayCache.Lookup.Conflict c ->
                    throw new SessionException("msg_id " + msgId + " reused with different payload — MC_MALFORMED");
            case ReplayCache.Lookup.Incomplete i -> {
                // A prior attempt crashed after recording intent but before
                // storing a response. For state-changing ops the safe answer is
                // to re-execute only if the op is idempotent at the mint (NUT-19)
                // — for the PoC we re-dispatch, relying on mint-side idempotency
                // for SWAP/CHECKSTATE (same-mint, §11.4).
                log.warn("msg_id {} had intent but no response; re-dispatching", msgId);
                return executeAndStore(walletKey, keys, epoch, msgId, l3);
            }
            case ReplayCache.Lookup.Miss m -> {
                replayCache.recordIntent(walletKey, epoch, msgId, l3);
                return executeAndStore(walletKey, keys, epoch, msgId, l3);
            }
        }
    }

    private byte[] executeAndStore(byte[] walletPubkey, KeyAgreement.DirectionalKeys keys,
                                   int epoch, int msgId, byte[] l3) {
        Envelope req;
        try {
            req = Envelope.decode(l3);
        } catch (RuntimeException e) {
            // Malformed L3 (bad CBOR, missing fields) → MC_MALFORMED, §10.3/H3.
            log.warn("malformed L3 for msg_id {}: {}", msgId, e.toString());
            return sealError(keys, walletPubkey, msgId, 0xF002);
        }
        Envelope resp;
        try {
            resp = dispatcher.dispatch(req);
        } catch (OpDispatcher.StaleHandleException e) {
            resp = Ops.error(0xF003); // MC_STALE_HANDLE (§10.3)
        } catch (meshu.gateway.mint.MintClient.MintException e) {
            resp = mintErrorResponse(msgId, e);
        } catch (IllegalArgumentException | IndexOutOfBoundsException | IllegalStateException e) {
            // Decoder/validation bugs in op handling must surface as a protocol
            // error to the wallet, never as a transport-level crash (H3).
            log.warn("malformed request for msg_id {}: {}", msgId, e.toString());
            resp = Ops.error(0xF002); // MC_MALFORMED
        }

        // Cache everything EXCEPT the indeterminate codes (§10.3): if the mint
        // was unreachable/timed out the op may or may not have executed, and a
        // retry must be allowed to proceed (the Incomplete path re-dispatches
        // byte-identically). Deterministic outcomes — success, Cashu codes,
        // malformed/stale-handle — are safely replayable.
        boolean indeterminate = resp.opcode() == Op.ERROR && hasCode(resp, 0xF004, 0xF005);
        byte[] sealed = sealForWallet(keys, walletPubkey, msgId, resp.opcode(), resp.encode());
        if (!indeterminate) {
            replayCache.store(walletPubkey, epoch, msgId, sealed);
        }
        return sealed;
    }

    /** True if the ERROR envelope's code equals one of {@code codes}. */
    private static boolean hasCode(Envelope err, long... codes) {
        if (err.fields().isEmpty()
                || !(err.fields().getFirst() instanceof meshu.core.l3.Cbor.Value.Uint u)) {
            return false;
        }
        long code = u.longValue();
        for (long c : codes) {
            if (code == c) {
                return true;
            }
        }
        return false;
    }

    /**
     * Map a mint failure to the ERROR envelope the wallet needs (§10.2/§10.3):
     * deterministic Cashu codes are forwarded verbatim; only transport failures
     * become the indeterminate MC_MINT_UNREACHABLE / MC_MINT_TIMEOUT.
     */
    private static Envelope mintErrorResponse(int msgId, meshu.gateway.mint.MintClient.MintException e) {
        log.warn("mint error for msg_id {}: {}", msgId, e.getMessage());
        return switch (e.kind()) {
            case CASHU -> Ops.error(e.cashuCode());          // deterministic: 11001 etc.
            case TIMEOUT -> Ops.error(0xF005);               // MC_MINT_TIMEOUT — indeterminate
            case TRANSPORT -> Ops.error(0xF004);             // MC_MINT_UNREACHABLE — indeterminate
            case HTTP -> Ops.error(0xF009);                  // MC_MINT_HTTP_ERROR
        };
    }

    /** Seal an ERROR envelope with the given code under k_g2w. */
    private byte[] sealError(KeyAgreement.DirectionalKeys keys, byte[] walletPubkey,
                             int msgId, long code) {
        Envelope err = Ops.error(code);
        return sealForWallet(keys, walletPubkey, msgId, err.opcode(), err.encode());
    }

    private byte[] sealForWallet(KeyAgreement.DirectionalKeys keys, byte[] walletPubkey,
                                 int msgId, int opcodeHint, byte[] l3Response) {
        // Responses travel gateway → wallet under k_g2w, dir = 0x01 (§4.5).
        // Epoch 0 for the PoC (no rekey yet, §4.6).
        return L2.seal(keys.gatewayToWallet(), 0, L2.DIR_G2W, msgId, opcodeHint, l3Response);
    }

    // ------------------------------------------------------------ AEAD open helper

    private record Opened(byte[] l3) {
    }

    /**
     * Try to open a sealed message under a candidate wallet key. Returns null on
     * tag-verification failure (wrong key), the plaintext on success.
     *
     * <p>§4.5's AAD commits to the opcode_hint, which the gateway cannot know
     * before decrypting (it lives inside the ciphertext). Resolution: the
     * request-opcode space is small and bounded (0x01–0x0D), so we trial-open
     * with each plausible hint — a wrong hint fails the Poly1305 tag exactly as
     * a wrong key would. The L3 is NOT decoded here: malformed plaintext must
     * surface as MC_MALFORMED in {@link #executeAndStore}, not as a false
     * "wrong key" during identification.
     */
    private Opened tryOpen(byte[] walletPubkey, int msgId, byte[] l2Body, int epoch) {
        KeyAgreement.DirectionalKeys keys = pairing.keysFor(walletPubkey);
        byte[] l3 = openLenient(keys.walletToGateway(), msgId, l2Body, epoch);
        if (l3 == null) {
            return null;
        }
        return new Opened(l3);
    }

    /**
     * Open a wallet→gateway sealed message by trial over the bounded
     * request-opcode space (0x01–0x0D), since the AAD's opcode_hint is only
     * knowable after decryption. The correct (key, hint) pair verifies the tag.
     */
    private byte[] openLenient(byte[] key, int msgId, byte[] l2Body, int epoch) {
        byte[] sealed = l2Body.clone();
        sealed[0] = (byte) epoch;
        for (int opcode = 0x01; opcode <= 0x0D; opcode++) {
            try {
                return L2.open(key, L2.DIR_W2G, msgId, opcode, sealed);
            } catch (L2.AeadException e) {
                // wrong hint or wrong key — try next
            }
        }
        return null;
    }

    /** Inbound message could not be authenticated (→ NACK DECRYPT_FAILED, §3.8). */
    public static final class DecryptFailedException extends RuntimeException {
        public DecryptFailedException(String message) {
            super(message);
        }
    }

    /** A session-level failure (bootstrap misuse, pairing, replay conflict). */
    public static final class SessionException extends RuntimeException {
        public SessionException(String message) {
            super(message);
        }
    }
}
