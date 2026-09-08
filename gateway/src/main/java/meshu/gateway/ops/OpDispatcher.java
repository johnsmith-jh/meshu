package meshu.gateway.ops;

import meshu.core.l3.Cbor;
import meshu.core.l3.Envelope;
import meshu.core.l3.Op;
import meshu.core.l3.Ops;
import meshu.core.l3.PackedBlobs;
import meshu.gateway.mint.MintClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Routes decoded Meshu L3 requests to the mint and builds L3 responses.
 *
 * <p>This is the heart of the gateway daemon: a wallet's sealed, decoded op
 * arrives as an {@link Envelope}; the dispatcher resolves session handles
 * (§6.4/§6.5), calls the {@link MintClient}, and encodes the response. Replay
 * caching (§11.1) wraps this at the transport layer, keyed by
 * (wallet_pubkey, epoch, msg_id, hash(L3)) — see the caller.
 *
 * <p>Keyset handles are the position of a keyset in the gateway's advertised
 * KEYSETS list (§8.10); mint handles index the HELLO mint list (§6.5). Both are
 * per-session and MUST be re-resolved on stale-handle errors.
 */
@Component
public final class OpDispatcher {

    private final MintClient mint;
    private final SessionState session;

    @Autowired
    public OpDispatcher(MintClient mint, meshu.gateway.config.GatewayProperties props) {
        this.mint = mint;
        this.session = new SessionState();
        this.session.mintUrls.add(props.mint().url());
    }

    /** Test/CLI constructor with an explicit session cache. */
    public OpDispatcher(MintClient mint, SessionState session) {
        this.mint = mint;
        this.session = session;
    }

    /** Per-wallet session state: handle tables + cached keysets. */
    public static final class SessionState {
        /** Mint URLs in HELLO order (§8.1); mint_handle is the index. */
        public final List<String> mintUrls = new ArrayList<>();
        /** Keyset IDs in KEYSETS order (§8.10); keyset handle is the index. */
        public final List<String> keysetIds = new ArrayList<>();
        /** Short keyset IDs (8 bytes) aligned with keysetIds, for the wire. */
        public final List<byte[]> keysetShortIds = new ArrayList<>();
    }

    /** Dispatch one decoded request envelope to a response envelope. */
    public Envelope dispatch(Envelope req) throws MintClient.MintException {
        return switch (req.opcode()) {
            case Op.HELLO -> hello(req);
            case Op.KEYSETS -> keysets(req);
            case Op.KEYS -> keys(req);
            case Op.CHECKSTATE -> checkstate(req);
            case Op.SWAP -> swap(req);
            case Op.RESTORE -> restore(req);
            case Op.MINT_INFO -> mintInfo(req);
            default -> Ops.error(0xF001); // MC_UNSUPPORTED_OP (§10.3)
        };
    }

    // ------------------------------------------------------------ HELLO (§8.1)

    /**
     * Build a HELLO response with the real gateway pubkey (§8.1). Called by the
     * session layer, which owns the daemon identity; {@code walletPubkey} is the
     * pinned identity the response is sealed to.
     */
    public Envelope dispatchHello(byte[] walletPubkey, byte[] gatewayPubkey) {
        if (session.mintUrls.isEmpty()) {
            session.mintUrls.add(mintBaseUrl());
        }
        return Ops.helloResponse(
                1,
                gatewayPubkey,
                session.mintUrls,
                nut19CachedPaths(),
                40000,                           // MESHU_MAX_MSG (§3.2)
                System.currentTimeMillis() / 1000);
    }

    private Envelope hello(Envelope req) throws MintClient.MintException {
        // HELLO via generic dispatch (no wallet/daemon identity in scope): the
        // session layer should use dispatchHello instead. This path exists for
        // direct testing.
        return dispatchHello(new byte[32], new byte[32]);
    }

    // ------------------------------------------------------------ KEYSETS (§8.10)

    private Envelope keysets(Envelope req) throws MintClient.MintException {
        int mintHandle = uint(req, 0, "mint_handle");
        requireMintHandle(mintHandle);

        List<MintClient.KeysetInfo> keysets = mint.getKeysets();
        session.keysetIds.clear();
        session.keysetShortIds.clear();

        List<Ops.KeysetEntry> entries = new ArrayList<>();
        for (MintClient.KeysetInfo k : keysets) {
            byte[] idBytes = MintClient.hex(k.id());
            byte[] shortId = new byte[8];
            System.arraycopy(idBytes, 0, shortId, 0, 8);
            session.keysetIds.add(k.id());
            session.keysetShortIds.add(shortId);
            entries.add(new Ops.KeysetEntry(
                    shortId, k.unit(), k.active(), k.inputFeePpk(),
                    k.finalExpiry() == null ? 0 : k.finalExpiry()));
        }
        return Ops.keysetsResponse(entries);
    }

    // ------------------------------------------------------------ KEYS (§8.11)

    private Envelope keys(Envelope req) throws MintClient.MintException {
        int handle = uint(req, 0, "keyset_handle");
        String keysetId = resolveKeyset(handle);
        Integer fromExp = optUint(req, 1);
        Integer toExp = optUint(req, 2);

        Map<Integer, byte[]> keysByExp = mint.getKeys(keysetId);
        // Range-request: only exponents from_exp..to_exp (§8.11).
        int from = fromExp == null ? 0 : fromExp;
        int to = toExp == null ? 63 : toExp;
        List<byte[]> keys = new ArrayList<>();
        for (int e = from; e <= to; e++) {
            byte[] k = keysByExp.get(e);
            if (k == null) {
                throw new IllegalArgumentException("mint has no key for exponent " + e);
            }
            keys.add(k);
        }
        // §8.11 response carries s_id + keys blob. NOTE: PackedBlobs.packKeys
        // expects exactly 64; for ranged responses we pack the sublist directly.
        byte[] shortId = session.keysetShortIds.get(handle);
        return keysResponseRanged(shortId, keys);
    }

    /** KEYS response with a (possibly ranged) keys blob — n×33, not fixed 64. */
    private static Envelope keysResponseRanged(byte[] shortId, List<byte[]> keys) {
        return Envelope.of(Op.responseOf(Op.KEYS),
                Cbor.bytes(shortId),
                Cbor.bytes(PackedBlobs.packSignatures(keys)));
    }

    // ------------------------------------------------------------ CHECKSTATE (§8.9)

    private Envelope checkstate(Envelope req) throws MintClient.MintException {
        byte[] yBlob = bytes(req, 0, "y_blob");
        List<byte[]> ys = PackedBlobs.unpackYs(yBlob);
        List<MintClient.ProofState> states = mint.checkState(ys);
        int[] packed = new int[states.size()];
        for (int i = 0; i < states.size(); i++) {
            packed[i] = switch (states.get(i)) {
                case UNSPENT -> Ops.STATE_UNSPENT;
                case PENDING -> Ops.STATE_PENDING;
                case SPENT -> Ops.STATE_SPENT;
            };
        }
        return Ops.checkstateResponse(packed);
    }

    // ------------------------------------------------------------ SWAP (§8.13)

    private Envelope swap(Envelope req) throws MintClient.MintException {
        int handle = uint(req, 0, "keyset_handle");
        String keysetId = resolveKeyset(handle);
        List<PackedBlobs.Proof> inputs = PackedBlobs.unpackProofs(bytes(req, 1, "inputs_blob"));
        List<PackedBlobs.Output> outputs = PackedBlobs.unpackOutputs(bytes(req, 2, "outputs_blob"));

        List<MintClient.Proof> in = inputs.stream()
                .map(p -> new MintClient.Proof(
                        1L << p.exponent(), keysetId,
                        MintClient.hexStr(p.secret()), p.c()))
                .toList();
        List<MintClient.BlindedMessage> out = outputs.stream()
                .map(o -> new MintClient.BlindedMessage(1L << o.exponent(), keysetId, o.blindedMessage()))
                .toList();

        List<MintClient.BlindSignature> sigs = mint.swap(in, out);
        return Ops.swapResponse(sigs.stream().map(MintClient.BlindSignature::c).toList());
    }

    // ------------------------------------------------------------ RESTORE (§8.8)

    private Envelope restore(Envelope req) throws MintClient.MintException {
        // req fields (after opcode): [0]=keyset_handle [1]=counter_start
        // [2]=count [3]=outputs_blob — matching Ops.restoreRequest.
        int handle = uint(req, 0, "keyset_handle");
        String keysetId = resolveKeyset(handle);
        long counterStart = longOf(req, 1, "counter_start");
        int count = uint(req, 2, "count");
        List<PackedBlobs.Output> outputs = PackedBlobs.unpackOutputs(bytes(req, 3, "outputs_blob"));

        List<MintClient.BlindedMessage> blinded = outputs.stream()
                .map(o -> new MintClient.BlindedMessage(1L << o.exponent(), keysetId, o.blindedMessage()))
                .toList();
        MintClient.RestoreResult result = mint.restore(blinded);

        // Build the hit bitmap: which requested outputs came back signed (§8.8).
        byte[] bitmap = new byte[(count + 7) / 8];
        List<byte[]> sigs = new ArrayList<>();
        // Mint returns only the hits, in the order they matched. Match by B_ bytes.
        List<byte[]> returnedB = result.outputs().stream().map(MintClient.BlindedMessage::blinded).toList();
        for (int i = 0; i < outputs.size() && i < count; i++) {
            int idx = indexOfBytes(returnedB, outputs.get(i).blindedMessage());
            if (idx >= 0) {
                bitmap[i >> 3] |= (byte) (1 << (i & 7));
                sigs.add(result.signatures().get(idx).c());
            }
        }
        return Ops.restoreResponse(bitmap, sigs);
    }

    // ------------------------------------------------------------ MINT_INFO (§8.12)

    private Envelope mintInfo(Envelope req) throws MintClient.MintException {
        int mintHandle = uint(req, 0, "mint_handle");
        requireMintHandle(mintHandle);
        // The gateway projects only a subset of NUT-06 (§8.12); for the PoC we
        // return a minimal, well-formed response. Full projection is a TODO.
        return Envelope.of(Op.responseOf(Op.MINT_INFO),
                Cbor.text(mintBaseUrl()),
                Cbor.array(List.of()),           // nut numbers — TODO: project from /v1/info
                Cbor.uint(1),                    // min_amount
                Cbor.uint(1_000_000),            // max_amount
                Cbor.array(List.of()),           // method_unit_pairs — TODO
                Cbor.Value.Null.INSTANCE);       // nut19_ttl
    }

    // ------------------------------------------------------------ helpers

    private String mintBaseUrl() {
        // Single-mint PoC: the one configured mint URL.
        return session.mintUrls.isEmpty() ? "" : session.mintUrls.get(0);
    }

    private List<String> nut19CachedPaths() {
        // TODO(§11.3): read 19.cached_endpoints from mint info.
        return List.of();
    }

    private String resolveKeyset(int handle) {
        if (handle < 0 || handle >= session.keysetIds.size()) {
            throw new StaleHandleException("keyset handle " + handle + " unknown (§6.4)");
        }
        return session.keysetIds.get(handle);
    }

    private void requireMintHandle(int handle) {
        if (handle != 0) {
            throw new StaleHandleException("mint handle " + handle + " unknown — single-mint PoC (§6.5)");
        }
    }

    private static int uint(Envelope e, int idx, String what) {
        Cbor.Value v = e.fields().get(idx);
        if (!(v instanceof Cbor.Value.Uint u)) {
            throw new IllegalArgumentException("expected uint for " + what);
        }
        return u.intValue();
    }

    private static Integer optUint(Envelope e, int idx) {
        if (idx >= e.fields().size()) {
            return null;
        }
        Cbor.Value v = e.fields().get(idx);
        return v instanceof Cbor.Value.Uint u ? u.intValue() : null;
    }

    private static long longOf(Envelope e, int idx, String what) {
        Cbor.Value v = e.fields().get(idx);
        if (!(v instanceof Cbor.Value.Uint u)) {
            throw new IllegalArgumentException("expected uint for " + what);
        }
        return u.longValue();
    }

    private static byte[] bytes(Envelope e, int idx, String what) {
        Cbor.Value v = e.fields().get(idx);
        if (!(v instanceof Cbor.Value.Bytes b)) {
            throw new IllegalArgumentException("expected bytes for " + what);
        }
        return b.value();
    }

    private static int indexOfBytes(List<byte[]> list, byte[] target) {
        for (int i = 0; i < list.size(); i++) {
            if (java.util.Arrays.equals(list.get(i), target)) {
                return i;
            }
        }
        return -1;
    }

    /** Handle resolution failure → gateway replies MC_STALE_HANDLE (§10.3). */
    public static final class StaleHandleException extends RuntimeException {
        public StaleHandleException(String message) {
            super(message);
        }
    }
}
