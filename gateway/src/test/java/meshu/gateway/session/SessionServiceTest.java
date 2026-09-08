package meshu.gateway.session;

import meshu.core.l2.KeyAgreement;
import meshu.core.l2.L2;
import meshu.core.l3.Envelope;
import meshu.core.l3.Op;
import meshu.core.l3.Ops;
import meshu.core.l3.PackedBlobs;
import meshu.gateway.mint.MintClient;
import meshu.gateway.ops.OpDispatcher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Session pipeline: TOFU pairing, sealed-message open, replay cache, dispatch.
 * Uses an in-memory SQLite database and a stubbed mint.
 */
class SessionServiceTest {

    private SingleConnectionDataSource ds;
    private JdbcTemplate db;
    private PairingService pairing;
    private ReplayCache replayCache;
    private StubMint mint;
    private OpDispatcher dispatcher;
    private SessionService service;

    private KeyPair walletKey;

    static class StubMint extends MintClient {
        List<KeysetInfo> keysets = new ArrayList<>();
        Map<Integer, byte[]> keys = new LinkedHashMap<>();
        int checkStateCalls = 0;
        List<ProofState> states = new ArrayList<>();
        // When set, the corresponding call throws instead of answering.
        MintException swapError;
        MintException checkStateError;

        StubMint() {
            super("https://mint.test/Bitcoin");
        }

        @Override
        public List<KeysetInfo> getKeysets() {
            return keysets;
        }

        @Override
        public Map<Integer, byte[]> getKeys(String keysetId) {
            return keys;
        }

        @Override
        public List<ProofState> checkState(List<byte[]> ys) throws MintException {
            checkStateCalls++;
            if (checkStateError != null) {
                throw checkStateError;
            }
            return states;
        }

        @Override
        public List<BlindSignature> swap(List<Proof> inputs, List<BlindedMessage> outputs) throws MintException {
            if (swapError != null) {
                throw swapError;
            }
            return new ArrayList<>();
        }
    }

    private static byte[] rawPub(KeyPair kp) {
        byte[] enc = kp.getPublic().getEncoded();
        return Arrays.copyOfRange(enc, enc.length - 32, enc.length);
    }

    @BeforeEach
    void setup() throws Exception {
        ds = new SingleConnectionDataSource("jdbc:sqlite::memory:", true);
        db = new JdbcTemplate(ds);
        runSchema();

        // Daemon identity with a fresh in-memory key.
        meshu.gateway.crypto.DaemonIdentity daemonIdentity =
                new meshu.gateway.crypto.DaemonIdentity(db);
        pairing = new PairingService(db, daemonIdentity);
        replayCache = new ReplayCache(db);
        mint = new StubMint();
        OpDispatcher.SessionState sessionState = new OpDispatcher.SessionState();
        sessionState.mintUrls.add("https://mint.test/Bitcoin");
        dispatcher = new OpDispatcher(mint, sessionState);
        service = new SessionService(pairing, replayCache, dispatcher);

        walletKey = KeyPairGenerator.getInstance("X25519").generateKeyPair();

        // Seed the stub mint with one active keyset.
        mint.keysets.add(new MintClient.KeysetInfo(
                "01fc0ec0e59cd6fa01b7a88f8cd77fce81fd1e64bca67d752e984992b7a3c3a821",
                "sat", true, 0, null));
        for (int e = 0; e < 32; e++) {
            byte[] k = new byte[33];
            k[0] = 0x02;
            k[32] = (byte) e;
            mint.keys.put(e, k);
        }
    }

    private void runSchema() throws Exception {
        String schema = new String(java.util.Objects.requireNonNull(
                getClass().getResourceAsStream("/schema.sql")).readAllBytes());
        // Strip line comments so ';' inside them don't break statement splitting.
        StringBuilder cleaned = new StringBuilder();
        for (String line : schema.split("\n")) {
            int comment = line.indexOf("--");
            cleaned.append(comment >= 0 ? line.substring(0, comment) : line).append('\n');
        }
        for (String stmt : cleaned.toString().split(";")) {
            String s = stmt.strip();
            if (!s.isEmpty()) {
                db.execute(s);
            }
        }
    }

    // ------------------------------------------------------------ TOFU pairing

    @Test
    void bootstrapHelloPinsWalletAndReturnsSealedResponse() {
        byte[] walletPub = rawPub(walletKey);
        Envelope helloReq = Ops.helloRequest(1, walletPub, new int[]{Op.HELLO, Op.KEYSETS});
        byte[] bootstrap = L2.bootstrap(helloReq.encode());

        byte[] respBody = service.handleMessage(1, bootstrap, walletPub[0] & 0xFF);

        assertTrue(pairing.isPinned(walletPub));
        // Response must be sealed (not bootstrap form).
        assertFalse(L2.isBootstrap(respBody));
        // Wallet can open it under k_g2w.
        KeyAgreement.DirectionalKeys walletKeys = KeyAgreement.derive(walletKey.getPrivate(), pairing.daemonPublicKey());
        byte[] l3 = L2.open(walletKeys.gatewayToWallet(), L2.DIR_G2W, 1, Op.responseOf(Op.HELLO), respBody);
        Envelope resp = Envelope.decode(l3);
        assertEquals(Op.responseOf(Op.HELLO), resp.opcode());
    }

    @Test
    void pinnedKeyIsNeverReplaced() {
        byte[] walletPub = rawPub(walletKey);
        pairing.pinIfNew(walletPub);
        // A second bootstrap with the same key must not error or alter the pairing.
        assertDoesNotThrow(() -> pairing.pinIfNew(walletPub));
        assertTrue(pairing.isPinned(walletPub));
    }

    @Test
    void bootstrapWithNonHelloOpcodeIsRejected() {
        byte[] walletPub = rawPub(walletKey);
        Envelope notHello = Ops.keysetsRequest(0);
        byte[] bootstrap = L2.bootstrap(notHello.encode());
        assertThrows(SessionService.SessionException.class,
                () -> service.handleMessage(1, bootstrap, walletPub[0] & 0xFF));
    }

    @Test
    void pairingTableIsBounded() {
        // Fill to MAX_WALLETS with throwaway keys.
        for (int i = 0; i < PairingService.MAX_WALLETS; i++) {
            byte[] k = new byte[32];
            k[31] = (byte) i;
            k[30] = (byte) (i >> 8);
            db.update("INSERT INTO pairing(wallet_pubkey) VALUES (?)", k);
        }
        byte[] extra = rawPub(walletKey);
        assertThrows(PairingService.PairingException.class, () -> pairing.pinIfNew(extra));
    }

    // ------------------------------------------------------------ replay cache

    @Test
    void exactRetryReplaysWithoutReexecuting() throws Exception {
        byte[] walletPub = rawPub(walletKey);
        pairing.pinIfNew(walletPub);
        // Pre-seed keyset handles so KEYS resolves.
        service.handleMessage(1, L2.bootstrap(Ops.helloRequest(1, walletPub, new int[]{Op.HELLO}).encode()), walletPub[0] & 0xFF);
        dispatcher.dispatch(Ops.keysetsRequest(0)); // populate keysetIds in dispatcher session

        // Wallet seals a CHECKSTATE request.
        mint.states.add(MintClient.ProofState.UNSPENT);
        List<byte[]> ys = List.of(fillByte33((byte) 7));
        Envelope checkReq = Ops.checkstateRequest(ys);
        KeyAgreement.DirectionalKeys walletKeys = KeyAgreement.derive(walletKey.getPrivate(), pairing.daemonPublicKey());
        byte[] sealed = L2.seal(walletKeys.walletToGateway(), 0, L2.DIR_W2G, 42, Op.CHECKSTATE, checkReq.encode());

        byte[] resp1 = service.handleMessage(42, sealed, walletPub[0] & 0xFF);
        assertEquals(1, mint.checkStateCalls);

        // Identical retry → cached response, no re-execution.
        byte[] resp2 = service.handleMessage(42, sealed, walletPub[0] & 0xFF);
        assertEquals(1, mint.checkStateCalls, "retry must not re-execute the mint call");
        assertArrayEquals(resp1, resp2);
    }

    @Test
    void msgIdConflictIsMalformed() throws Exception {
        byte[] walletPub = rawPub(walletKey);
        pairing.pinIfNew(walletPub);
        service.handleMessage(1, L2.bootstrap(Ops.helloRequest(1, walletPub, new int[]{Op.HELLO}).encode()), walletPub[0] & 0xFF);
        dispatcher.dispatch(Ops.keysetsRequest(0));

        // First message with msg_id 42.
        mint.states.add(MintClient.ProofState.UNSPENT);
        KeyAgreement.DirectionalKeys walletKeys = KeyAgreement.derive(walletKey.getPrivate(), pairing.daemonPublicKey());
        byte[] first = L2.seal(walletKeys.walletToGateway(), 0, L2.DIR_W2G, 42, Op.CHECKSTATE,
                Ops.checkstateRequest(List.of(fillByte33((byte) 1))).encode());
        service.handleMessage(42, first, walletPub[0] & 0xFF);

        // Same msg_id, DIFFERENT payload → conflict.
        byte[] second = L2.seal(walletKeys.walletToGateway(), 0, L2.DIR_W2G, 42, Op.CHECKSTATE,
                Ops.checkstateRequest(List.of(fillByte33((byte) 2), fillByte33((byte) 3))).encode());
        assertThrows(SessionService.SessionException.class,
                () -> service.handleMessage(42, second, walletPub[0] & 0xFF));
    }

    @Test
    void unknownKeyFailsDecrypt() {
        // No pairing for this wallet; a sealed message should not verify.
        KeyPair stranger;
        try {
            stranger = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        KeyAgreement.DirectionalKeys keys = KeyAgreement.derive(stranger.getPrivate(), pairing.daemonPublicKey());
        byte[] sealed = L2.seal(keys.walletToGateway(), 0, L2.DIR_W2G, 1, Op.CHECKSTATE,
                Ops.checkstateRequest(List.of(fillByte33((byte) 1))).encode());
        assertThrows(SessionService.DecryptFailedException.class,
                () -> service.handleMessage(1, sealed, 0));
    }

    /** Review H3: malformed L3 plaintext → ERROR MC_MALFORMED envelope, not a crash. */
    @Test
    void malformedSealedL3ReturnsMcMalformed() throws Exception {
        byte[] walletPub = rawPub(walletKey);
        pairing.pinIfNew(walletPub);
        KeyAgreement.DirectionalKeys walletKeys = KeyAgreement.derive(walletKey.getPrivate(), pairing.daemonPublicKey());

        // Valid seal around a garbage "L3" payload (not CBOR).
        byte[] sealed = L2.seal(walletKeys.walletToGateway(), 0, L2.DIR_W2G, 55, Op.CHECKSTATE,
                new byte[]{(byte) 0xFF, 0x01, 0x02});
        byte[] respBody = service.handleMessage(55, sealed, walletPub[0] & 0xFF);

        byte[] l3 = L2.open(walletKeys.gatewayToWallet(), L2.DIR_G2W, 55, Op.ERROR, respBody);
        Envelope resp = Envelope.decode(l3);
        assertEquals(Op.ERROR, resp.opcode());
        Ops.ErrorResponse err = Ops.parseError(resp);
        assertEquals(0xF002, err.code());
    }

    /** Review H1: deterministic Cashu error (11001) forwarded verbatim. */
    @Test
    void cashuErrorCodeForwardedVerbatim() throws Exception {
        byte[] walletPub = rawPub(walletKey);
        pairing.pinIfNew(walletPub);
        KeyAgreement.DirectionalKeys walletKeys = KeyAgreement.derive(walletKey.getPrivate(), pairing.daemonPublicKey());

        // Seed the keyset handle table so SWAP's handle 0 resolves.
        dispatcher.dispatch(Ops.keysetsRequest(0));

        mint.swapError = new MintClient.MintException(
                MintClient.MintException.Kind.CASHU, 11001L, "proofs already spent");

        List<PackedBlobs.Proof> inputs = List.of(new PackedBlobs.Proof(1, fill32((byte) 3), fill33((byte) 4)));
        List<PackedBlobs.Output> outputs = List.of(new PackedBlobs.Output(1, fill33((byte) 5)));
        byte[] sealed = L2.seal(walletKeys.walletToGateway(), 0, L2.DIR_W2G, 60, Op.SWAP,
                Ops.swapRequest(0, inputs, outputs).encode());
        byte[] respBody = service.handleMessage(60, sealed, walletPub[0] & 0xFF);

        byte[] l3 = L2.open(walletKeys.gatewayToWallet(), L2.DIR_G2W, 60, Op.ERROR, respBody);
        Ops.ErrorResponse err = Ops.parseError(Envelope.decode(l3));
        assertEquals(11001, err.code(), "deterministic Cashu code must reach the wallet verbatim");
    }

    /** Review H1 corollary: indeterminate errors are NOT cached — retry re-dispatches. */
    @Test
    void indeterminateErrorIsNotCached() throws Exception {
        byte[] walletPub = rawPub(walletKey);
        pairing.pinIfNew(walletPub);
        KeyAgreement.DirectionalKeys walletKeys = KeyAgreement.derive(walletKey.getPrivate(), pairing.daemonPublicKey());

        mint.states.add(MintClient.ProofState.UNSPENT);
        mint.checkStateError = new MintClient.MintException(
                MintClient.MintException.Kind.TIMEOUT, null, "mint timeout");

        byte[] sealed = L2.seal(walletKeys.walletToGateway(), 0, L2.DIR_W2G, 70, Op.CHECKSTATE,
                Ops.checkstateRequest(List.of(fillByte33((byte) 9))).encode());
        byte[] first = service.handleMessage(70, sealed, walletPub[0] & 0xFF);
        byte[] firstL3 = L2.open(walletKeys.gatewayToWallet(), L2.DIR_G2W, 70, Op.ERROR, first);
        assertEquals(0xF005, Ops.parseError(Envelope.decode(firstL3)).code());

        // Mint recovers; the identical retry must re-execute and now succeed.
        mint.checkStateError = null;
        int callsBefore = mint.checkStateCalls;
        byte[] second = service.handleMessage(70, sealed, walletPub[0] & 0xFF);
        assertEquals(callsBefore + 1, mint.checkStateCalls, "retry after indeterminate must re-execute");
        byte[] secondL3 = L2.open(walletKeys.gatewayToWallet(), L2.DIR_G2W, 70, Op.responseOf(Op.CHECKSTATE), second);
        assertArrayEquals(new int[]{Ops.STATE_UNSPENT},
                Ops.parseCheckstateResponse(Envelope.decode(secondL3), 1));
    }

    private static byte[] fill32(byte seed) {
        byte[] b = new byte[32];
        java.util.Arrays.fill(b, seed);
        return b;
    }

    private static byte[] fill33(byte seed) {
        return fillByte33(seed);
    }

    private static byte[] fillByte33(byte seed) {
        byte[] b = new byte[33];
        Arrays.fill(b, seed);
        return b;
    }
}
