package meshu.gateway.mesh;

import meshu.core.l1.AirtimeGovernor;
import meshu.core.l1.FrameHeader;
import meshu.core.l1.FrameKind;
import meshu.core.l1.MessageSender;
import meshu.core.l1.Reassembler;
import meshu.core.l1.Segmenter;
import meshu.core.l2.KeyAgreement;
import meshu.core.l2.L2;
import meshu.core.l3.Envelope;
import meshu.core.l3.Op;
import meshu.core.l3.Ops;
import meshu.core.l3.PackedBlobs;
import meshu.gateway.mint.MintClient;
import meshu.gateway.ops.OpDispatcher;
import meshu.gateway.session.PairingService;
import meshu.gateway.session.ReplayCache;
import meshu.gateway.session.SessionService;
import org.junit.jupiter.api.AfterEach;
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
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

/**
 * MeshGateway over a fake radio: proves the §2 binding + §3.4/3.7 delivery +
 * session pipeline end-to-end WITHOUT hardware — bootstrap HELLO over the air,
 * fragmented requests with ACKBM exchange, PING echo, dst pre-filter, and
 * TABLE_FULL backpressure.
 */
class MeshGatewayTest {

    /** Scriptable radio: records transmissions, can fail the first K sends as TABLE_FULL. */
    static class FakeRawRadio implements RawDatagramRadio {
        final List<byte[]> transmitted = new CopyOnWriteArrayList<>();
        volatile Consumer<byte[]> handler;
        volatile int busyFirstSends = 0;

        @Override
        public void send(byte[] payload) throws RadioException {
            if (busyFirstSends > 0) {
                busyFirstSends--;
                throw new RadioBusyException();
            }
            transmitted.add(payload);
        }

        @Override
        public void onReceive(Consumer<byte[]> h) {
            this.handler = h;
        }

        void deliverToGateway(byte[] rawPayload) {
            handler.accept(rawPayload);
        }

        int dataFrameCount() {
            return (int) transmitted.stream().filter(t -> (t[2] & 0x3F) == FrameKind.DATA).count();
        }
    }

    static class StubMint extends MintClient {
        List<KeysetInfo> keysets = new ArrayList<>();
        Map<Integer, byte[]> keys = new LinkedHashMap<>();
        List<BlindedMessage> lastRestoreOutputs;

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
        public RestoreResult restore(List<BlindedMessage> outputs) {
            this.lastRestoreOutputs = outputs;
            return new RestoreResult(List.of(), List.of());
        }
    }

    SingleConnectionDataSource ds;
    JdbcTemplate db;
    PairingService pairing;
    StubMint mint;
    OpDispatcher dispatcher;
    SessionService session;
    FakeRawRadio radio;
    MeshGateway gateway;
    KeyPair walletKey;
    byte[] walletPub;

    // gateway node identity (radio), distinct from daemon X25519 identity
    final byte gatewayNodeHash = (byte) 0x7F;
    final byte walletNodeHash = (byte) 0x3A;

    @BeforeEach
    void setup() throws Exception {
        ds = new SingleConnectionDataSource("jdbc:sqlite::memory:", true);
        db = new JdbcTemplate(ds);
        runSchema();

        var daemonIdentity = new meshu.gateway.crypto.DaemonIdentity(db);
        pairing = new PairingService(db, daemonIdentity);
        var replayCache = new ReplayCache(db);
        mint = new StubMint();
        var sessionState = new OpDispatcher.SessionState();
        sessionState.mintUrls.add("https://mint.test/Bitcoin");
        dispatcher = new OpDispatcher(mint, sessionState);
        session = new SessionService(pairing, replayCache, dispatcher);

        walletKey = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        walletPub = rawPub(walletKey);

        mint.keysets.add(new MintClient.KeysetInfo(
                "01fc0ec0e59cd6fa01b7a88f8cd77fce81fd1e64bca67d752e984992b7a3c3a821",
                "sat", true, 0, null));

        radio = new FakeRawRadio();
        AirtimeGovernor governor = new AirtimeGovernor(1.0, 8, 20);
        gateway = new MeshGateway(radio, session, governor, gatewayNodeHash,
                MessageSender.Config.fast(250, 20));
        gateway.start();
    }

    @AfterEach
    void teardown() throws Exception {
        gateway.stop();
        ds.getConnection().close();
    }

    private void runSchema() throws Exception {
        String schema = new String(java.util.Objects.requireNonNull(
                getClass().getResourceAsStream("/schema.sql")).readAllBytes());
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

    private static byte[] rawPub(KeyPair kp) {
        byte[] enc = kp.getPublic().getEncoded();
        return Arrays.copyOfRange(enc, enc.length - 32, enc.length);
    }

    /** Wire a raw payload toward the gateway: dst ‖ src ‖ L1 frame. */
    private void sendOverAir(byte[] l1Frame) {
        byte[] raw = new byte[2 + l1Frame.length];
        raw[0] = gatewayNodeHash;
        raw[1] = walletNodeHash;
        System.arraycopy(l1Frame, 0, raw, 2, l1Frame.length);
        radio.deliverToGateway(raw);
    }

    /** Wait until the condition holds or timeout. */
    private static void await(long timeoutMs, Supplier<Boolean> cond) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (!Boolean.TRUE.equals(cond.get())) {
            if (System.currentTimeMillis() > deadline) {
                return;
            }
            Thread.sleep(25);
        }
    }

    // ------------------------------------------------------------ tests

    @Test
    void bootstrapHelloOverAirGetsSealedReply() throws Exception {
        Envelope helloReq = Ops.helloRequest(1, walletPub, new int[]{Op.HELLO});
        sendOverAir(concat(FrameHeader.dataSingle(1, 0, true).encode(), L2.bootstrap(helloReq.encode())));

        // Expect: an ACKBM for the inbound frame + a sealed response DATA frame.
        await(3000, () -> radio.dataFrameCount() >= 1);

        assertTrue(radio.dataFrameCount() >= 1, "sealed response should be transmitted");
        boolean sawAckbm = radio.transmitted.stream()
                .anyMatch(t -> (t[2] & 0xFF) == FrameKind.ACKBM);
        assertTrue(sawAckbm, "inbound REQ_ACK must be answered with an ACKBM");

        // Wallet side: open the response DATA frame.
        byte[] respFrame = radio.transmitted.stream()
                .filter(t -> (t[2] & 0xFF) == FrameKind.DATA)
                .findFirst().orElseThrow();
        FrameHeader.Parsed p = FrameHeader.parse(respFrame, 2);
        assertEquals(1, p.header().msgId());
        assertTrue(p.header().reqAck(), "response must request ACK");
        byte[] sealed = Arrays.copyOfRange(respFrame, p.bodyOffset(), respFrame.length);

        KeyAgreement.DirectionalKeys walletKeys =
                KeyAgreement.derive(walletKey.getPrivate(), pairing.daemonPublicKey());
        byte[] l3 = L2.open(walletKeys.gatewayToWallet(), L2.DIR_G2W, 1, Op.responseOf(Op.HELLO), sealed);
        Envelope resp = Envelope.decode(l3);
        assertEquals(Op.responseOf(Op.HELLO), resp.opcode());
        assertTrue(pairing.isPinned(walletPub));
    }

    @Test
    void fragmentedRequestOverAirGetsAssembledAndAnswered() throws Exception {
        // Establish pairing via bootstrap first.
        Envelope helloReq = Ops.helloRequest(1, walletPub, new int[]{Op.HELLO});
        sendOverAir(concat(FrameHeader.dataSingle(1, 0, true).encode(),
                L2.bootstrap(helloReq.encode())));
        await(3000, () -> radio.dataFrameCount() >= 1);

        // Seed keyset handles so RESTORE resolves.
        dispatcher.dispatch(Ops.keysetsRequest(0));

        // Build a big sealed RESTORE (>161 B body → 3 fragments).
        List<PackedBlobs.Output> outputs = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            byte[] b = new byte[33];
            b[0] = 0x02;
            b[31] = (byte) i;
            outputs.add(new PackedBlobs.Output(0, b));
        }
        byte[] l3 = Ops.restoreRequest(0, 0, 10, outputs).encode();
        KeyAgreement.DirectionalKeys walletKeys =
                KeyAgreement.derive(walletKey.getPrivate(), pairing.daemonPublicKey());
        int msgId = 42;
        byte[] sealed = L2.seal(walletKeys.walletToGateway(), 0, L2.DIR_W2G, msgId, Op.RESTORE, l3);

        // Send it as a wallet would: segmented, REQ_ACK per Segmenter policy.
        List<Segmenter.Frame> frames = Segmenter.segment(msgId, sealed, Segmenter.MTU_FLOOR);
        assertEquals(3, frames.size());
        for (Segmenter.Frame f : frames) {
            sendOverAir(f.encode());
            Thread.sleep(30); // let the gateway ACK between frames
        }

        // Wallet receives the response DATA frame(s); answer their REQ_ACKs so
        // the gateway's MessageSender completes instead of retrying forever.
        await(4000, () -> radio.dataFrameCount() >= 1);
        // Respond to every un-ACKed response frame with a full bitmap ACKBM.
        for (byte[] t : radio.transmitted) {
            if ((t[2] & 0xFF) == FrameKind.DATA) {
                var hp = FrameHeader.parse(t, 2).header();
                int total = hp.multi() ? hp.lastSeq() + 1 : 1;
                // Extra pad bits beyond total are ignored by the receiver (§3.6).
                byte[] bm = new byte[(total + 7) / 8];
                Arrays.fill(bm, (byte) 0xFF);
                byte[] ack = Reassembler.ackbmFrame(hp.msgId(), total, bm);
                byte[] raw = new byte[2 + ack.length];
                raw[0] = gatewayNodeHash;
                raw[1] = walletNodeHash;
                System.arraycopy(ack, 0, raw, 2, ack.length);
                radio.deliverToGateway(raw);
            }
        }

        // The gateway dispatched the op to the stub mint.
        await(2000, () -> mint.lastRestoreOutputs != null);
        assertNotNull(mint.lastRestoreOutputs);
        assertEquals(10, mint.lastRestoreOutputs.size());
        assertTrue(mint.lastRestoreOutputs.get(0).amount() == 1L);
    }

    @Test
    void pingEchoesBackWithSameMsgId() throws Exception {
        byte[] ping = new FrameHeader(0, FrameKind.PING, 0, 0x0099, null, null).encode();
        sendOverAir(ping);

        await(2000, () -> !radio.transmitted.isEmpty());
        assertEquals(1, radio.transmitted.size());
        byte[] reply = radio.transmitted.getFirst();
        // Reply is addressed to the wallet's node hash, from ours.
        assertEquals(walletNodeHash, reply[0]);
        assertEquals(gatewayNodeHash, reply[1]);
        FrameHeader.Parsed p = FrameHeader.parse(reply, 2);
        assertEquals(FrameKind.PING, p.header().kind());
        assertEquals(0x0099, p.header().msgId());
    }

    @Test
    void foreignDestinationDroppedBeforeCrypto() throws Exception {
        byte[] ping = new FrameHeader(0, FrameKind.PING, 0, 0x0001, null, null).encode();
        byte[] raw = new byte[2 + ping.length];
        raw[0] = 0x11; // NOT our hash
        raw[1] = walletNodeHash;
        System.arraycopy(ping, 0, raw, 2, ping.length);
        radio.deliverToGateway(raw);

        Thread.sleep(300);
        assertTrue(radio.transmitted.isEmpty(), "frame for another node must be silently dropped");
    }

    @Test
    void tableFullRetriesUntilAccepted() throws Exception {
        radio.busyFirstSends = 2; // first two transmits bounce off a full queue
        byte[] ping = new FrameHeader(0, FrameKind.PING, 0, 0x0077, null, null).encode();
        sendOverAir(ping);

        await(5000, () -> !radio.transmitted.isEmpty());
        assertEquals(1, radio.transmitted.size(), "exactly one copy after retries");
        FrameHeader.Parsed p = FrameHeader.parse(radio.transmitted.getFirst(), 2);
        assertEquals(0x0077, p.header().msgId());
    }

    // ------------------------------------------------------------ helpers

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
