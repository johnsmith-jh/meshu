package meshu.gateway.mesh;

import meshu.core.l1.AirtimeGovernor;
import meshu.core.l1.FrameHeader;
import meshu.core.l1.FrameKind;
import meshu.core.l1.MessageSender;
import meshu.core.l1.Reassembler;
import meshu.core.l1.Segmenter;
import meshu.gateway.session.SessionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The mesh-side gateway: binds a {@link RawDatagramRadio} to the L1/L2/session
 * stack (PROTOCOL.md §2–§4). This is where frames meet air.
 *
 * <p>Inbound (radio reader thread → queue → processor):
 * <ol>
 *   <li>{@code dst} filter — mismatch drops the frame BEFORE any crypto (§2.3).</li>
 *   <li>DATA frames feed the {@link Reassembler}; REQ_ACK partials are answered
 *       immediately with the wire-ready ACKBM; a completed message is dispatched
 *       to {@link SessionService#handleMessage} and the sealed response is sent
 *       back via a {@link MessageSender} addressed to the peer's src hash.</li>
 *   <li>PING echoes PING (bench path probe).</li>
 * </ol>
 * Outbound ACKBMs from wallets are routed on the reader thread straight into
 * the in-flight {@code MessageSender}.
 */
public final class MeshGateway {

    private static final Logger log = LoggerFactory.getLogger(MeshGateway.class);

    private final RawDatagramRadio radio;
    private final SessionService session;
    private final AirtimeGovernor governor;
    /** Our own node hash (gateway node pubkey[0], §2.2). */
    private final byte selfHash;
    /** MessageSender tuning for over-the-air responses. */
    private final MessageSender.Config senderConfig;

    private final BlockingQueue<byte[]> inbox = new LinkedBlockingQueue<>();
    private final Reassembler inboundReassembler = new Reassembler();
    /** The response currently being delivered, for ACKBM routing. */
    private final AtomicReference<MessageSender> outbound = new AtomicReference<>();
    /** Last peer seen (bench PoC: single wallet); replies go to this node hash (§2.3). */
    private volatile byte peerHash;
    private volatile boolean running;

    private ExecutorService processor;

    public MeshGateway(RawDatagramRadio radio, SessionService session,
                       AirtimeGovernor governor, byte selfHash, MessageSender.Config senderConfig) {
        this.radio = radio;
        this.session = session;
        this.governor = governor;
        this.selfHash = selfHash;
        this.senderConfig = senderConfig;
    }

    /** Start receiving. Returns immediately; processing runs on a worker thread. */
    public void start() {
        running = true;
        radio.onReceive(this::onRadioFrame);
        processor = Executors.newSingleThreadExecutor(r ->
                Thread.ofPlatform().name("mesh-gateway").daemon(true).unstarted(r));
        processor.submit(() -> {
            while (running) {
                try {
                    handle(inbox.take());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                } catch (Exception e) {
                    log.warn("mesh frame processing failed: {}", e.toString());
                }
            }
        });
        log.info("mesh gateway listening (self hash 0x{})", Integer.toHexString(selfHash & 0xFF));
    }

    public void stop() {
        running = false;
        if (processor != null) {
            processor.shutdownNow();
        }
    }

    /**
     * Radio reader-thread callback: keep it O(1). The dst pre-filter and the
     * ACKBM fast-path happen here; everything else is queued for the processor.
     */
    void onRadioFrame(byte[] rawPayload) {
        // §2.3: dst filter before ANY crypto; dst match is never authentication.
        if (rawPayload.length < 3 || (rawPayload[0] & 0xFF) != (selfHash & 0xFF)) {
            log.info("dropped inbound datagram: {} B, dst=0x{} (we are 0x{}) — not for us",
                    rawPayload.length,
                    rawPayload.length > 0 ? Integer.toHexString(rawPayload[0] & 0xFF) : "??",
                    Integer.toHexString(selfHash & 0xFF));
            return;
        }
        // ACKBM fast path: L1 header starts at payload[2]; route directly into
        // any in-flight outbound sender (its onFrameReceived is thread-safe).
        if ((rawPayload[2] & 0xFF) == FrameKind.ACKBM) {
            MessageSender s = outbound.get();
            if (s != null) {
                byte[] frame = new byte[rawPayload.length - 2];
                System.arraycopy(rawPayload, 2, frame, 0, frame.length);
                s.onFrameReceived(frame);
            }
            return;
        }
        inbox.add(rawPayload);
    }

    /** Processor-thread: one inbound datagram (dst already verified). */
    void handle(byte[] raw) throws Exception {
        byte src = raw[1]; // peer's companion node hash (§2.3)
        peerHash = src;
        byte[] frame = new byte[raw.length - 2];
        System.arraycopy(raw, 2, frame, 0, frame.length);

        FrameHeader.Parsed parsed = FrameHeader.parse(frame, 0);
        FrameHeader h = parsed.header();
        switch (h.kind()) {
            case FrameKind.DATA -> handleData(src, h,
                    java.util.Arrays.copyOfRange(frame, parsed.bodyOffset(), frame.length));
            case FrameKind.PING -> {
                log.info("PING msg_id 0x{} from 0x{} — echoing back",
                        Integer.toHexString(h.msgId()), Integer.toHexString(src & 0xFF));
                transmitFrame(src, pingReply(h.msgId()));
            }
            case FrameKind.ACKBM -> { /* handled on reader thread */ }
            case FrameKind.NACK, FrameKind.ABORT ->
                    log.info("peer NACK/ABORT msg_id=0x{} (wallet will re-bootstrap/retry)",
                            Integer.toHexString(h.msgId()));
            default -> log.debug("ignoring frame kind 0x{}", Integer.toHexString(h.kind()));
        }
    }

    private void handleData(byte src, FrameHeader h, byte[] body) throws Exception {
        Reassembler.Result r = inboundReassembler.feed(h, body);
        switch (r) {
            case Reassembler.Result.Pending p -> {
                if (p.ack() != null) {
                    transmitFrame(src, p.ack());
                }
            }
            case Reassembler.Result.Complete c -> {
                if (c.ack() != null) {
                    transmitFrame(src, c.ack()); // confirm completion first
                }
                respond(src, h.msgId(), c.body());
            }
            case Reassembler.Result.Duplicate d -> log.debug("duplicate seq ignored");
            case Reassembler.Result.Inconsistent i -> {
                // ABORT with MALFORMED reason (§3.5, §3.8).
                byte[] head = new FrameHeader(0, FrameKind.ABORT, 0, h.msgId(), null, null).encode();
                byte[] out = new byte[head.length + 1];
                System.arraycopy(head, 0, out, 0, head.length);
                out[head.length] = FrameKind.Reason.MALFORMED;
                transmitFrame(src, out);
            }
        }
    }

    /** Decrypt-dispatch-encrypt, then reliably deliver the response over the mesh. */
    private void respond(byte src, int msgId, byte[] l2Body) throws Exception {
        long t0 = System.currentTimeMillis();
        byte[] sealedResp = session.handleMessage(msgId, l2Body, src & 0xFF);
        log.info("responding to msg_id 0x{} ({} ms session time)", Integer.toHexString(msgId),
                System.currentTimeMillis() - t0);

        MessageSender sender = new MessageSender(
                frame -> {
                    try {
                        transmitFrame(src, frame);
                    } catch (RawDatagramRadio.RadioException e) {
                        throw new RuntimeException("radio transmit failed", e);
                    }
                }, governor, senderConfig);
        outbound.set(sender);
        try {
            MessageSender.Result result = sender.send(msgId, sealedResp);
            if (result.status() != MessageSender.Status.ACKED) {
                // §3.7/§11: give-up means the wallet retries via replay cache.
                log.warn("response msg_id 0x{} NOT delivered after {} rounds",
                        Integer.toHexString(msgId), result.roundsNoProgress());
            }
        } finally {
            outbound.set(null);
        }
    }

    private void transmitFrame(byte dstHash, byte[] l1Frame) throws RawDatagramRadio.RadioException {
        byte[] payload = new byte[2 + l1Frame.length];
        payload[0] = dstHash;
        payload[1] = selfHash;
        System.arraycopy(l1Frame, 0, payload, 2, l1Frame.length);
        transmitWithBackoff(payload);
    }

    /**
     * §2.8: TABLE_FULL means pause + retry the SAME frame; not an error. Other
     * failures propagate after bounded retries.
     */
    private void transmitWithBackoff(byte[] payload) throws RawDatagramRadio.RadioException {
        int attempts = 6;
        for (int i = 1; i <= attempts; i++) {
            try {
                radio.send(payload);
                return;
            } catch (RawDatagramRadio.RadioBusyException e) {
                long waitMs = Math.max(governor.millisUntilSendable(), 500L * i);
                log.debug("node queue full; backing off {} ms", waitMs);
                sleep(waitMs);
            } catch (RawDatagramRadio.RadioException e) {
                if (i == attempts) {
                    throw e;
                }
                log.debug("transmit failed ({}) retry {}/{}", e.getMessage(), i, attempts);
                sleep(200L * i);
            }
        }
    }

    /** PING echo: same header, kind PING, empty body (§3.1). */
    private static byte[] pingReply(int msgId) {
        return new FrameHeader(0, FrameKind.PING, 0, msgId, null, null).encode();
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Visible for tests. */
    void injectInbound(byte[] rawPayload) {
        inbox.add(rawPayload);
    }
}
