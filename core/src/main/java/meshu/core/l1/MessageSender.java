package meshu.core.l1;

import java.util.Arrays;
import java.util.List;

/**
 * Reliable delivery of one message over an L1 transport (PROTOCOL.md §3.4–§3.7).
 *
 * <p>Segments the sealed body, paces frames through the {@link AirtimeGovernor},
 * keeps at most MESHU_WINDOW frames unacknowledged, and retransmits exactly the
 * frames the peer's ACKBM marks missing — each with ATTEMPT incremented so no
 * resend is byte-identical (§2.8 duplicate suppression). An RTO timer covers
 * lost ACKBMs; after MESHU_MAX_RETRY rounds without bitmap progress the sender
 * gives up and reports failure (the caller must then use §11 recovery rather
 * than blindly resending).
 *
 * <p>Threading: one message in flight per sender instance. {@link #send}
 * blocks until ACKed or give-up; {@link #onFrameReceived} is called from the
 * transport's reader thread. Send operations happen under the monitor (serial
 * writes are quick; waits release the monitor), acceptable for this link's
 * timescales.
 */
public final class MessageSender {

    /** The wire: push one encoded L1 frame. Implementations must be thread-safe
     *  or the caller must serialize; pacing already happened upstream. */
    public interface Transport {
        void sendFrame(byte[] l1Frame);
    }

    /** Tunables; defaults per PROTOCOL.md Appendix B. */
    public record Config(
            long minRtoMs,       // MESHU_MIN_RTO
            int maxRetryRounds,  // MESHU_MAX_RETRY
            int window,          // MESHU_WINDOW
            long frameAirtimeMs, // measured airtime per frame (§12.1)
            int mtu,             // current path MTU (§2.7)
            long rtoExtraMs) {   // the fixed +4000 ms term of the §3.7 formula

        public static Config defaults(long frameAirtimeMs) {
            return new Config(15_000, 4, Segmenter.WINDOW, frameAirtimeMs,
                    Segmenter.MTU_FLOOR, 4000);
        }

        /** Fast settings for tests / bench links (scales the whole RTO down). */
        public static Config fast(long minRtoMs, long frameAirtimeMs) {
            return new Config(minRtoMs, 4, Segmenter.WINDOW, frameAirtimeMs,
                    Segmenter.MTU_FLOOR, 100);
        }
    }

    public enum Status {ACKED, GAVE_UP}

    public record Result(Status status, int frames, int transmissions, int roundsNoProgress) {
    }

    private final Transport transport;
    private final AirtimeGovernor governor;
    private final Config cfg;

    // Per-message state (one send() at a time).
    private List<Segmenter.Frame> frames;
    private boolean[] acked;
    private boolean[] sent;
    private int[] attempts;
    private int nextToSend;
    private int ackCount;
    private int ackCountAtLastRto;
    private int roundsNoProgress;
    private boolean ackArrived;

    public MessageSender(Transport transport, AirtimeGovernor governor, Config cfg) {
        this.transport = transport;
        this.governor = governor;
        this.cfg = cfg;
    }

    /** Send one message reliably; blocks until ACKed or give-up (§3.7). */
    public synchronized Result send(int msgId, byte[] body) throws InterruptedException {
        if (frames != null) {
            throw new IllegalStateException("a message is already in flight");
        }
        try {
            return doSend(msgId, body);
        } finally {
            resetState();
        }
    }

    private Result doSend(int msgId, byte[] body) throws InterruptedException {
        List<Segmenter.Frame> seg = Segmenter.segment(msgId, body, cfg.mtu());
        this.frames = seg;
        this.acked = new boolean[seg.size()];
        this.sent = new boolean[seg.size()];
        this.attempts = new int[seg.size()];
        this.nextToSend = 0;
        this.ackCount = 0;
        this.roundsNoProgress = 0;

        fillWindow();
        long deadline = rtoDeadline();

        while (true) {
            if (ackCount == frames.size()) {
                return new Result(Status.ACKED, frames.size(), totalTransmissions(), roundsNoProgress);
            }
            long waitMs = deadline - System.currentTimeMillis();
            if (waitMs <= 0) {
                // RTO fired: retransmit everything not yet known-received.
                int before = ackCount;
                retransmitMissing();
                if (ackCount == frames.size()) {
                    return new Result(Status.ACKED, frames.size(), totalTransmissions(), roundsNoProgress);
                }
                if (ackCount <= before) {
                    roundsNoProgress++;
                } else {
                    roundsNoProgress = 0;
                }
                if (roundsNoProgress >= cfg.maxRetryRounds()) {
                    return new Result(Status.GAVE_UP, frames.size(),
                            totalTransmissions(), roundsNoProgress);
                }
                deadline = rtoDeadline();
                continue;
            }
            wait(Math.min(waitMs, 100)); // bounded slices; ackArrived handled below

            if (ackArrived) {
                ackArrived = false;
                if (ackCount == frames.size()) {
                    return new Result(Status.ACKED, frames.size(), totalTransmissions(), roundsNoProgress);
                }
                // §3.7: on an advancing ACKBM, immediately retransmit exactly
                // the clear-bit frames and open the window for new ones.
                fillWindow();
                deadline = rtoDeadline();
            }
        }
    }

    /** Feed one inbound frame (any kind; only ACKBM matters here). */
    public synchronized void onFrameReceived(byte[] frame) {
        FrameHeader.Parsed parsed;
        try {
            parsed = FrameHeader.parse(frame, 0);
        } catch (RuntimeException e) {
            return; // not ours / malformed
        }
        if (parsed.header().kind() != FrameKind.ACKBM) {
            return;
        }
        if (frames == null || parsed.header().msgId() != frames.getFirst().header().msgId()) {
            return; // stale or foreign ACK
        }
        int off = parsed.bodyOffset();
        if (frame.length < off + 1) {
            return;
        }
        int total = frame[off] & 0xFF;
        if (total != frames.size()) {
            return; // ACKBM for a different fragmentation of this msg_id — ignore
        }
        byte[] bitmap = Arrays.copyOfRange(frame, off + 1, frame.length);
        for (int seq = 0; seq < total && (seq >> 3) < bitmap.length; seq++) {
            if ((bitmap[seq >> 3] >> (seq & 7) & 1) != 0 && !acked[seq]) {
                acked[seq] = true;
                ackCount++;
            }
        }
        ackArrived = true;
        notifyAll();
    }

    // ------------------------------------------------------------ internals

    /** Send unsent frames while the window has room (§12.3). */
    private void fillWindow() throws InterruptedException {
        while (nextToSend < frames.size() && inflight() < cfg.window()) {
            sendOne(nextToSend);
            nextToSend++;
        }
    }

    /** Retransmit all not-known-received frames with ATTEMPT incremented (§3.7). */
    private void retransmitMissing() throws InterruptedException {
        for (int seq = 0; seq < frames.size(); seq++) {
            if (!acked[seq]) {
                sendOne(seq); // attempts[seq] incremented inside
            }
        }
    }

    private void sendOne(int seq) throws InterruptedException {
        governor.acquireBlocking(); // §3.5 step 5 / §3.7: every transmission is paced
        Segmenter.Frame f = frames.get(seq);
        int attempt = (attempts[seq] + 1) & 0x3; // wrap at 4 (§3.1)
        attempts[seq] = attempt;
        FrameHeader h = f.header().multi()
                ? FrameHeader.dataMulti(f.header().msgId(), f.header().seq(),
                        f.header().lastSeq(), attempt, f.header().reqAck())
                : FrameHeader.dataSingle(f.header().msgId(), attempt, f.header().reqAck());
        transport.sendFrame(new Segmenter.Frame(h, f.body()).encode());
        sent[seq] = true;
    }

    private int inflight() {
        int n = 0;
        for (int seq = 0; seq < frames.size(); seq++) {
            if (sent[seq] && !acked[seq]) {
                n++;
            }
        }
        return n;
    }

    private int totalTransmissions() {
        int n = 0;
        for (int a : attempts) {
            n += a + 1;
        }
        return n;
    }

    /** timeout = max(MIN_RTO, 2 × inflight × airtime + rtoExtraMs) (§3.7). */
    private long rtoDeadline() {
        long computed = 2L * Math.max(1, inflight()) * cfg.frameAirtimeMs() + cfg.rtoExtraMs();
        long rto = Math.max(cfg.minRtoMs(), computed);
        return System.currentTimeMillis() + rto;
    }

    private void resetState() {
        frames = null;
        acked = null;
        sent = null;
        attempts = null;
        nextToSend = 0;
        ackCount = 0;
        ackArrived = false;
        roundsNoProgress = 0;
    }
}
