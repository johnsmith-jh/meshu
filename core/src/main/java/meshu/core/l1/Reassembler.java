package meshu.core.l1;

import java.util.ArrayList;
import java.util.List;

/**
 * L1 reassembly of fragmented DATA frames (PROTOCOL.md §3.5, §3.6).
 *
 * <p>Per-`msg_id` state: the received-frame bitmap, fragment buffers,
 * `last_seq`, and first-seen timestamp. Duplicates are discarded idempotently;
 * inconsistent `last_seq` aborts the message. On REQ_ACK the receiver replies
 * with an ACKBM carrying the current bitmap.
 */
public final class Reassembler {

    /** Default max concurrent reassemblies (§3.5 MESHU_MAX_REASM). */
    public static final int MAX_REASM = 4;

    /** Outcome of feeding one DATA frame. */
    public sealed interface Result {
        /** Frame stored; message not yet complete. `ack` is non-null when REQ_ACK was set. */
        record Pending(byte[] ack) implements Result {
        }

        /**
         * Message complete: the reassembled body (sealed L2 bytes), plus a full
         * ACKBM frame when the completing (or single) frame requested one —
         * without it the sender never learns of completion and would RTO-retry
         * a message that already arrived.
         */
        record Complete(byte[] body, byte[] ack) implements Result {
            public Complete(byte[] body) {
                this(body, null);
            }
        }

        /** A duplicate seq — idempotent, not an error (§3.5). */
        record Duplicate() implements Result {
            static final Duplicate INSTANCE = new Duplicate();
        }

        /** Inconsistent last_seq — the message must be ABORTed (§3.5). */
        record Inconsistent() implements Result {
            static final Inconsistent INSTANCE = new Inconsistent();
        }
    }

    /** Completed msg_id → frame count, remembered so late duplicates get re-ACKed
     *  with a full bitmap (the completing ACKBM itself may have been lost). */
    private static final int COMPLETED_CACHE_SIZE = 64;
    private final java.util.LinkedHashMap<Integer, Integer> completed =
            new java.util.LinkedHashMap<>(16, 0.75f, false) {
                @Override
                protected boolean removeEldestEntry(java.util.Map.Entry<Integer, Integer> eldest) {
                    return size() > COMPLETED_CACHE_SIZE;
                }
            };

    private final int maxReasm;
    private final java.util.LinkedHashMap<Integer, State> states = new java.util.LinkedHashMap<>();

    public Reassembler() {
        this(MAX_REASM);
    }

    public Reassembler(int maxReasm) {
        this.maxReasm = maxReasm;
    }

    private static final class State {
        final int lastSeq;
        final byte[][] fragments;
        final byte[] bitmap;
        int received;

        State(int lastSeq) {
            this.lastSeq = lastSeq;
            this.fragments = new byte[lastSeq + 1][];
            this.bitmap = new byte[(lastSeq + 1 + 7) / 8];
        }

        void store(int seq, byte[] body) {
            fragments[seq] = body;
            bitmap[seq >> 3] |= (byte) (1 << (seq & 7));
            received++;
        }

        boolean has(int seq) {
            return (bitmap[seq >> 3] >> (seq & 7) & 1) != 0;
        }

        boolean complete() {
            return received == fragments.length;
        }

        byte[] assemble() {
            int total = 0;
            for (byte[] f : fragments) {
                total += f.length;
            }
            byte[] out = new byte[total];
            int pos = 0;
            for (byte[] f : fragments) {
                System.arraycopy(f, 0, out, pos, f.length);
                pos += f.length;
            }
            return out;
        }
    }

    /**
     * Feed one inbound DATA frame body (after header parse).
     *
     * @param header the parsed frame header
     * @param body   the frame body (L2 fragment, or full sealed message for single frames)
     */
    public Result feed(FrameHeader header, byte[] body) {
        int msgId = header.msgId();
        if (!header.multi()) {
            // Single-frame message: complete immediately (§3.5). Always re-ACK
            // when requested — a retry here means our previous ACK was lost.
            completed.put(msgId, 1);
            byte[] ack = header.reqAck() ? ackbmFrame(msgId, 1, new byte[]{0x01}) : null;
            return new Result.Complete(body, ack);
        }
        Integer completedTotal = completed.get(msgId);
        if (completedTotal != null) {
            // Message already assembled; the duplicate means our ACKBM was lost.
            // Answer with a full bitmap so the sender can finish immediately.
            return new Result.Pending(fullAckbmFrame(msgId, completedTotal));
        }

        int seq = header.seq();
        int lastSeq = header.lastSeq();

        if (seq > lastSeq) {
            // Malformed framing (seq beyond the declared end): same class as an
            // inconsistent last_seq — abort the message, never index out of
            // bounds (§3.5).
            states.remove(msgId);
            return Result.Inconsistent.INSTANCE;
        }

        State s = states.get(msgId);
        if (s != null && s.lastSeq != lastSeq) {
            // Inconsistent last_seq: abort and discard (§3.5).
            states.remove(msgId);
            return Result.Inconsistent.INSTANCE;
        }
        if (s == null) {
            if (states.size() >= maxReasm) {
                evictLeastRecentlyAdvanced();
            }
            s = new State(lastSeq);
            states.put(msgId, s);
        }

        if (s.has(seq)) {
            return Result.Duplicate.INSTANCE;
        }
        s.store(seq, body);

        if (s.complete()) {
            states.remove(msgId);
            completed.put(msgId, s.lastSeq + 1);
            byte[] ack = header.reqAck() ? fullAckbmFrame(msgId, s.lastSeq + 1) : null;
            return new Result.Complete(s.assemble(), ack);
        }
        byte[] ack = header.reqAck() ? ackbmFrame(msgId, s.lastSeq + 1, s.bitmap) : null;
        return new Result.Pending(ack);
    }

    /** ACKBM frame with every bit set — "I have the whole message." */
    private static byte[] fullAckbmFrame(int msgId, int total) {
        byte[] bitmap = new byte[(total + 7) / 8];
        for (int i = 0; i < total; i++) {
            bitmap[i >> 3] |= (byte) (1 << (i & 7));
        }
        return ackbmFrame(msgId, total, bitmap);
    }

    /** Full ACKBM frame (header ‖ body) for a given state. */
    public static byte[] ackbmFrame(int msgId, int total, byte[] bitmap) {
        FrameHeader h = FrameHeader.ackbm(msgId);
        byte[] head = h.encode();
        byte[] out = new byte[head.length + 1 + bitmap.length];
        System.arraycopy(head, 0, out, 0, head.length);
        out[head.length] = (byte) total;
        System.arraycopy(bitmap, 0, out, head.length + 1, bitmap.length);
        return out;
    }

    private void evictLeastRecentlyAdvanced() {
        // LinkedHashMap iteration order is insertion order; simplest correct
        // bound is to evict the eldest. (§3.5: least recently advanced.)
        var it = states.entrySet().iterator();
        if (it.hasNext()) {
            it.next();
            it.remove();
        }
    }

    /** Bitmap of received frames for a message, for testing. */
    public List<Integer> receivedSeqs(int msgId) {
        State s = states.get(msgId);
        List<Integer> out = new ArrayList<>();
        if (s == null) {
            return out;
        }
        for (int i = 0; i <= s.lastSeq; i++) {
            if (s.has(i)) {
                out.add(i);
            }
        }
        return out;
    }
}
