package meshu.core.l1;

import java.util.ArrayList;
import java.util.List;

/**
 * L1 frame header (PROTOCOL.md §3.1) — 4 bytes single-frame, 6 bytes fragmented.
 *
 * <pre>
 * byte 0  VVKKKKKK   VV = version (2 bits, 0b00 v1), KKKKKK = frame kind
 * byte 1  flags      MULTI 0x01 | REQ_ACK 0x02 | ATTEMPT 0x0C | reserved 0xF0
 * byte 2  msg_id high
 * byte 3  msg_id low
 * byte 4  seq        (only when MULTI)  0-based frame index
 * byte 5  last_seq   (only when MULTI)  index of final frame
 * </pre>
 */
public record FrameHeader(
        int version,
        int kind,
        int flags,
        int msgId,
        Integer seq,
        Integer lastSeq) {

    public static final int FLAG_MULTI = 0x01;
    public static final int FLAG_REQ_ACK = 0x02;
    public static final int FLAG_ATTEMPT_MASK = 0x0C;
    public static final int ATTEMPT_SHIFT = 2;

    public static final int HEADER_SINGLE = 4;
    public static final int HEADER_MULTI = 6;

    public FrameHeader {
        if (version < 0 || version > 3) {
            throw new IllegalArgumentException("version out of range: " + version);
        }
        if (kind < 0 || kind > 0x3F) {
            throw new IllegalArgumentException("kind out of range: " + kind);
        }
        if (msgId < 0 || msgId > 0xFFFF) {
            throw new IllegalArgumentException("msg_id out of range: " + msgId);
        }
        boolean multi = (flags & FLAG_MULTI) != 0;
        if (multi && (seq == null || lastSeq == null)) {
            throw new IllegalArgumentException("MULTI set but seq/lastSeq missing");
        }
        if (!multi && (seq != null || lastSeq != null)) {
            throw new IllegalArgumentException("seq/lastSeq present but MULTI clear");
        }
    }

    public boolean multi() {
        return (flags & FLAG_MULTI) != 0;
    }

    public boolean reqAck() {
        return (flags & FLAG_REQ_ACK) != 0;
    }

    /** Retransmission counter 0–3 (§3.1, §2.8). */
    public int attempt() {
        return (flags & FLAG_ATTEMPT_MASK) >> ATTEMPT_SHIFT;
    }

    public int headerSize() {
        return multi() ? HEADER_MULTI : HEADER_SINGLE;
    }

    /** Serialize header only (no body). */
    public byte[] encode() {
        byte[] h = new byte[headerSize()];
        h[0] = (byte) ((version << 6) | kind);
        h[1] = (byte) flags;
        h[2] = (byte) (msgId >> 8);
        h[3] = (byte) msgId;
        if (multi()) {
            h[4] = (byte) (int) seq;
            h[5] = (byte) (int) lastSeq;
        }
        return h;
    }

    /** Parse a header from the start of {@code frame}. Returns header + body offset. */
    public static Parsed parse(byte[] frame, int offset) {
        if (frame.length - offset < HEADER_SINGLE) {
            throw new IllegalArgumentException("frame too short for header: " + (frame.length - offset));
        }
        int b0 = frame[offset] & 0xFF;
        int version = b0 >> 6;
        int kind = b0 & 0x3F;
        int flags = frame[offset + 1] & 0xFF;
        int msgId = ((frame[offset + 2] & 0xFF) << 8) | (frame[offset + 3] & 0xFF);
        boolean multi = (flags & FLAG_MULTI) != 0;
        Integer seq = null, lastSeq = null;
        int bodyOffset = offset + HEADER_SINGLE;
        if (multi) {
            if (frame.length - offset < HEADER_MULTI) {
                throw new IllegalArgumentException("frame too short for MULTI header");
            }
            seq = frame[offset + 4] & 0xFF;
            lastSeq = frame[offset + 5] & 0xFF;
            bodyOffset = offset + HEADER_MULTI;
        }
        return new Parsed(new FrameHeader(version, kind, flags, msgId, seq, lastSeq), bodyOffset);
    }

    public record Parsed(FrameHeader header, int bodyOffset) {
    }

    // ------------------------------------------------------------ builders

    /** Single-frame DATA header (MULTI clear). */
    public static FrameHeader dataSingle(int msgId, int attempt) {
        return dataSingle(msgId, attempt, false);
    }

    /**
     * Single-frame DATA header with optional REQ_ACK. Reliable delivery of a
     * one-frame message needs the ACK just as a fragmented one does; callers
     * that genuinely want fire-and-forget pass {@code false}.
     */
    public static FrameHeader dataSingle(int msgId, int attempt, boolean reqAck) {
        int flags = (attempt << ATTEMPT_SHIFT) | (reqAck ? FLAG_REQ_ACK : 0);
        return new FrameHeader(0, FrameKind.DATA, flags, msgId, null, null);
    }

    /** Fragmented DATA header. */
    public static FrameHeader dataMulti(int msgId, int seq, int lastSeq, int attempt, boolean reqAck) {
        int flags = FLAG_MULTI | (attempt << ATTEMPT_SHIFT) | (reqAck ? FLAG_REQ_ACK : 0);
        return new FrameHeader(0, FrameKind.DATA, flags, msgId, seq, lastSeq);
    }

    /** ACKBM header. */
    public static FrameHeader ackbm(int msgId) {
        return new FrameHeader(0, FrameKind.ACKBM, 0, msgId, null, null);
    }

    /** Missing sequence numbers given a received bitmap (§3.6, §3.7). */
    public static List<Integer> missingFromBitmap(int total, byte[] bitmap) {
        List<Integer> missing = new ArrayList<>();
        for (int i = 0; i < total; i++) {
            if ((bitmap[i >> 3] >> (i & 7) & 1) == 0) {
                missing.add(i);
            }
        }
        return missing;
    }
}
