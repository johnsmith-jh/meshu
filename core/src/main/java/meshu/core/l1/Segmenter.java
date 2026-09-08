package meshu.core.l1;

import java.util.ArrayList;
import java.util.List;

/**
 * L1 segmentation of one message into DATA frames (PROTOCOL.md §3.2, §3.4).
 *
 * <p>Payload capacity against the MTU floor (§2.7):
 * <pre>
 * single frame   165 − 4 = 161 bytes of body
 * fragmented     165 − 6 = 159 bytes of body per frame
 * </pre>
 *
 * REQ_ACK is set on the final frame of a fragmented message, on every 8th frame
 * (early loss detection), and whenever the in-flight window fills with frames of
 * the message still unsent (§3.4).
 */
public final class Segmenter {

    /** MTU floor (§2.7); valid to 7 hops with 1-byte path hashes. */
    public static final int MTU_FLOOR = 165;
    public static final int PAYLOAD_SINGLE = MTU_FLOOR - FrameHeader.HEADER_SINGLE; // 161
    public static final int PAYLOAD_MULTI = MTU_FLOOR - FrameHeader.HEADER_MULTI;   // 159

    /** Default in-flight window (§12.3 MESHU_WINDOW). */
    public static final int WINDOW = 6;
    /** Set REQ_ACK on every Nth frame (§3.4). */
    public static final int REQ_ACK_CADENCE = 8;

    private Segmenter() {
    }

    /** One DATA frame ready for the transport (header ‖ body fragment). */
    public record Frame(FrameHeader header, byte[] body) {
        public byte[] encode() {
            byte[] h = header.encode();
            byte[] out = new byte[h.length + body.length];
            System.arraycopy(h, 0, out, 0, h.length);
            System.arraycopy(body, 0, out, h.length, body.length);
            return out;
        }
    }

    /**
     * Segment a message body (the sealed L2 output) into DATA frames.
     *
     * @param msgId   16-bit message id (§3.3)
     * @param body    sealed L2 bytes (epoch ‖ ciphertext ‖ tag)
     * @param mtu     current path MTU (§2.7); use {@link #MTU_FLOOR} when unknown
     */
    public static List<Frame> segment(int msgId, byte[] body, int mtu) {
        int singleCap = mtu - FrameHeader.HEADER_SINGLE;
        int multiCap = mtu - FrameHeader.HEADER_MULTI;
        if (multiCap <= 0) {
            throw new IllegalArgumentException("MTU too small for fragmentation: " + mtu);
        }

        List<Frame> out = new ArrayList<>();
        if (body.length <= singleCap) {
            // Reliable single-frame send: request the ACK like any final frame.
            out.add(new Frame(FrameHeader.dataSingle(msgId, 0, true), body));
            return out;
        }

        int count = (body.length + multiCap - 1) / multiCap;
        if (count - 1 > 254) {
            throw new IllegalArgumentException("message too large: " + count + " frames > 255 (§3.2)");
        }
        int lastSeq = count - 1;
        for (int seq = 0; seq < count; seq++) {
            int off = seq * multiCap;
            int len = Math.min(multiCap, body.length - off);
            byte[] frag = new byte[len];
            System.arraycopy(body, off, frag, 0, len);
            boolean reqAck = shouldReqAck(seq, lastSeq);
            out.add(new Frame(FrameHeader.dataMulti(msgId, seq, lastSeq, 0, reqAck), frag));
        }
        return out;
    }

    /** REQ_ACK on the final frame, on every 8th, and at window boundaries (§3.4). */
    private static boolean shouldReqAck(int seq, int lastSeq) {
        if (seq == lastSeq) {
            return true;                                    // final frame
        }
        if ((seq + 1) % REQ_ACK_CADENCE == 0) {
            return true;                                    // every 8th frame
        }
        return (seq + 1) % WINDOW == 0 && seq < lastSeq;    // window fills, frames remain
    }

    /**
     * Frame count and total wire bytes for a message, matching TESTVECTORS.md
     * §9.1. Used to size operations before building them.
     */
    public static int[] framesAndWire(int l3Length) {
        int body = l3Length + 17; // L2 overhead (§4.4)
        if (body <= PAYLOAD_SINGLE) {
            return new int[]{1, body + FrameHeader.HEADER_SINGLE};
        }
        int n = (int) Math.ceil((double) body / PAYLOAD_MULTI);
        return new int[]{n, body + n * FrameHeader.HEADER_MULTI};
    }
}
