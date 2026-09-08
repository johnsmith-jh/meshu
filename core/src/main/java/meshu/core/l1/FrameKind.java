package meshu.core.l1;

/**
 * L1 frame kinds (PROTOCOL.md §3.1). The on-wire first byte is
 * {@code VVKKKKKK} — version in the top 2 bits (0b00 for v1), kind in the low 6.
 */
public final class FrameKind {

    public static final int DATA = 0x10;   // L2 payload fragment
    public static final int ACKBM = 0x12;  // acknowledge with received-frame bitmap
    public static final int NACK = 0x13;   // reject message
    public static final int ABORT = 0x14;  // abandon an in-progress message
    public static final int PING = 0x15;   // liveness / path probe

    private FrameKind() {
    }

    /** NACK / ABORT reason codes (§3.8). */
    public static final class Reason {
        public static final int UNSUPPORTED_VERSION = 0x01;
        public static final int MSG_TOO_LARGE = 0x02;
        public static final int DECRYPT_FAILED = 0x03;
        public static final int REASM_TIMEOUT = 0x04;
        public static final int BUSY = 0x05;
        public static final int MALFORMED = 0x06;

        private Reason() {
        }
    }
}
