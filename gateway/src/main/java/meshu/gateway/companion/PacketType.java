package meshu.gateway.companion;

/**
 * Companion-protocol packet types (first payload byte of a device-to-host frame).
 * Values per MeshCore docs/companion_protocol.md; only what the gateway needs now.
 */
public final class PacketType {

    public static final int OK = 0x00;
    public static final int ERROR = 0x01;
    public static final int SELF_INFO = 0x05;
    public static final int DEVICE_INFO = 0x0D;
    public static final int BATTERY = 0x0C;

    private PacketType() {
    }

    /** Command opcodes (host to device). */
    public static final class Cmd {
        public static final int APP_START = 0x01;
        public static final int DEVICE_QUERY = 0x16;
        public static final int GET_BATTERY = 0x14;
        /** Send a raw custom datagram (PROTOCOL.md §2.4). Payload: path_len ‖ path ‖ data. */
        public static final int SEND_RAW_DATA = 0x19;

        private Cmd() {
        }
    }

    /** Async push codes (device to host, not tied to a command). */
    public static final class Push {
        /** Received raw custom datagram (§2.5): SNR ‖ RSSI ‖ 0xFF ‖ payload. */
        public static final int RAW_DATA = 0x84;
        /** RF log (Dispatcher::logRxRaw): SNR ‖ RSSI ‖ raw air packet — one per heard packet. */
        public static final int LOG_RX_DATA = 0x88;

        private Push() {
        }
    }

    /** ERR_CODE_* values carried by PACKET_ERROR byte 1 (docs §Errors). */
    public static final class Err {
        public static final int TABLE_FULL = 3;

        private Err() {
        }
    }
}
