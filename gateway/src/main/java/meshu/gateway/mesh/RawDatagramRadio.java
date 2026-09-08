package meshu.gateway.mesh;

import java.util.function.Consumer;

/**
 * One raw-custom-datagram radio link (PROTOCOL.md §2). Abstracts the companion
 * node so the mesh glue is testable against a fake.
 */
public interface RawDatagramRadio {

    /**
     * Transmit one raw packet payload ({@code dst ‖ src ‖ L1 frame}).
     *
     * @throws RadioBusyException the node's outbound queue is full (§2.8) —
     *                            pause, apply the governor, retry
     * @throws RadioException     any other transmit failure
     */
    void send(byte[] payload) throws RadioException;

    /**
     * Register the receive handler. Called on the radio's reader thread with
     * each received payload ({@code dst ‖ src ‖ L1 frame}); handlers must be
     * fast/non-blocking (enqueue internally).
     */
    void onReceive(Consumer<byte[]> handler);

    /** Transmit-side failure. */
    class RadioException extends Exception {
        public RadioException(String message) {
            super(message);
        }

        public RadioException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Node outbound queue saturated (ERR_CODE_TABLE_FULL, §2.8) — not an error. */
    final class RadioBusyException extends RadioException {
        public RadioBusyException() {
            super("node outbound queue full (TABLE_FULL)");
        }
    }
}
