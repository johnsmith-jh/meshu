package meshu.gateway.companion;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * MeshCore companion-protocol serial framing.
 *
 * <p>Every frame on the wire is {@code marker ‖ uint16 LE length ‖ payload}:
 * <ul>
 *   <li>host → device frames start with {@code '<'} (0x3C)</li>
 *   <li>device → host frames start with {@code '>'} (0x3E)</li>
 * </ul>
 * Radios may interleave console/debug text on the same UART, so the deframer
 * scans for the marker and discards leading junk (mirrors meshcore_py's
 * serial_cx.py).
 */
public final class CompanionFrameCodec {

    /** Frame marker, host to device. */
    public static final byte OUT_MARKER = 0x3C; // '<'
    /** Frame marker, device to host. */
    public static final byte IN_MARKER = 0x3E; // '>'

    /** Sanity cap on a device-to-host payload; anything larger means we lost sync. */
    static final int MAX_FRAME = 512;

    private CompanionFrameCodec() {
    }

    /** Wrap a command payload in a host-to-device frame. */
    public static byte[] encode(byte[] payload) {
        if (payload.length > 0xFFFF) {
            throw new IllegalArgumentException("payload too large: " + payload.length);
        }
        ByteBuffer buf = ByteBuffer.allocate(3 + payload.length).order(ByteOrder.LITTLE_ENDIAN);
        buf.put(OUT_MARKER).putShort((short) payload.length).put(payload);
        return buf.array();
    }

    /**
     * Incremental deframer for the device-to-host byte stream. Feed arbitrary
     * chunks; complete frame payloads are returned in order.
     */
    public static final class Deframer {
        private byte[] buf = new byte[1024];
        private int len = 0;

        public List<byte[]> feed(byte[] data, int off, int n) {
            ensure(n);
            System.arraycopy(data, off, buf, len, n);
            len += n;

            List<byte[]> frames = new ArrayList<>();
            int pos = 0;
            while (true) {
                int marker = -1;
                for (int i = pos; i < len; i++) {
                    if (buf[i] == IN_MARKER) {
                        marker = i;
                        break;
                    }
                }
                if (marker < 0) {
                    // No marker at all: everything buffered is junk (marker is a single byte).
                    len = 0;
                    pos = 0;
                    break;
                }
                pos = marker;
                int avail = len - pos;
                if (avail < 3) {
                    break; // wait for length bytes
                }
                int size = (buf[pos + 1] & 0xFF) | ((buf[pos + 2] & 0xFF) << 8);
                if (size > MAX_FRAME) {
                    pos++; // lost sync: skip this marker and rescan
                    continue;
                }
                if (avail < 3 + size) {
                    break; // wait for the rest of the frame
                }
                frames.add(Arrays.copyOfRange(buf, pos + 3, pos + 3 + size));
                pos += 3 + size;
            }
            if (pos > 0) {
                System.arraycopy(buf, pos, buf, 0, len - pos);
                len -= pos;
            }
            return frames;
        }

        private void ensure(int extra) {
            if (len + extra > buf.length) {
                buf = Arrays.copyOf(buf, Math.max(buf.length * 2, len + extra));
            }
        }
    }
}
