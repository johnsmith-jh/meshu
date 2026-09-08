package meshu.gateway.companion;

import com.fazecast.jSerialComm.SerialPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * A blocking, one-command-at-a-time link to a MeshCore companion node over USB
 * serial. A reader thread deframes inbound bytes into a queue; commands are
 * matched to their expected response packet type (docs/companion_protocol.md:
 * "send one command at a time, wait for a response").
 */
public final class MeshCoreNode implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(MeshCoreNode.class);

    private final SerialPort port;
    private final BlockingQueue<byte[]> inbound = new LinkedBlockingQueue<>();
    private final Thread readerThread;
    private volatile boolean open = true;
    /** Handlers for async push frames (e.g. PUSH_CODE_RAW_DATA); bypass the command queue. */
    private final Map<Integer, Consumer<byte[]>> pushHandlers = new ConcurrentHashMap<>();

    private MeshCoreNode(SerialPort port) {
        this.port = port;
        this.readerThread = Thread.ofPlatform().name("meshcore-serial-reader").start(this::readLoop);
    }

    /** Open a serial link (115200 8N1, no flow control) and start the reader thread. */
    public static MeshCoreNode open(String portName, int baud) throws IOException {
        SerialPort port = SerialPort.getCommPort(portName);
        port.setBaudRate(baud);
        port.setNumDataBits(8);
        port.setNumStopBits(SerialPort.ONE_STOP_BIT);
        port.setParity(SerialPort.NO_PARITY);
        port.setComPortTimeouts(SerialPort.TIMEOUT_READ_SEMI_BLOCKING, 500, 0);
        if (!port.openPort()) {
            throw new IOException("could not open serial port " + portName);
        }
        // ESP32-S3 native USB CDC gates its serial output on DTR; RTS held low
        // (meshcore_py does the same).
        port.setDTR();
        port.clearRTS();
        try {
            Thread.sleep(300); // let the firmware see the port open
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        log.info("opened {} @ {} baud", portName, baud);
        return new MeshCoreNode(port);
    }

    /** System port names of candidate companion nodes (usbmodem / usbserial). */
    public static List<String> detectPorts() {
        List<String> names = new ArrayList<>();
        for (SerialPort p : SerialPort.getCommPorts()) {
            String n = p.getSystemPortName().toLowerCase();
            // macOS lists each device as both cu.* and tty.*; use cu.* for outbound connections
            if (n.startsWith("tty.")) {
                continue;
            }
            if (n.contains("usbmodem") || n.contains("usbserial")) {
                names.add(p.getSystemPortName());
            }
        }
        return names;
    }

    /** CMD_APP_START → PACKET_SELF_INFO. Retries: a freshly opened port can eat the first command. */
    public synchronized SelfInfo appStart(String appName, Duration timeout)
            throws IOException, TimeoutException {
        byte[] name = appName.getBytes(StandardCharsets.UTF_8);
        byte[] cmd = new byte[8 + name.length];
        cmd[0] = (byte) PacketType.Cmd.APP_START;
        cmd[1] = 0x03;                  // protocol version (meshcore_py sends 3)
        cmd[2] = ' '; cmd[3] = ' ';     // reserved padding
        cmd[4] = ' '; cmd[5] = ' ';
        cmd[6] = ' '; cmd[7] = ' ';
        System.arraycopy(name, 0, cmd, 8, name.length);
        TimeoutException last = null;
        for (int attempt = 1; attempt <= 3; attempt++) {
            try {
                return SelfInfo.parse(exchange(cmd, PacketType.SELF_INFO, timeout));
            } catch (TimeoutException e) {
                log.debug("APP_START attempt {} timed out", attempt);
                last = e;
            }
        }
        throw last;
    }

    /**
     * Send one command and wait for a frame of the expected packet type.
     * Unrelated async frames (adverts, pushes) are logged and discarded.
     */
    public synchronized byte[] exchange(byte[] command, int expectedType, Duration timeout)
            throws IOException, TimeoutException {
        inbound.clear(); // stale frames from earlier traffic
        write(CompanionFrameCodec.encode(command));
        long deadline = System.nanoTime() + timeout.toNanos();
        while (true) {
            long remainingMs = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
            if (remainingMs <= 0) {
                throw new TimeoutException(
                        "no 0x%02x response within %s".formatted(expectedType, timeout));
            }
            byte[] frame;
            try {
                frame = inbound.poll(remainingMs, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted waiting for response", e);
            }
            if (frame == null) {
                throw new TimeoutException(
                        "no 0x%02x response within %s".formatted(expectedType, timeout));
            }
            if (frame.length > 0 && (frame[0] & 0xFF) == expectedType) {
                return frame;
            }
            log.debug("discarding async frame type=0x{} len={}",
                    frame.length > 0 ? "%02x".formatted(frame[0] & 0xFF) : "??", frame.length);
        }
    }

    /**
     * Register a handler for an async push code (e.g. PUSH_CODE_RAW_DATA).
     * Frames of this type bypass the command queue entirely and are handed to
     * {@code handler} on the reader thread — handlers must be fast/non-blocking.
     */
    public void onPush(int pushCode, Consumer<byte[]> handler) {
        pushHandlers.put(pushCode, handler);
    }

    /**
     * CMD_SEND_RAW_DATA (§2.4): enqueue one raw custom datagram.
     *
     * @param pathLen number of path hash bytes (0 = zero-hop direct)
     * @param path    the path bytes (empty for zero-hop)
     * @param payload the raw packet payload ({@code dst ‖ src ‖ L1 frame}, ≤174 B)
     * @return the node's verdict: SENT, or TABLE_FULL (retry after a pause, §2.8)
     */
    public synchronized RawSendResult sendRawData(int pathLen, byte[] path, byte[] payload,
                                                  Duration timeout)
            throws IOException, TimeoutException {
        if (pathLen < 0) {
            throw new IllegalArgumentException("flood routing of raw data is not supported (§2.4)");
        }
        byte[] cmd = new byte[2 + pathLen + payload.length];
        cmd[0] = (byte) PacketType.Cmd.SEND_RAW_DATA;
        cmd[1] = (byte) pathLen;
        System.arraycopy(path, 0, cmd, 2, pathLen);
        System.arraycopy(payload, 0, cmd, 2 + pathLen, payload.length);
        write(CompanionFrameCodec.encode(cmd));

        long deadline = System.nanoTime() + timeout.toNanos();
        while (true) {
            long remainingMs = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
            if (remainingMs <= 0) {
                throw new TimeoutException("no response to SEND_RAW_DATA within " + timeout);
            }
            byte[] frame;
            try {
                frame = inbound.poll(remainingMs, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted waiting for SEND_RAW_DATA response", e);
            }
            if (frame == null) {
                throw new TimeoutException("no response to SEND_RAW_DATA within " + timeout);
            }
            int type = frame.length > 0 ? frame[0] & 0xFF : -1;
            if (type == PacketType.OK) {
                return RawSendResult.ofSent();
            }
            if (type == PacketType.ERROR && frame.length >= 2) {
                return RawSendResult.ofError(frame[1] & 0xFF);
            }
            log.debug("SEND_RAW_DATA: discarding async frame type=0x{} len={}",
                    type, frame.length);
        }
    }

    /** Outcome of one SEND_RAW_DATA command. */
    public record RawSendResult(boolean sent, int errCode) {
        public static RawSendResult ofSent() {
            return new RawSendResult(true, 0);
        }

        public static RawSendResult ofError(int errCode) {
            return new RawSendResult(false, errCode);
        }

        /** Node's outbound queue is full — pause, apply governor, retry (§2.8). */
        public boolean tableFull() {
            return !sent && errCode == PacketType.Err.TABLE_FULL;
        }
    }

    private void write(byte[] frame) throws IOException {
        OutputStream out = port.getOutputStream();
        out.write(frame);
        out.flush();
        log.trace("tx {} bytes", frame.length);
    }

    private void readLoop() {
        CompanionFrameCodec.Deframer deframer = new CompanionFrameCodec.Deframer();
        byte[] chunk = new byte[4096];
        InputStream in = port.getInputStream();
        while (open) {
            try {
                int n = in.read(chunk);
                if (n > 0) {
                    if (log.isTraceEnabled()) {
                        log.trace("raw rx {} bytes: {}", n,
                                java.util.HexFormat.of().formatHex(chunk, 0, n));
                    }
                    for (byte[] frame : deframer.feed(chunk, 0, n)) {
                        log.trace("rx frame type=0x{} len={}",
                                frame.length > 0 ? "%02x".formatted(frame[0] & 0xFF) : "??", frame.length);
                        int type = frame.length > 0 ? frame[0] & 0xFF : -1;
                        Consumer<byte[]> handler = pushHandlers.get(type);
                        if (handler != null) {
                            handler.accept(frame);
                        } else {
                            inbound.add(frame);
                        }
                    }
                }
            } catch (IOException e) {
                if (open) {
                    log.debug("serial read error (continuing): {}", e.toString());
                }
                // TIMEOUT_READ_SEMI_BLOCKING can surface as an IOException instead
                // of a zero read; keep reading.
            }
        }
    }

    @Override
    public void close() {
        open = false;
        readerThread.interrupt();
        port.closePort();
    }

    @Override
    public String toString() {
        return "MeshCoreNode{" + port.getSystemPortName() + "}";
    }
}
