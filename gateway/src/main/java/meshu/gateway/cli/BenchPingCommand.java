package meshu.gateway.cli;

import meshu.core.l1.FrameHeader;
import meshu.core.l1.FrameKind;
import meshu.gateway.companion.MeshCoreNode;
import meshu.gateway.companion.PacketType;
import meshu.gateway.companion.SelfInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * {@code java -jar gateway.jar bench-ping --dst=XX} — wallet-side bench rig.
 *
 * <p>Runs against node#2 (the wallet-side companion) and proves the radio path
 * end-to-end: sends PING L1 frames (PROTOCOL.md §3.1) wrapped in raw datagrams
 * addressed to the gateway's node hash, and matches the echoed PONGs coming
 * back over the air. First milestone of the live bring-up (STATUS.md §8).
 *
 * <p>Options:
 * <ul>
 *   <li>{@code --dst=XX}       gateway node hash, hex (required; printed by mesh-radio)</li>
 *   <li>{@code --count=N}      pings to send (default 5)</li>
 *   <li>{@code --interval-ms=N} spacing between pings (default 2000 ≥ one SF8 airtime)</li>
 *   <li>{@code --timeout-ms=N} how long to wait for the final echo (default 30000)</li>
 *   <li>{@code --port=NAME}    serial port override (needed when both nodes are
 *                              tethered — each process gets its own port)</li>
 * </ul>
 *
 * <p>This is a bench tool, not the wallet: it will migrate into a proper wallet
 * module when that exists.
 */
@Component
public class BenchPingCommand implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(BenchPingCommand.class);
    /** SNR ‖ RSSI ‖ reserved precede the raw payload on PUSH_CODE_RAW_DATA (§2.5). */
    private static final int PUSH_HEADER_LEN = 4;

    private final meshu.gateway.config.GatewayProperties props;

    public BenchPingCommand(meshu.gateway.config.GatewayProperties props) {
        this.props = props;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        if (!args.getNonOptionArgs().contains("bench-ping")) {
            return;
        }

        List<String> dstValues = args.getOptionValues("dst");
        if (dstValues == null || dstValues.isEmpty()) {
            throw new IllegalStateException("bench-ping requires --dst=<gateway node hash hex>");
        }
        int dstHash = Integer.parseInt(dstValues.getFirst(), 16) & 0xFF;
        int count = optInt(args, "count", 5);
        long intervalMs = optLong(args, "interval-ms", 2000);
        long timeoutMs = optLong(args, "timeout-ms", 30_000);

        String port = resolvePort(args);
        int baud = props.serial().baud();

        try (MeshCoreNode node = MeshCoreNode.open(port, baud)) {
            SelfInfo me = node.appStart("meshu-bench", Duration.ofSeconds(5));
            int myHash = me.publicKey()[0] & 0xFF;
            System.out.printf("bench-ping: node %s hash 0x%02x -> gateway 0x%02x via %s%n",
                    me.name(), myHash, dstHash, port);

            // Echo tracking: reader thread records PONGs; main thread waits.
            Map<Integer, Long> pendingByMsgId = new ConcurrentHashMap<>();
            ConcurrentLinkedQueue<Long> rtts = new ConcurrentLinkedQueue<>();
            AtomicInteger echoed = new AtomicInteger();

            node.onPush(PacketType.Push.RAW_DATA, frame -> {
                // Minimum legal pong: push header(4) + dst(1) + src(1) + L1 header(4) = 10 B.
                if (frame.length < PUSH_HEADER_LEN + 6) {
                    return;
                }
                byte[] payload = new byte[frame.length - PUSH_HEADER_LEN];
                System.arraycopy(frame, PUSH_HEADER_LEN, payload, 0, payload.length);
                // §2.3: keep only frames addressed to OUR node hash.
                if ((payload[0] & 0xFF) != myHash || payload.length < 6) {
                    return;
                }
                FrameHeader.Parsed parsed = FrameHeader.parse(payload, 2);
                if (parsed.header().kind() != FrameKind.PING) {
                    return;
                }
                Long sentAt = pendingByMsgId.remove(parsed.header().msgId());
                if (sentAt == null) {
                    return; // not ours / duplicate
                }
                long rttMs = (System.nanoTime() - sentAt) / 1_000_000;
                rtts.add(rttMs);
                echoed.incrementAndGet();
                System.out.printf("pong msg_id=0x%04x rtt=%d ms%n", parsed.header().msgId(), rttMs);
            });

            int sent = 0;
            int sendFailures = 0;
            for (int i = 1; i <= count; i++) {
                int msgId = i & 0xFFFF;
                if (msgId == 0) {
                    msgId = 1; // 0x0000 is reserved (§3.3)
                }
                byte[] l1Frame = new FrameHeader(0, FrameKind.PING, 0, msgId, null, null).encode();
                byte[] payload = new byte[2 + l1Frame.length];
                payload[0] = (byte) dstHash;
                payload[1] = (byte) myHash;
                System.arraycopy(l1Frame, 0, payload, 2, l1Frame.length);

                // §2.8: TABLE_FULL means pause and retry the same frame.
                boolean enqueued = false;
                for (int attempt = 1; attempt <= 6 && !enqueued; attempt++) {
                    MeshCoreNode.RawSendResult r =
                            node.sendRawData(0, new byte[0], payload, Duration.ofSeconds(5));
                    if (r.sent()) {
                        enqueued = true;
                    } else if (r.tableFull()) {
                        long backoff = Math.max(500L * attempt, 1000);
                        System.out.printf("node queue full; retry %d in %d ms%n", attempt, backoff);
                        Thread.sleep(backoff);
                    } else {
                        System.out.printf("SEND_RAW_DATA failed, ERR_CODE=%d%n", r.errCode());
                        break;
                    }
                }
                if (enqueued) {
                    pendingByMsgId.put(msgId, System.nanoTime());
                    sent++;
                    System.out.printf("ping msg_id=0x%04x sent%n", msgId);
                } else {
                    sendFailures++;
                }
                Thread.sleep(intervalMs);
            }

            // Drain window for stragglers (multi-hop scheduling, duty-cycle pauses).
            long deadline = System.currentTimeMillis() + timeoutMs;
            while (echoed.get() < sent && System.currentTimeMillis() < deadline) {
                Thread.sleep(100);
            }

            int lost = sent - echoed.get();
            System.out.println();
            System.out.println("=== bench-ping summary ===");
            System.out.printf("sent=%d echoed=%d lost=%d sendFailures=%d%n",
                    sent, echoed.get(), lost, sendFailures);
            if (!rtts.isEmpty()) {
                long min = Long.MAX_VALUE, max = Long.MIN_VALUE, sum = 0;
                for (long r : rtts) {
                    min = Math.min(min, r);
                    max = Math.max(max, r);
                    sum += r;
                }
                System.out.printf("rtt min/avg/max = %d/%d/%d ms%n",
                        min, sum / rtts.size(), max);
            }
            if (lost > 0 || sendFailures > 0) {
                System.out.println("RESULT: FAIL");
            } else {
                System.out.println("RESULT: PASS — frames crossed the air both ways");
            }
        }
    }

    private static int optInt(ApplicationArguments args, String name, int def) {
        List<String> v = args.getOptionValues(name);
        return v == null || v.isEmpty() ? def : Integer.parseInt(v.getFirst());
    }

    private static long optLong(ApplicationArguments args, String name, long def) {
        List<String> v = args.getOptionValues(name);
        return v == null || v.isEmpty() ? def : Long.parseLong(v.getFirst());
    }

    /** Precedence: --port=NAME > meshu.serial.port property > auto-detect. */
    private String resolvePort(ApplicationArguments args) {
        List<String> v = args.getOptionValues("port");
        if (v != null && !v.isEmpty()) {
            return v.getFirst();
        }
        String configured = props.serial().port();
        if (configured != null && !configured.isBlank()) {
            return configured;
        }
        List<String> candidates = MeshCoreNode.detectPorts();
        if (candidates.isEmpty()) {
            throw new IllegalStateException(
                    "no serial port found — plug in node#2 or pass --port=NAME");
        }
        if (candidates.size() > 1) {
            throw new IllegalStateException("multiple candidate ports " + candidates
                    + " — pass --port=NAME (both nodes tethered?)");
        }
        return candidates.getFirst();
    }
}
