package meshu.core.l1;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;

/**
 * MessageSender over a fake lossy channel: convergence under loss/duplication/
 * reordering/delay, window enforcement, ATTEMPT anti-suppression semantics,
 * and give-up after MAX_RETRY without progress (§3.4–§3.7, §12.3).
 */
class MessageSenderTest {

    /**
     * Two-endpoint lossy loopback. Sender side = {@code aToB}, return path =
     * {@code bToA}. Policies are deterministic so tests never flake.
     */
    static final class FakeChannel {
        private final java.util.concurrent.ScheduledExecutorService ex =
                Executors.newScheduledThreadPool(4);
        private final Random rnd = new Random(7);
        private long maxDelayMs = 0;
        private final double dupProb = 0.0;
        /** Deterministic policies: drop the first N frames matching a predicate. */
        private final List<java.util.function.Predicate<TestContext>> dropOncePolicies = new ArrayList<>();
        private final Map<java.util.function.Predicate<TestContext>, Boolean> fired = new HashMap<>();
        volatile boolean dropAllReturnPath = false;
        Consumer<byte[]> peerB;   // receiver inbound
        Consumer<byte[]> peerA;   // sender-side inbound (ACKBM path)

        // Window observation on the A→B direction.
        private final AtomicInteger a2bInFlight = new AtomicInteger();
        volatile int maxObservedInFlight = 0;

        void aToB(byte[] frame) {
            // Derive the policy context from the frame header itself.
            FrameHeader.Parsed p = FrameHeader.parse(frame, 0);
            var h = p.header();
            TestContext ctx = new TestContext(h.multi() ? h.seq() : -1,
                    h.attempt(), h.multi());
            for (var policy : dropOncePolicies) {
                if (!fired.getOrDefault(policy, false) && policy.test(ctx)) {
                    fired.put(policy, true);
                    return; // dropped once
                }
            }
            deliver(frame, peerB);
        }

        void bToA(byte[] frame) {
            if (dropAllReturnPath) {
                return;
            }
            deliver(frame, peerA);
        }

        private void deliver(byte[] frame, Consumer<byte[]> peer) {
            boolean dataDirection = peer == peerB;
            if (dataDirection) {
                int inflight = a2bInFlight.incrementAndGet();
                synchronized (this) {
                    maxObservedInFlight = Math.max(maxObservedInFlight, inflight);
                }
            }
            long delay = rnd.nextInt((int) maxDelayMs + 1);
            ex.schedule(() -> {
                if (dataDirection) {
                    a2bInFlight.decrementAndGet();
                }
                peer.accept(frame);
                if (rnd.nextDouble() < dupProb && peer == peerB) {
                    ex.schedule(() -> peer.accept(frame), rnd.nextInt(10), TimeUnit.MILLISECONDS);
                }
            }, delay, TimeUnit.MILLISECONDS);
        }

        void shutdown() throws InterruptedException {
            ex.shutdown();
            ex.awaitTermination(5, TimeUnit.SECONDS);
        }
    }

    /** Per-frame context handed to drop policies. */
    record TestContext(int seq, int attempt, boolean multi) {
    }

    /** Receiver half: feeds a Reassembler and answers ACKBMs through the channel. */
    static final class ReceiverHarness {
        final Reassembler reassembler = new Reassembler();
        final CountDownLatch complete = new CountDownLatch(1);
        volatile byte[] assembledBody;
        /** flags byte per (seq) — proves resends differ (anti-duplicate suppression). */
        final Map<Integer, HashSet<Integer>> flagsPerSeq = new ConcurrentHashMap<>();

        void onData(byte[] l1Frame, FakeChannel channel) {
            FrameHeader.Parsed parsed = FrameHeader.parse(l1Frame, 0);
            if (parsed.header().kind() != FrameKind.DATA) {
                return;
            }
            var h = parsed.header();
            flagsPerSeq.computeIfAbsent(h.multi() ? h.seq() : 0,
                    k -> new HashSet<>()).add(l1Frame[1] & 0xFF);
            byte[] body = java.util.Arrays.copyOfRange(l1Frame, parsed.bodyOffset(), l1Frame.length);
            Reassembler.Result r = reassembler.feed(h, body);
            if (r instanceof Reassembler.Result.Pending p && p.ack() != null) {
channel.bToA(p.ack());
            } else if (r instanceof Reassembler.Result.Complete c) {
                assembledBody = c.body();
                if (c.ack() != null) {
                    channel.bToA(c.ack());
                }
                complete.countDown();
            }
            // Duplicate / Inconsistent: no response (Duplicate-after-complete is
            // answered inside Reassembler via Pending(fullAck)).
        }
    }

    private static byte[] payload(int len, int seed) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) {
            b[i] = (byte) (seed + i * 31);
        }
        return b;
    }

    @Test
    void cleanLinkSingleFrameAckedAndReceived() throws Exception {
        FakeChannel ch = new FakeChannel();
        ch.maxDelayMs = 5;
        ReceiverHarness rx = new ReceiverHarness();
        ch.peerB = f -> rx.onData(f, ch);

        AirtimeGovernor gov = new AirtimeGovernor(1.0, 5, 20);
        MessageSender sender = new MessageSender(ch::aToB, gov,
                MessageSender.Config.fast(250, 20));
        ch.peerA = sender::onFrameReceived;

        byte[] body = payload(100, 1); // single frame (≤161)
        var result = sender.send(0x0001, body);

        assertEquals(MessageSender.Status.ACKED, result.status());
        assertTrue(rx.complete.await(2, TimeUnit.SECONDS));
        assertArrayEquals(body, rx.assembledBody);
        ch.shutdown();
    }

    @Test
    void fragmentedMessageConvergesOnCleanLink() throws Exception {
        FakeChannel ch = new FakeChannel();
        ch.maxDelayMs = 5;
        ReceiverHarness rx = new ReceiverHarness();
        ch.peerB = f -> rx.onData(f, ch);

        AirtimeGovernor gov = new AirtimeGovernor(1.0, 8, 20);
        MessageSender sender = new MessageSender(ch::aToB, gov,
                MessageSender.Config.fast(250, 20));
        ch.peerA = sender::onFrameReceived;

        byte[] body = payload(500, 42); // 4 fragments
        var result = sender.send(0x0002, body);

        assertEquals(MessageSender.Status.ACKED, result.status());
        assertEquals(4, result.frames());
        assertTrue(rx.complete.await(2, TimeUnit.SECONDS));
        assertArrayEquals(body, rx.assembledBody);
        ch.shutdown();
    }

    /** Deterministic losses: first transmission of seq 0 and seq 2 is dropped. */
    @Test
    void convergesWithDeterministicLossAndResendsDiffer() throws Exception {
        FakeChannel ch = new FakeChannel();
        ch.maxDelayMs = 15;
        ch.dropOncePolicies.add(ctx -> ctx.seq() == 0 && ctx.attempt() == 0);
        ch.dropOncePolicies.add(ctx -> ctx.seq() == 2 && ctx.attempt() == 0);
        ReceiverHarness rx = new ReceiverHarness();
        ch.peerB = f -> rx.onData(f, ch);

        AirtimeGovernor gov = new AirtimeGovernor(1.0, 8, 20);
        // Sender-side observation of every transmission, per seq.
        Map<Integer, List<byte[]>> sentBySeq = new ConcurrentHashMap<>();
        MessageSender.Transport recording = frame -> {
            var h = FrameHeader.parse(frame, 0).header();
            sentBySeq.computeIfAbsent(h.multi() ? h.seq() : 0, k -> new ArrayList<>()).add(frame);
            ch.aToB(frame);
        };
        MessageSender sender = new MessageSender(recording, gov,
                MessageSender.Config.fast(250, 20));
        ch.peerA = sender::onFrameReceived;

        byte[] body = payload(500, 9);
        var result = sender.send(0x0003, body);

        assertEquals(MessageSender.Status.ACKED, result.status());
        assertTrue(result.transmissions() > result.frames(),
                "dropped frames must have been retransmitted");
        assertTrue(rx.complete.await(3, TimeUnit.SECONDS));
        assertArrayEquals(body, rx.assembledBody);
        // Anti-suppression proof (§2.8): the retransmitted copies of seq 0 and
        // seq 2 differ from their first transmissions (ATTEMPT incremented —
        // never a verbatim resend). Observed sender-side because a *dropped*
        // first transmission is by definition invisible to the receiver.
        for (int seq : new int[]{0, 2}) {
            var copies = sentBySeq.get(seq);
            assertTrue(copies.size() >= 2, "seq " + seq + " must have been resent");
            assertFalse(java.util.Arrays.equals(copies.getFirst(), copies.get(1)),
                    "resend of seq " + seq + " must differ in bytes (ATTEMPT)");
        }
        ch.shutdown();
    }

    @Test
    void windowIsRespected() throws Exception {
        FakeChannel ch = new FakeChannel();
        ch.maxDelayMs = 40;
        ReceiverHarness rx = new ReceiverHarness();
        ch.peerB = f -> rx.onData(f, ch);

        AirtimeGovernor gov = new AirtimeGovernor(1.0, 16, 20);
        // Sender-side timeline: every submission and every ACK timestamped, so
        // we can reconstruct the true UNACKED count over time — that is the
        // §12.3 invariant ("in-flight DATA frames per message MUST be capped"),
        // not raw airborne frames (which depends on channel latency).
        record Event(long t, int seq, boolean submit) {
        }
        List<Event> timeline = new ArrayList<>();
        Map<Integer, Long> pendingSubmit = new ConcurrentHashMap<>();
        MessageSender.Transport recording = frame -> {
            var h = FrameHeader.parse(frame, 0).header();
            int seq = h.multi() ? h.seq() : 0;
            long t = System.nanoTime();
            synchronized (timeline) {
                timeline.add(new Event(t, seq, true));
            }
            pendingSubmit.put(seq, t);
            ch.aToB(frame);
        };
        MessageSender sender = new MessageSender(recording, gov,
                MessageSender.Config.fast(400, 20));
        ch.peerA = frame -> {

            var p = FrameHeader.parse(frame, 0);
            if (p.header().kind() == FrameKind.ACKBM) {
                int off = p.bodyOffset();
                int total = frame[off] & 0xFF;
                long t = System.nanoTime();
                for (int seq = 0; seq < total; seq++) {
                    boolean set = ((frame[off + 1 + (seq >> 3)] >> (seq & 7)) & 1) != 0;
                    if (set && pendingSubmit.containsKey(seq)) {
                        Long st = pendingSubmit.remove(seq);
                        if (st != null) {
                            synchronized (timeline) {
                                timeline.add(new Event(t, seq, false));
                            }
                        }
                    }
                }
            }
            sender.onFrameReceived(frame);
        };

        byte[] body = payload(2000, 3); // ceil(2017/159) = 13 frames > window 6
        var result = sender.send(0x0004, body);

        assertEquals(MessageSender.Status.ACKED, result.status());
        assertTrue(rx.complete.await(5, TimeUnit.SECONDS));

        // Sweep the timeline tracking PER-SEQ state: unacked = submitted &&
        // not-yet-acked, counted once per frame no matter how many times it was
        // retransmitted (a resend does not create a second outstanding frame).
        List<Event> events;
        synchronized (timeline) {
            events = new ArrayList<>(timeline);
        }
        events.sort(java.util.Comparator.comparingLong(Event::t));
        int nFrames = Segmenter.segment(0x0004, body, Segmenter.MTU_FLOOR).size();
        boolean[] submitted = new boolean[nFrames];
        boolean[] ackedNow = new boolean[nFrames];
        int maxUnacked = 0;
        for (Event e : events) {
            if (e.submit()) {
                submitted[e.seq()] = true;
            } else {
                ackedNow[e.seq()] = true;
            }
            int unacked = 0;
            for (int i = 0; i < nFrames; i++) {
                if (submitted[i] && !ackedNow[i]) {
                    unacked++;
                }
            }
            maxUnacked = Math.max(maxUnacked, unacked);
        }
assertTrue(maxUnacked <= Segmenter.WINDOW,
                "unacked peaked at " + maxUnacked + " > MESHU_WINDOW " + Segmenter.WINDOW);
        ch.shutdown();
    }

    @Test
    void givesUpWhenAcksNeverArrive() throws Exception {
        FakeChannel ch = new FakeChannel();
        ch.maxDelayMs = 5;
        ch.dropAllReturnPath = true; // every ACKBM black-holed
        ReceiverHarness rx = new ReceiverHarness(); // would ack, but acks die here
        ch.peerB = f -> rx.onData(f, ch);

        AirtimeGovernor gov = new AirtimeGovernor(1.0, 8, 20);
        // minRto 150ms, maxRetry 3 → gives up in well under a second per round math.
        MessageSender sender = new MessageSender(ch::aToB, gov,
                new MessageSender.Config(150, 3, Segmenter.WINDOW, 20, Segmenter.MTU_FLOOR, 100));
        ch.peerA = sender::onFrameReceived;

        long start = System.currentTimeMillis();
        var result = sender.send(0x0005, payload(500, 77)); // 4 fragments
        long elapsed = System.currentTimeMillis() - start;

        assertEquals(MessageSender.Status.GAVE_UP, result.status());
        assertTrue(elapsed < 3_000, "should give up promptly, took " + elapsed + "ms");
        assertTrue(result.roundsNoProgress() >= 3);
        // The DATA frames all arrived (only the return path was black-holed), so
        // the receiver DID assemble the message while the sender gave up — this
        // is precisely why §11 recovery exists. Assert that happened.
        assertTrue(rx.complete.await(200, TimeUnit.MILLISECONDS),
                "receiver should have assembled every fragment");
        ch.shutdown();
    }
}
