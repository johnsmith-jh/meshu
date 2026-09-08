package meshu.core.l1;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AirtimeGovernorTest {

    @Test
    void burstFramesAvailableImmediately() {
        // 5-frame burst at 100 ms/frame: all 5 acquire without waiting.
        AirtimeGovernor g = new AirtimeGovernor(0.10, 5, 100);
        for (int i = 0; i < 5; i++) {
            assertTrue(g.tryAcquire(), "burst frame " + i + " should be immediately available");
        }
        assertFalse(g.tryAcquire(), "6th frame must wait for duty-cycle refill");
    }

    @Test
    void refillAccruesAtDutyCycleRate() throws Exception {
        // 50% duty, 20 ms frames → a frame costs 40 ms of wall time.
        AirtimeGovernor g = new AirtimeGovernor(0.50, 1, 20);
        assertTrue(g.tryAcquire());          // bucket empties
        assertFalse(g.tryAcquire());
        Thread.sleep(60);                    // ~30 ms credit accrued > one frame
        assertTrue(g.tryAcquire(), "duty-cycle refill should permit a frame after 3x airtime wall time");
    }

    @Test
    void millisUntilSendableIsMonotoneAndSane() throws Exception {
        AirtimeGovernor g = new AirtimeGovernor(0.10, 1, 100);
        g.tryAcquire();                      // empty the bucket
        long wait = g.millisUntilSendable();
        assertTrue(wait > 0 && wait <= 1100,
                "at 10% duty a 100 ms frame needs ≤1.1 s wall time; got " + wait);
        Thread.sleep(Math.min(wait, 200));
        // Not necessarily sendable yet, but the estimate must have shrunk or hit 0.
        long later = g.millisUntilSendable();
        assertTrue(later <= wait);
    }

    @Test
    void capacityCapsCredit() throws Exception {
        // Long idle period must not accumulate more than burst capacity.
        AirtimeGovernor g = new AirtimeGovernor(0.10, 2, 10);
        Thread.sleep(30); // far more than needed to refill both frames
        int sent = 0;
        while (g.tryAcquire()) {
            sent++;
            if (sent > 2) break;
        }
        assertEquals(2, sent, "credit must cap at burst capacity (2 frames)");
    }

    @Test
    void rejectsInvalidParameters() {
        assertThrows(IllegalArgumentException.class, () -> new AirtimeGovernor(0, 5, 100));
        assertThrows(IllegalArgumentException.class, () -> new AirtimeGovernor(1.5, 5, 100));
        assertThrows(IllegalArgumentException.class, () -> new AirtimeGovernor(0.1, 0, 100));
        assertThrows(IllegalArgumentException.class, () -> new AirtimeGovernor(0.1, 5, 0));
    }
}
