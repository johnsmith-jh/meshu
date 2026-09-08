package meshu.core.l1;

/**
 * Transmit airtime governor (PROTOCOL.md §12.2–§12.3): a token bucket over
 * transmit airtime that enforces the duty cycle.
 *
 * <ul>
 *   <li>Capacity: MESHU_BURST frames' worth of airtime (default 5)</li>
 *   <li>Refill: {@code duty_cycle × elapsed} — i.e. at 10% duty the channel
 *       accrues 100 ms of transmit credit per second of wall time</li>
 *   <li>A frame goes out only when the bucket covers its airtime</li>
 * </ul>
 *
 * <p>Frame airtime should come from the live radio parameters (§12.1: SF8 /
 * BW62.5 ≈ 1025 ms per frame); it is injected here so callers can compute it
 * from SELF_INFO rather than hardcoding.
 *
 * <p>This class paces; it does not queue. Callers that must not drop frames
 * wait between {@code tryAcquire()} attempts (see {@link #millisUntilSendable()}).
 */
public final class AirtimeGovernor {

    /** Default duty cycle (§12.2 MESHU_DUTY_CYCLE) — EU 869.525 MHz sub-band. */
    public static final double DEFAULT_DUTY_CYCLE = 0.10;
    /** Default burst (§12.3 MESHU_BURST), in frames. */
    public static final int DEFAULT_BURST_FRAMES = 5;

    private final long frameAirtimeMs;
    private final long capacityTokensMs;
    private final double dutyCycle;

    private long tokensMs;
    private long lastRefillNanos;

    /**
     * @param dutyCycle      fraction of wall time the channel may transmit (0–1)
     * @param burstFrames    bucket capacity, expressed in frames of airtime
     * @param frameAirtimeMs time-on-air of one full-size frame, in ms
     */
    public AirtimeGovernor(double dutyCycle, int burstFrames, long frameAirtimeMs) {
        if (dutyCycle <= 0 || dutyCycle > 1) {
            throw new IllegalArgumentException("dutyCycle must be in (0, 1]: " + dutyCycle);
        }
        if (burstFrames < 1 || frameAirtimeMs <= 0) {
            throw new IllegalArgumentException("burstFrames >= 1 and frameAirtimeMs > 0 required");
        }
        this.dutyCycle = dutyCycle;
        this.frameAirtimeMs = frameAirtimeMs;
        this.capacityTokensMs = (long) burstFrames * frameAirtimeMs;
        this.tokensMs = capacityTokensMs; // start full: an idle channel may burst immediately
        this.lastRefillNanos = System.nanoTime();
    }

    /** Convenience constructor with spec defaults. */
    public static AirtimeGovernor withDefaults(long frameAirtimeMs) {
        return new AirtimeGovernor(DEFAULT_DUTY_CYCLE, DEFAULT_BURST_FRAMES, frameAirtimeMs);
    }

    /**
     * Try to take one frame's worth of airtime. Refills first from elapsed
     * wall time. Non-blocking by design — pacing is the caller's job.
     */
    public synchronized boolean tryAcquire() {
        refill();
        if (tokensMs >= frameAirtimeMs) {
            tokensMs -= frameAirtimeMs;
            return true;
        }
        return false;
    }

    /** How long to wait until a frame can be sent (0 = now). Never negative. */
    public synchronized long millisUntilSendable() {
        refill();
        long deficit = frameAirtimeMs - tokensMs;
        if (deficit <= 0) {
            return 0;
        }
        // deficit / (dutyCycle ms credit per ms wall) — round up.
        return (long) Math.ceil(deficit / dutyCycle);
    }

    /** Block until one frame can be sent (polling sleep; fine at these timescales). */
    public void acquireBlocking() throws InterruptedException {
        while (!tryAcquire()) {
            Thread.sleep(Math.max(1, millisUntilSendable()));
        }
    }

    /** Accrue duty-cycle credit for the time since the last refill, capped at capacity. */
    private void refill() {
        long now = System.nanoTime();
        long elapsedMs = (now - lastRefillNanos) / 1_000_000;
        if (elapsedMs > 0) {
            tokensMs = Math.min(capacityTokensMs, tokensMs + Math.round(elapsedMs * dutyCycle));
            lastRefillNanos = now;
        }
    }
}
