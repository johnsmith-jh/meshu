/**
 * Transmit airtime governor (PROTOCOL.md §12.2–12.3): a token bucket over
 * transmit airtime enforcing the duty cycle. TS port of AirtimeGovernor.java.
 */
export const DEFAULT_DUTY_CYCLE = 0.1;
export const DEFAULT_BURST_FRAMES = 5;

export class AirtimeGovernor {
  private tokensMs: number;
  private lastRefill = Date.now();

  constructor(
    private readonly dutyCycle: number,
    private readonly burstFrames: number,
    private readonly frameAirtimeMs: number,
  ) {
    if (dutyCycle <= 0 || dutyCycle > 1) throw new Error(`dutyCycle must be in (0,1]: ${dutyCycle}`);
    if (burstFrames < 1 || frameAirtimeMs <= 0) {
      throw new Error('burstFrames >= 1 and frameAirtimeMs > 0 required');
    }
    this.tokensMs = burstFrames * frameAirtimeMs; // start full: idle channel may burst
  }

  static withDefaults(frameAirtimeMs: number): AirtimeGovernor {
    return new AirtimeGovernor(DEFAULT_DUTY_CYCLE, DEFAULT_BURST_FRAMES, frameAirtimeMs);
  }

  /** Take one frame's airtime credit if available (non-blocking). */
  tryAcquire(): boolean {
    this.refill();
    if (this.tokensMs >= this.frameAirtimeMs) {
      this.tokensMs -= this.frameAirtimeMs;
      return true;
    }
    return false;
  }

  /** ms until a frame can be sent (0 = now). */
  millisUntilSendable(): number {
    this.refill();
    const deficit = this.frameAirtimeMs - this.tokensMs;
    return deficit <= 0 ? 0 : Math.ceil(deficit / this.dutyCycle);
  }

  /** Block until one frame can be sent. */
  async acquireBlocking(): Promise<void> {
    while (!this.tryAcquire()) {
      await sleep(Math.max(1, this.millisUntilSendable()));
    }
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    if (elapsed > 0) {
      const cap = this.burstFrames * this.frameAirtimeMs;
      this.tokensMs = Math.min(cap, this.tokensMs + Math.round(elapsed * this.dutyCycle));
      this.lastRefill = now;
    }
  }
}

export const sleep = (ms: number): Promise<void> => new Promise(r => setTimeout(r, ms));
