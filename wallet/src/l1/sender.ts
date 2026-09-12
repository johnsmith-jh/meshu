/**
 * Reliable delivery of one message over an L1 transport (PROTOCOL.md §3.4–3.7).
 * TS port of core/MessageSender.java — window cap, ACKBM-driven selective
 * retransmit with ATTEMPT increment, RTO, give-up after rounds without progress.
 */
import {
  dataMulti,
  dataSingle,
  encodeFrame,
  isMulti,
  KIND_ACKBM,
  parseHeader,
} from './frame';
import { AirtimeGovernor } from './governor';
import { MTU_FLOOR, segment, WINDOW, type Frame } from './segmenter';

export interface SenderConfig {
  minRtoMs: number; // MESHU_MIN_RTO
  maxRetryRounds: number; // MESHU_MAX_RETRY
  window: number; // MESHU_WINDOW
  frameAirtimeMs: number; // §12.1 measured airtime
  mtu: number; // §2.7 current path MTU
  rtoExtraMs: number; // fixed +4000 ms term of the §3.7 formula
}

export const SenderConfigFactory = {
  defaults: (frameAirtimeMs: number): SenderConfig => ({
    minRtoMs: 15_000,
    maxRetryRounds: 4,
    window: WINDOW,
    frameAirtimeMs,
    mtu: MTU_FLOOR,
    rtoExtraMs: 4000,
  }),
  fast: (minRtoMs: number, frameAirtimeMs: number): SenderConfig => ({
    minRtoMs,
    maxRetryRounds: 4,
    window: WINDOW,
    frameAirtimeMs,
    mtu: MTU_FLOOR,
    rtoExtraMs: 100,
  }),
};

export type SendStatus = 'acked' | 'gave_up';

export interface SendResult {
  status: SendStatus;
  frames: number;
  transmissions: number;
  roundsNoProgress: number;
}

export interface L1SenderTransport {
  /** Push one encoded L1 frame (already governor-paced). */
  sendFrame(l1Frame: Uint8Array): void;
}

interface TxState {
  frames: Frame[];
  acked: boolean[];
  sent: boolean[];
  attempts: number[];
  nextToSend: number;
  ackCount: number;
  roundsNoProgress: number;
}

export class MessageSender {
  private tx: TxState | null = null;

  constructor(
    private readonly transport: L1SenderTransport,
    private readonly governor: AirtimeGovernor,
    private readonly cfg: SenderConfig,
  ) {}

  /** Send one message reliably; resolves on ACK or give-up (§3.7). */
  async send(msgId: number, body: Uint8Array): Promise<SendResult> {
    if (this.tx) throw new Error('a message is already in flight');
    const frames = segment(msgId, body, this.cfg.mtu);
    const tx: TxState = {
      frames,
      acked: new Array(frames.length).fill(false),
      sent: new Array(frames.length).fill(false),
      attempts: new Array(frames.length).fill(0),
      nextToSend: 0,
      ackCount: 0,
      roundsNoProgress: 0,
    };
    this.tx = tx;
    try {
      return await this.doSend(tx, msgId);
    } finally {
      this.tx = null;
    }
  }

  private async doSend(tx: TxState, msgId: number): Promise<SendResult> {
    await this.fillWindow(tx);
    let deadline = this.rtoDeadline(tx);

    const done = (status: SendStatus): SendResult => ({
      status,
      frames: tx.frames.length,
      transmissions: tx.attempts.reduce((n, a) => n + a + 1, 0),
      roundsNoProgress: tx.roundsNoProgress,
    });

    for (;;) {
      if (tx.ackCount === tx.frames.length) return done('acked');
      const waitMs = deadline - Date.now();
      if (waitMs <= 0) {
        // RTO fired: retransmit everything not yet known-received (§3.7).
        const before = tx.ackCount;
        await this.retransmitMissing(tx);
        if (tx.ackCount === tx.frames.length) return done('acked');
        tx.roundsNoProgress = tx.ackCount <= before ? tx.roundsNoProgress + 1 : 0;
        if (tx.roundsNoProgress >= this.cfg.maxRetryRounds) return done('gave_up');
        deadline = this.rtoDeadline(tx);
        continue;
      }
      // Bounded slices; ACKs mutate tx state and are observed on wake.
      const ackBefore = tx.ackCount;
      await sleep(Math.min(waitMs, 100));
      if (tx.ackCount === tx.frames.length) return done('acked');
      // Reset the RTO deadline ONLY when ACKs actually advanced (§3.7) —
      // resetting unconditionally would postpone RTO forever (porting bug).
      if (tx.ackCount > ackBefore) {
        await this.fillWindow(tx);
        deadline = this.rtoDeadline(tx);
      }
    }
  }

  /**
   * Feed one inbound frame (any kind; only ACKBM matters). Called from the
   * transport's reader path. Safe during an in-flight send.
   */
  onFrameReceived(frame: Uint8Array): void {
    const tx = this.tx;
    if (!tx) return;
    let parsed;
    try {
      parsed = parseHeader(frame, 0);
    } catch {
      return; // not ours / malformed
    }
    if (parsed.header.kind !== KIND_ACKBM) return;
    if (tx.frames.length === 0 || parsed.header.msgId !== tx.frames[0]!.header.msgId) return;
    const off = parsed.bodyOffset;
    if (frame.length < off + 1) return;
    const total = frame[off]! & 0xff;
    if (total !== tx.frames.length) return; // ACK for different fragmentation
    const bitmap = frame.slice(off + 1);
    for (let seq = 0; seq < total && seq >> 3 < bitmap.length; seq++) {
      if (((bitmap[seq >> 3]! >> (seq & 7)) & 1) !== 0 && !tx.acked[seq]) {
        tx.acked[seq] = true;
        tx.ackCount++;
      }
    }
  }

  // ------------------------------------------------------------ internals

  private async fillWindow(tx: TxState): Promise<void> {
    while (tx.nextToSend < tx.frames.length && this.inflight(tx) < this.cfg.window) {
      await this.sendOne(tx, tx.nextToSend);
      tx.nextToSend++;
    }
  }

  /** §3.7: retransmit all not-known-received frames with ATTEMPT incremented. */
  private async retransmitMissing(tx: TxState): Promise<void> {
    for (let seq = 0; seq < tx.frames.length; seq++) {
      if (!tx.acked[seq]) await this.sendOne(tx, seq);
    }
  }

  private async sendOne(tx: TxState, seq: number): Promise<void> {
    await this.governor.acquireBlocking(); // every transmission is paced (§3.5)
    const f = tx.frames[seq]!;
    // §3.1: ATTEMPT is 0 on FIRST transmission, increments per retry. Read the
    // counter (never the stale segmented header — copies must differ, §2.8).
    const attempt = (tx.attempts[seq] ?? 0) & 0x3;
    tx.attempts[seq] = (attempt + 1) & 0x3;
    const reqAck = (f.header.flags & 0x02) !== 0;
    const h = isMulti(f.header)
      ? dataMulti(f.header.msgId, f.header.seq!, f.header.lastSeq!, attempt, reqAck)
      : dataSingle(f.header.msgId, attempt, reqAck);
    this.transport.sendFrame(encodeFrame(h, f.body));
    tx.sent[seq] = true;
  }

  private inflight(tx: TxState): number {
    let n = 0;
    for (let seq = 0; seq < tx.frames.length; seq++) {
      if (tx.sent[seq] && !tx.acked[seq]) n++;
    }
    return n;
  }

  /** timeout = max(MIN_RTO, 2 × inflight × airtime + rtoExtraMs) (§3.7). */
  private rtoDeadline(tx: TxState): number {
    const computed = 2 * Math.max(1, this.inflight(tx)) * this.cfg.frameAirtimeMs + this.cfg.rtoExtraMs;
    return Date.now() + Math.max(this.cfg.minRtoMs, computed);
  }
}

const sleep = (ms: number): Promise<void> => new Promise(r => setTimeout(r, ms));

/** Exposed helpers re-exported for tests. */
export { parseHeader, KIND_ACKBM };
