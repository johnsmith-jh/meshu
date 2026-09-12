import { describe, expect, test } from 'vitest';
import { dataSingle, encodeFrame, parseHeader } from './frame';
import { KIND_DATA } from './frameKind';
import { AirtimeGovernor } from './governor';
import { MessageSender, SenderConfigFactory, type L1SenderTransport, type SenderConfig } from './sender';
import { Reassembler, ackbmFrame, fullAckbmFrame } from './reassembler';
import { MTU_FLOOR, segment, WINDOW } from './segmenter';

/**
 * Mirrors core's MessageSenderTest: MessageSender over a fake lossy channel,
 * with deterministic drop policies (never flaky) and a receiver harness that
 * answers ACKBMs — the full §3.4–3.7 loop without a radio.
 */

class FakeChannel {
  private readonly timers: ReturnType<typeof setTimeout>[] = [];
  readonly transmitted: Uint8Array[] = [];
  private dropPolicies: Array<(seq: number, attempt: number) => boolean> = [];
  private fired = new Set<string>();
  dropAllReturnPath = false;
  peerB: ((frame: Uint8Array) => void) | null = null;
  peerA: ((frame: Uint8Array) => void) | null = null;

  aToB(frame: Uint8Array): void {
    const h = parseHeader(frame, 0).header;
    const seq = h.seq ?? -1;
    const attempt = (h.flags & 0x0c) >> 2;
    for (const p of this.dropPolicies) {
      const key = `${p.toString().slice(0, 40)}:${seq}:${attempt}`;
      if (!this.fired.has(key) && p(seq, attempt)) {
        this.fired.add(key);
        return; // dropped once
      }
    }
    this.deliver(frame, this.peerB);
  }

  bToA(frame: Uint8Array): void {
    if (this.dropAllReturnPath) return;
    this.deliver(frame, this.peerA);
  }

  private deliver(frame: Uint8Array, peer: ((f: Uint8Array) => void) | null): void {
    if (!peer) return;
    const t = setTimeout(() => peer(frame), 1 + Math.floor(Math.random() * 3));
    this.timers.push(t);
  }

  dropFirst(seq: number): void {
    this.dropPolicies.push((s, a) => s === seq && a === 0);
  }

  async drain(): Promise<void> {
    await new Promise(r => setTimeout(r, 30));
    await Promise.all(this.timers.map(t => new Promise(r => setTimeout(r, 0))));
  }
}

class ReceiverHarness {
  readonly reassembler = new Reassembler();
  complete: { body: Uint8Array; ack: Uint8Array | null } | null = null;
  private resolver: ((v: { body: Uint8Array; ack: Uint8Array | null }) => void) | null = null;

  constructor(private readonly channel: FakeChannel) {}

  /** Resolves when the full message assembles (or never, on give-up paths). */
  get onComplete(): Promise<{ body: Uint8Array; ack: Uint8Array | null }> {
    return new Promise(resolve => {
      this.resolver = resolve;
    });
  }

  onData(l1Frame: Uint8Array): void {
    const parsed = parseHeader(l1Frame, 0);
    if (parsed.header.kind !== KIND_DATA) return;
    const body = l1Frame.slice(parsed.bodyOffset);
    const r = this.reassembler.feed(parsed.header, body);
    if (r.kind === 'pending' && r.ack) this.channel.bToA(r.ack);
    else if (r.kind === 'complete') {
      if (r.ack) this.channel.bToA(r.ack);
      this.complete = { body: r.body, ack: r.ack };
      this.resolver?.(this.complete);
    }
  }
}

const payload = (n: number, seed: number): Uint8Array => {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (seed + i * 31) & 0xff;
  return b;
};

const fastCfg = (minRtoMs = 250): SenderConfig => SenderConfigFactory.fast(minRtoMs, 20);
const governor = (): AirtimeGovernor => new AirtimeGovernor(1.0, 8, 20);

describe('MessageSender over a fake lossy channel (§3.4–3.7, §12.3)', () => {
  test('clean link, single frame: acked and received', async () => {
    const ch = new FakeChannel();
    const rx = new ReceiverHarness(ch);
    ch.peerB = f => rx.onData(f);
    const sender = new MessageSender({ sendFrame: f => ch.aToB(f) }, governor(), fastCfg());
    ch.peerA = f => sender.onFrameReceived(f);

    const body = payload(100, 1);
    const result = await sender.send(1, body);
    await ch.drain();

    expect(result.status).toBe('acked');
    expect(rx.complete?.body).toEqual(body);
  });

  test('fragmented message converges on a clean link', async () => {
    const ch = new FakeChannel();
    const rx = new ReceiverHarness(ch);
    ch.peerB = f => rx.onData(f);
    const sender = new MessageSender({ sendFrame: f => ch.aToB(f) }, governor(), fastCfg());
    ch.peerA = f => sender.onFrameReceived(f);

    const body = payload(500, 42);
    const result = await sender.send(2, body);
    await ch.drain();

    expect(result.status).toBe('acked');
    expect(result.frames).toBe(4);
    expect(rx.complete?.body).toEqual(body);
  });

  test('deterministic loss: retransmitted and bytes differ (§2.8)', async () => {
    const ch = new FakeChannel();
    ch.dropFirst(0);
    ch.dropFirst(2);
    const rx = new ReceiverHarness(ch);
    ch.peerB = f => rx.onData(f);

    const seenBySeq = new Map<number, Uint8Array[]>();
    const transport: L1SenderTransport = {
      sendFrame: f => {
        const seq = parseHeader(f, 0).header.seq ?? 0;
        const list = seenBySeq.get(seq) ?? [];
        list.push(f);
        seenBySeq.set(seq, list);
        ch.aToB(f);
      },
    };
    const sender = new MessageSender(transport, governor(), fastCfg());
    ch.peerA = f => sender.onFrameReceived(f);

    const body = payload(500, 9);
    const result = await sender.send(3, body);
    await ch.drain();

    expect(result.status).toBe('acked');
    expect(result.transmissions).toBeGreaterThan(result.frames);
    expect(rx.complete?.body).toEqual(body);
    for (const seq of [0, 2]) {
      const copies = seenBySeq.get(seq)!;
      expect(copies.length).toBeGreaterThanOrEqual(2);
      expect(Array.from(copies[0]!)).not.toEqual(Array.from(copies[1]!)); // ATTEMPT changed
    }
  });

  test('window invariant: unacked ≤ MESHU_WINDOW (§12.3)', async () => {
    const ch = new FakeChannel();
    const rx = new ReceiverHarness(ch);
    ch.peerB = f => rx.onData(f);

    // Timeline accounting: unacked = distinct frames submitted but not yet
    // ACKed — counted live, decremented when the ACK bitmap covers a seq.
    let unacked = 0;
    let maxUnacked = 0;
    const ackedSeen = new Set<number>();
    const transport: L1SenderTransport = {
      sendFrame: f => {
        const seq = parseHeader(f, 0).header.seq ?? 0;
        if (!ackedSeen.has(seq)) {
          unacked++;
          maxUnacked = Math.max(maxUnacked, unacked);
        }
        ch.aToB(f);
      },
    };
    const sender = new MessageSender(transport, governor(), fastCfg(400));
    ch.peerA = f => {
      const p = parseHeader(f, 0);
      if (p.header.kind === 0x12 /* ACKBM */) {
        const off = p.bodyOffset;
        const total = f[off]! & 0xff;
        for (let seq = 0; seq < total; seq++) {
          if (((f[off + 1 + (seq >> 3)]! >> (seq & 7)) & 1) !== 0 && !ackedSeen.has(seq)) {
            ackedSeen.add(seq);
            unacked--;
          }
        }
      }
      sender.onFrameReceived(f);
    };

    const result = await sender.send(4, payload(2000, 3)); // 13 frames > window 6
    await ch.drain();

    expect(result.status).toBe('acked');
    expect(rx.complete).not.toBeNull();
    expect(maxUnacked).toBeLessThanOrEqual(WINDOW);
  });

  test('gives up when ACKs never arrive (§3.7)', async () => {
    const ch = new FakeChannel();
    ch.dropAllReturnPath = true;
    const rx = new ReceiverHarness(ch);
    ch.peerB = f => rx.onData(f);
    const sender = new MessageSender(
      { sendFrame: f => ch.aToB(f) },
      governor(),
      { ...SenderConfigFactory.fast(150, 20), maxRetryRounds: 3 },
    );
    ch.peerA = f => sender.onFrameReceived(f);

    const start = Date.now();
    const result = await sender.send(5, payload(500, 77));
    const elapsed = Date.now() - start;
    await ch.drain();

    expect(result.status).toBe('gave_up');
    expect(elapsed).toBeLessThan(5000);
    expect(result.roundsNoProgress).toBeGreaterThanOrEqual(3);
    // The receiver DID assemble everything — exactly why §11 recovery exists.
    expect(rx.complete).not.toBeNull();
  });
});
