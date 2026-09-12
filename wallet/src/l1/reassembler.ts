/**
 * L1 reassembly of fragmented DATA frames (PROTOCOL.md §3.5–3.6).
 * TS port of core/Reassembler.java, including the wire-ready ACKBM fix and the
 * completed-message cache that re-ACKs late duplicates (the completing ACKBM
 * itself may have been lost).
 */
import { ackbm, encodeFrame, isMulti, isReqAck, parseHeader, type FrameHeader } from './frame';
import { KIND_ACKBM, KIND_DATA } from './frameKind';

export const MAX_REASM = 4;
const COMPLETED_CACHE_SIZE = 64;

export type ReasmResult =
  | { kind: 'pending'; ack: Uint8Array | null }
  | { kind: 'complete'; body: Uint8Array; ack: Uint8Array | null }
  | { kind: 'duplicate' }
  | { kind: 'inconsistent' };

interface State {
  lastSeq: number;
  fragments: (Uint8Array | null)[];
  bitmap: Uint8Array;
  received: number;
}

export class Reassembler {
  private readonly states = new Map<number, State>();
  private readonly completed = new Map<number, number>(); // msgId → total
  private readonly maxReasm: number;

  constructor(maxReasm: number = MAX_REASM) {
    this.maxReasm = maxReasm;
  }

  feed(header: FrameHeader, body: Uint8Array): ReasmResult {
    const msgId = header.msgId;
    if (!isMulti(header)) {
      // Single-frame message: complete immediately (§3.5). Always re-ACK when
      // requested — a retry here means our previous ACK was lost.
      this.setCompleted(msgId, 1);
      const ack = isReqAck(header) ? fullAckbmFrame(msgId, 1) : null;
      return { kind: 'complete', body, ack };
    }
    const completedTotal = this.completed.get(msgId);
    if (completedTotal !== undefined) {
      // Already assembled; the duplicate means our ACKBM was lost. Answer with
      // a full bitmap so the sender can finish immediately.
      return { kind: 'pending', ack: fullAckbmFrame(msgId, completedTotal) };
    }

    const seq = header.seq!;
    const lastSeq = header.lastSeq!;
    if (seq > lastSeq) {
      // Malformed framing (§3.5): abort the message, never index out of bounds.
      this.states.delete(msgId);
      return { kind: 'inconsistent' };
    }

    let s = this.states.get(msgId);
    if (s && s.lastSeq !== lastSeq) {
      this.states.delete(msgId);
      return { kind: 'inconsistent' };
    }
    if (!s) {
      if (this.states.size >= this.maxReasm) {
        this.evictEldest();
      }
      s = {
        lastSeq,
        fragments: new Array(lastSeq + 1).fill(null),
        bitmap: new Uint8Array((lastSeq + 1 + 7) >> 3),
        received: 0,
      };
      this.states.set(msgId, s);
    }
    const byteIdx = seq >> 3;
    if (((s.bitmap[byteIdx] ?? 0) >> (seq & 7)) & 1) {
      return { kind: 'duplicate' };
    }
    s.fragments[seq] = body;
    s.bitmap[byteIdx] = (s.bitmap[byteIdx] ?? 0) | (1 << (seq & 7));
    s.received++;

    if (s.received === s.fragments.length) {
      this.states.delete(msgId);
      this.setCompleted(msgId, s.lastSeq + 1);
      const total = s.fragments.reduce((n, f) => n + (f?.length ?? 0), 0);
      const body = new Uint8Array(total);
      let pos = 0;
      for (const f of s.fragments) body.set(f!, pos), (pos += f!.length);
      const ack = isReqAck(header) ? fullAckbmFrame(msgId, s.lastSeq + 1) : null;
      return { kind: 'complete', body, ack };
    }
    return { kind: 'pending', ack: isReqAck(header) ? ackbmFrame(msgId, s.lastSeq + 1, s.bitmap) : null };
  }

  private evictEldest(): void {
    // §3.5: evict least recently advanced — eldest inserted is the PoC stand-in.
    const first = this.states.keys().next();
    if (!first.done) this.states.delete(first.value);
  }

  /** Record a completion, evicting the eldest beyond COMPLETED_CACHE_SIZE. */
  private setCompleted(msgId: number, total: number): void {
    this.completed.set(msgId, total);
    if (this.completed.size > COMPLETED_CACHE_SIZE) {
      const first = this.completed.keys().next();
      if (!first.done) this.completed.delete(first.value);
    }
  }
}

/** ACKBM body (§3.6): `total ‖ bitmap` (headerless — internal use). */
function ackbmFrameBody(_msgId: number, total: number, bitmap: Uint8Array): Uint8Array {
  const body = new Uint8Array(1 + bitmap.length);
  body[0] = total;
  body.set(bitmap, 1);
  return body;
}

/** Full ACKBM frame (header ‖ body) — wire-ready. */
export function ackbmFrame(msgId: number, total: number, bitmap: Uint8Array): Uint8Array {
  return encodeFrame(ackbm(msgId), ackbmFrameBody(msgId, total, bitmap));
}

/** ACKBM with every bit set — "I have the whole message." */
export function fullAckbmFrame(msgId: number, total: number): Uint8Array {
  const bitmap = new Uint8Array((total + 7) >> 3);
  for (let i = 0; i < total; i++) bitmap[i >> 3] = (bitmap[i >> 3] ?? 0) | (1 << (i & 7));
  return ackbmFrame(msgId, total, bitmap);
}

/** Convenience for tests/tools: parse any frame and feed DATA bodies through. */
export function feedWire(reassembler: Reassembler, frame: Uint8Array): ReasmResult {
  const parsed = parseHeader(frame, 0);
  if (parsed.header.kind !== KIND_DATA && parsed.header.kind !== KIND_ACKBM) {
    throw new Error(`not a DATA/ACKBM frame: 0x${parsed.header.kind.toString(16)}`);
  }
  const body = frame.slice(parsed.bodyOffset);
  return reassembler.feed(parsed.header, body);
}
