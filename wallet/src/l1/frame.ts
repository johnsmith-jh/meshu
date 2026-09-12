/**
 * L1 frame header (PROTOCOL.md §3.1) — 4 B single-frame, 6 B fragmented.
 *
 * byte 0  VVKKKKKK   VV = version (0b00 v1), KKKKKK = kind
 * byte 1  flags      MULTI 0x01 | REQ_ACK 0x02 | ATTEMPT 0x0C | reserved 0xF0
 * byte 2-3  msg_id (BE)
 * byte 4-5  seq / last_seq (only when MULTI)
 *
 * TS port of core/FrameHeader.java.
 */
import { KIND_ACKBM, KIND_DATA } from './frameKind';
export { KIND_ACKBM, KIND_DATA };

export const FLAG_MULTI = 0x01;
export const FLAG_REQ_ACK = 0x02;
export const FLAG_ATTEMPT_MASK = 0x0c;
export const ATTEMPT_SHIFT = 2;
export const HEADER_SINGLE = 4;
export const HEADER_MULTI = 6;

export interface FrameHeader {
  version: number; // 0..3
  kind: number; // 0..0x3F
  flags: number;
  msgId: number; // 0..0xFFFF
  seq: number | null; // only when MULTI
  lastSeq: number | null;
}

export interface ParsedFrame {
  header: FrameHeader;
  bodyOffset: number;
}

export function dataSingle(msgId: number, attempt: number, reqAck = false): FrameHeader {
  return make(0, KIND_DATA, (attempt << ATTEMPT_SHIFT) | (reqAck ? FLAG_REQ_ACK : 0), msgId, null, null);
}

export function dataMulti(
  msgId: number,
  seq: number,
  lastSeq: number,
  attempt: number,
  reqAck: boolean,
): FrameHeader {
  const flags = FLAG_MULTI | (attempt << ATTEMPT_SHIFT) | (reqAck ? FLAG_REQ_ACK : 0);
  return make(0, KIND_DATA, flags, msgId, seq, lastSeq);
}

export function ackbm(msgId: number): FrameHeader {
  return make(0, KIND_ACKBM, 0, msgId, null, null);
}

export function make(
  version: number,
  kind: number,
  flags: number,
  msgId: number,
  seq: number | null,
  lastSeq: number | null,
): FrameHeader {
  if (version < 0 || version > 3) throw new Error(`version out of range: ${version}`);
  if (kind < 0 || kind > 0x3f) throw new Error(`kind out of range: ${kind}`);
  if (msgId < 0 || msgId > 0xffff) throw new Error(`msg_id out of range: ${msgId}`);
  const multi = (flags & FLAG_MULTI) !== 0;
  if (multi && (seq === null || lastSeq === null)) {
    throw new Error('MULTI set but seq/lastSeq missing');
  }
  if (!multi && (seq !== null || lastSeq !== null)) {
    throw new Error('seq/lastSeq present but MULTI clear');
  }
  return { version, kind, flags, msgId, seq, lastSeq };
}

export const isMulti = (h: FrameHeader): boolean => (h.flags & FLAG_MULTI) !== 0;
export const isReqAck = (h: FrameHeader): boolean => (h.flags & FLAG_REQ_ACK) !== 0;
export const attemptOf = (h: FrameHeader): number => (h.flags & FLAG_ATTEMPT_MASK) >> ATTEMPT_SHIFT;
export const headerSize = (h: FrameHeader): number => (isMulti(h) ? HEADER_MULTI : HEADER_SINGLE);

export function encodeHeader(h: FrameHeader): Uint8Array {
  const out = new Uint8Array(headerSize(h));
  out[0] = ((h.version & 3) << 6) | (h.kind & 0x3f);
  out[1] = h.flags & 0xff;
  out[2] = (h.msgId >> 8) & 0xff;
  out[3] = h.msgId & 0xff;
  if (isMulti(h)) {
    out[4] = h.seq! & 0xff;
    out[5] = h.lastSeq! & 0xff;
  }
  return out;
}

/** Parse a header from {@code frame} at {@code offset}. */
export function parseHeader(frame: Uint8Array, offset: number): ParsedFrame {
  if (frame.length - offset < HEADER_SINGLE) {
    throw new Error(`frame too short for header: ${frame.length - offset}`);
  }
  const b0 = frame[offset]! & 0xff;
  const version = b0 >> 6;
  const kind = b0 & 0x3f;
  const flags = frame[offset + 1]! & 0xff;
  const msgId = ((frame[offset + 2]! & 0xff) << 8) | (frame[offset + 3]! & 0xff);
  let seq: number | null = null;
  let lastSeq: number | null = null;
  let bodyOffset = offset + HEADER_SINGLE;
  if ((flags & FLAG_MULTI) !== 0) {
    if (frame.length - offset < HEADER_MULTI) {
      throw new Error('frame too short for MULTI header');
    }
    seq = frame[offset + 4]! & 0xff;
    lastSeq = frame[offset + 5]! & 0xff;
    bodyOffset = offset + HEADER_MULTI;
  }
  return { header: make(version, kind, flags, msgId, seq, lastSeq), bodyOffset };
}

/** Encode a full frame (header ‖ body). */
export function encodeFrame(h: FrameHeader, body: Uint8Array): Uint8Array {
  const head = encodeHeader(h);
  const out = new Uint8Array(head.length + body.length);
  out.set(head, 0);
  out.set(body, head.length);
  return out;
}

/** Missing sequence numbers given a received bitmap (§3.6, §3.7). */
export function missingFromBitmap(total: number, bitmap: Uint8Array): number[] {
  const missing: number[] = [];
  for (let i = 0; i < total; i++) {
    if (((bitmap[i >> 3]! >> (i & 7)) & 1) === 0) missing.push(i);
  }
  return missing;
}
