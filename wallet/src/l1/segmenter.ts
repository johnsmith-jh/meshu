/**
 * L1 segmentation of one message into DATA frames (PROTOCOL.md §3.2, §3.4).
 * TS port of core/Segmenter.java.
 */
import {
  dataMulti,
  dataSingle,
  encodeFrame,
  HEADER_MULTI,
  HEADER_SINGLE,
  type FrameHeader,
} from './frame';

/** MTU floor (§2.7): valid to 7 hops with 1-byte path hashes. */
export const MTU_FLOOR = 165;
export const PAYLOAD_SINGLE = MTU_FLOOR - HEADER_SINGLE; // 161
export const PAYLOAD_MULTI = MTU_FLOOR - HEADER_MULTI; // 159
/** Default in-flight window (§12.3 MESHU_WINDOW). */
export const WINDOW = 6;
/** REQ_ACK every Nth frame (§3.4). */
export const REQ_ACK_CADENCE = 8;

export interface Frame {
  header: FrameHeader;
  body: Uint8Array;
}

export function encodeSegment(frame: Frame): Uint8Array {
  return encodeFrame(frame.header, frame.body);
}

/**
 * Segment a message body (sealed L2 output) into DATA frames.
 * REQ_ACK on the final frame, every 8th, and at window boundaries (§3.4).
 */
export function segment(msgId: number, body: Uint8Array, mtu: number): Frame[] {
  const singleCap = mtu - HEADER_SINGLE;
  const multiCap = mtu - HEADER_MULTI;
  if (multiCap <= 0) throw new Error(`MTU too small for fragmentation: ${mtu}`);

  const out: Frame[] = [];
  if (body.length <= singleCap) {
    // Reliable single-frame send: request the ACK like any final frame.
    out.push({ header: dataSingle(msgId, 0, true), body });
    return out;
  }

  const count = Math.ceil(body.length / multiCap);
  if (count - 1 > 254) {
    throw new Error(`message too large: ${count} frames > 255 (§3.2)`);
  }
  const lastSeq = count - 1;
  for (let seq = 0; seq < count; seq++) {
    const off = seq * multiCap;
    const len = Math.min(multiCap, body.length - off);
    const frag = body.slice(off, off + len);
    out.push({ header: dataMulti(msgId, seq, lastSeq, 0, shouldReqAck(seq, lastSeq)), body: frag });
  }
  return out;
}

function shouldReqAck(seq: number, lastSeq: number): boolean {
  if (seq === lastSeq) return true; // final frame
  if ((seq + 1) % REQ_ACK_CADENCE === 0) return true; // every 8th
  return (seq + 1) % WINDOW === 0 && seq < lastSeq; // window boundary
}

/** Frame count + total wire bytes for a message — TESTVECTORS §9.1 arithmetic. */
export function framesAndWire(l3Length: number): [frames: number, wire: number] {
  const body = l3Length + 17; // L2 overhead (§4.4)
  if (body <= PAYLOAD_SINGLE) return [1, body + HEADER_SINGLE];
  const n = Math.ceil(body / PAYLOAD_MULTI);
  return [n, body + n * HEADER_MULTI];
}
