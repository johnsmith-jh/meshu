import { describe, expect, test } from 'vitest';
import {
  dataMulti,
  dataSingle,
  encodeFrame,
  encodeHeader,
  HEADER_MULTI,
  HEADER_SINGLE,
  missingFromBitmap,
  parseHeader,
} from './frame';
import { KIND_ACKBM, KIND_DATA } from './frameKind';
import { Reassembler, ackbmFrame } from './reassembler';
import { MTU_FLOOR, framesAndWire, segment, WINDOW } from './segmenter';

const hex = (b: Uint8Array) => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');

describe('L1 header (§3.1)', () => {
  test('single-frame header is 4 bytes', () => {
    const h = dataSingle(0x1234, 0);
    expect(encodeHeader(h).length).toBe(4);
    expect(hex(encodeHeader(h))).toBe('10001234');
  });

  test('fragmented header is 6 bytes with MULTI|REQ_ACK', () => {
    const h = dataMulti(0x1234, 3, 8, 0, true);
    const enc = encodeHeader(h);
    expect(enc.length).toBe(6);
    expect(enc[0]).toBe(0x10);
    expect(enc[1]).toBe(0x03);
  });

  test('ATTEMPT occupies bits 2–3', () => {
    expect(encodeHeader(dataSingle(1, 1))[1]).toBe(0x04);
    expect(parseHeader(encodeFrame(dataSingle(1, 3), new Uint8Array(0)), 0).header.flags & 0x0c).toBe(0x0c);
  });

  test('version is top two bits (v1 → byte0 = kind only)', () => {
    const p = parseHeader(new Uint8Array([0x10, 0x00, 0x12, 0x34]), 0);
    expect(p.header.version).toBe(0);
    expect(p.header.kind).toBe(KIND_DATA);
  });
});

describe('vector 6: ACK bitmap (§3.6)', () => {
  test('9-frame message, frames 3 and 7 lost → 12 00 1234 09 7701', () => {
    const frame = ackbmFrame(0x1234, 9, new Uint8Array([0x77, 0x01]));
    expect(hex(frame)).toBe('1200123409' + '7701');
    expect(frame.length).toBe(7);
  });

  test('missing frames from bitmap', () => {
    expect(missingFromBitmap(9, new Uint8Array([0x77, 0x01]))).toEqual([3, 7]);
  });

  test('255-frame max bitmap', () => {
    const bitmap = new Uint8Array(32);
    bitmap.fill(0xff);
    bitmap[31] = 0x7f;
    expect(missingFromBitmap(255, bitmap)).toEqual([]);
  });
});

describe('segmentation boundary (§3.2)', () => {
  test('≤161 bytes → single frame with REQ_ACK', () => {
    const frames = segment(1, new Uint8Array(161), MTU_FLOOR);
    expect(frames.length).toBe(1);
    expect(frames[0]!.body.length).toBe(161);
    expect((frames[0]!.header.flags & 0x02) !== 0).toBe(true);
  });

  test('162 bytes → 2 fragments, final REQ_ACK', () => {
    const frames = segment(1, new Uint8Array(162), MTU_FLOOR);
    expect(frames.length).toBe(2);
    expect(frames[0]!.body.length).toBe(159);
    expect(frames[1]!.body.length).toBe(3);
    expect((frames[1]!.header.flags & 0x02) !== 0).toBe(true);
  });
});

describe('§9.1 frame arithmetic — TESTVECTORS table (26 ops)', () => {
  const cases: Array<[l3: number, frames: number, wire: number]> = [
    [41, 1, 62], [42, 1, 63], [228, 2, 257], [122, 1, 143], [292, 2, 321],
    [361, 3, 396], [905, 6, 958], [203, 2, 232], [200, 2, 229], [28, 1, 49],
    [495, 4, 536], [826, 6, 879], [1354, 9, 1425], [478, 4, 519], [809, 6, 862],
    [335, 3, 370], [7, 1, 28], [1655, 11, 1738], [17, 1, 38], [49, 1, 70],
    [2127, 14, 2228], [3409, 22, 3558], [18, 1, 39], [184, 2, 213],
    [680, 5, 727], [3320, 21, 3463],
  ];
  test.each(cases)('l3=%i → %i frames / %i wire bytes', (l3, frames, wire) => {
    const [f, w] = framesAndWire(l3);
    expect(f).toBe(frames);
    expect(w).toBe(wire);
  });
});

describe('reassembly (§3.5)', () => {
  const bodyOf = (n: number) => new Uint8Array(n).map((_, i) => i & 0xff);

  test('fragmented message reassembles', () => {
    const r = new Reassembler();
    const body = bodyOf(400);
    const frames = segment(7, body, MTU_FLOOR);
    expect(frames.length).toBe(3);
    const r0 = r.feed(frames[0]!.header, frames[0]!.body);
    expect(r0.kind).toBe('pending');
    const r1 = r.feed(frames[1]!.header, frames[1]!.body);
    expect(r1.kind).toBe('pending');
    const r2 = r.feed(frames[2]!.header, frames[2]!.body);
    expect(r2.kind).toBe('complete');
    expect(r2.kind === 'complete' && r2.body.length).toBe(body.length);
  });

  test('single frame completes immediately with ACK when requested', () => {
    const r = new Reassembler();
    const res = r.feed(dataSingle(1, 0, true), new Uint8Array([1, 2, 3]));
    expect(res.kind).toBe('complete');
    expect(res.kind === 'complete' && res.ack).not.toBeNull();
  });

  test('duplicate seq discarded idempotently', () => {
    const r = new Reassembler();
    const frames = segment(1, new Uint8Array(200), MTU_FLOOR);
    r.feed(frames[0]!.header, frames[0]!.body);
    expect(r.feed(frames[0]!.header, frames[0]!.body).kind).toBe('duplicate');
  });

  test('inconsistent last_seq aborts', () => {
    const r = new Reassembler();
    r.feed(dataMulti(1, 0, 4, 0, false), new Uint8Array(10));
    expect(r.feed(dataMulti(1, 1, 7, 0, false), new Uint8Array(10)).kind).toBe('inconsistent');
  });

  test('seq beyond last_seq aborts cleanly (review C3)', () => {
    const r = new Reassembler();
    expect(r.feed(dataMulti(2, 200, 4, 0, false), new Uint8Array(10)).kind).toBe('inconsistent');
    r.feed(dataMulti(3, 0, 4, 0, false), new Uint8Array(10));
    expect(r.feed(dataMulti(3, 9, 4, 0, false), new Uint8Array(10)).kind).toBe('inconsistent');
    expect(r.feed(dataMulti(3, 0, 4, 0, false), new Uint8Array(10)).kind).toBe('pending');
  });

  test('late duplicate after completion answers full ACKBM', () => {
    const r = new Reassembler();
    const frames = segment(1, new Uint8Array(162), MTU_FLOOR);
    r.feed(frames[0]!.header, frames[0]!.body);
    const final = r.feed(frames[1]!.header, frames[1]!.body);
    expect(final.kind).toBe('complete');
    // Simulate lost completing ACK: the sender retransmits seq 0.
    const dup = r.feed(frames[0]!.header, frames[0]!.body);
    expect(dup.kind).toBe('pending');
    expect(dup.kind === 'pending' && dup.ack).not.toBeNull();
  });

  test('completed cache is bounded at COMPLETED_CACHE_SIZE (review fix)', () => {
    const r = new Reassembler();
    const frames = segment(1, new Uint8Array(162), MTU_FLOOR);
    r.feed(frames[0]!.header, frames[0]!.body);
    r.feed(frames[1]!.header, frames[1]!.body);
    // In cache: a late duplicate gets the full-ACKBM answer…
    const cached = r.feed(frames[0]!.header, frames[0]!.body);
    expect(cached.kind === 'pending' && cached.ack).not.toBeNull();
    // …until 64 newer completions evict it; then it is a fresh reassembly.
    for (let id = 2; id <= 66; id++) r.feed(dataSingle(id, 0), new Uint8Array(1));
    const dup = r.feed(frames[0]!.header, frames[0]!.body);
    expect(dup.kind).toBe('pending');
    expect(dup.kind === 'pending' && dup.ack).toBeNull();
  });
});
