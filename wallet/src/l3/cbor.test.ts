import { describe, expect, test } from 'vitest';
import {
  array,
  asArray,
  asUint,
  bytes,
  decode,
  encode,
  isBytes,
  text,
  uint,
} from './cbor';
import { Envelope } from './envelope';

const hex = (b: Uint8Array) => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
const unhex = (s: string) => new Uint8Array(s.match(/.{2}/g)!.map(x => parseInt(x, 16)));

describe('CBOR codec (port of core/Cbor.java, TESTVECTORS conformance)', () => {
  // Vector 8: ERROR response must encode to exactly 7 bytes.
  test('vector 8: ERROR [0xFE, 20001, 0] → 8318fe194e2100', () => {
    const env = Envelope.of(0xfe, uint(20001), uint(0));
    expect(hex(env.encode())).toBe('8318fe194e2100');
    expect(env.encode().length).toBe(7);
  });

  test('vector 4: MINT_QUOTE request → exact 42 bytes', () => {
    const pk = new Uint8Array(33);
    pk[0] = 0x02;
    pk.fill(0xa1, 1);
    const env = Envelope.of(0x01, uint(1), uint(1000), uint(0), bytes(pk));
    const expected = '8501011903e800582102' + 'a1'.repeat(32);
    expect(hex(env.encode())).toBe(expected);
    expect(env.encode().length).toBe(42);
  });

  test('canonical minimal int encoding', () => {
    expect(hex(encode(uint(1000)))).toBe('1903e8');
    expect(hex(encode(uint(23)))).toBe('17');
    expect(hex(encode(uint(24)))).toBe('1818');
    expect(hex(encode(uint(0)))).toBe('00');
  });

  test('envelope round trip; opcode is first ELEMENT', () => {
    const env = Envelope.of(0x0d, uint(1), bytes(new Uint8Array(32)), array(uint(0x0d)));
    const back = Envelope.decode(env.encode());
    expect(back.opcode).toBe(0x0d);
    expect(back.fields.length).toBe(3);
  });

  test('unknown trailing array elements ignored (§5.2 forward compat)', () => {
    const v2 = encode(array(uint(0x0a), uint(0), uint(999)));
    const env = Envelope.decode(v2);
    expect(env.opcode).toBe(0x0a);
    expect(env.fields.length).toBe(2);
  });

  test('rejects indefinite-length items (§5.2)', () => {
    expect(() => decode(unhex('9f01ff'))).toThrow(/indefinite/);
  });

  test('rejects maps (§5.1)', () => {
    expect(() => decode(unhex('a10102'))).toThrow(/major type/);
  });

  test('rejects negative ints', () => {
    expect(() => decode(unhex('20'))).toThrow();
  });

  test('rejects trailing bytes', () => {
    expect(() => decode(unhex('0102'))).toThrow(/trailing/);
  });

  // ---- adversarial (review C1 class: attacker-controlled lengths must not allocate)

  test('rejects oversized byte-string length', () => {
    // 0x5A = byte string w/ 4-byte length claiming 0x10000000; input is tiny.
    expect(() => decode(unhex('5a1000000041'))).toThrow(/exceeds/);
  });

  test('rejects oversized text length', () => {
    expect(() => decode(unhex('7a7fffffff6162'))).toThrow(/exceeds/);
  });

  test('rejects huge array count', () => {
    expect(() => decode(unhex('9a7fffffff01'))).toThrow(/exceeds input size/);
  });

  test('rejects truncated length header', () => {
    expect(() => decode(unhex('5a00'))).toThrow(/truncated/);
  });

  test('rejects excessive nesting (review fix: stack exhaustion)', () => {
    // array(1) × 100, terminated by uint 0 — 100 bytes, 100 stack frames.
    const deep = new Uint8Array(100).fill(0x81);
    deep[99] = 0x00;
    expect(() => decode(deep)).toThrow(/nesting/);
  });

  test('legitimate nesting well under the cap decodes fine', () => {
    // 10 levels of array(1) around uint 0.
    let v = uint(0);
    for (let i = 0; i < 10; i++) v = array(v);
    let d = decode(encode(v));
    for (let i = 0; i < 10; i++) d = asArray(d, `level ${i}`)[0]!;
    expect(d).toEqual({ t: 'uint', v: 0n });
  });

  test('round trip: bytes and text', () => {
    const data = new Uint8Array([1, 2, 3]);
    const b = decode(encode(bytes(data)));
    expect(isBytes(b) && Array.from(b.v)).toEqual([1, 2, 3]);
    const t = decode(encode(text('meshu')));
    expect(t).toEqual({ t: 'text', v: 'meshu' });
  });

  test('nested array decode', () => {
    const inner = array(bytes(new Uint8Array(8)), uint(0), uint(1), uint(0), uint(0));
    const outer = array(uint(0x8a), inner);
    const decoded = decode(encode(outer));
    const items = asArray(decoded, 'outer');
    expect(items.length).toBe(2);
    expect(asUint(asArray(items[1]!, 'inner')[2]!, 'active')).toBe(1n);
  });
});
