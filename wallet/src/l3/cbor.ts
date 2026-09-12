/**
 * Strict CBOR reader/writer for meshu L3 — TS port of core/Cbor.java.
 *
 * L3 disciplines (PROTOCOL.md §5):
 *  - positional definite-length arrays, never maps (§5.1)
 *  - integers in canonical minimal form (§5.2)
 *  - indefinite-length items rejected (§5.2)
 *  - unknown trailing array elements ignored by decoders (§5.2)
 *
 * Encoding is canonical (RFC 8949 §4.2); decoding accepts any well-formed
 * definite-length form (§5.3). Attacker-controlled input is assumed: every
 * length is bounds-checked against the remaining input BEFORE allocation, and
 * nesting depth is capped so a malicious message cannot exhaust the stack.
 */

export type CborValue =
  | { t: 'uint'; v: bigint }
  | { t: 'bytes'; v: Uint8Array }
  | { t: 'text'; v: string }
  | { t: 'array'; v: CborValue[] }
  | { t: 'null' };

export const uint = (v: bigint | number): CborValue => {
  const n = typeof v === 'bigint' ? v : BigInt(v);
  if (n < 0n) throw new Error(`CBOR uint cannot be negative: ${n}`);
  return { t: 'uint', v: n };
};
export const bytes = (v: Uint8Array): CborValue => ({ t: 'bytes', v });
export const text = (v: string): CborValue => ({ t: 'text', v });
export const array = (...items: CborValue[]): CborValue => ({ t: 'array', v: items });

export const isUint = (v: CborValue): v is Extract<CborValue, { t: 'uint' }> => v.t === 'uint';
export const isBytes = (v: CborValue): v is Extract<CborValue, { t: 'bytes' }> => v.t === 'bytes';
export const isText = (v: CborValue): v is Extract<CborValue, { t: 'text' }> => v.t === 'text';
export const isArray = (v: CborValue): v is Extract<CborValue, { t: 'array' }> => v.t === 'array';

export function asUint(v: CborValue, what: string): bigint {
  if (!isUint(v)) throw new Error(`expected uint for ${what}`);
  return v.v;
}
export function asBytes(v: CborValue, what: string): Uint8Array {
  if (!isBytes(v)) throw new Error(`expected bytes for ${what}`);
  return v.v;
}
export function asArray(v: CborValue, what: string): CborValue[] {
  if (!isArray(v)) throw new Error(`expected array for ${what}`);
  return v.v;
}

// ------------------------------------------------------------------ encode

export function encode(v: CborValue): Uint8Array {
  const out = new DynamicBytes(64);
  writeValue(out, v);
  return out.take();
}

class DynamicBytes {
  private buf: Uint8Array;
  private len = 0;
  constructor(cap: number) {
    this.buf = new Uint8Array(cap);
  }
  private ensure(n: number): void {
    if (this.len + n > this.buf.length) {
      const next = new Uint8Array(Math.max(this.buf.length * 2, this.len + n));
      next.set(this.buf.subarray(0, this.len));
      this.buf = next;
    }
  }
  push(b: number): void {
    this.ensure(1);
    this.buf[this.len++] = b & 0xff;
  }
  pushAll(bs: Uint8Array): void {
    this.ensure(bs.length);
    this.buf.set(bs, this.len);
    this.len += bs.length;
  }
  take(): Uint8Array {
    return this.buf.slice(0, this.len);
  }
}

function writeValue(out: DynamicBytes, v: CborValue): void {
  switch (v.t) {
    case 'uint':
      writeTypeAndValue(out, 0, v.v);
      break;
    case 'bytes':
      writeTypeAndValue(out, 2, BigInt(v.v.length));
      out.pushAll(v.v);
      break;
    case 'text': {
      const utf8 = new TextEncoder().encode(v.v);
      writeTypeAndValue(out, 3, BigInt(utf8.length));
      out.pushAll(utf8);
      break;
    }
    case 'null':
      out.push(0xf6);
      break;
    case 'array':
      writeTypeAndValue(out, 4, BigInt(v.v.length));
      for (const item of v.v) writeValue(out, item);
      break;
  }
}

/** Major-type/argument pair in canonical minimal form (RFC 8949 §4.2). */
function writeTypeAndValue(out: DynamicBytes, majorType: number, value: bigint): void {
  const mt = majorType << 5;
  if (value < 0n) throw new Error('CBOR uint cannot be negative');
  if (value < 24n) {
    out.push(mt | Number(value));
  } else if (value <= 0xffn) {
    out.push(mt | 24);
    out.push(Number(value));
  } else if (value <= 0xffffn) {
    out.push(mt | 25);
    out.push(Number(value >> 8n));
    out.push(Number(value & 0xffn));
  } else if (value <= 0xffffffffn) {
    out.push(mt | 26);
    for (let s = 24n; s >= 0n; s -= 8n) out.push(Number((value >> s) & 0xffn));
  } else {
    out.push(mt | 27);
    for (let s = 56n; s >= 0n; s -= 8n) out.push(Number((value >> s) & 0xffn));
  }
}

// ------------------------------------------------------------------ decode

/** Decode one CBOR item. Indefinite-length items and maps are rejected (§5.2). */
export function decode(data: Uint8Array): CborValue {
  const pos = { i: 0 };
  const v = readValue(data, pos, 0);
  if (pos.i !== data.length) throw new Error('trailing bytes after CBOR item');
  return v;
}

/**
 * Nesting cap: a definite-length `81 81 81 …` chain costs an attacker 1 byte
 * per level but one stack frame per level here — a MESHU_MAX_MSG-sized message
 * would otherwise overflow the stack (review fix). 32 levels is far beyond any
 * legitimate L3 message (deepest is ~3: envelope → row list → row).
 */
const MAX_DEPTH = 32;

function readValue(data: Uint8Array, pos: { i: number }, depth: number): CborValue {
  if (depth > MAX_DEPTH) throw new Error(`CBOR nesting exceeds ${MAX_DEPTH} levels`);
  if (pos.i >= data.length) throw new Error('truncated CBOR');
  const initial = (data[pos.i++] ?? 0) & 0xff;
  const major = initial >> 5;
  const ai = initial & 0x1f;
  switch (major) {
    case 0:
      return { t: 'uint', v: readArgument(data, pos, ai) };
    case 2: {
      const len = readBoundedLength(data, pos, ai);
      const out = new Uint8Array(len);
      out.set(data.subarray(pos.i, pos.i + len));
      pos.i += len;
      return { t: 'bytes', v: out };
    }
    case 3: {
      const len = readBoundedLength(data, pos, ai);
      const s = new TextDecoder('utf-8', { fatal: true }).decode(
        data.subarray(pos.i, pos.i + len),
      );
      pos.i += len;
      return { t: 'text', v: s };
    }
    case 4: {
      // Each item takes ≥1 byte: a count larger than the remaining input is
      // impossible for well-formed data — reject before allocating.
      const countBig = readArgument(data, pos, ai);
      if (countBig > BigInt(data.length - pos.i)) {
        throw new Error('CBOR array count exceeds input size');
      }
      const count = Number(countBig);
      const items: CborValue[] = new Array(count);
      for (let i = 0; i < count; i++) items[i] = readValue(data, pos, depth + 1);
      return { t: 'array', v: items };
    }
    case 7:
      if (ai === 22) return { t: 'null' };
      throw new Error(`unsupported simple/float CBOR value: 0x${initial.toString(16)}`);
    default:
      throw new Error(`unsupported CBOR major type ${major} (maps are forbidden, §5.1)`);
  }
}

/**
 * Read a length argument for major types 2/3 and verify it fits the remaining
 * input BEFORE the caller allocates (attacker-controlled lengths must fail
 * here, not in `new Uint8Array(len)`).
 */
function readBoundedLength(data: Uint8Array, pos: { i: number }, ai: number): number {
  const l = readArgument(data, pos, ai);
  if (l > 0xffffffffn) throw new Error(`CBOR length out of range: ${l}`);
  const len = Number(l);
  if (len < 0 || len > data.length - pos.i) {
    throw new Error(`CBOR length ${len} exceeds remaining input ${data.length - pos.i}`);
  }
  return len;
}

function readArgument(data: Uint8Array, pos: { i: number }, ai: number): bigint {
  if (ai === 31) throw new Error('indefinite-length CBOR item rejected (§5.2)');
  if (ai < 24) return BigInt(ai);
  const n = ai === 24 ? 1 : ai === 25 ? 2 : ai === 26 ? 4 : ai === 27 ? 8 : -1;
  if (n < 0) throw new Error(`bad additional info: ${ai}`);
  if (pos.i + n > data.length) throw new Error('truncated CBOR length header');
  let v = 0n;
  for (let i = 0; i < n; i++) {
    v = (v << 8n) | BigInt((data[pos.i++] ?? 0) & 0xff);
  }
  return v;
}
