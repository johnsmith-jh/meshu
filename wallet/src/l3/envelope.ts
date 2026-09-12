/**
 * The L3 message envelope (PROTOCOL.md §5.2): a CBOR array whose first element
 * is the opcode. Decoders ignore unknown trailing elements for forward compat
 * (§5.2, §13.2). TS port of core/Envelope.java.
 */
import { array, CborValue, decode, encode, isUint, uint } from './cbor';

const MAX_OPCODE = 0xff;

export class Envelope {
  private constructor(
    public readonly opcode: number,
    public readonly fields: CborValue[],
  ) {
    if (!Number.isInteger(opcode) || opcode < 0 || opcode > MAX_OPCODE) {
      throw new Error(`opcode out of range: ${opcode}`);
    }
  }

  static of(opcode: number, ...fields: CborValue[]): Envelope {
    return new Envelope(opcode, fields);
  }

  /** Encode to CBOR: [opcode, field1, field2, ...] */
  encode(): Uint8Array {
    return encode(array(uint(this.opcode), ...this.fields));
  }

  /**
   * Decode from CBOR. The opcode is the first *element* of the array (the
   * §4.5 opcode_hint), not the first byte (which is the array header).
   */
  static decode(data: Uint8Array): Envelope {
    const v = decode(data);
    if (v.t !== 'array' || v.v.length === 0) {
      throw new Error('L3 message must be a non-empty CBOR array');
    }
    const op = v.v[0]!;
    if (!isUint(op)) throw new Error('first array element must be the opcode (uint)');
    const opcode = Number(op.v);
    if (opcode < 0 || opcode > MAX_OPCODE) {
      throw new Error(`opcode out of range: ${opcode}`);
    }
    return new Envelope(opcode, v.v.slice(1));
  }

  /** The opcode hint used in L2 AEAD associated data (§4.5). */
  get opcodeHint(): number {
    return this.opcode;
  }
}
