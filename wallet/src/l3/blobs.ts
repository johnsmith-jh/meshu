/**
 * Packed blob formats (PROTOCOL.md §6.7) — TS port of core/PackedBlobs.java.
 * Binary packing avoids per-item CBOR framing:
 *  - outputs:     n × 34 (exponent 1 ‖ B_ 33)
 *  - signatures:  n × 33 (C_)
 *  - proofs:      n × 66 (exponent 1 ‖ secret 32 ‖ C 33)
 *  - Y blob:      n × 33 (CHECKSTATE)
 *  - keys blob:   exactly 64 × 33 (entry i = pubkey for amount 2^i)
 */

export interface Output {
  exponent: number;
  blindedMessage: Uint8Array; // 33-byte compressed secp256k1 point B_
}
export interface Proof {
  exponent: number;
  secret: Uint8Array; // exactly 32 bytes
  c: Uint8Array; // 33-byte compressed point C
}

const assertLen = (b: Uint8Array, n: number, what: string): void => {
  if (b.length !== n) throw new Error(`${what} must be ${n} bytes, got ${b.length}`);
};

// ------------------------------------------------------------ outputs

export function packOutputs(outputs: Output[]): Uint8Array {
  const blob = new Uint8Array(outputs.length * 34);
  outputs.forEach((o, i) => {
    assertLen(o.blindedMessage, 33, 'B_');
    if (o.exponent < 0 || o.exponent > 63) throw new Error(`exponent out of range: ${o.exponent}`);
    blob[i * 34] = o.exponent;
    blob.set(o.blindedMessage, i * 34 + 1);
  });
  return blob;
}

export function unpackOutputs(blob: Uint8Array): Output[] {
  if (blob.length % 34 !== 0) {
    throw new Error(`outputs blob length not a multiple of 34: ${blob.length}`);
  }
  const out: Output[] = [];
  for (let i = 0; i < blob.length; i += 34) {
    out.push({ exponent: blob[i]!, blindedMessage: blob.slice(i + 1, i + 34) });
  }
  return out;
}

// ------------------------------------------------------------ signatures (also Y blob)

export function packSignatures(signatures: Uint8Array[]): Uint8Array {
  const blob = new Uint8Array(signatures.length * 33);
  signatures.forEach((c, i) => {
    assertLen(c, 33, 'C_');
    blob.set(c, i * 33);
  });
  return blob;
}

export function unpackSignatures(blob: Uint8Array): Uint8Array[] {
  if (blob.length % 33 !== 0) {
    throw new Error(`signatures blob length not a multiple of 33: ${blob.length}`);
  }
  const out: Uint8Array[] = [];
  for (let i = 0; i < blob.length; i += 33) out.push(blob.slice(i, i + 33));
  return out;
}

// ------------------------------------------------------------ proofs

export function packProofs(proofs: Proof[]): Uint8Array {
  const blob = new Uint8Array(proofs.length * 66);
  proofs.forEach((p, i) => {
    assertLen(p.secret, 32, 'secret'); // NUT-10 secrets cannot use this blob (§6.7)
    assertLen(p.c, 33, 'C');
    blob[i * 66] = p.exponent;
    blob.set(p.secret, i * 66 + 1);
    blob.set(p.c, i * 66 + 33);
  });
  return blob;
}

export function unpackProofs(blob: Uint8Array): Proof[] {
  if (blob.length % 66 !== 0) {
    throw new Error(`proofs blob length not a multiple of 66: ${blob.length}`);
  }
  const out: Proof[] = [];
  for (let i = 0; i < blob.length; i += 66) {
    out.push({
      exponent: blob[i]!,
      secret: blob.slice(i + 1, i + 33),
      c: blob.slice(i + 33, i + 66),
    });
  }
  return out;
}

// ------------------------------------------------------------ keys blob

export function packKeys(keys: Uint8Array[]): Uint8Array {
  if (keys.length !== 64) {
    throw new Error(`keys blob must hold exactly 64 keys, got ${keys.length}`);
  }
  return packSignatures(keys);
}

export function unpackKeys(blob: Uint8Array): Uint8Array[] {
  if (blob.length !== 64 * 33) {
    throw new Error(`keys blob must be 64×33 = 2112 bytes, got ${blob.length}`);
  }
  return unpackSignatures(blob);
}
