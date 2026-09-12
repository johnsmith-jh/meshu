/**
 * §8 op wire-format builders/parsers for the PoC subset — TS port of
 * core/Ops.java. Decoders ignore unknown trailing elements (§5.2).
 */
import {
  array,
  asArray,
  asBytes,
  asUint,
  bytes,
  CborValue,
  isBytes,
  isText,
  isUint,
  text,
  uint,
} from './cbor';
import { Envelope } from './envelope';
import * as op from './op';
import * as blobs from './blobs';

// ============================================================ HELLO (§8.1)

export function helloRequest(
  l1Version: number,
  walletPubkey: Uint8Array, // 32-byte X25519
  supportedOps: number[],
): Envelope {
  if (walletPubkey.length !== 32) throw new Error('wallet_pubkey must be 32 bytes');
  return Envelope.of(
    op.HELLO,
    uint(l1Version),
    bytes(walletPubkey),
    array(...supportedOps.map(o => uint(o))),
  );
}

export interface HelloResponse {
  l1Version: number;
  gatewayPubkey: Uint8Array; // 32-byte X25519
  mintUrls: string[];
  nut19CachedPaths: string[];
  maxMsg: bigint;
  serverTime: bigint;
}

export function parseHelloResponse(env: Envelope): HelloResponse {
  requireOp(env, op.responseOf(op.HELLO));
  const f = env.fields;
  return {
    l1Version: Number(asUint(f[0]!, 'l1_version')),
    gatewayPubkey: asBytes(f[1]!, 'gateway_pubkey'),
    mintUrls: textList(f[2]!, 'mint_urls'),
    nut19CachedPaths: textList(f[3]!, 'nut19_cached_paths'),
    maxMsg: asUint(f[4]!, 'max_msg'),
    serverTime: asUint(f[5]!, 'server_time'),
  };
}

// ============================================================ KEYSETS (§8.10)

export function keysetsRequest(mintHandle: number): Envelope {
  return Envelope.of(op.KEYSETS, uint(mintHandle));
}

export interface KeysetEntry {
  shortId: Uint8Array; // 8 bytes
  unit: string;
  active: boolean;
  inputFeePpk: bigint;
  finalExpiry: bigint;
}

export function parseKeysetsResponse(env: Envelope): KeysetEntry[] {
  requireOp(env, op.responseOf(op.KEYSETS));
  return asArray(env.fields[0]!, 'keysets').map(row => {
    const e = asArray(row, 'keyset entry');
    return {
      shortId: asBytes(e[0]!, 's_id'),
      unit: unitFromCbor(e[1]!),
      active: asUint(e[2]!, 'active') !== 0n,
      inputFeePpk: asUint(e[3]!, 'input_fee_ppk'),
      finalExpiry: asUint(e[4]!, 'final_expiry'),
    };
  });
}

// ============================================================ KEYS (§8.11)

export function keysRequest(
  keysetHandle: number,
  fromExp: number | null,
  toExp: number | null,
): Envelope {
  return Envelope.of(
    op.KEYS,
    uint(keysetHandle),
    fromExp === null ? { t: 'null' } : uint(fromExp),
    toExp === null ? { t: 'null' } : uint(toExp),
  );
}

export interface KeysResponse {
  shortId: Uint8Array;
  keys: Uint8Array[]; // index i = pubkey for amount 2^i (ranged!)
}

export function parseKeysResponse(env: Envelope): KeysResponse {
  requireOp(env, op.responseOf(op.KEYS));
  const f = env.fields;
  // KEYS responses may be ranged: n×33, not fixed 64 (gateway packs directly).
  return { shortId: asBytes(f[0]!, 's_id'), keys: blobs.unpackSignatures(asBytes(f[1]!, 'keys_blob')) };
}

// ============================================================ CHECKSTATE (§8.9)

export const STATE_UNSPENT = 0;
export const STATE_PENDING = 1;
export const STATE_SPENT = 2;

export function checkstateRequest(ys: Uint8Array[]): Envelope {
  return Envelope.of(op.CHECKSTATE, bytes(blobs.packSignatures(ys)));
}

export function parseCheckstateResponse(env: Envelope, proofCount: number): number[] {
  requireOp(env, op.responseOf(op.CHECKSTATE));
  return unpackStates(asBytes(env.fields[0]!, 'packed_states'), proofCount);
}

/** 2 bits per proof, LSB-first (§8.9). */
export function packStates(states: number[]): Uint8Array {
  const out = new Uint8Array(Math.ceil((states.length * 2) / 8));
  states.forEach((s, i) => {
    if (s < 0 || s > 2) throw new Error(`state out of range: ${s}`);
    const idx = (i * 2) >> 3;
    out[idx] = (out[idx] ?? 0) | (s << ((i * 2) & 7));
  });
  return out;
}

export function unpackStates(packed: Uint8Array, count: number): number[] {
  const out: number[] = [];
  for (let i = 0; i < count; i++) {
    out.push((packed[(i * 2) >> 3]! >> ((i * 2) & 7)) & 0x3);
  }
  return out;
}

// ============================================================ SWAP (§8.13)

export function swapRequest(
  keysetHandle: number,
  inputs: blobs.Proof[],
  outputs: blobs.Output[],
): Envelope {
  return Envelope.of(
    op.SWAP,
    uint(keysetHandle),
    bytes(blobs.packProofs(inputs)),
    bytes(blobs.packOutputs(outputs)),
  );
}

export function parseSwapResponse(env: Envelope): Uint8Array[] {
  requireOp(env, op.responseOf(op.SWAP));
  return blobs.unpackSignatures(asBytes(env.fields[0]!, 'signatures_blob'));
}

// ============================================================ RESTORE (§8.8)

export function restoreRequest(
  keysetHandle: number,
  counterStart: bigint | number,
  count: number,
  outputs: blobs.Output[],
): Envelope {
  return Envelope.of(
    op.RESTORE,
    uint(keysetHandle),
    uint(counterStart),
    uint(count),
    bytes(blobs.packOutputs(outputs)),
  );
}

export interface RestoreResponse {
  hitBitmap: Uint8Array; // bit i set → counter (start+i) signed
  signatures: Uint8Array[]; // for set bits only, ascending
}

export function parseRestoreResponse(env: Envelope): RestoreResponse {
  requireOp(env, op.responseOf(op.RESTORE));
  const f = env.fields;
  return {
    hitBitmap: asBytes(f[0]!, 'hit_bitmap'),
    signatures: blobs.unpackSignatures(asBytes(f[1]!, 'signatures_blob')),
  };
}

// ============================================================ ERROR (§8.14, §10)

export interface ErrorResponse {
  code: bigint;
  detailKind: number; // 0 none, 1 text, 2 bytes
  detailText: string | null;
  detailBytes: Uint8Array | null;
}

export function error(code: bigint | number): Envelope {
  return Envelope.of(op.ERROR, uint(code), uint(0));
}

export function parseError(env: Envelope): ErrorResponse {
  requireOp(env, op.ERROR);
  const f = env.fields;
  const code = asUint(f[0]!, 'code');
  const kind = Number(asUint(f[1]!, 'detail_kind'));
  let detailText: string | null = null;
  let detailBytes: Uint8Array | null = null;
  if (kind === 1 && f.length > 2 && isText(f[2]!)) detailText = f[2].v;
  else if (kind === 2 && f.length > 2 && isBytes(f[2]!)) detailBytes = f[2].v;
  return { code, detailKind: kind, detailText, detailBytes };
}

// ============================================================ helpers

function requireOp(env: Envelope, expected: number): void {
  if (env.opcode !== expected) {
    throw new Error(`expected opcode 0x${expected.toString(16)}, got 0x${env.opcode.toString(16)}`);
  }
}

function textList(v: CborValue, what: string): string[] {
  return asArray(v, what).map(item => {
    if (!isText(item)) throw new Error(`expected text in ${what}`);
    return item.v;
  });
}

/** §6.6: well-known units as uint, custom units as text. */
function unitFromCbor(v: CborValue): string {
  if (isUint(v)) {
    return ['sat', 'msat', 'usd', 'eur', 'btc'][Number(v.v)] ?? `unit:${v.v}`;
  }
  if (isText(v)) return v.v;
  throw new Error('unit must be uint or text');
}
