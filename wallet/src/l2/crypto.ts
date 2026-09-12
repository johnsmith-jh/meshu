/**
 * L2 crypto (PROTOCOL.md §4) — TS port of core/KeyAgreement.java + L2.java.
 *
 * X25519 static-static ECDH → HKDF-SHA256 directional keys → ChaCha20-Poly1305
 * with the §4.5 implicit nonce and opcode-binding AAD. Bootstrap form (0xFF)
 * carries the plaintext HELLO (§4.2.1).
 */
import { x25519 } from '@noble/curves/ed25519.js';
import { extract, expand } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';

const SALT = new TextEncoder().encode('meshu/v1/salt');
const INFO_W2G = new TextEncoder().encode('meshu/v1/w2g');
const INFO_G2W = new TextEncoder().encode('meshu/v1/g2w');

export const EPOCH_BOOTSTRAP = 0xff;
export const DIR_W2G = 0x00;
export const DIR_G2W = 0x01;
/** L2 overhead: 1-byte epoch + 16-byte Poly1305 tag (§4.4). */
export const L2_OVERHEAD = 17;

export interface DirectionalKeys {
  walletToGateway: Uint8Array; // k_w2g
  gatewayToWallet: Uint8Array; // k_g2w
}

/** Derive directional keys: own X25519 private ↔ peer's raw 32-byte public (§4.2). */
export function deriveKeys(ownPrivate: Uint8Array, peerPublicRaw: Uint8Array): DirectionalKeys {
  if (ownPrivate.length !== 32) throw new Error('X25519 private key must be 32 bytes');
  if (peerPublicRaw.length !== 32) throw new Error('peer public key must be 32 bytes');
  const shared = x25519.getSharedSecret(ownPrivate, peerPublicRaw);
  // HKDF-Extract(salt = "meshu/v1/salt", ikm = shared) — noble v2 arg order:
  // extract(hash, ikm, salt).
  const prk = extract(sha256, shared, SALT);
  return {
    walletToGateway: expand(sha256, prk, INFO_W2G, 32),
    gatewayToWallet: expand(sha256, prk, INFO_G2W, 32),
  };
}

export function x25519PublicKey(privateKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(privateKey);
}

export function randomPrivateKey(): Uint8Array {
  const k = new Uint8Array(32);
  crypto.getRandomValues(k);
  return k;
}

// ------------------------------------------------------------ AEAD (§4.3–4.5)

export class AeadError extends Error {}

function nonce(epoch: number, dir: number, msgId: number): Uint8Array {
  // §4.5: epoch(1) ‖ dir(1) ‖ msg_id(BE) ‖ 0×8 — implicit, never transmitted.
  const n = new Uint8Array(12);
  n[0] = epoch;
  n[1] = dir;
  n[2] = (msgId >> 8) & 0xff;
  n[3] = msgId & 0xff;
  return n;
}

function aad(opcodeHint: number, dir: number, epoch: number, msgId: number): Uint8Array {
  // §4.5: version_byte ‖ opcode_hint ‖ dir ‖ epoch ‖ msg_id
  return new Uint8Array([
    0x00, // L1 version 0 (§13.1)
    opcodeHint & 0xff,
    dir & 0xff,
    epoch & 0xff,
    (msgId >> 8) & 0xff,
    msgId & 0xff,
  ]);
}

function validateEpoch(epoch: number): void {
  if (!Number.isInteger(epoch) || epoch < 0 || epoch >= EPOCH_BOOTSTRAP) {
    throw new Error(`epoch must be 0x00–0xFE, got ${epoch}`);
  }
}

/** Seal an L3 message → `epoch ‖ ciphertext ‖ tag` (§4.4). */
export function seal(
  key: Uint8Array,
  epoch: number,
  dir: number,
  msgId: number,
  opcodeHint: number,
  plaintext: Uint8Array,
): Uint8Array {
  validateEpoch(epoch);
  const aead = chacha20poly1305(key, nonce(epoch, dir, msgId), aad(opcodeHint, dir, epoch, msgId));
  const ct = aead.encrypt(plaintext);
  const out = new Uint8Array(1 + ct.length);
  out[0] = epoch;
  out.set(ct, 1);
  return out;
}

/** Open a sealed message → L3 plaintext. Throws AeadError on tag failure. */
export function open(
  key: Uint8Array,
  dir: number,
  msgId: number,
  opcodeHint: number,
  sealed: Uint8Array,
): Uint8Array {
  if (sealed.length < 1 + 16) throw new AeadError(`sealed message too short: ${sealed.length}`);
  const epoch = sealed[0]! & 0xff;
  if (epoch === EPOCH_BOOTSTRAP) {
    throw new AeadError('bootstrap form is not a sealed message (§4.2.1)');
  }
  const aead = chacha20poly1305(key, nonce(epoch, dir, msgId), aad(opcodeHint, dir, epoch, msgId));
  try {
    return aead.decrypt(sealed.subarray(1));
  } catch {
    throw new AeadError('tag verification failed');
  }
}

/** Bootstrap form: `0xFF ‖ L3 plaintext` — gateway HELLO only (§4.2.1). */
export function bootstrap(l3Plaintext: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + l3Plaintext.length);
  out[0] = EPOCH_BOOTSTRAP;
  out.set(l3Plaintext, 1);
  return out;
}

export function isBootstrap(message: Uint8Array): boolean {
  return message.length >= 1 && message[0] === EPOCH_BOOTSTRAP;
}

export function parseBootstrap(message: Uint8Array): Uint8Array {
  if (!isBootstrap(message)) throw new AeadError('not bootstrap form');
  return message.slice(1);
}

export { sha256 };
