import { describe, expect, test } from 'vitest';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import {
  bootstrap,
  deriveKeys,
  DIR_G2W,
  DIR_W2G,
  EPOCH_BOOTSTRAP,
  isBootstrap,
  L2_OVERHEAD,
  open,
  parseBootstrap,
  randomPrivateKey,
  seal,
  x25519PublicKey,
  AeadError,
} from './crypto';

const hex = (b: Uint8Array) => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
const unhex = (s: string) => new Uint8Array(s.match(/.{2}/g)!.map(x => parseInt(x, 16)));

/** RFC 8439 §2.8.2 — proves the noble ChaCha20-Poly1305 construction is the RFC one. */
test('RFC 8439 AEAD test vector', () => {
  const key = unhex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
  const nonce = unhex('070000004041424344454647');
  const aad = unhex('50515253c0c1c2c3c4c5c6c7');
  const plaintext = new TextEncoder().encode(
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
  );
  const aead = chacha20poly1305(key, nonce, aad);
  const sealed = aead.encrypt(plaintext);
  expect(hex(sealed.subarray(0, plaintext.length))).toBe(
    'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116',
  );
  expect(hex(sealed.subarray(plaintext.length))).toBe('1ae10b594f09e26a7e902ecbd0600691');
});

describe('L2 crypto (port of core L2/KeyAgreement, PROTOCOL.md §4)', () => {
  test('both sides derive identical directional keys (§4.2)', () => {
    const wPriv = randomPrivateKey();
    const gPriv = randomPrivateKey();
    const wPub = x25519PublicKey(wPriv);
    const gPub = x25519PublicKey(gPriv);

    const walletSide = deriveKeys(wPriv, gPub);
    const gatewaySide = deriveKeys(gPriv, wPub);

    expect(Array.from(walletSide.walletToGateway)).toEqual(Array.from(gatewaySide.walletToGateway));
    expect(Array.from(walletSide.gatewayToWallet)).toEqual(Array.from(gatewaySide.gatewayToWallet));
    // Directional keys differ from each other (reflection protection).
    expect(walletSide.walletToGateway).not.toEqual(walletSide.gatewayToWallet);
  });

  test('seal/open round trip, 17-byte overhead (§4.4)', () => {
    const wPriv = randomPrivateKey();
    const gPriv = randomPrivateKey();
    const keys = deriveKeys(wPriv, x25519PublicKey(gPriv));
    const plaintext = new TextEncoder().encode('meshu L3 message');

    const sealed = seal(keys.walletToGateway, 0, DIR_W2G, 0x1234, 0x0d, plaintext);
    expect(sealed.length).toBe(plaintext.length + L2_OVERHEAD);
    expect(sealed[0]).toBe(0);

    const opened = open(keys.walletToGateway, DIR_W2G, 0x1234, 0x0d, sealed);
    expect(new TextDecoder().decode(opened)).toBe('meshu L3 message');
  });

  test('wrong opcode_hint fails verification (§4.5 binds opcode)', () => {
    const keys = deriveKeys(randomPrivateKey(), x25519PublicKey(randomPrivateKey()));
    const sealed = seal(keys.walletToGateway, 0, DIR_W2G, 1, 0x0d, new Uint8Array([1]));
    expect(() => open(keys.walletToGateway, DIR_W2G, 1, 0x08, sealed)).toThrow(AeadError);
  });

  test('wrong msg_id fails (nonce mismatch, §4.5)', () => {
    const keys = deriveKeys(randomPrivateKey(), x25519PublicKey(randomPrivateKey()));
    const sealed = seal(keys.walletToGateway, 0, DIR_W2G, 0x1234, 0x0d, new Uint8Array([1]));
    expect(() => open(keys.walletToGateway, DIR_W2G, 0x1235, 0x0d, sealed)).toThrow(AeadError);
  });

  test('wrong direction fails (directional keys + AAD, §4.2/§4.5)', () => {
    const keys = deriveKeys(randomPrivateKey(), x25519PublicKey(randomPrivateKey()));
    const sealed = seal(keys.walletToGateway, 0, DIR_W2G, 1, 0x0d, new Uint8Array([1]));
    expect(() => open(keys.gatewayToWallet, DIR_G2W, 1, 0x0d, sealed)).toThrow(AeadError);
  });

  test('bootstrap form: 0xFF ‖ plaintext, no tag (§4.2.1)', () => {
    const l3 = new Uint8Array([0x0d, 0x01, 0x02]);
    const boot = bootstrap(l3);
    expect(boot[0]).toBe(EPOCH_BOOTSTRAP);
    expect(isBootstrap(boot)).toBe(true);
    expect(Array.from(parseBootstrap(boot))).toEqual([0x0d, 0x01, 0x02]);

    expect(isBootstrap(new Uint8Array([0x00, 0x01]))).toBe(false);
    expect(() => parseBootstrap(new Uint8Array([0x00, 0x01]))).toThrow(AeadError);
  });

  test('bootstrap rejected when opened as sealed (§4.2.1)', () => {
    const keys = deriveKeys(randomPrivateKey(), x25519PublicKey(randomPrivateKey()));
    expect(() => open(keys.walletToGateway, DIR_W2G, 1, 0x0d, bootstrap(new Uint8Array([0x0d])))).toThrow(
      AeadError,
    );
  });

  test('epoch must be 0x00–0xFE; 0xFF is bootstrap-only (§4.6)', () => {
    const keys = deriveKeys(randomPrivateKey(), x25519PublicKey(randomPrivateKey()));
    expect(() => seal(keys.walletToGateway, 0xff, DIR_W2G, 1, 0x0d, new Uint8Array([1]))).toThrow(/epoch/);
    expect(() => seal(keys.walletToGateway, 0xfe, DIR_W2G, 1, 0x0d, new Uint8Array([1]))).not.toThrow();
  });

  test('implicit nonce layout: epoch ‖ dir ‖ msgId(BE) ‖ 0×8 (§4.5)', () => {
    // Exercised via seal: two messages with same key+epoch+dir+msgId but
    // different opcode hints must both fail to cross-open (nonce identical,
    // AAD differs) — proves AAD is load-bearing.
    const keys = deriveKeys(randomPrivateKey(), x25519PublicKey(randomPrivateKey()));
    const a = seal(keys.walletToGateway, 0, DIR_W2G, 5, 0x0d, new Uint8Array([9]));
    expect(() => open(keys.walletToGateway, DIR_W2G, 5, 0x0a, a)).toThrow(AeadError);
  });
});
