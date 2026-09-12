import { beforeEach, describe, expect, test } from 'vitest';
import { bootstrap, deriveKeys, DIR_G2W, DIR_W2G, open, randomPrivateKey, seal, x25519PublicKey } from './crypto';
import { MeshSession, nextMsgId, openReply, SessionError } from './session';
import { Envelope } from '../l3/envelope';
import { array, bytes, text, uint } from '../l3/cbor';
import * as Ops from '../l3/ops';
import * as Op from '../l3/op';

/**
 * In-memory gateway with daemon parity: accepts the bootstrap HELLO, pins the
 * wallet key, derives directional keys from its own private + the wallet's
 * public, seals replies — the exact SessionService flow (§4.2.1/§11.1). The
 * session under test cannot distinguish this from the real daemon at the
 * byte level.
 */
class FakeGateway {
  readonly pinned = new Set<string>();
  /** Simulate the gateway having lost its pairing table (§4.2.1 re-bootstrap). */
  lostPairing = false;
  /** When set, reply to bootstrap HELLO with a sealed ERROR envelope (§10). */
  rejectHelloCode: number | null = null;
  mintUrl = 'https://mint.test/Bitcoin';
  lastReplyMsgId: number | null = null;

  constructor(
    readonly gatewayPriv: Uint8Array,
    readonly gatewayPub: Uint8Array,
  ) {}

  /** Build a HELLO response envelope (§8.1) — the daemon's dispatcher does this. */
  helloResponse(gatewayPub: Uint8Array): Envelope {
    return Envelope.of(
      Op.responseOf(Op.HELLO),
      uint(1),
      bytes(gatewayPub),
      array(text(this.mintUrl)),
      array(), // nut19 cached paths
      uint(40000n), // max_msg
      uint(1750000000n), // server_time
    );
  }

  keysetsResponse(): Envelope {
    return Envelope.of(
      Op.responseOf(Op.KEYSETS),
      array(array(bytes(new Uint8Array(8).fill(1)), text('sat'), uint(1), uint(0), uint(0))),
    );
  }

  /** Handle one inbound L2 body (correlated by msg_id); return sealed reply. */
  onInbound(msgId: number, body: Uint8Array): Uint8Array {
    this.lastReplyMsgId = msgId;
    if (body[0] === 0xff) {
      // ---- bootstrap HELLO (§4.2.1)
      const env = Envelope.decode(body.slice(1));
      if (env.opcode !== Op.HELLO) throw new Error('bootstrap form accepted only for HELLO');
      const f1 = env.fields[1]!;
      if (f1.t !== 'bytes') throw new Error('wallet_pubkey must be bytes');
      const walletPub = f1.v;
      if (this.rejectHelloCode !== null) {
        const keys = deriveKeys(this.gatewayPriv, walletPub);
        const err = Envelope.of(Op.ERROR, uint(this.rejectHelloCode), uint(0));
        return seal(keys.gatewayToWallet, 0, DIR_G2W, msgId, Op.ERROR, err.encode());
      }
      if (!this.lostPairing) this.pinned.add(hex(walletPub));
      const keys = deriveKeys(this.gatewayPriv, walletPub);
      const resp = this.helloResponse(this.gatewayPub);
      return seal(keys.gatewayToWallet, 0, DIR_G2W, msgId, Op.responseOf(Op.HELLO), resp.encode());
    }
    // ---- sealed request (established session): trial-open like the daemon
    const walletPubHex = firstOf(this.pinned);
    if (!walletPubHex) throw new Error('no pinned wallet');
    const keys = deriveKeys(this.gatewayPriv, unhex(walletPubHex));
    let l3: Uint8Array | null = null;
    for (let requestOp = 0x01; requestOp <= 0x0d; requestOp++) {
      try {
        l3 = open(keys.walletToGateway, DIR_W2G, msgId, requestOp, body);
        break;
      } catch {
        /* trial-open, §4.5 receiver recovery */
      }
    }
    if (!l3) throw new Error('no pinned key verified the message');
    const req = Envelope.decode(l3);
    if (req.opcode === Op.KEYSETS) {
      return seal(
        keys.gatewayToWallet,
        0,
        DIR_G2W,
        msgId,
        Op.responseOf(Op.KEYSETS),
        this.keysetsResponse().encode(),
      );
    }
    const err = Envelope.of(Op.ERROR, uint(0xf001), uint(0));
    return seal(keys.gatewayToWallet, 0, DIR_G2W, msgId, Op.ERROR, err.encode());
  }
}

function hex(b: Uint8Array): string {
  return Array.from(b)
    .map(x => x.toString(16).padStart(2, '0'))
    .join('');
}
function unhex(s: string): Uint8Array {
  return new Uint8Array(s.match(/.{2}/g)!.map(x => parseInt(x, 16)));
}
function firstOf(set: Set<string>): string | undefined {
  return set.values().next().value;
}

// ------------------------------------------------------------------ tests

let gateway: FakeGateway;
let walletPriv: Uint8Array;
let walletPub: Uint8Array;

beforeEach(() => {
  localStorage.clear();
  const gwPriv = randomPrivateKey();
  gateway = new FakeGateway(gwPriv, x25519PublicKey(gwPriv));
  walletPriv = randomPrivateKey();
  walletPub = x25519PublicKey(walletPriv);
});

const SUPPORTED_OPS = [Op.HELLO, Op.KEYSETS, Op.SWAP, Op.CHECKSTATE];

/** Wire a MeshSession to the fake gateway through an async raw-body pipe. */
function wired(dropReplies = false): MeshSession {
  const session = new MeshSession(
    async (body) => {
      if (dropReplies) return; // black-hole (timeout paths)
      // Correlate on the session's outgoing msg_id — a real transport reads
      // this from the L1 header it transmitted (and the gateway mirrors it).
      const msgId = session.lastOutgoingMsgId ?? nextMsgId();
      const reply = gateway.onInbound(msgId, body);
      setTimeout(() => session.onInboundBody(msgId, reply), 1);
    },
    walletPriv,
    walletPub,
    gateway.gatewayPub,
  );
  return session;
}

describe('MeshSession (wallet side of §4.2.1)', () => {
  test('bootstrap: pins wallet, sealed reply opens, mint URL visible', async () => {
    const session = wired();
    const resp = await session.establish(SUPPORTED_OPS);
    expect(gateway.pinned.size).toBe(1);
    expect(resp.mintUrls).toEqual(['https://mint.test/Bitcoin']);
    expect(resp.gatewayPubkey).toEqual(gateway.gatewayPub);
    expect(session.established).toBe(true);
  });

  test('sealed exchange after establishment (opcode trial-open both sides)', async () => {
    const session = wired();
    await session.establish(SUPPORTED_OPS);
    const resp = await session.request(Ops.keysetsRequest(0));
    expect(resp.opcode).toBe(Op.responseOf(Op.KEYSETS));
  });

  test('hostile gateway sealing to a different key fails loudly', async () => {
    const attackerPriv = randomPrivateKey();
    const session = new MeshSession(
      async (body) => {
        const msgId = session.lastOutgoingMsgId!;
        // attacker derives with ITS key, not the QR key
        const keys = deriveKeys(attackerPriv, walletPub);
        const resp = gateway.helloResponse(gateway.gatewayPub);
        const sealed = seal(keys.gatewayToWallet, 0, DIR_G2W, msgId, Op.responseOf(Op.HELLO), resp.encode());
        setTimeout(() => session.onInboundBody(msgId, sealed), 1);
      },
      walletPriv,
      walletPub,
      gateway.gatewayPub,
    );
    // The hostile reply must fail verification (wallet opens with the QR key;
    // the attacker sealed under a different one). openReply aggregates the
    // per-candidate tag failures into one loud error.
    await expect(session.establish(SUPPORTED_OPS)).rejects.toThrow(/failed to open/i);
  }, 5000);

  test('gateway NEVER sends bootstrap form — wallet discards it (§4.2.1)', () => {
    const session = new MeshSession(
      async () => {},
      walletPriv,
      walletPub,
      gateway.gatewayPub,
    );
    // A bootstrap-form inbound (0xFF) with no pending exchange: must not crash
    // and must not be treated as a reply.
    expect(() => session.onInboundBody(1, bootstrap(new Uint8Array([0x0d])))).not.toThrow();
  });

  test('msg_id allocation: monotonic, time-seeded, persisted (§3.3 + bench lesson)', () => {
    const a = nextMsgId();
    const b = nextMsgId();
    expect(b).toBe((a % 65535) + 1);
    expect(a).toBeGreaterThanOrEqual(501); // time-seeded floor
  });

  test('timeout on silent gateway', async () => {
    const session = wired(true);
    await expect(session.establish(SUPPORTED_OPS, 200)).rejects.toThrow(/no reply/);
  });

  test('gateway ERROR envelope surfaces with its code, not as AEAD failure (§10)', async () => {
    gateway.rejectHelloCode = 0xf008; // MC_NOT_PERMITTED
    const session = wired();
    await expect(session.establish(SUPPORTED_OPS)).rejects.toThrow(/0xf008/);
    expect(session.established).toBe(false);
  });

  test('sendRaw transport failure settles immediately, session stays usable', async () => {
    let fail = true;
    const session = new MeshSession(
      async body => {
        if (fail) throw new Error('BLE write failed');
        const msgId = session.lastOutgoingMsgId!;
        const reply = gateway.onInbound(msgId, body);
        setTimeout(() => session.onInboundBody(msgId, reply), 1);
      },
      walletPriv,
      walletPub,
      gateway.gatewayPub,
    );
    await expect(session.establish(SUPPORTED_OPS, 5000)).rejects.toThrow(/BLE write failed/);
    expect(session.established).toBe(false);
    // No leaked pending entry: a retry on the same session works.
    fail = false;
    const resp = await session.establish(SUPPORTED_OPS);
    expect(resp.mintUrls.length).toBe(1);
  });

  test('openReply fails when no opcode opens the reply', () => {
    const junk = seal(randomPrivateKey(), 0, DIR_G2W, 9, 0x0d, new Uint8Array([1]));
    expect(() => openReply(randomPrivateKey(), 9, junk)).toThrow(SessionError);
  });
});
