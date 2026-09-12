/**
 * Client session layer (PROTOCOL.md §4.2.1, §8.1, §11.2) — the wallet side of
 * the gateway conversation.
 *
 * Responsibilities:
 *  - persistent monotonic msg_id allocation (§3.3; seen-table lesson §2.8:
 *    seed from the clock on first run, persist in localStorage, NEVER reset)
 *  - bootstrap HELLO in plaintext (§4.2.1) until the sealed reply verifies —
 *    which also authenticates the gateway (only the QR key holder could reply)
 *  - sealed exchange: seal under k_w2g, trial-open the reply across the
 *    response-opcode space (§4.5 receiver-side recovery — the opcode hint is
 *    inside the ciphertext; mirrors the gateway's own approach)
 *  - gateway error envelopes surface as-is (§10.3) for the caller to map
 *
 * Transport-agnostic: the caller supplies a raw-body sender and feeds inbound
 * sealed bodies (with their L1 msg_id) into {@link MeshSession.onInboundBody}.
 */
import {
  bootstrap,
  deriveKeys,
  DIR_G2W,
  DIR_W2G,
  isBootstrap,
  open,
  parseBootstrap,
  seal,
  type DirectionalKeys,
} from './crypto';
import { Envelope } from '../l3/envelope';
import { ERROR, HELLO, responseOf } from '../l3/op';
import * as Ops from '../l3/ops';

const STORAGE_KEY = 'meshu-wallet-msg-id';

/** Persistent monotonic msg_id (§3.3). Time-seeded on first run. */
export function nextMsgId(): number {
  let last = 0;
  try {
    last = parseInt(localStorage.getItem(STORAGE_KEY) ?? '0', 10) || 0;
  } catch {
    // localStorage unavailable — in-memory fallback for this session.
  }
  if (last <= 0) {
    // Seed past any (msg_id, ATTEMPT) bytes previously sent by ANY session —
    // the node's 160-slot seen table silently drops byte-identical packets
    // for ~an hour (bench lesson, MESHCORE-RADIO.md §6).
    last = Math.floor((Date.now() / 1000) % 65000) + 500;
  }
  const id = (last % 65535) + 1; // 0x0000 reserved (§3.3)
  try {
    localStorage.setItem(STORAGE_KEY, String(id));
  } catch {
    // ignore — counter survives in memory for this session
  }
  return id;
}

export class SessionError extends Error {}

export type SessionKeys = DirectionalKeys & { walletPubkey: Uint8Array };

/**
 * Trial-open a sealed reply across the bounded response-opcode space
 * (0x81..0x8D + 0xFE). A wrong hint fails the Poly1305 tag exactly like a
 * wrong key (§4.5) — the correct pair verifies.
 */
export function openReply(key: Uint8Array, msgId: number, sealed: Uint8Array): Envelope {
  const candidates: number[] = [];
  for (let requestOp = 0x01; requestOp <= 0x0d; requestOp++) candidates.push(responseOf(requestOp));
  candidates.push(ERROR); // 0xFE
  for (const hint of candidates) {
    try {
      const l3 = open(key, DIR_G2W, msgId, hint, sealed);
      return Envelope.decode(l3);
    } catch {
      // wrong hint — next
    }
  }
  throw new SessionError('reply failed to open under any response opcode — session key mismatch?');
}

/** Open a known-opcode sealed reply (no trial loop). */
export function openSealed(key: Uint8Array, msgId: number, sealed: Uint8Array, opcodeHint: number): Uint8Array {
  return open(key, DIR_G2W, msgId, opcodeHint, sealed);
}

/**
 * Transport-aware session: wires a raw-body sender and a correlated push
 * delivery into the bootstrap + sealed-exchange state machine. This is the
 * object the UI drives.
 */
export class MeshSession {
  private keys: SessionKeys | null = null;
  private readonly pending = new Map<number, (body: Uint8Array) => void>();

  constructor(
    private readonly sendRaw: (body: Uint8Array) => Promise<void>,
    private readonly walletPriv: Uint8Array,
    private readonly walletPub: Uint8Array,
    private readonly gatewayPub: Uint8Array, // from the connection QR (§8)
  ) {
    if (walletPriv.length !== 32 || walletPub.length !== 32 || gatewayPub.length !== 32) {
      throw new SessionError('all session keys must be 32-byte X25519');
    }
  }

  get established(): boolean {
    return this.keys !== null;
  }

  /** The msg_id of the in-flight (or most recent) outgoing request. Transports
   *  use it to correlate replies before handing them to onInboundBody. */
  lastOutgoingMsgId: number | null = null;

  get sessionKeys(): SessionKeys {
    if (!this.keys) throw new SessionError('session not established');
    return this.keys;
  }

  /** Feed an inbound sealed body (transport parsed the L1 msg_id already). */
  onInboundBody(msgId: number, body: Uint8Array): void {
    if (isBootstrap(body)) {
      // §4.2.1: the gateway NEVER sends bootstrap form — wallet MUST discard.
      return;
    }
    const resolver = this.pending.get(msgId);
    if (resolver) {
      this.pending.delete(msgId);
      resolver(body);
    }
    // Unmatched bodies: stale replies after a restart — silently drop; the
    // gateway's replay cache makes re-requests cheap (§11.1).
  }

  /** Await a reply correlated to msgId while `sendRaw` runs. */
  private async exchange(msgId: number, body: Uint8Array, timeoutMs: number): Promise<Uint8Array> {
    let timer: ReturnType<typeof setTimeout> | null = null;
    const promise = new Promise<Uint8Array>((resolve, reject) => {
      this.pending.set(msgId, resolve);
      timer = setTimeout(() => {
        if (this.pending.delete(msgId)) {
          reject(new SessionError(`no reply for msg_id 0x${msgId.toString(16)} within ${timeoutMs} ms`));
        }
      }, timeoutMs);
    });
    this.lastOutgoingMsgId = msgId;
    try {
      await this.sendRaw(body);
    } catch (e) {
      // Transport failed: settle now, don't linger until the timeout rejects
      // a promise nobody holds (unhandled rejection + leaked pending entry).
      if (timer) clearTimeout(timer);
      this.pending.delete(msgId);
      throw e;
    }
    return promise.finally(() => {
      if (timer) clearTimeout(timer);
    });
  }

  /** First contact: bootstrap HELLO → sealed, verified reply (§4.2.1). */
  async establish(supportedOps: number[], timeoutMs = 20000): Promise<Ops.HelloResponse> {
    const msgId = nextMsgId();
    const hello = Ops.helloRequest(1, this.walletPub, supportedOps);
    const sealedReply = await this.exchange(msgId, bootstrap(hello.encode()), timeoutMs);

    const keys: SessionKeys = {
      ...deriveKeys(this.walletPriv, this.gatewayPub),
      walletPubkey: this.walletPub.slice(),
    };
    // Trial-open: a gateway ERROR envelope (e.g. MC_NOT_PERMITTED) must
    // surface with its code, not as a bare AEAD failure (§10).
    const replyEnv = openReply(keys.gatewayToWallet, msgId, sealedReply);
    if (replyEnv.opcode === ERROR) {
      const err = Ops.parseError(replyEnv);
      throw new SessionError(`gateway rejected HELLO: error 0x${err.code.toString(16)}`);
    }
    const response = Ops.parseHelloResponse(replyEnv);
    this.keys = keys;
    return response;
  }

  /** Established-session request/response round trip (§4.5). */
  async request(request: Envelope, timeoutMs = 20000): Promise<Envelope> {
    const keys = this.sessionKeys;
    const msgId = nextMsgId();
    const sealed = seal(keys.walletToGateway, 0, DIR_W2G, msgId, request.opcodeHint, request.encode());
    const reply = await this.exchange(msgId, sealed, timeoutMs);
    return openReply(keys.gatewayToWallet, msgId, reply);
  }
}

// Re-exports for callers building on the session.
export { ERROR, HELLO, responseOf, Envelope, bootstrap, isBootstrap, parseBootstrap, DIR_W2G, DIR_G2W };
