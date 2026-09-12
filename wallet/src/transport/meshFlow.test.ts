import { describe, expect, test } from 'vitest';
import { buildSingleDataFrame, MeshOpFlow } from './meshFlow';
import { MeshSession } from '../l2/session';
import { randomPrivateKey, x25519PublicKey } from '../l2/crypto';
import { ERR_TABLE_FULL, F_LOG_RX, type BleLink, type InboundPush } from './ble';

/**
 * Wire-format and routing tests for the BLE raw-datagram transport — the
 * layer the Phase-0 session tests bypassed (and where the >10-byte push bug
 * lived). No radio: a stub link captures writes and replays pushes.
 */

const GW_HASH = 0xeb;
const NODE_HASH = 0xc7;

function fakeLink() {
  const writes: Uint8Array[] = [];
  let handler: ((push: InboundPush) => void) | null = null;
  const link = {
    selfInfo: { publicKey: new Uint8Array(32).map((_, i) => (i === 0 ? NODE_HASH : i & 0xff)) },
    onPush(h: (push: InboundPush) => void): void {
      handler = h;
    },
    async write(frame: Uint8Array): Promise<void> {
      writes.push(frame);
    },
  };
  return {
    link: link as unknown as BleLink,
    writes,
    emit: (p: InboundPush): void => handler?.(p),
  };
}

function fakeSession() {
  const received: Array<{ msgId: number; body: Uint8Array }> = [];
  const priv = randomPrivateKey();
  const gw = randomPrivateKey();
  const session = new MeshSession(async () => {}, priv, x25519PublicKey(priv), x25519PublicKey(gw));
  const orig = session.onInboundBody.bind(session);
  session.onInboundBody = (msgId: number, body: Uint8Array): void => {
    received.push({ msgId, body: body.slice() });
    orig(msgId, body);
  };
  return { session, received };
}

const raw = (...bytes: number[]): InboundPush => ({ kind: 'raw', payload: new Uint8Array(bytes) });
/** Single-frame L1 DATA: header ‖ body. */
const dataFrame = (msgId: number, body: number[], flags = 0x02): number[] => [
  0x10,
  flags,
  (msgId >> 8) & 0xff,
  msgId & 0xff,
  ...body,
];

describe('buildSingleDataFrame (§3.1)', () => {
  test('layout: 0x10 ‖ REQ_ACK ‖ msg_id BE ‖ body', () => {
    const f = buildSingleDataFrame(0x1234, new Uint8Array([0xaa, 0xbb]));
    expect(Array.from(f)).toEqual([0x10, 0x02, 0x12, 0x34, 0xaa, 0xbb]);
  });
});

describe('MeshOpFlow.sendL2Body (§2.4)', () => {
  test('companion frame: [0x19][path_len=0][dst][src][L1]', async () => {
    const { link, writes } = fakeLink();
    const { session } = fakeSession();
    session.lastOutgoingMsgId = 0x1234;
    const flow = new MeshOpFlow(link, session, GW_HASH);

    await flow.sendL2Body(new Uint8Array([0xff, 0x01, 0x02]));

    expect(writes.length).toBe(1);
    const w = writes[0]!;
    expect(w[0]).toBe(0x19); // CMD_SEND_RAW_DATA
    expect(w[1]).toBe(0); // path_len = 0 (zero-hop)
    expect(w[2]).toBe(GW_HASH); // dst
    expect(w[3]).toBe(NODE_HASH); // src
    expect(Array.from(w.slice(4))).toEqual([0x10, 0x02, 0x12, 0x34, 0xff, 0x01, 0x02]);
  });
});

describe('MeshOpFlow.bindReceive routing (§2.3, §2.5)', () => {
  const setup = () => {
    const { link, emit } = fakeLink();
    const { session, received } = fakeSession();
    const logs: string[] = [];
    const flow = new MeshOpFlow(link, session, GW_HASH);
    flow.log = m => logs.push(m);
    flow.bindReceive();
    return { emit, received, logs };
  };

  test('single-frame DATA for our node hash reaches the session', () => {
    const { emit, received } = setup();
    emit(raw(GW_HASH === 0xeb ? NODE_HASH : 0xeb, 0x99, ...dataFrame(0x1234, [0xaa, 0xbb])));
    expect(received.length).toBe(1);
    expect(received[0]!.msgId).toBe(0x1234);
    expect(Array.from(received[0]!.body)).toEqual([0xaa, 0xbb]);
  });

  test('dst mismatch is dropped before any parsing (§2.3 pre-crypto filter)', () => {
    const { emit, received } = setup();
    emit(raw(0x42, 0x99, ...dataFrame(0x1234, [0xaa])));
    expect(received.length).toBe(0);
  });

  test('non-DATA frames (ACKBM) are dropped', () => {
    const { emit, received } = setup();
    emit(raw(NODE_HASH, 0x99, 0x12, 0x00, 0x12, 0x34, 0x01, 0x01)); // ACKBM total=1 bitmap=1
    expect(received.length).toBe(0);
  });

  test('MULTI-flagged DATA is dropped in Phase 1 (reassembly loop is Phase 2)', () => {
    const { emit, received } = setup();
    emit(raw(NODE_HASH, 0x99, 0x10, 0x03, 0x12, 0x34, 0x00, 0x01, 0xaa)); // MULTI seq 0 of 2
    expect(received.length).toBe(0);
  });

  test('unknown L1 version is dropped', () => {
    const { emit, received } = setup();
    emit(raw(NODE_HASH, 0x99, 0x50, 0x02, 0x12, 0x34, 0xaa)); // version 1 ‖ DATA
    expect(received.length).toBe(0);
  });

  test('malformed short frame never wedges the listener', () => {
    const { emit, received, logs } = setup();
    emit(raw(NODE_HASH, 0x99, 0x10)); // L1 header truncated to 1 byte — parseHeader throws
    expect(logs.some(m => m.includes('malformed'))).toBe(true);
    // …and the very next valid push still routes:
    emit(raw(NODE_HASH, 0x99, ...dataFrame(0x1235, [0x01])));
    expect(received.length).toBe(1);
    expect(received[0]!.msgId).toBe(0x1235);
  });

  test('RF log / OK / ERR pushes surface helloworld-style (§8, §10.4)', () => {
    const { emit, logs } = setup();
    emit({ kind: 'rflog', airPacket: new Uint8Array([0x3c, 0x00, 0x06]), snr: 12, rssi: -16 });
    emit({ kind: 'ok' });
    emit({ kind: 'err', errCode: ERR_TABLE_FULL });
    emit({ kind: 'err', errCode: 2 });
    expect(logs.some(m => m.includes('RF rx: type=0xf') && m.includes('rssi=-16'))).toBe(true);
    expect(logs.some(m => m.includes('queued for the air'))).toBe(true);
    expect(logs.some(m => m.includes('queue FULL'))).toBe(true);
    expect(logs.some(m => m.includes('ERR code 2'))).toBe(true);
  });
});
