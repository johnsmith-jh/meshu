import { describe, expect, test } from 'vitest';
import {
  appStart,
  CompanionParser,
  parseSelfInfo,
  F_OK,
  F_ERR,
  F_RAW_PUSH,
  F_LOG_RX,
  F_SELF_INFO,
  ERR_TABLE_FULL,
} from './ble';

const hex = (b: Uint8Array) => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');

describe('BLE companion transport (port of helloworld v9 lessons)', () => {
  test('APP_START carries protocol version 0x03 in byte 1 (gotcha #1)', () => {
    const cmd = appStart('meshu-w');
    expect(cmd[0]).toBe(0x01);
    expect(cmd[1]).toBe(0x03);
    expect(cmd[2]).toBe(0x20);
    expect(new TextDecoder().decode(cmd.slice(8))).toBe('meshu-w');
  });

  test('single frames parse: OK, ERR(TABLE_FULL)', () => {
    const p = new CompanionParser();
    expect(p.feed(new Uint8Array([F_OK]))).toEqual([{ kind: 'ok' }]);
    const errs = p.feed(new Uint8Array([F_ERR, ERR_TABLE_FULL]));
    expect(errs).toEqual([{ kind: 'err', errCode: ERR_TABLE_FULL }]);
  });

  test('COALESCED frames all survive (the pong-killer bug)', () => {
    // RF-log + raw push concatenated in ONE notification — the exact shape
    // that destroyed every pong before the fix.
    const rflog = new Uint8Array([F_LOG_RX, 0x0a, 0xa0, 0x3c, 0x00, 0x06, 0xc7, 0xeb, 0x15, 0x00, 0x00, 0x07]);
    const pong = new Uint8Array([F_RAW_PUSH, 0x0a, 0xa0, 0xff, 0xc7, 0xeb, 0x15, 0x00, 0x00, 0x07]);
    const merged = new Uint8Array(rflog.length + pong.length);
    merged.set(rflog);
    merged.set(pong, rflog.length);

    const p = new CompanionParser();
    const pushes = p.feed(merged);
    const kinds = pushes.map(x => x.kind);
    expect(kinds).toContain('rflog');
    expect(kinds).toContain('raw');
    const pongPush = pushes.find(x => x.kind === 'raw')!;
    expect(pongPush.payload![0]).toBe(0xc7); // dst = us (payload excludes the 4-B prefix)
    expect(pongPush.snr).toBe(2.5);
    expect(pongPush.rssi).toBe(-96);
  });

  test('raw push layout: payload begins at offset 4 (§2.5 asymmetry)', () => {
    const p = new CompanionParser();
    const pushes = p.feed(new Uint8Array([F_RAW_PUSH, 0x0a, 0xa0, 0xff, 0xeb, 0xc7, 0x15, 0x00, 0x00, 0x01]));
    expect(pushes.length).toBe(1);
    expect(pushes[0]!.kind).toBe('raw');
    expect(Array.from(pushes[0]!.payload!)).toEqual([0xeb, 0xc7, 0x15, 0x00, 0x00, 0x01]);
  });

  test('raw push payload is capped at the 10-byte consumption (review fix)', () => {
    // A push coalesced with a following frame: the payload must not absorb the
    // next frame's bytes, and the next frame must still parse.
    const pong = new Uint8Array([F_RAW_PUSH, 0x0a, 0xa0, 0xff, 0xc7, 0xeb, 0x15, 0x00, 0x00, 0x07]);
    const merged = new Uint8Array(pong.length + 1);
    merged.set(pong);
    merged.set(new Uint8Array([F_OK]), pong.length);

    const p = new CompanionParser();
    const pushes = p.feed(merged);
    expect(pushes.map(x => x.kind)).toEqual(['raw', 'ok']);
    expect(pushes[0]!.payload!.length).toBe(6); // dst ‖ src ‖ 4-byte L1 header, nothing more
  });

  test('SELF_INFO parses all fields (name, pubkey, radio)', () => {
    const payload = new Uint8Array(58 + 3);
    payload[0] = F_SELF_INFO;
    payload[1] = 2; // adv type
    payload[2] = 20; // tx power
    payload[3] = 30; // max tx power
    for (let i = 0; i < 32; i++) payload[4 + i] = i;
    new DataView(payload.buffer).setInt32(36, 52351777, true);
    new DataView(payload.buffer).setInt32(40, 13405222, true);
    new DataView(payload.buffer).setUint32(48, 869618, true);
    new DataView(payload.buffer).setUint32(52, 62500, true);
    payload[56] = 8; // SF
    payload[57] = 5; // CR
    payload.set(new TextEncoder().encode('Jhs'), 58);

    const info = parseSelfInfo(payload);
    expect(info.name).toBe('Jhs');
    expect(hex(info.publicKey)).toBe(Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, '0')).join(''));
    expect(info.radioFreqMhz).toBe(869.618);
    expect(info.radioBwKhz).toBe(62.5);
    expect(info.radioSf).toBe(8);
    expect(info.txPower).toBe(20);
  });

  test('chunked notifications accumulate before parse', () => {
    const p = new CompanionParser();
    const selfInfo = new Uint8Array(60);
    selfInfo[0] = F_SELF_INFO;
    const first = p.feed(selfInfo.slice(0, 30)); // half a frame
    expect(first.length).toBe(0); // nothing yet
    const second = p.feed(selfInfo.slice(30)); // rest
    expect(second.length).toBe(1);
  });

  test('unknown frame type drops to resync (never wedges)', () => {
    const p = new CompanionParser();
    const pushes = p.feed(new Uint8Array([0x96, 1, 2, 3]));
    expect(pushes.length).toBe(0);
    // parser still works after resync:
    expect(p.feed(new Uint8Array([F_OK]))).toEqual([{ kind: 'ok' }]);
  });
});
