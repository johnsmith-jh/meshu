/**
 * Web Bluetooth transport to the wallet-side MeshCore companion node.
 *
 * Port of the helloworld client's battle-tested transport (v9 lessons baked
 * in): Nordic UART GATT, one raw frame per GATT write, and a notification
 * parser that (a) survives coalesced multi-frame notifications and (b) offers
 * RF-log (0x88) visibility — MESHCORE-RADIO.md §3/§8.
 *
 * Companion frames over BLE have NO length prefix, so lengths are derived per
 * type; remainder-terminated types (0x88, SELF_INFO) are handled by scanning
 * for unambiguous signatures rather than exact consumption.
 */

export const NUS_SERVICE = '6e400001-b5a3-f393-e0a9-e50e24dcca9e';
export const NUS_RX = '6e400002-b5a3-f393-e0a9-e50e24dcca9e'; // app → node (write)
export const NUS_TX = '6e400003-b5a3-f393-e0a9-e50e24dcca9e'; // node → app (notify)

/** APP_START: [0x01][protocol version = 0x03][6 pad][name] — byte 1 is REQUIRED (docs lie). */
export function appStart(name: string): Uint8Array {
  const cmd = new Uint8Array(8 + name.length);
  cmd[0] = 0x01;
  cmd[1] = 0x03;
  cmd.fill(0x20, 2, 8);
  cmd.set(new TextEncoder().encode(name), 8);
  return cmd;
}

/** Companion push frame types (MESHCORE-RADIO.md §10). */
export const F_OK = 0x00;
export const F_ERR = 0x01;
export const F_SELF_INFO = 0x05;
export const F_RAW_PUSH = 0x84;
export const F_LOG_RX = 0x88;

/** Err codes carried by 0x01 frames (docs §Errors). */
export const ERR_TABLE_FULL = 3;

export interface InboundPush {
  kind: 'ok' | 'err' | 'raw' | 'rflog';
  errCode?: number;
  /** For 'raw': payload after the 4-byte push prefix (§2.5: SNR/RSSI/0xFF). */
  payload?: Uint8Array;
  snr?: number;
  rssi?: number;
  /** For 'rflog': the raw air packet bytes (type nibble = (hdr>>2)&0xF). */
  airPacket?: Uint8Array;
}

const signed8 = (b: number): number => (b > 127 ? b - 256 : b);

/**
 * Incremental notification parser. Handles coalesced frames by per-type
 * consumption where lengths are derivable; remainder-terminated types are
 * consumed by signature-scan (see MESHCORE-RADIO.md §3/§8).
 */
export class CompanionParser {
  private buf = new Uint8Array(0);

  /** Feed a BLE notification chunk; returns the push frames it completed. */
  feed(chunk: Uint8Array): InboundPush[] {
    const merged = new Uint8Array(this.buf.length + chunk.length);
    merged.set(this.buf);
    merged.set(chunk, this.buf.length);
    this.buf = merged;

    const out: InboundPush[] = [];
    let guard = 0;
    while (this.buf.length > 0 && guard++ < 64) {
      const t = this.buf[0]!;
      if (t === F_OK) {
        out.push({ kind: 'ok' });
        this.buf = this.buf.slice(1); // RESP_CODE_OK is exactly 1 byte
        continue;
      }
      if (t === F_ERR) {
        if (this.buf.length < 2) break; // incomplete
        out.push({ kind: 'err', errCode: this.buf[1]! });
        this.buf = this.buf.slice(2);
        continue;
      }
      if (t === F_RAW_PUSH) {
        if (this.buf.length < 10) break; // min: 4 prefix + dst + src + L1 header
        // PING-shaped raw pushes are exactly 10 B; longer ones carry L2/DATA
        // bodies with no self-describing length — out of helloworld scope and
        // out of Phase-0 scope. The payload is capped at the 10-byte
        // consumption so the two never disagree (review fix); anything beyond
        // is parsed as the next frame. Phase 1 must give raw pushes the same
        // anchor-scan treatment as 0x88 — they are remainder-terminated (§2.5).
        const snr = signed8(this.buf[1]!) / 4;
        const rssi = signed8(this.buf[2]!);
        out.push({ kind: 'raw', payload: this.buf.slice(4, 10), snr, rssi });
        this.buf = this.buf.slice(10);
        continue;
      }
      if (t === F_LOG_RX) {
        // [0x88][SNR×4][RSSI][raw air packet — remainder-terminated]. Its end
        // is unknowable when coalesced, so scan for the NEXT recognizable
        // frame start (typically the 0x84 pong it precedes — v9 lesson).
        if (this.buf.length < 4) break;
        const next = this.findEmbeddedFrameStart(3);
        const snr = signed8(this.buf[1]!) / 4;
        const rssi = signed8(this.buf[2]!);
        out.push({ kind: 'rflog', airPacket: this.buf.slice(3, next < 0 ? undefined : next), snr, rssi });
        this.buf = next < 0 ? new Uint8Array(0) : this.buf.slice(next);
        continue;
      }
      if (t === F_SELF_INFO) {
        // Remainder-terminated (name); ≥58 B minimum. Always arrives alone as
        // a direct command response — consume-all once complete.
        if (this.buf.length < 58) break; // incomplete — wait for more chunks
        out.push({ kind: 'raw', payload: this.buf });
        this.buf = new Uint8Array(0);
        continue;
      }
      // Unknown type: drop to resync (never wedge).
      this.buf = new Uint8Array(0);
      break;
    }
    return out;
  }

  /**
   * Scan for the next UNAMBIGUOUS companion frame start at/after `offset`:
   * a raw push (0x84 with its reserved 0xFF byte at +3). Generic values
   * (0x00/0x01/0x05) match air-packet padding constantly — the helloworld's
   * 0x84+0xFF signature is the only safe anchor (v9 lesson).
   */
  private findEmbeddedFrameStart(offset: number): number {
    for (let i = offset; i + 3 < this.buf.length; i++) {
      if (this.buf[i] === F_RAW_PUSH && this.buf[i + 3] === 0xff) return i;
    }
    return -1;
  }
}

/** Parsed SELF_INFO (companion docs layout; §2 of MESHCORE-RADIO.md). */
export interface SelfInfo {
  advType: number;
  txPower: number;
  maxTxPower: number;
  publicKey: Uint8Array; // 32-byte Ed25519 — hash = pubkey[0] (§2.2)
  advLat: number;
  advLon: number;
  radioFreqMhz: number;
  radioBwKhz: number;
  radioSf: number;
  radioCr: number;
  name: string;
}

export function parseSelfInfo(payload: Uint8Array): SelfInfo {
  if (payload.length < 2 || payload[0] !== F_SELF_INFO) {
    throw new Error('not a SELF_INFO payload');
  }
  if (payload.length < 58) {
    throw new Error(`SELF_INFO too short: ${payload.length} < 58`);
  }
  const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const latRaw = dv.getInt32(36, true);
  const lonRaw = dv.getInt32(40, true);
  const name = new TextDecoder().decode(payload.slice(58)).replace(/\0/g, '').trim();
  return {
    advType: payload[1]!,
    txPower: payload[2]!,
    maxTxPower: payload[3]!,
    publicKey: payload.slice(4, 36),
    advLat: latRaw / 1e6,
    advLon: lonRaw / 1e6,
    radioFreqMhz: dv.getUint32(48, true) / 1000,
    radioBwKhz: dv.getUint32(52, true) / 1000,
    radioSf: payload[56]!,
    radioCr: payload[57]!,
    name,
  };
}

/** Full BLE link: connect, exchange, and subscribe. Phase-0 scope: no L1 yet. */
export class BleLink {
  private rxChar: BluetoothRemoteGATTCharacteristic | null = null;
  private device: BluetoothDevice | null = null;
  private parser = new CompanionParser();
  private pushHandler: ((push: InboundPush) => void) | null = null;

  static available(): boolean {
    return typeof navigator !== 'undefined' && !!navigator.bluetooth;
  }

  /** Connect + APP_START + resolve node identity. Must be called from a gesture. */
  async connect(appName: string): Promise<SelfInfo> {
    const bt = navigator.bluetooth;
    if (!bt) throw new Error("Web Bluetooth unavailable (secure context required)");
    const device = await bt.requestDevice({
      filters: [{ services: [NUS_SERVICE] }],
    });
    this.device = device;
    device.addEventListener('gattserverdisconnected', () => {
      this.rxChar = null;
    });

    const server = await device.gatt!.connect();
    const svc = await server.getPrimaryService(NUS_SERVICE);
    this.rxChar = await svc.getCharacteristic(NUS_RX);
    const txChar = await svc.getCharacteristic(NUS_TX);
    await txChar.startNotifications();
    txChar.addEventListener('characteristicvaluechanged', ev => {
      const chunk = new Uint8Array((ev.target as BluetoothRemoteGATTCharacteristic).value!.buffer);
      for (const push of this.parser.feed(chunk)) {
        this.pushHandler?.(push);
      }
    });

    await this.write(appStart(appName));
    return await this.awaitSelfInfo(5000);
  }

  onPush(handler: (push: InboundPush) => void): void {
    this.pushHandler = handler;
  }

  async write(frame: Uint8Array): Promise<void> {
    if (!this.rxChar) throw new Error('BLE not connected');
    await this.rxChar.writeValueWithResponse(frame as unknown as BufferSource);
  }

  private awaitSelfInfo(timeoutMs: number): Promise<SelfInfo> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('no SELF_INFO within timeout')), timeoutMs);
      this.pushHandler = push => {
        if (push.kind === 'raw' && push.payload && push.payload[0] === F_SELF_INFO) {
          clearTimeout(timer);
          resolve(parseSelfInfo(push.payload));
        }
      };
    });
  }

  get connected(): boolean {
    return this.rxChar !== null;
  }

  disconnect(): void {
    this.device?.gatt?.disconnect();
    this.rxChar = null;
  }
}
