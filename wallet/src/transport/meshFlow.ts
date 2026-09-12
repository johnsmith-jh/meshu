/**
 * Mesh op flow: BLE raw-datagram transport for sealed L2 bodies (PROTOCOL.md
 * §2.3–2.5, zero-hop). Bridges the session layer to Web Bluetooth:
 *
 *   send:  CMD_SEND_RAW_DATA(path_len=0, dst‖src‖L1(L2 body))
 *   recv:  PUSH_CODE_RAW_DATA payload (dst‖src‖L1...) → strip prefix, parse
 *          the L1 header for msg_id, hand (msgId, L2 body) to the session.
 *
 * L1 framing note (Phase-1 scope): a single-frame DATA frame is
 * header(4) ‖ L2 body, so the msg_id lives at body-offset 2..3 of the L1
 * frame. Multi-frame responses arrive through the same receive path and are
 * reassembled by the L1 Reassembler — Phase 2 wires that loop; the session's
 * exchange() already survives dropped replies via timeout + manual retry.
 */
import { parseHeader, KIND_DATA } from '../l1/frame';
import { CMD_SEND_RAW, ERR_TABLE_FULL, type BleLink, type InboundPush } from './ble';
import { MeshSession } from '../l2/session';

/** Error codes the mesh flow maps to user-actionable outcomes (§10.3). */
export const MC_STALE_HANDLE = 0xf003;
export const MC_MINT_UNREACHABLE = 0xf004;
export const MC_MINT_TIMEOUT = 0xf005;

export class MeshOpFlow {
  private readonly nodeHash: number; // our wallet node hash (§2.2: pubkey[0])
  private readonly gatewayHash: number; // from the connection QR input
  /** Debug log sink (helloworld style); null = silent. Set by the UI. */
  log: ((msg: string) => void) | null = null;

  constructor(
    readonly link: BleLink,
    readonly session: MeshSession,
    gatewayHash: number,
  ) {
    if (!link.selfInfo) throw new Error('BLE link must be connected (selfInfo present)');
    this.nodeHash = link.selfInfo.publicKey[0]!;
    this.gatewayHash = gatewayHash & 0xff;
  }

  /**
   * Send one opaque L2 body as a zero-hop raw datagram and resolve with the
   * correlated sealed reply. Used by MeshSession via its sendRaw contract.
   */
  async sendL2Body(l2Body: Uint8Array): Promise<void> {
    // L1 single-frame DATA: msg_id is this transport's correlation key.
    // The session already allocated it (lastOutgoingMsgId); the L1 header
    // needs the SAME value for the gateway's reply correlation.
    const msgId = this.session.lastOutgoingMsgId ?? 0;
    const l1 = buildSingleDataFrame(msgId, l2Body);
    const payload = new Uint8Array(2 + l1.length);
    payload[0] = this.gatewayHash; // dst
    payload[1] = this.nodeHash; // src
    payload.set(l1, 2);

    const cmd = new Uint8Array(2 + payload.length);
    cmd[0] = CMD_SEND_RAW;
    cmd[1] = 0; // path_len = 0 (zero-hop, §2.6)
    cmd.set(payload, 2);
    this.log?.(`tx: raw datagram ${payload.length} B → gateway hash 0x${this.gatewayHash.toString(16).padStart(2, '0')}`);
    await this.link.write(cmd);
  }

  /**
   * Subscribe to pushes: route raw DATA frames into the session, log
   * everything else helloworld-style (RF visibility is the #1 diagnostic —
   * MESHCORE-RADIO §8). A malformed frame must never wedge the listener:
   * each push is routed inside its own try/catch.
   */
  bindReceive(): void {
    this.link.onPush((push: InboundPush) => {
      try {
        this.route(push);
      } catch (e) {
        this.log?.(`push dropped (malformed): ${e instanceof Error ? e.message : String(e)}`);
      }
    });
  }

  private route(push: InboundPush): void {
    if (push.kind === 'rflog') {
      // Heard-vs-delivered ground truth. Type nibble per MESHCORE-RADIO §7.
      const pkt = push.airPacket;
      const type = pkt && pkt.length > 0 ? (pkt[0]! >> 2) & 0xf : -1;
      this.log?.(
        `RF rx: type=0x${type.toString(16)} snr=${push.snr?.toFixed(1)}dB rssi=${push.rssi}dBm (${pkt?.length ?? 0} B)`,
      );
      return;
    }
    if (push.kind === 'ok') {
      this.log?.('node: OK — datagram queued for the air');
      return;
    }
    if (push.kind === 'err') {
      // §10.4: companion errors are local BLE conditions — surface distinctly.
      this.log?.(
        push.errCode === ERR_TABLE_FULL
          ? 'node: queue FULL (§2.8) — datagram refused; back off and retry'
          : `node: ERR code ${push.errCode}`,
      );
      return;
    }
    if (push.kind !== 'raw' || !push.payload) return;
    const p = push.payload;
    if (p.length < 2) return;
    const dst = p[0]!;
    if (dst !== this.nodeHash) return; // §2.3 pre-crypto filter
    const src = p[1]!;
    void src;
    const l1 = p.slice(2);
    const parsed = parseHeader(l1, 0);
    if (parsed.header.kind !== KIND_DATA) return; // ACKBM/PING replies handled later
    if (parsed.header.version !== 0) return;
    // Single-frame only in Phase 1 (MULTI requires reassembly loop).
    if ((parsed.header.flags & 0x01) !== 0) return;
    const l2Body = l1.slice(parsed.bodyOffset);
    this.session.onInboundBody(parsed.header.msgId, l2Body);
  }
}

/** Build a single-frame L1 DATA frame carrying the sealed L2 body. */
export function buildSingleDataFrame(msgId: number, l2Body: Uint8Array): Uint8Array {
  const header = new Uint8Array(4);
  header[0] = 0x10; // version 0 ‖ KIND_DATA
  header[1] = 0x02; // REQ_ACK (single-frame reliable, §3.4)
  header[2] = (msgId >> 8) & 0xff;
  header[3] = msgId & 0xff;
  const out = new Uint8Array(4 + l2Body.length);
  out.set(header, 0);
  out.set(l2Body, 4);
  return out;
}

