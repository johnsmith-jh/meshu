import { useState } from 'preact/hooks';
import { x25519 } from '@noble/curves/ed25519.js';
import { BleLink } from '../transport/ble';
import { MeshOpFlow } from '../transport/meshFlow';
import { MeshSession } from '../l2/session';
import * as Op from '../l3/op';
import type { HelloResponse } from '../l3/ops';
import { hex } from './hex';

type Phase = 'idle' | 'connecting' | 'connected' | 'establishing' | 'established';

const inputStyle = {
  width: '95%',
  marginTop: '0.4rem',
  fontFamily: 'ui-monospace, monospace',
  fontSize: '0.8rem',
};

/**
 * Phase-1 screen: connect over BLE, establish the mesh session (bootstrap
 * HELLO → sealed reply over the air), display the HELLO response.
 *
 * Out-of-band inputs (both printed by the gateway side):
 *  - gateway node hash     → L1 dst byte (mesh-radio log "up on hash 0x..")
 *  - gateway X25519 pubkey → L2 key agreement (self-info / §8.2 fingerprint)
 * The connection-QR import (§8) replaces both inputs in the Phase-2
 * onboarding screen.
 *
 * Phase-1 key scope: session-scoped ephemeral wallet keypair (no
 * persistence); seed-derived persistent identity lands in Phase 2. Each
 * establish() creates a new gateway pairing (bounded table §4.2.1) —
 * bench-acceptable, warned in the UI copy.
 */
export function App() {
  const [phase, setPhase] = useState<Phase>('idle');
  const [log, setLog] = useState<string[]>([]);
  const [nodeInfo, setNodeInfo] = useState<string | null>(null);
  const [hello, setHello] = useState<HelloResponse | null>(null);
  const [gatewayHash, setGatewayHash] = useState('');
  const [gatewayX, setGatewayX] = useState('');
  const [error, setError] = useState<string | null>(null);

  const appendLog = (msg: string) =>
    setLog(prev => [...prev.slice(-200), `[${new Date().toISOString().slice(11, 23)}] ${msg}`]);

  async function connectAndEstablish() {
    setError(null);
    setHello(null);
    const dst = parseGatewayHash(gatewayHash);
    const gwX = parseHex32(gatewayX);
    if (dst === null) {
      setError('gateway node hash: enter 2 hex chars or the 64-hex pubkey');
      return;
    }
    if (gwX === null) {
      setError('gateway X25519 pubkey: 64 hex chars (self-info output)');
      return;
    }

    // Phase-1 wallet keypair: ephemeral (Phase 2 derives it from the seed).
    const walletPriv = new Uint8Array(32);
    crypto.getRandomValues(walletPriv);
    const walletPub = x25519.getPublicKey(walletPriv);

    setPhase('connecting');
    appendLog('requesting BLE device…');
    const link = new BleLink();
    const session = new MeshSession(
      async (body) => {
        const flow = new MeshOpFlow(link, session, dst);
        await flow.sendL2Body(body);
      },
      walletPriv,
      walletPub,
      gwX,
    );

    try {
      const info = await link.connect('meshu-wallet');
      setNodeInfo(
        `${info.name} hash 0x${info.publicKey[0]!.toString(16).padStart(2, '0')} @ ${info.radioFreqMhz} MHz SF${info.radioSf}`,
      );
      appendLog(`connected: ${info.name} (node hash 0x${info.publicKey[0]!.toString(16).padStart(2, '0')})`);
      setPhase('connected');

      // Route pushes into the session; RF/node events into the debug log
      // (helloworld-style visibility — MESHCORE-RADIO §8).
      const flow = new MeshOpFlow(link, session, dst);
      flow.log = appendLog;
      flow.bindReceive();

      setPhase('establishing');
      appendLog('establishing mesh session — bootstrap HELLO over the air…');
      const response = await session.establish(
        [Op.HELLO, Op.KEYSETS, Op.KEYS, Op.CHECKSTATE, Op.SWAP],
        30000,
      );
      setHello(response);
      setPhase('established');
      appendLog(`session established: mints=${response.mintUrls.join(', ')}`);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
      appendLog(`error: ${e instanceof Error ? e.message : String(e)}`);
      setPhase('idle');
    }
  }

  return (
    <>
      <div class="card">
        <b>gateway node hash</b> (L1 dst)
        <input value={gatewayHash} onInput={(e) => setGatewayHash((e.target as HTMLInputElement).value)} style={inputStyle} placeholder="eb" />
      </div>
      <div class="card">
        <b>gateway X25519 pubkey</b> (L2, from self-info / QR §8)
        <input value={gatewayX} onInput={(e) => setGatewayX((e.target as HTMLInputElement).value)} style={inputStyle} placeholder="64 hex" />
      </div>
      <button onClick={connectAndEstablish} disabled={phase !== 'idle'}>
        {phase === 'idle' ? 'Connect & establish session' : `${phase}…`}
      </button>
      {nodeInfo && <div class="card">node: {nodeInfo}</div>}
      {hello && (
        <div class="card">
          <b>HELLO response (sealed, verified)</b>
          <div>mints: {hello.mintUrls.join(', ')}</div>
          <div>gateway pubkey: {hex(hello.gatewayPubkey)}</div>
          <div>max_msg: {hello.maxMsg.toString()}</div>
          <div>server_time: {hello.serverTime.toString()}</div>
        </div>
      )}
      {error && <div class="card" style={{ borderColor: '#c00' }}>error: {error}</div>}
      <div id="log">{log.join('\n')}</div>
    </>
  );
}

function parseGatewayHash(input: string): number | null {
  const raw = input.replace(/[\s:.-]/g, '').toLowerCase();
  const t = raw.startsWith('0x') ? raw.slice(2) : raw;
  if (!/^[0-9a-f]+$/.test(t)) return null;
  if (t.length === 2) return parseInt(t, 16);
  if (t.length === 64) return parseInt(t.slice(0, 2), 16); // pubkey[0]
  return null;
}

function parseHex32(input: string): Uint8Array | null {
  const raw = input.replace(/[\s:.-]/g, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(raw)) return null;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(raw.slice(i * 2, i * 2 + 2), 16);
  return out;
}
