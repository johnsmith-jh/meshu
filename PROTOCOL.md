# Meshu Protocol Specification

**Version:** 1 (draft)
**Status:** Draft — not yet implemented, not yet security reviewed
**Date:** 2026-07-27

A compact binary protocol for operating a [Cashu](https://cashu.space) ecash wallet
over a [MeshCore](https://github.com/meshcore-dev/MeshCore) LoRa mesh network,
via a gateway that translates to the Cashu HTTP API.

---

## Table of Contents

1. [Scope, Architecture, Trust Model](#1-scope-architecture-trust-model)
2. [Transport Binding](#2-transport-binding)
3. [L1 — Segmentation and Reliability](#3-l1--segmentation-and-reliability)
4. [L2 — End-to-End Encryption](#4-l2--end-to-end-encryption)
5. [L3 — Message Encoding](#5-l3--message-encoding)
6. [Compact Type Encodings](#6-compact-type-encodings)
7. [Operation Codes](#7-operation-codes)
8. [Operation Wire Formats](#8-operation-wire-formats)
9. [Mandatory NUT-20 Profile](#9-mandatory-nut-20-profile)
10. [Errors](#10-errors)
11. [Idempotency and Recovery](#11-idempotency-and-recovery)
12. [Airtime Governance](#12-airtime-governance)
13. [Versioning and Extension](#13-versioning-and-extension)

**Conventions.** "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "MAY" are to be
interpreted as in RFC 2119. All multi-byte integers in L1 and L2 headers are
**big-endian** unless stated otherwise. Note that MeshCore's own companion
frames use **little-endian**; the boundary is at §2.

**Transport summary.** Meshu addresses the gateway node directly by identity
using `PAYLOAD_TYPE_RAW_CUSTOM`. There is no shared MeshCore channel and no
channel secret. End-to-end encryption (§4) is mandatory because the transport
provides none.

---

## 1. Scope, Architecture, Trust Model

### 1.1 Topology

```
┌───────────────────┐
│  Wallet (PWA)     │  TypeScript, IndexedDB, Web Bluetooth
└─────────┬─────────┘
          │  BLE GATT (Nordic UART UUIDs)
          │  MeshCore Companion Protocol
┌─────────▼─────────┐
│ Companion node    │  STOCK MeshCore firmware, unmodified
└─────────┬─────────┘
          │  LoRa — MeshCore mesh, 0..n repeater hops
          │  addressed directly to the gateway's node identity
┌─────────▼─────────┐
│ Gateway node      │  STOCK MeshCore firmware, unmodified
└─────────┬─────────┘
          │  USB serial (or BLE)
┌─────────▼─────────┐
│ Gateway daemon    │  Go or Rust, has Internet access
└─────────┬─────────┘
          │  HTTPS
┌─────────▼─────────┐
│  Cashu mint(s)    │
└───────────────────┘
```

The wallet never contacts a mint directly. The gateway daemon is the only
component with Internet access.

The wallet is configured with **one gateway identity** — the gateway node's
32-byte MeshCore public key, plus its X25519 key for L2. There is no shared
MeshCore channel and no group membership anywhere in the design.

The gateway needs no per-wallet provisioning: a wallet introduces its L2 key in
its first `HELLO`, which the gateway pins (§4.2.1). There is no out-of-band
step on the gateway side.

### 1.2 Design constraints

This protocol is shaped by one dominant fact: **the usable application payload
is at most 170 bytes per LoRa packet, and at MeshCore's default radio preset one
packet costs ~1.03 s of airtime**, limiting a duty-cycle-compliant node to
roughly **16 bytes per second sustained**. Every design decision below trades
complexity for bytes. For sizing purposes the spec uses a conservative
**165-byte** floor that holds at any realistic path length (§2.7).

A second constraint: **no custom firmware.** Both MeshCore nodes run stock
builds. All Meshu logic lives in the PWA and the gateway daemon. This is a
deliberate deployment choice — it means a gateway operator flashes a normal
MeshCore image and runs a userspace daemon.

A third: **direct addressing, no shared channel.** The wallet talks to one
gateway identity. This removes the shared-secret exposure a MeshCore channel
would impose, at the cost of losing the channel-data offline queue (§2.5) and
flood-based discovery (§2.6).

### 1.3 Trust model

This section is normative and deliberately blunt. Implementers MUST surface
these properties to users.

**T1 — Mint front-running is prevented.**
NUT-04 warns: *"A third party who knows the `quote` ID can front-run and steal
the tokens that this operation mints."* The gateway necessarily learns every
quote ID. Therefore **NUT-20 quote locking is MANDATORY** in Meshu (§9), not
optional as it is in Cashu generally. Without it, a malicious gateway steals
100% of every mint. A gateway MUST reject a mint request lacking a valid
signature, and a wallet MUST NOT request an unlocked mint quote.

**T2 — Melt inputs are unavoidably exposed to the gateway.**
Cashu proofs are bearer instruments. To melt, the wallet must transmit spendable
proofs to the gateway, which forwards them to the mint. A malicious gateway can
steal any proof it is given. This is intrinsic to any proxy design and cannot be
fixed at the protocol layer. Mitigations, all of which a wallet SHOULD
implement:

- Send only the proofs needed for the current melt, never the whole balance.
- Prefer several small melts over one large melt when latency permits.
- Reconcile with `CHECKSTATE` (§8.9) after every melt; a proof reported `SPENT`
  with no corresponding payment indicates gateway theft.
- Treat a gateway as an amount-bounded counterparty and expose that bound in UI.

**T3 — Metadata is exposed to the gateway and to radio observers.**
The gateway learns amounts, timing, mint identity, and invoice contents.

Because Meshu addresses the gateway directly rather than through a shared
MeshCore channel (§2), there is no channel key held by third parties, and no
group of unrelated users inside the same cryptographic blast radius. However,
LoRa is a broadcast medium: **any node in radio range can receive every frame**,
and `PAYLOAD_TYPE_RAW_CUSTOM` frames are unencrypted at the transport layer. An
observer therefore sees the L1 header, the 1-byte source and destination hashes,
and message sizes and timing. L2 (§4) protects payload confidentiality and
integrity; it does not conceal that a conversation is occurring or how large it
is. Traffic analysis against a low-volume link is straightforward.

Implementations SHOULD NOT rely on the 1-byte hashes for privacy — they are a
routing filter, not a pseudonym, and a wallet's hash is stable across sessions.
The plaintext bootstrap `HELLO` additionally exposes the wallet's full
long-term L2 public key (§4.2.1, T7).

**T4 — Ecash at rest is the wallet's responsibility.**
Out of scope here. The wallet SHOULD encrypt IndexedDB contents.

**T5 — Denial of service is not prevented.**
A jammer, or any node in radio range choosing to transmit continuously, can
prevent operation. L1 (§3) provides recovery from loss, not resistance to a
determined attacker. Note also that Meshu frames are trivially identifiable on
air, so selective jamming of Meshu traffic specifically is feasible.

**T6 — Inbound frames are lost while the wallet is offline.**
Direct addressing forgoes MeshCore's channel-data offline queue: a gateway reply
arriving while the wallet's BLE link is down is discarded by the companion node,
not buffered (§2.5). This is a availability property, not a confidentiality one —
no funds are lost — but it makes the §11 recovery procedures mandatory rather
than advisory.

**T7 — Wallet key bootstrap is trust-on-first-use, and the first message is
plaintext.**
The wallet introduces its L2 key to the gateway in an unencrypted `HELLO`
(§4.2.1): there is no out-of-band channel on the gateway side. A radio observer
therefore learns the wallet's long-term public key and can link it to the
1-byte `src` hash from then on, strengthening the linkage caveat of T3. An
active attacker gains little: she cannot read wallet→gateway traffic (sealed to
the gateway's out-of-band key), cannot redirect an established pairing (the
gateway never replaces a pinned key), and cannot steal minted funds (NUT-20,
§9). A forged bootstrap `HELLO` merely pairs the gateway with the attacker
herself. The realistic abuses are pairing-table exhaustion and the generic
denial of service of T5; gateways MUST bound the pairing table and SHOULD log
pairing events for operator audit.

---

## 2. Transport Binding

Meshu uses MeshCore's **raw custom datagram** facility, addressing the gateway
**directly by its node identity**. There is no shared MeshCore channel, no
channel secret, and no group membership.

This is a deliberate security choice. A MeshCore channel key is shared by every
member of that channel, so a channel-based transport would place every wallet's
traffic inside a blast radius shared with strangers. Direct addressing removes
that entirely: the wallet is configured with one gateway identity and talks only
to it. See [Appendix A](#appendix-a-transport-alternatives-considered) for the
alternatives and the measured reasons they were rejected.

### 2.1 Companion commands used

| Direction | Companion frame | Code |
|---|---|---|
| Wallet → node (send) | `CMD_SEND_RAW_DATA` | `25` / `0x19` |
| Node → wallet (receive) | `PUSH_CODE_RAW_DATA` | `0x84` |
| Wallet → node (path lookup) | `CMD_GET_ADVERT_PATH` | `42` / `0x2A` |
| Node → wallet (path result) | `RESP_CODE_ADVERT_PATH` | `22` / `0x16` |
| Node → wallet (advert seen) | `PUSH_CODE_ADVERT` | `0x80` |
| Wallet → node (path probe) | `CMD_SEND_TRACE_PATH` | `36` / `0x24` |
| Node → wallet (trace result) | `PUSH_CODE_TRACE_DATA` | `0x89` |
| Node → wallet (success) | `RESP_CODE_OK` | `0` / `0x00` |
| Node → wallet (failure) | `RESP_CODE_ERR` | `1` / `0x01` |

No channel configuration is required on either node. `CMD_SET_CHANNEL` is not
used by Meshu.

### 2.2 Gateway identity and addressing
The wallet is configured with the gateway's **full 32-byte MeshCore Ed25519
public key**, entered by QR scan or manual import. It MUST persist the full
key. A concrete connection-string and QR encoding for this configuration —
binding the Ed25519 identity and the X25519 L2 key with a checksum and
verification fingerprint — is defined in `POC-WALLET.md` §8.

On the wire, Meshu spends only **1 byte** on addressing: the gateway's node
hash, which per MeshCore convention is the **first byte of its public key**.

```
gateway_hash = gateway_pubkey[0]
```

A 1-byte hash collides readily — roughly a 1-in-256 chance against any given
other node. Meshu tolerates this because the hash is a **cheap filter, not an
authenticator**:

- A frame whose `dst` does not match the receiver's own hash is discarded
  immediately, before any cryptography.
- A frame that passes the filter is still subject to L2 AEAD verification (§4),
  whose key is derived from the **full 32-byte** identity via X25519. A colliding
  node cannot produce a valid tag.

Therefore a collision costs one wasted AEAD attempt and nothing more. Receivers
MUST NOT treat a matching `dst` byte as evidence of authenticity, and MUST NOT
skip AEAD verification on that basis.

Because `PAYLOAD_TYPE_RAW_CUSTOM` carries no MeshCore-level source or
destination fields, Meshu supplies both itself (§2.3).

### 2.3 Frame layout on air

The Meshu L1 frame (§3) is preceded by a 2-byte routing prefix:

```
Offset  Size  Field
0       1     dst      destination node hash (gateway_pubkey[0] or wallet_pubkey[0])
1       1     src      sender node hash
2       n     L1 frame (§3)
```

`src` lets the gateway select the correct L2 key when serving several wallets,
without a full pubkey on every packet. It is a hint only: the gateway MUST
confirm the sender by successful AEAD verification, trying candidate keys if
`src` is ambiguous.

The `src` hash is a *node* hash — the first byte of the companion radio's
MeshCore identity, not of the wallet's L2 key. One wallet may appear from
different radios over time, and several wallets may share one radio, so
gateways MUST NOT key any state by this hash (§4.2.1).

### 2.4 Send: `CMD_SEND_RAW_DATA`

Written to the BLE RX characteristic:

```
Offset  Size  Field
0       1     0x19                  CMD_SEND_RAW_DATA
1       1     path_len              number of path hash bytes (0 = zero-hop direct)
2       p     path                  p = path_len bytes
2+p     ≤174  payload               dst ‖ src ‖ L1 frame
```

From `MyMesh.cpp`, the firmware requires `path_len >= 0` and at least 4 payload
bytes; a negative `path_len` yields `ERR_CODE_UNSUPPORTED_CMD` because flood
routing of raw data is not implemented. **Meshu therefore always sends
directly along a known path** (§2.6).

The node replies `RESP_CODE_OK` on enqueue, or `RESP_CODE_ERR` with
`ERR_CODE_TABLE_FULL` (3) when the outbound queue is full (§2.8).

### 2.5 Receive: `PUSH_CODE_RAW_DATA`

Delivered as a BLE TX notification:

```
Offset  Size  Field
0       1     0x84                  PUSH_CODE_RAW_DATA
1       1     SNR, signed int8, ×4
2       1     RSSI, signed int8
3       1     0xFF                  reserved — MUST be ignored
4       n     payload               dst ‖ src ‖ L1 frame
```

The payload begins at **offset 4**, and unlike the channel-data frame there is no
length byte: the payload runs to the end of the BLE frame.

> **No offline queue.** `MyMesh::onRawDataRecv()` writes to the serial interface
> only when `_serial->isConnected()`; otherwise the frame is **discarded**. There
> is no `addToOfflineQueue()` call on this path, unlike channel data. A wallet
> that is disconnected from BLE — backgrounded PWA, closed tab, dead Bluetooth —
> **loses inbound frames permanently**. This is the principal cost of direct
> addressing and it is not recoverable at the transport layer. §11 recovery
> procedures are therefore mandatory, not advisory: every operation must be
> resumable from a state query after arbitrary frame loss.

### 2.6 Path establishment

Raw custom packets are not flood-routed. From `Mesh.cpp`, inbound
`PAYLOAD_TYPE_RAW_CUSTOM` is delivered only when `isRouteDirect()`, and the
`ROUTE_TYPE_FLOOD` case is explicitly absent (*"don't flood route these (yet)"*).
A path to the gateway MUST therefore exist before any Meshu traffic flows.

Multi-hop **does** work once a path is known: the forwarding logic in
`Mesh.onRecvPacket()` for `isRouteDirect() && getPathHashCount() > 0` is
payload-type-agnostic and executes before the payload-type switch, so ordinary
repeaters relay raw custom packets along the supplied path.

A wallet MUST obtain a path by one of:

1. **Zero-hop.** `path_len = 0` when the gateway is in direct radio range. Always
   try this first; it is the cheapest and most common deployment.
2. **Advert path cache.** The gateway node advertises periodically. On
   `PUSH_CODE_ADVERT` (0x80) for the configured gateway key, query
   `CMD_GET_ADVERT_PATH` (42) and use the returned path. The firmware caches
   inbound advert paths for exactly this purpose.
3. **Trace.** `CMD_SEND_TRACE_PATH` (36) and read the path from
   `PUSH_CODE_TRACE_DATA` (0x89).

The wallet MUST cache the working path persistently and MUST record the reverse
path for the gateway's replies. The gateway learns its return path from the
`src` hash plus the observed inbound path.

If `MESHU_PATH_RETRY` (default 3) consecutive sends elicit no response, the
wallet MUST discard the cached path and re-establish it, escalating zero-hop →
advert → trace.

### 2.7 MTU derivation

Raw custom packets carry no MeshCore encryption or framing, so the on-air limit
is the full packet payload. The binding constraint is the companion BLE frame:

```c
// src/MeshCore.h
#define MAX_PACKET_PAYLOAD  184        // createRawData() accepts up to this

// src/helpers/BaseSerialInterface.h
#define MAX_FRAME_SIZE  176            // companion frame ceiling
```

For a zero-hop send, the companion frame spends 1 byte on the command and 1 on
`path_len`:

```
raw capacity (send) = min(184, 176 − 1 − 1 − path_len)
                    = 174 − path_len          (zero-hop: 174)
```

The return direction is tighter. `PUSH_CODE_RAW_DATA` (§2.5) spends 4 bytes on
its own prefix against the same `MAX_FRAME_SIZE` ceiling — the firmware buffer
is `out_frame[MAX_FRAME_SIZE + 1]`, whose guard nominally admits a 173-byte
payload, but the resulting 177-byte frame exceeds `MAX_FRAME_SIZE`, so 172 is
the largest inbound payload guaranteed to traverse the link. This bound is
independent of `path_len`, because the path travels in the MeshCore packet
header on air, not in the payload. The operative MTU is the minimum over both
directions:

```
raw capacity   = min(174 − path_len, 172)
MESHU_MTU   = raw capacity − 2        (dst ‖ src)
               = 170 bytes at zero hops
```

Each path hop beyond the second costs 1 further byte (assuming 1-byte path
hashes; MeshCore also supports 2- and 3-byte hashes, which cost proportionally
more):

| Hops | Outbound raw | Inbound raw | L1 MTU |
|---|---|---|---|
| 0 | 174 | 172 | **170** |
| 1 | 173 | 172 | 170 |
| 2 | 172 | 172 | 170 |
| 3 | 171 | 172 | 169 |
| 5 | 169 | 172 | 167 |
| 7 | 167 | 172 | **165** |
| 8 | 166 | 172 | 164 |

A gateway that sized a zero-hop reply to the send-path figure (172) would see
the frame dropped by the companion node. Implementations MUST compute the MTU
from the current `path_len` and hash size, taking the minimum over both
directions, and MUST NOT emit a frame exceeding it.

For spec-wide sizing, Meshu fixes a **conservative floor of 165 bytes**
(`MESHU_MTU_FLOOR`), which holds for paths up to **7 hops** with 1-byte
hashes. All frame counts in §8 and `TESTVECTORS.md` use this floor, so they
remain valid at any path length within that bound and improve slightly at zero
hops.

Beyond 7 hops the true MTU falls below the floor. A sender MUST then fragment
according to the real computed MTU, which yields slightly more frames than the
tables predict. A sender SHOULD prefer a shorter path when one is available;
paths that long are in any case impractical at these data rates.

### 2.8 Backpressure and duplicate suppression

`RESP_CODE_ERR` / `ERR_CODE_TABLE_FULL` (3) means the node's outbound queue is
full. The sender MUST pause, apply the airtime governor (§12), and retry the
same frame. This is not a protocol error.

> **Byte-identical retransmission is silently dropped.** Every MeshCore node
> keeps a 160-entry table of recently seen packet hashes
> (`SimpleMeshTables::hasSeen`, `MAX_PACKET_HASHES = 128+32`), and
> `Packet::calculatePacketHash()` hashes the payload bytes together with the
> payload type. A retransmitted frame whose bytes are unchanged will be
> suppressed as a duplicate by every repeater along the path.
>
> Therefore an L1 retransmission (§3.7) **MUST** differ in at least one payload
> byte. Meshu guarantees this with the 2-bit `ATTEMPT` counter in the L1
> header (§3.1), which changes the hash on every attempt. An
> implementation that resends verbatim bytes will observe its retries vanish with
> no error anywhere — a failure mode that is extremely difficult to diagnose in
> the field.

### 2.9 Alternate transports

L1, L2, and L3 are transport-agnostic: L2 seals and L3 encodes identical bytes
whatever carries them, and L1 exists only because the radio link is lossy and
MTU-bound. A deployment MAY therefore run the same protocol over a reliable
transport — for example HTTPS from the wallet to the gateway daemon when
ordinary internet is available — bypassing L1 and the airtime governor while
preserving L2, L3, and the `msg_id` idempotency and nonce semantics unchanged.
One such binding, including provisioning, browser constraints, and the wallet's
transport toggle, is specified in `POC-WALLET.md` §9.

## 3. L1 — Segmentation and Reliability

L1 turns the 165-byte datagram into a reliable, ordered byte stream for one
message. It uses **selective retransmission driven by an ACK bitmap**.

> **Why not per-chunk CRC16.** A CRC per chunk would be the fourth integrity
> check on the same bytes: LoRa already applies a hardware CRC, MeshCore adds a
> 2-byte HMAC over the group payload, and L2 adds a 16-byte Poly1305 tag over
> the whole message. A per-chunk CRC would consume ~1.2% of payload to detect
> what is already detected. L1 spends those bytes on sequencing instead, and
> relies on the L2 tag for end-to-end integrity.

### 3.1 Frame header

The header is 4 bytes for a single-frame message and 6 bytes when fragmented,
so the common case pays nothing for sequencing.

```
Byte 0:  VVKKKKKK   VV = version (2 bits, = 0b00 for v1)
                    KKKKKK = frame kind (6 bits)
Byte 1:  flags
Byte 2:  msg_id high byte
Byte 3:  msg_id low byte
--- following 2 bytes present only when flags.MULTI is set ---
Byte 4:  seq        0-based frame index
Byte 5:  last_seq   index of final frame; frame count = last_seq + 1
```

Flags:

| Bit | Mask | Name | Meaning |
|---|---|---|---|
| 0 | `0x01` | `MULTI` | Fragmented; `seq`/`last_seq` present |
| 1 | `0x02` | `REQ_ACK` | Sender requests an `ACKBM` |
| 2–3 | `0x0C` | `ATTEMPT` | Retransmission counter, 0–3, incremented per attempt |
| 4–7 | `0xF0` | — | Reserved, MUST be 0, MUST be ignored on receipt |

`ATTEMPT` is 0 on first transmission and increments on each retry, wrapping at 4.
It replaces a plain boolean retry flag for a specific reason: it perturbs the
payload bytes so that MeshCore's duplicate-suppression table does not silently
discard retransmissions (§2.8). A receiver MUST treat frames differing only in
`ATTEMPT` as the same frame and deduplicate on (`msg_id`, `seq`).

Four attempts fit the 2-bit field, matching `MESHU_MAX_RETRY` (default 4). A
sender needing more MUST bump the L2 epoch and restart with a fresh `msg_id`,
which changes the payload wholesale.

Frame kinds:

| Kind | Value | Body | Purpose |
|---|---|---|---|
| `DATA` | `0x10` | L2 payload fragment | Carries message bytes |
| `ACKBM` | `0x12` | `total` ‖ bitmap | Acknowledge with received-frame bitmap |
| `NACK` | `0x13` | `reason` | Reject message (unknown op, too large, bad epoch) |
| `ABORT` | `0x14` | `reason` | Abandon an in-progress message |
| `PING` | `0x15` | — | Liveness / path probe; peer replies `PING` |

Note the header on-wire begins `0x10` for a `DATA` frame at version 0 — version
bits are the two most significant bits and are zero in v1.

### 3.2 Payload capacity

```
Single frame:   165 − 4 = 161 bytes of L2 payload
Fragmented:     165 − 6 = 159 bytes of L2 payload per frame
```

Since L2 adds a fixed 17 bytes per message (§4.4), usable **L3** bytes are:

```
Single-frame message:  161 − 17 = 144 bytes of L3
Fragmented message:    159 × (last_seq + 1) − 17 bytes of L3
```

Maximum message size is bounded by `last_seq ≤ 254`, i.e. 255 frames, but
implementations MUST additionally enforce a configured ceiling
`MESHU_MAX_MSG` (default **40 000** bytes) and reply `NACK` to anything
larger. At 16 B/s a 40 KB message takes over 40 minutes; the ceiling exists to
make that a deliberate choice rather than an accident.

### 3.3 `msg_id`

A 16-bit identifier chosen by the **initiator** of a request. A response reuses
the request's `msg_id`. It serves three purposes simultaneously: fragment
reassembly key, ACK correlator, and **idempotency key** (§11).

Requirements:

- A wallet MUST NOT reuse a `msg_id` while a previous message with that id is
  unacknowledged or within the gateway's replay cache TTL.
- A wallet SHOULD allocate `msg_id` from a persistent monotonic counter stored
  alongside its wallet state, so that ids survive a page reload. Random
  allocation is permitted but risks collision with in-flight retries.
- `msg_id` `0x0000` is reserved and MUST NOT be used.

### 3.4 Sending

1. Encode L3 (§5), seal to L2 (§4), producing `body`.
2. If `len(body) ≤ 161`, send one `DATA` frame with `MULTI` clear.
3. Otherwise split `body` into `ceil(len/159)` fragments; send each as a `DATA`
   frame with `MULTI` set, ascending `seq`, `last_seq` = count − 1.
4. Set `REQ_ACK` on the final frame of a fragmented message. A sender SHOULD
   also set it on every 8th frame so that loss in long transfers is detected
   early rather than at the end, and MUST set it on the last frame the
   in-flight window (§12.3) permits whenever frames of the message remain
   unsent — otherwise the sender stalls with the window full, no `ACKBM`
   requested, and no retransmission timer running (§3.7).
5. Pace every transmission through the airtime governor (§12).

### 3.5 Receiving and reassembly

A receiver keeps per-`msg_id` reassembly state: the bitmap of received `seq`,
the fragment buffers, `last_seq`, and a first-seen timestamp.

- On a `DATA` frame with `MULTI` clear: the message is complete; process it.
- On a fragmented `DATA` frame: store it, set its bitmap bit. If `REQ_ACK` is
  set, reply `ACKBM`. When all bits 0..`last_seq` are set, concatenate and
  process.
- A duplicate `seq` MUST be discarded idempotently, not treated as an error.
- Inconsistent `last_seq` across frames of one `msg_id` MUST abort the message
  with `ABORT` and discard state.
- Reassembly state MUST be discarded after `MESHU_REASM_TIMEOUT`
  (default 600 s) without progress, and the receiver MUST bound concurrent
  reassemblies to `MESHU_MAX_REASM` (default 4) to cap memory. On overflow,
  evict the least recently advanced.

### 3.6 ACK bitmap

```
Byte 0:  0x12
Byte 1:  flags (0)
Byte 2:  msg_id high
Byte 3:  msg_id low
Byte 4:  total          = last_seq + 1
Byte 5+: bitmap         ceil(total / 8) bytes, LSB-first within each byte
```

Bit `i` set means frame `seq = i` was received. Bit `i` of byte `j` corresponds
to `seq = j × 8 + i`.

A 255-frame message needs a 32-byte bitmap, so an `ACKBM` always fits one frame.

### 3.7 Retransmission

On `REQ_ACK` the sender starts a timer of

```
timeout = max(MESHU_MIN_RTO, 2 × frames_in_flight × measured_airtime + 4000 ms)
```

where `measured_airtime` is the observed per-frame airtime (§12.1).
`MESHU_MIN_RTO` defaults to 15 000 ms — deliberately large, because a
multi-hop mesh with repeater scheduling delays routinely exceeds naive
expectations.

On `ACKBM`, the sender retransmits exactly the frames whose bits are clear, each
with `ATTEMPT` incremented. On timeout, it retransmits the frames not yet
known-received, likewise incrementing `ATTEMPT`. After `MESHU_MAX_RETRY`
(default 4) rounds without the bitmap advancing, it MUST give up and report
failure to the application, which MUST then use the recovery procedures of §11
rather than blindly re-sending the operation.

Incrementing `ATTEMPT` is mandatory, not cosmetic: a verbatim resend is
suppressed by every repeater's duplicate table (§2.8) and would fail silently.

Retransmission MUST be paced by the governor. A retry storm is
indistinguishable from a jammer.

### 3.8 `NACK` and `ABORT` reasons

| Value | Name | Meaning |
|---|---|---|
| `0x01` | `UNSUPPORTED_VERSION` | L1 version not understood |
| `0x02` | `MSG_TOO_LARGE` | Exceeds `MESHU_MAX_MSG` |
| `0x03` | `DECRYPT_FAILED` | L2 tag or epoch invalid |
| `0x04` | `REASM_TIMEOUT` | State expired |
| `0x05` | `BUSY` | Too many concurrent reassemblies |
| `0x06` | `MALFORMED` | L3 could not be decoded |

---

## 4. L2 — End-to-End Encryption

### 4.1 Why this is mandatory

`PAYLOAD_TYPE_RAW_CUSTOM` provides **no transport encryption and no integrity
check whatsoever** — MeshCore passes the payload through untouched (§2.4). LoRa
is a broadcast medium, so every frame is receivable by any node in radio range.

Without L2, Meshu would transmit Cashu proofs in clear over the air. Proofs
are bearer instruments: reading one is equivalent to stealing it. L2 is therefore
not optional hardening, it is the only thing making the transport usable at all,
and an implementation that omits or defers it is not Meshu.

This is also why the choice of a transport with no built-in encryption costs
nothing in practice. A MeshCore channel key would have been shared with every
member of that channel and would not have protected proofs from co-members; L2
over an unencrypted transport is strictly stronger than a shared channel key,
because the key is derived from the gateway's specific identity and shared with
no one else.

### 4.2 Key agreement

Each party holds a long-term X25519 keypair. The wallet learns the gateway's
X25519 public key out of band (QR code, config import), alongside the gateway's
32-byte MeshCore Ed25519 identity used for addressing (§2.2). These are distinct
keys serving distinct purposes; a deployment MAY derive both from one seed but
MUST NOT reuse the same key material for signing and Diffie–Hellman. The
gateway has no such channel in the reverse direction; it learns the wallet's
key from the wallet's first `HELLO` (§4.2.1).

Both parties derive:

```
shared    = X25519(own_private, peer_public)
prk       = HKDF-Extract(salt = "meshu/v1/salt", ikm = shared)
k_w2g     = HKDF-Expand(prk, "meshu/v1/w2g", 32)   # wallet → gateway
k_g2w     = HKDF-Expand(prk, "meshu/v1/g2w", 32)   # gateway → wallet
```

HKDF is HMAC-SHA256. Separate directional keys prevent reflection.

This is static-static ECDH: 0-RTT, no handshake, no round trips — essential when
a round trip costs seconds. The cost is no forward secrecy; §4.6 addresses this.

### 4.2.1 Wallet key bootstrap (TOFU)

The wallet knows the gateway's X25519 key out of band, but the gateway has no
out-of-band channel for learning wallet keys, and `PAYLOAD_TYPE_RAW_CUSTOM`
frames carry no sender identity (§2.2). The gateway therefore learns the
wallet's key from the wallet's first `HELLO`, sent in **bootstrap form** —
plaintext and unauthenticated, since the shared key does not exist yet.

- A bootstrap `HELLO` is the only Meshu message ever sent unencrypted. Its
  L2 form is the single byte `0xFF` in place of `epoch`, followed by the L3
  plaintext with no tag (§4.4).
- A gateway MUST accept bootstrap form only when the L3 opcode is `HELLO` and
  MUST discard any other bootstrap-form message. A wallet MUST discard any
  inbound bootstrap-form frame — the gateway never sends one.
- On a bootstrap `HELLO` with an unknown `wallet_pubkey`, the gateway derives
  the shared keys, **pins** `wallet_pubkey → (k_w2g, k_g2w)` durably, and
  replies with a sealed `HELLO` response. On one whose `wallet_pubkey` is
  already pinned, it replies again — replays of a bootstrap `HELLO` are
  harmless, since the response is sealed to the pinned key either way.
- A pinned key MUST NOT be replaced or modified via bootstrap. A bootstrap
  `HELLO` creates a new pairing or none; it never alters an existing one. This
  rule is what makes first-contact TOFU safe here (§1.3 T7).
- The wallet MUST NOT send any operation other than bootstrap `HELLO` until a
  sealed `HELLO` response verifies, and MUST NOT treat anything in the
  bootstrap exchange as confirmed until then. Successful verification also
  authenticates the gateway to the wallet: only the holder of the configured
  private key could produce it.
- If a wallet's sealed frames are rejected with `NACK` `DECRYPT_FAILED` — for
  example the gateway lost its pairing table — the wallet MUST fall back to a
  bootstrap `HELLO`. The wallet's L2 keypair SHOULD be derived from the wallet
  seed, so re-pairing restores the same identity and with it the gateway's
  replay-cache (§11.1) and melt-retention (§8.6) continuity. Gateways SHOULD
  persist the pairing table across restarts; losing it costs each wallet one
  bootstrap round trip and no funds.

**Identity is the key, not the hash.** All gateway state — pairings, replay
cache, melt retention — is keyed by the full 32-byte `wallet_pubkey`, never by
the 1-byte `src` hash, which belongs to the companion *node* (§2.3). AEAD
verification is the only sender authentication.

**Why this is enough.** The static-static design confines the exposure
asymmetrically. Wallet→gateway traffic is always sealed to the gateway's real,
out-of-band key, so a forged bootstrap message lets an attacker read nothing
the wallet sends — including proofs. Gateway→wallet replies are sealed to
whatever key arrived in the `HELLO`, so a forged `HELLO` yields the attacker
only responses to her own request. She cannot redirect an existing pairing
(never-replace rule) and cannot steal minted funds at all (NUT-20, §9). The
residual exposures are the plaintext key disclosure itself (T3, T7) and
resource abuse: gateways MUST bound the pairing table (`MESHU_MAX_WALLETS`,
default 64) and SHOULD rate-limit bootstrap responses per `src` hash, since a
bootstrap `HELLO` costs the attacker nothing to forge.

### 4.3 AEAD

ChaCha20-Poly1305 (RFC 8439). Chosen over AES-GCM because it needs no hardware
support and is constant-time in pure JS/WASM, which matters in a browser.

### 4.4 Sealed message layout

```
Byte 0:      epoch          key epoch (§4.6); 0xFF = bootstrap form (§4.2.1)
Bytes 1..n:  ciphertext     ChaCha20-Poly1305 encryption of the L3 message
Last 16:     tag            Poly1305 authenticator
```

Overhead is **17 bytes per message** — not per frame. A 20-frame transfer pays
17 bytes total, not 340.

**Bootstrap form.** For the single unencrypted message in the protocol
(§4.2.1), this layout is replaced entirely: byte 0 is `0xFF` and the remaining
bytes are the L3 plaintext, with no tag. It carries no secrets; everything
after it is sealed.

### 4.5 Implicit nonce

The 96-bit nonce is **never transmitted**; it is reconstructed from context:

```
nonce = epoch (1 byte) ‖ dir (1 byte) ‖ msg_id (2 bytes BE) ‖ 0x00 × 8
dir = 0x00 for wallet→gateway, 0x01 for gateway→wallet
```

Associated data binds the transport framing:

```
aad = version_byte ‖ opcode_hint ‖ dir ‖ epoch ‖ msg_id
```

where `opcode_hint` is the message's opcode — the first *element* of the L3
CBOR array (§5.2), not its first byte, which is the array header and nearly
constant across messages. This prevents an attacker replaying a sealed payload
under a different opcode.

> **Nonce reuse is catastrophic** for ChaCha20-Poly1305 — it leaks the keystream
> and allows forgery. Because the nonce derives from `msg_id`, the `msg_id`
> reuse rules of §3.3 are a **security requirement**, not merely a correctness
> one. A sender MUST NOT transmit two different plaintexts with the same
> (`epoch`, `dir`, `msg_id`) triple. Implementations SHOULD persist the last
> used `msg_id` and MUST bump `epoch` if that state is ever lost.

### 4.6 Epoch and rekeying

Valid epochs are `0x00`–`0xFE`; `0xFF` is reserved for bootstrap form (§4.2.1)
and is not an epoch. `epoch` starts at 0 and is incremented to retire the
`msg_id` space or to recover from lost sender state. A receiver MUST accept the
current epoch and current + 1 (to tolerate a peer that has rotated), MUST
reject lower epochs, and MUST reply `NACK` `DECRYPT_FAILED` on rejection.

For forward secrecy, an implementation MAY perform an ephemeral rekey by
exchanging fresh X25519 public keys inside an authenticated Meshu message and
mixing them into `prk`. This is OPTIONAL in v1 and the mechanism is reserved for
v2; implementers should not invent an incompatible one.

### 4.7 Replay protection

A receiver MUST maintain, per direction and epoch, a sliding window of accepted
`msg_id` values (default 256 entries). A `msg_id` already in the window MUST be
handled as a **retry**, returning the cached response (§11) rather than
re-executing — for `MINT` and `MELT` this is the difference between idempotence
and losing funds.

---

## 5. L3 — Message Encoding

### 5.1 Encoding choice

CBOR (RFC 8949) with two disciplines:

1. **Positional definite-length arrays, never maps.** Map keys would repeat
   field names on every message. A CBOR array of 5 items costs 1 byte of framing
   for the whole array.
2. **Packed byte strings for repetitive cryptographic material.** An array of
   6 blinded messages as CBOR structures would cost ~6 × 40 bytes of framing and
   type tags. As a single 204-byte string it costs 3 bytes of framing.

Measured against equivalent Cashu JSON, a 6-output mint request is
**292 bytes vs 1064 — a 73% reduction**, which is 2 frames instead of 7.

The hybrid is within ~2% of a hand-rolled binary format while remaining
inspectable with standard CBOR tooling and extensible without a version bump.

### 5.2 Envelope

Every L3 message is a CBOR array whose **first element is the opcode**:

```
[ opcode, field1, field2, ... ]
```

Encoding rules:

- Definite-length arrays only. Indefinite-length items MUST be rejected.
- Integers in canonical minimal form.
- Byte strings for all binary; text strings only where a Cashu field is
  genuinely human-readable text (memos, mint URLs during discovery).
- `null` for absent optional trailing fields, or omit them entirely.
- A decoder MUST ignore unknown trailing array elements. This is the forward
  compatibility mechanism: v2 appends fields, v1 decoders keep working.

### 5.3 Canonical form

Senders SHOULD emit deterministically encoded CBOR (RFC 8949 §4.2). Receivers
MUST NOT require it — because L2 authenticates the exact bytes, re-encoding is
never necessary for verification.

---

## 6. Compact Type Encodings

These encodings are where most of the savings live.

### 6.1 Amounts as exponents

Cashu denominations are always powers of two. Transmitting `1024` as a varint
costs 3 bytes; transmitting the exponent `10` costs 1.

```
amount = 1 << exponent      exponent ∈ 0..63
```

A target amount decomposes into the set bits of its binary representation:

| Amount | Exponents | Bytes |
|---|---|---|
| 1 | `[0]` | `00` |
| 8 | `[3]` | `03` |
| 1000 | `[3,5,6,7,8,9]` | `030506070809` |
| 100000 | `[5,7,9,10,15,16]` | `0507090a0f10` |

Any amount that is not a power of two MUST be rejected as an output amount.
Aggregate amounts (invoice totals, `fee_reserve`, `amount_paid`) are ordinary
CBOR integers, since they are not constrained to powers of two.

### 6.2 Quote IDs

NUT-04 and NUT-05 specify quote IDs as UUIDv7. Canonical string form is 36
bytes; the packed form is 16 — a saving of 20 bytes on every quote-bearing
message.

```
"019e6d5a-2347-7000-8322-05d51d498303"
→ 019e6d5a23477000832205d51d498303
```

The round trip is lossless. A mint is not strictly required to use UUID quote
IDs, so `quote_id` fields are typed bytes-or-text: a gateway MUST pack a
UUID-form ID to 16 bytes, and MUST pass a non-UUID ID through as a CBOR text
string instead of rejecting it. Decoders MUST accept both forms wherever
`quote_id` appears (§8.2–§8.7), and MUST NOT attempt to parse a text-form ID.

> **Critical interaction with §9:** NUT-20's `msg_to_sign` commits to the quote
> ID **as a UTF-8 string**. The wallet MUST re-expand the 16-byte form to the
> 36-character canonical lowercase form before signing. Signing the packed bytes
> produces a signature the mint will reject.

### 6.3 BOLT11 invoices via bech32 repacking

A BOLT11 invoice is bech32: every character after the separator carries exactly
5 bits. Transmitting it as ASCII wastes 3 bits per character. Repacking to 5-bit
groups saves **31–37%**, more for longer invoices.

Wire form:

```
hrp        text string    e.g. "lnbc100n" — the part before the final "1"
nvals      uint           number of 5-bit data characters
packed     byte string    ceil(nvals × 5 / 8) bytes, big-endian bit order
```

| Invoice chars | Packed | Wire total | Saving |
|---|---|---|---|
| 267 | 162 | 173 | 35.2% |
| 300 | 182 | 193 | 35.7% |
| 500 | 307 | 318 | 36.4% |
| 700 | 432 | 443 | 36.7% |

The transform is a pure bit repack — no checksum recomputation, no semantic
parsing. It is exactly reversible, and implementations MUST verify round-trip
equality before transmitting. The trailing pad bits MUST be zero.

Because the reconstruction is exact, the bech32 checksum still validates at the
far end, which gives a free integrity check on the invoice.

### 6.4 Keyset IDs

Keyset IDs V2 are 33 bytes (`0x01` ‖ SHA-256), 66 characters as hex. Meshu
never transmits the hex form, and avoids the 33-byte form on the hot path via
two mechanisms:

- **Short keyset ID (8 bytes).** NUT-00 defines `s_id = id_bytes[:8]`. Wallets
  MUST support resolving short to full, and MUST fail on ambiguity.
- **Keyset handle (1 byte).** Negotiated in `KEYSETS` (§8.10). A per-session
  index into the gateway's advertised keyset list. Used in `MINT`, `MELT`,
  `SWAP`, `RESTORE`.

A handle is valid only for the current session and MUST be invalidated on epoch
change or gateway restart. On an unrecognised handle a gateway MUST reply
`ERROR` `MC_STALE_HANDLE` (§10) and the wallet MUST re-run `KEYSETS`.

### 6.5 Mint handles

Mint URLs are ~20–40 bytes. `HELLO` (§8.1) advertises the gateway's mints as a
list; subsequent messages reference a **1-byte index**. Same invalidation rules
as keyset handles.

### 6.6 Units

| Value | Unit |
|---|---|
| `0` | `sat` |
| `1` | `msat` |
| `2` | `usd` |
| `3` | `eur` |
| `4` | `btc` |
| `0x80`+ | text string follows, for unknown units |

### 6.7 Packed blob formats

**Outputs blob** — `n × 34` bytes:

```
per output:  exponent (1 byte)  ‖  B_ (33 bytes compressed secp256k1)
```

The keyset ID is *not* repeated per output; it is carried once as a handle. This
is valid because a single Cashu operation's outputs all belong to one keyset.

**Signatures blob** — `n × 33` bytes:

```
per signature:  C_ (33 bytes)
```

Amounts and keyset are implied positionally by the request's outputs, per NUT-04
which returns signatures corresponding to the submitted outputs.

**Proofs blob** — `n × 66` bytes:

```
per proof:  exponent (1 byte)  ‖  secret (32 bytes)  ‖  C (33 bytes)
```

Secrets MUST be exactly 32 bytes in this blob. A wallet using NUT-10
well-known secrets (P2PK, HTLC) or any non-32-byte secret MUST use the
extended proof list form (§8.6.1) instead.

**Y blob** — `n × 33` bytes, for `CHECKSTATE`.

**Keys blob** — `64 × 33` bytes. Amounts are implicit: entry `i` is the public
key for amount `2^i`. This is the largest single response in the protocol at
2127 bytes / 14 frames, and is why §8.11 makes it cacheable and range-requestable.

---

## 7. Operation Codes

Requests are `0x00`–`0x7F`; the matching response is `0x80 | request`.

| Op | Request | Response | Purpose | NUT |
|---|---|---|---|---|
| `0x01` | `MINT_QUOTE` | `0x81` | Request an invoice to mint against | 04, 23 |
| `0x02` | `MINT_QUOTE_STATE` | `0x82` | Poll whether the invoice was paid | 04 |
| `0x03` | `MINT` | `0x83` | Exchange a paid quote for signatures | 04, 20 |
| `0x04` | `MELT_QUOTE` | `0x84` | Price a BOLT11 payment | 05, 23 |
| `0x05` | `MELT` | `0x85` | Spend proofs to pay an invoice | 05, 08 |
| `0x06` | `MELT_QUOTE_STATE` | `0x86` | Poll melt outcome | 05 |
| `0x07` | `RESTORE` | `0x87` | Recover signatures from seed | 09, 13 |
| `0x08` | `SWAP` | `0x88` | Exchange proofs for new proofs | 03 |
| `0x09` | `CHECKSTATE` | `0x89` | Query proof spent/pending state | 07 |
| `0x0A` | `KEYSETS` | `0x8A` | List keysets, establish handles | 02 |
| `0x0B` | `KEYS` | `0x8B` | Fetch public keys for a keyset | 01 |
| `0x0C` | `MINT_INFO` | `0x8C` | Mint capabilities and limits | 06 |
| `0x0D` | `HELLO` | `0x8D` | Session setup, mint handles | — |
| — | — | `0xFE` `ERROR` | Error response to any request | — |

`SWAP` and `CHECKSTATE` are not optional conveniences. Without `SWAP` the wallet
cannot redeem a token received from another wallet and cannot manage its
denomination mix. Without `CHECKSTATE` an interrupted melt is unrecoverable and
funds can be silently lost.

---

## 8. Operation Wire Formats

Sizes below are **measured** by encoding the actual CBOR, not estimated. "Frames"
includes L1 and L2 overhead. Airtime assumes MeshCore's default SF8/BW62.5 at
~1.03 s per frame.

### 8.1 `HELLO` / `0x8D`

```
req:  [ 0x0D, l1_version, wallet_pubkey, [supported_ops...] ]
resp: [ 0x8D, l1_version, gateway_pubkey, [mint_urls...],
        [nut19_cached_paths...], max_msg, server_time ]
```

41 bytes, 1 frame. Establishes mint handles by list position, exchanges
capabilities, and lets the wallet learn which endpoints the mint caches per
NUT-19 (§11.3). `server_time` allows the wallet to sanity-check quote expiries
without a trusted local clock.

`wallet_pubkey` is the wallet's 32-byte X25519 key (§4.2), not the companion
node's Ed25519 identity. A wallet's first `HELLO` to a gateway is sent in
bootstrap form (§4.2.1); the response and every later `HELLO` are sealed. In a
sealed `HELLO`, `wallet_pubkey` MUST equal the identity the frame verified
under; a gateway MUST treat a mismatch as `MC_MALFORMED`.

A wallet SHOULD issue `HELLO` on first contact and after any epoch change,
MUST NOT send any other operation before the sealed response verifies, and MUST
treat all handles as invalid until it completes.

### 8.2 `MINT_QUOTE` / `0x81`

```
req:  [ 0x01, mint_handle, amount, unit, quote_pubkey, description? ]
resp: [ 0x81, quote_id, hrp, nvals, packed_invoice,
        expiry, amount_paid, amount_issued, updated_at ]
```

| | Size | Frames |
|---|---|---|
| Request | 42 B | 1 |
| Response (300-char invoice) | 228 B | 2 |

`quote_pubkey` is 33 bytes and is **MANDATORY** (§9). A gateway MUST reject a
`MINT_QUOTE` without it.

The response carries NUT-04's current accounting fields. The deprecated `state`
enum is not transmitted.

### 8.3 `MINT_QUOTE_STATE` / `0x82`

```
req:  [ 0x02, quote_id ]
resp: [ 0x82, amount_paid, amount_issued, updated_at, expiry ]
```

~20 B request, ~14 B response — both 1 frame. This is the polling hot path, so
it is kept minimal.

Wallets MUST use `amount_paid`/`amount_issued` rather than the deprecated
`state`, and MUST NOT overwrite local quote state with a response whose
`updated_at` is lower than the highest already seen (NUT-04 requires this
monotonicity guard).

The mintable amount is `amount_paid − amount_issued`.

Polling MUST respect §12.4 backoff. A wallet SHOULD NOT poll faster than every
60 s at default radio settings; the user pays the invoice out of band and human
timescales dominate.

### 8.4 `MINT` / `0x83`

```
req:  [ 0x03, quote_id, keyset_handle, outputs_blob, signature ]
resp: [ 0x83, signatures_blob ]
```

`signature` is the 64-byte BIP-340 signature of §9. `outputs_blob` is §6.7.

| Amount | Outputs | Request | Frames | Airtime |
|---|---|---|---|---|
| 1 | 1 | 122 B | 1 | 1.0 s |
| 1 000 | 6 | 292 B | 2 | 2.0 s |
| 255 | 8 | 361 B | 3 | 3.1 s |
| 16 777 215 | 24 | 905 B | 6 | 6.1 s |

Response for 6 outputs: 203 B, 2 frames.

Because output count drives cost, wallets SHOULD prefer amounts with low
Hamming weight when the user has latitude — `1024` needs 1 output where `1023`
needs 10.

`MINT` is the most dangerous operation to retry blindly; see §11.

### 8.5 `MELT_QUOTE` / `0x84`

```
req:  [ 0x04, mint_handle, hrp, nvals, packed_invoice, unit, amount_msat? ]
resp: [ 0x84, quote_id, amount, fee_reserve, state, expiry ]
```

Request with a 300-char invoice: 200 B, 2 frames. Response: 28 B, 1 frame.

`amount_msat` is present only for NUT-23 amountless invoices.

The wallet MUST provide proofs totalling at least
`amount + fee_reserve + input_fees`, where `input_fees` derives from
`input_fee_ppk` per NUT-02: `fees = ceil(sum(input_fee_ppk) / 1000)`.

### 8.6 `MELT` / `0x85`

```
req:  [ 0x05, quote_id, keyset_handle, inputs_blob, change_outputs_blob? ]
resp: [ 0x85, state, payment_preimage?, change_blob? ]
```

| Inputs | Request | Frames | Airtime |
|---|---|---|---|
| 3 | 495 B | 4 | 4.1 s |
| 8 | 826 B | 6 | 6.1 s |
| 16 | 1354 B | 9 | 9.2 s |

**Asynchronous execution is MANDATORY.** NUT-05 states that a synchronous melt
blocks until the Lightning payment resolves, and instructs clients to *"use no
(or a very long) timeout"*. That is impossible to hold across a LoRa link with
minute-scale latencies and BLE disconnections.

Therefore:

- The gateway MUST send `prefer_async: true` to the mint.
- The gateway MUST return promptly with `state = PENDING`.
- The wallet MUST poll `MELT_QUOTE_STATE` (§8.7) for the outcome.
- The gateway MUST retain the melt outcome for at least
  `MESHU_MELT_RETENTION` (default 24 h) so a wallet that goes offline can
  still learn it.

`change_outputs_blob` requests NUT-08 change for overpaid fee reserve. Wallets
SHOULD include it; unclaimed fee reserve is a real loss.

#### 8.6.1 Extended proof list

When a proof's secret is not exactly 32 bytes — NUT-10 well-known secrets, NUT-11
P2PK, NUT-14 HTLC — the packed blob cannot represent it. Such requests MUST use:

```
inputs_ext: [ [ exponent, secret_bytes, C, witness? ], ... ]
```

as a trailing field, with `inputs_blob` empty. This costs roughly 12 bytes of
CBOR framing per proof and SHOULD be avoided when plain 32-byte secrets suffice.

### 8.7 `MELT_QUOTE_STATE` / `0x86`

```
req:  [ 0x06, quote_id ]
resp: [ 0x86, state, payment_preimage?, change_blob? ]
```

`state`: `0` = `UNPAID`, `1` = `PENDING`, `2` = `PAID`.

A wallet MUST NOT treat `UNPAID` after a submitted melt as "safe to respend"
until it has confirmed via `CHECKSTATE` that its inputs are `UNSPENT`. NUT-07
exists precisely for this reconciliation.

### 8.8 `RESTORE` / `0x87`

NUT-09 restore is the heaviest operation. The wallet regenerates deterministic
blinded messages from its seed (NUT-13) and asks the mint which it has already
signed. Scanning is inherently speculative, so most probed outputs are misses.

```
req:  [ 0x07, keyset_handle, counter_start, count, outputs_blob ]
resp: [ 0x87, hit_bitmap, signatures_blob ]
```

`hit_bitmap` is `ceil(count / 8)` bytes, bit `i` set meaning counter
`counter_start + i` was signed. `signatures_blob` contains 33-byte `C_` values
for the set bits only, in ascending counter order. The bitmap makes the
correspondence unambiguous without echoing the outputs back, which is what
NUT-09's `outputs` response field would otherwise cost.

> **The request dominates, and this is unavoidable.** Each probed output is
> 34 bytes of blinded message, so a 100-counter batch is a ~3.5 KB / 22-frame
> *upload* no matter what the mint replies. The wallet cannot delegate derivation
> to the gateway, because deriving outputs requires the wallet seed and handing
> that over would surrender the entire wallet. An earlier draft of this spec used
> a two-phase probe to shrink the response; it was removed because it added a
> full round trip while the request cost stayed identical — strictly worse. The
> bitmap keeps the *response* minimal, which is all that is achievable here.

Per-batch cost, single round trip:

| Batch | Request | Resp (0 hits) | Resp (all hit) | Round trip, 0 hits |
|---|---|---|---|---|
| 10 | 383 B / 3 fr | 28 B / 1 fr | 384 B / 3 fr | 4 frames / ~4 s |
| 25 | 912 B / 6 fr | 30 B / 1 fr | 914 B / 6 fr | 7 frames / ~7 s |
| 50 | 1792 B / 11 fr | 33 B / 1 fr | 1797 B / 11 fr | 12 frames / ~12 s |
| 100 | 3558 B / 22 fr | 39 B / 1 fr | 3569 B / 22 fr | 23 frames / ~24 s |

Request sizes are ±1 byte depending on the CBOR width of `counter_start`
(1-byte encoding below 24, 2-byte below 256): the batch-10 row assumes the
former, the 25–100 rows the latter.

An all-miss batch of 100 returns **39 bytes in 1 frame** rather than the
~3.5 KB / 22 frames that echoing outputs and signatures would require.

**Batch sizing.** Because the fixed request cost dominates, *larger batches are
cheaper per counter scanned*. Scanning 200 counters that are all empty:

| Batch | Batches | Total frames | Airtime |
|---|---|---|---|
| 10 | 20 | 80 | ~82 s |
| 25 | 8 | 56 | ~57 s |
| 50 | 4 | 48 | ~49 s |
| 100 | 2 | 46 | ~47 s |

Wallets SHOULD use a batch size of 50–100. NUT-13 conventionally uses 100, which
is also near-optimal here. Smaller batches only make sense when
`MESHU_MAX_MSG` or reassembly memory forces them.

For comparison, the same 100-output restore in Cashu JSON is 16 713 bytes /
106 frames / ~109 s in the request direction alone.

Wallets MUST follow NUT-13 gap-limit semantics: continue scanning while any
batch yields hits, stop after a configured number of consecutive empty batches
(default 3), and advance the per-keyset counter past the highest hit found.

Because restore is read-only and idempotent, any batch may be safely retried.

Derivation is keyset-version dependent (NUT-13): HMAC-SHA256 for V2 keysets
(`01…`), legacy BIP32 for V1 (`00…`).

### 8.9 `CHECKSTATE` / `0x89`

```
req:  [ 0x09, y_blob ]
resp: [ 0x89, packed_states ]
```

`packed_states` is 2 bits per proof, in request order, LSB-first:
`0` = `UNSPENT`, `1` = `PENDING`, `2` = `SPENT`.

| Proofs | Request | Response |
|---|---|---|
| 10 | 335 B / 3 frames | 7 B / 1 frame |
| 50 | 1655 B / 11 frames | 17 B / 1 frame |

The request dominates because each `Y` is a 33-byte curve point
(`hash_to_curve(secret)`), which cannot be compressed further. Wallets SHOULD
check only proofs whose state is genuinely uncertain.

If any proof carries a witness the wallet needs, it MUST use the extended form
with an explicit witness array, since witnesses do not fit the 2-bit encoding.

### 8.10 `KEYSETS` / `0x8A`

```
req:  [ 0x0A, mint_handle ]
resp: [ 0x8A, [ [ s_id, unit, active, input_fee_ppk, final_expiry ], ... ] ]
```

49 B for 3 keysets, 1 frame. Response order defines the **keyset handles** used
elsewhere: handle `i` is entry `i`.

Wallets MUST honour `active` (only active keysets may receive new outputs),
MUST apply `input_fee_ppk` when balancing transactions, and SHOULD prioritise
spending proofs from inactive keysets.

### 8.11 `KEYS` / `0x8B`

```
req:  [ 0x0B, keyset_handle, from_exp?, to_exp? ]
resp: [ 0x8B, s_id, keys_blob ]
```

A full 64-key response is 2127 B / 14 frames / ~14.3 s — the largest routine
transfer in the protocol.

Mitigations, both normative:

- Wallets MUST cache keys persistently, keyed by full keyset ID. Keys for a
  keyset never change, so this is a once-per-keyset cost.
- Wallets SHOULD range-request with `from_exp`/`to_exp`, fetching only the
  exponents they will actually use. A wallet handling amounts below 65 536 needs
  exponents 0–16, which is 17 keys / 578 B / 4 frames.

Wallets SHOULD verify the keyset ID by recomputing it from the received keys per
NUT-02, which detects a gateway substituting its own keys. A wallet that skips
this check trusts the gateway with its ecash validity.

### 8.12 `MINT_INFO` / `0x8C`

```
req:  [ 0x0C, mint_handle ]
resp: [ 0x8C, name?, [ nut_numbers... ], min_amount, max_amount,
        [ method_unit_pairs... ], nut19_ttl? ]
```

A gateway MUST NOT forward the mint's full NUT-06 document — it is JSON with
long descriptions and icon URLs, easily several kilobytes. It MUST project only
the fields above.

### 8.13 `SWAP` / `0x88`

```
req:  [ 0x08, keyset_handle, inputs_blob, outputs_blob ]
resp: [ 0x88, signatures_blob ]
```

`inputs_blob` and `outputs_blob` are §6.7; the response's signatures correspond
positionally to the request's outputs, as in `MINT`. The operation MUST balance
exactly per NUT-02: `sum(inputs) = sum(outputs) + input_fees`, with
`input_fees = ceil(sum(input_fee_ppk) / 1000)` (error `11005` otherwise).

| Inputs | Outputs | Request | Frames | Airtime |
|---|---|---|---|---|
| 3 | 8 | 478 B | 4 | 4.1 s |
| 8 | 8 | 809 B | 6 | 6.1 s |

When an input's secret is not exactly 32 bytes (NUT-10/11/14), the request MUST
use the extended proof list form of §8.6.1: `inputs_ext` as a trailing field,
with `inputs_blob` empty.

`SWAP` is state-changing: it MUST be retried with the identical `msg_id` and
identical payload bytes (§11.2), and an interrupted swap is recovered per §11.4
— retry identical, and on `11003` use `RESTORE` at the same counters.

Wallets use `SWAP` to redeem tokens received from other wallets and to manage
their denomination mix (§7). As with `MELT`, the inputs are exposed to the
gateway (T2); wallets SHOULD swap only the proofs the operation needs.

### 8.14 `ERROR` / `0xFE`

```
resp: [ 0xFE, code, detail_kind, detail? ]
```

See §10.

---

## 9. Mandatory NUT-20 Profile

### 9.1 Requirement

Per T1 (§1.3), every mint quote MUST be locked to a wallet-held key.

- The wallet MUST include a 33-byte compressed secp256k1 `quote_pubkey` in
  every `MINT_QUOTE`.
- The gateway MUST forward it as NUT-20 `pubkey` and MUST reject a request
  lacking it.
- The wallet MUST include a valid 64-byte BIP-340 signature in every `MINT`.
- The gateway MUST reject an unsigned `MINT` for a locked quote rather than
  forwarding it.

### 9.2 Message construction

Per NUT-20, with `len32(x)` a 4-byte big-endian length:

```
msg_to_sign = "Cashu_MintQuoteSig_v1"                  (ASCII, not length-prefixed)
              ‖ len32(quote) ‖ quote                    (quote as UTF-8 STRING)
              ‖ for each output i, in request order:
                    len32(amount_i) ‖ amount_i          (minimal big-endian)
                  ‖ len32(B_i)      ‖ B_i               (33 raw bytes)
```

Then sign `SHA256(msg_to_sign)` with BIP-340 Schnorr.

Three traps, each of which produces a mint-side rejection:

1. **`quote` is the 36-character UTF-8 string**, not the 16-byte packed UUID of
   §6.2. Re-expand before signing. If the quote ID arrived in text form (§6.2),
   sign that string verbatim.
2. **`amount_i` is minimal big-endian**, so `0` is the empty string, `1` is
   `0x01`, `256` is `0x0100`. Expand the exponent to the amount first.
3. **Output order must match the request exactly** — the same order as
   `outputs_blob`.

A worked vector is in `TESTVECTORS.md`.

### 9.3 Key derivation

The quote keypair SHOULD be derived deterministically from the wallet seed so
that locked quotes remain claimable after a restore. NUT-20 notes this
explicitly. A wallet that generates a random quote key and loses it before
minting forfeits the funds even though the invoice was paid.

---

## 10. Errors

### 10.1 Format

```
[ 0xFE, code, detail_kind, detail? ]
```

`detail_kind`: `0` = none, `1` = text string, `2` = byte string. Gateways SHOULD
send `0` on the radio path — human-readable detail is a luxury at 16 B/s. A bare
error is 7 bytes.

### 10.2 Cashu error codes

Forwarded numerically from the mint per Cashu `error_codes.md`. Wallets MUST
handle at minimum:

| Code | Meaning | Wallet action |
|---|---|---|
| 10001 | Proof verification failed | Do not retry; proofs invalid |
| 11001 | Proofs already spent | Mark spent; reconcile |
| 11002 | Proofs are pending | Wait; poll `CHECKSTATE` |
| 11003 | Outputs already signed | **Retry with same outputs** to recover signatures, or `RESTORE` |
| 11004 | Outputs are pending | Wait and retry |
| 11005 | Transaction not balanced | Recompute fees per NUT-02 |
| 11006 | Amount outside limit range | Respect `MINT_INFO` bounds |
| 11007 | Duplicate inputs | Bug; do not retry |
| 11008 | Duplicate outputs | Bug; regenerate with fresh counters |
| 11009/11010 | Unit mismatch | Bug in keyset selection |
| 11011 | Amountless invoice unsupported | Fall back |
| 11012 | Amount does not equal invoice | Recompute |
| 11013 | Unit not supported | Choose another keyset |
| 11014/11015 | Max inputs/outputs exceeded | Split operation |
| 12001 | Keyset unknown | Re-run `KEYSETS` |
| 12002 | Keyset inactive | Select an active keyset |
| 12003 | Keyset expired | Migrate balance |
| 20001 | Quote not paid | Keep polling |
| 20002 | Quote already issued | Already minted; `RESTORE` to recover |
| 20003 | Minting disabled | Abort |
| 20004 | Lightning payment failed | Inputs should be unspent; verify |
| 20005 | Quote pending | Poll |
| 20006 | Invoice already paid | Abort |
| 20007 | Quote expired | Abort; request new quote |
| 20008 | Mint signature invalid | Bug in §9; do not retry unchanged |
| 20009 | Pubkey required | Bug; §9 violated |
| 30001–31004 | Auth required/failed (NUT-21/22) | Out of scope in v1 |

Code `11003` deserves emphasis: it means the mint already signed these outputs.
Retrying the identical request — ideally against a NUT-19 cached endpoint — is
how the wallet recovers signatures it lost in transit. Treating it as fatal
loses funds.

### 10.3 Meshu transport codes

Allocated at `0xF0xx` to avoid collision with Cashu's numeric space:

| Code | Name | Meaning |
|---|---|---|
| `0xF001` | `MC_UNSUPPORTED_OP` | Opcode unknown to gateway |
| `0xF002` | `MC_MALFORMED` | L3 decode failure |
| `0xF003` | `MC_STALE_HANDLE` | Mint or keyset handle invalid; re-run `HELLO`/`KEYSETS` |
| `0xF004` | `MC_MINT_UNREACHABLE` | Gateway could not reach the mint |
| `0xF005` | `MC_MINT_TIMEOUT` | Mint did not respond in time |
| `0xF006` | `MC_RATE_LIMITED` | Gateway airtime budget exhausted; back off |
| `0xF007` | `MC_TOO_LARGE` | Response exceeds `MESHU_MAX_MSG` |
| `0xF008` | `MC_NOT_PERMITTED` | Gateway policy refusal |
| `0xF009` | `MC_MINT_HTTP_ERROR` | Non-conforming mint response |
| `0xF00A` | `MC_INTERNAL` | Gateway fault |

`MC_MINT_UNREACHABLE` and `MC_MINT_TIMEOUT` are explicitly **indeterminate** for
`MINT` and `MELT`: the operation may or may not have executed. The wallet MUST
resolve via §11, never by assuming failure.

### 10.4 MeshCore errors

Companion-layer `ERR_CODE_*` values (`1` unsupported cmd, `2` not found,
`3` table full, `4` bad state, `5` file I/O, `6` illegal arg) are local BLE
conditions, not protocol errors. They MUST be surfaced distinctly in logs, since
confusing "my radio is busy" with "the mint rejected my proofs" leads to exactly
the wrong recovery action.

---

## 11. Idempotency and Recovery

At 16 B/s with multi-minute operations, **interruption is the normal case**. This
section is the most safety-critical part of the specification.

### 11.1 Gateway replay cache

A gateway MUST maintain a cache keyed by
`(wallet_pubkey, epoch, msg_id, hash(plaintext_L3))`.

- On a cache hit, the gateway MUST return the stored response and MUST NOT
  re-execute the mint call.
- On a hit where the payload hash differs for the same `msg_id`, the gateway
  MUST reply `MC_MALFORMED` — this is either a bug or an attack, and executing
  it could double-spend.
- Entries MUST be retained at least `MESHU_CACHE_TTL` (default 24 h) for
  `MINT`, `MELT`, and `SWAP`. Other operations MAY use a shorter TTL.
- The cache MUST survive gateway restart for `MINT`/`MELT`/`SWAP`. An in-memory
  cache lost on restart converts a safe retry into a potential double-spend.

### 11.2 Wallet obligations

A wallet MUST persist its intent **before** transmitting a state-changing
operation, recording `msg_id`, the operation, and all outputs or inputs. It MUST
retry with the **identical** `msg_id` and identical payload bytes. Re-deriving
fresh outputs for a retry is the single most common way to lose funds in Cashu.

### 11.3 NUT-19 interaction

NUT-19 defines mint-side response caching, keyed on method, path, and payload.
It composes with §11.1: Meshu's cache protects the radio hop, NUT-19 protects
the HTTP hop.

A gateway SHOULD read `19.cached_endpoints` from mint info and report it in
`HELLO`. When an endpoint is NUT-19-cached, the gateway MAY safely replay to the
mint after an indeterminate failure. When it is not, the gateway MUST prefer the
state-query recovery paths below.

### 11.4 Recovery matrix

| Interrupted at | Risk | Recovery |
|---|---|---|
| `MINT_QUOTE` sent, no response | None — no funds committed | Retry; a duplicate quote merely expires unpaid |
| Invoice paid, `MINT` not sent | Funds held by mint | `MINT_QUOTE_STATE`; mint when `amount_paid > amount_issued` |
| `MINT` sent, response lost | **Signatures may exist but be unknown** | Retry identical `msg_id`. On `11003`, use `RESTORE` at the counters used |
| `MELT` sent, response lost | **Proofs may be spent** | `MELT_QUOTE_STATE`, then `CHECKSTATE` on inputs. `SPENT` + `PAID` = success; `UNSPENT` = safe to reuse; `PENDING` = wait |
| `SWAP` sent, response lost | Inputs may be spent | Retry identical. On `11003`, `RESTORE` |
| `RESTORE` interrupted | None — read-only | Retry any batch |

A wallet MUST NOT delete a proof merely because a melt appeared to succeed; it
MUST confirm `SPENT` via `CHECKSTATE` first. Conversely it MUST NOT respend a
proof after an indeterminate melt until confirmed `UNSPENT`.

### 11.5 Deterministic outputs

Wallets MUST use NUT-13 deterministic derivation for all outputs, so that a lost
response is recoverable via `RESTORE`. Random blinding factors make the funds
unrecoverable if the response is lost — over LoRa, that is a question of when,
not if.

The wallet MUST persist its per-keyset counter **before** transmitting, and MUST
NOT reuse counters. Reuse produces `11008` at best and unspendable output
collisions at worst.

---

## 12. Airtime Governance

### 12.1 Airtime reality

Time-on-air for a 181-byte raw packet, computed with the Semtech LoRa formula
(explicit header, CR 4/5, 8-symbol preamble, CRC on):

| Preset | Airtime | Raw rate | Sustained @10% duty |
|---|---|---|---|
| SF7 / BW250 | 146 ms | 1130 B/s | **113 B/s** |
| SF8 / BW62.5 — *MeshCore default* | **1025 ms** | 161 B/s | **16 B/s** |
| SF10 / BW250 | 841 ms | 196 B/s | 20 B/s |
| SF11 / BW250 | 1681 ms | 98 B/s | 10 B/s |
| SF12 / BW125 | 6070 ms | 27 B/s | 3 B/s |

MeshCore's shipped default is SF8/BW62.5 (`platformio.ini`:
`LORA_BW=62.5`, `LORA_SF=8`). Implementations MUST NOT assume better.

A wallet SHOULD read actual radio parameters from `RESP_CODE_SELF_INFO` (bytes
48–57: frequency, bandwidth, spreading factor, coding rate) and compute the real
airtime rather than hardcoding, then use it for the timers in §3.7.

Each repeater hop **retransmits** the packet, so a 3-hop path multiplies mesh
airtime consumption by ~3 even though the sender's own duty cycle is unchanged.
Direct routing (§2.6) is the main lever.

### 12.2 Duty cycle

In EU 863–870 MHz, MeshCore's default 869.618 MHz sits in a **10% duty cycle**
sub-band. Regional limits differ and are the operator's legal responsibility.

Implementations MUST provide a configurable duty-cycle limiter, default 10%, and
MUST NOT exceed it. A single 40 KB transfer at SF8 would otherwise occupy the
channel for over 4 minutes of pure transmit time.

### 12.3 Token bucket

Both wallet and gateway MUST implement a token bucket over transmit airtime:

- Capacity: `MESHU_BURST` (default 5 frames)
- Refill: `duty_cycle_fraction × elapsed_time`
- A frame is sent only when the bucket covers its airtime

Additionally, in-flight `DATA` frames per message MUST be capped at
`MESHU_WINDOW` (default **6**). Because Meshu uses direct addressing there
is no inbound offline queue to overrun (§2.5); the window instead bounds the
receiver's outbound BLE notification burst and limits how much work is lost when
a single frame goes missing. A larger window increases goodput on a clean link
and increases retransmission cost on a lossy one. A sender that fills the window
with frames of the message still unsent MUST have requested an `ACKBM` on the
last in-flight frame (§3.4) — the window and the `REQ_ACK` cadence are only
safe in combination.

Senders MUST also respect `ERR_CODE_TABLE_FULL` (§2.8) as the authoritative
signal that the node's transmit queue is saturated, regardless of what the local
token bucket permits.

### 12.4 Polling backoff

`MINT_QUOTE_STATE` and `MELT_QUOTE_STATE` are the only polling operations and
MUST use exponential backoff with jitter:

```
interval(n) = min(MESHU_POLL_MAX, MESHU_POLL_BASE × 2^n) ± 20% jitter
```

Defaults: base 60 s, max 900 s. Jitter is required — without it, multiple
wallets synchronise into repeated collisions.

Gateways SHOULD reply `MC_RATE_LIMITED` to over-eager pollers, and wallets MUST
treat it as a signal to increase backoff, not to retry.

### 12.5 Worked latency

At SF8/BW62.5, one frame per ~1.03 s plus mesh scheduling delay:

| Operation | Frames | Airtime | Realistic wall-clock |
|---|---|---|---|
| `MINT_QUOTE` round trip | 3 | ~3 s | 10–30 s |
| `MINT` 1000 sat round trip | 4 | ~4 s | 15–45 s |
| `MELT` 8 inputs, submit | 6 | ~6 s | 20–60 s + Lightning |
| `KEYS` full 64 keys | 14 | ~14 s | 1–3 min |
| `RESTORE` batch, all miss | 2 | ~2 s | 10–20 s |
| `RESTORE` batch, all hit | 23 | ~24 s | 2–5 min |
| Full restore scan, 5 batches mostly empty | ~30 | ~31 s | 3–8 min |

Wall-clock exceeds airtime because of repeater scheduling delays, duty-cycle
pauses, BLE polling intervals, and the mint's own HTTP latency. Implementations
MUST present operations as asynchronous jobs with progress, never as blocking
calls, and MUST survive the PWA being backgrounded mid-operation.

---

## 13. Versioning and Extension

### 13.1 L1 version

Two bits in byte 0. v1 is `0b00`. A receiver seeing an unknown version MUST
reply `NACK` `UNSUPPORTED_VERSION` and discard.

### 13.2 L3 extension

Backward-compatible changes:

- Appending array elements to an existing message (decoders ignore unknown
  trailing elements, §5.2).
- New opcodes (unknown opcode → `MC_UNSUPPORTED_OP`).
- New error codes (unknown code → generic failure, log the number).

Breaking changes — reordering, retyping, or removing fields — require an L1
version bump.

### 13.3 Capability negotiation

`HELLO` exchanges supported opcode lists. A wallet MUST NOT send an operation the
gateway did not advertise. This allows a minimal gateway (mint/melt only) to
interoperate with a full wallet.

### 13.4 Reserved

- L1 frame kinds `0x00`–`0x0F` and `0x16`–`0x3F`
- L1 flag bits 4–7
- Opcodes `0x0E`–`0x7F`
- Error codes `0xF0xx` not listed in §10.3
- L2 epoch value `0xFF` (bootstrap form, §4.2.1)
- L2 epoch semantics beyond monotonic increment (for v2 ephemeral rekey, §4.6)

---

## Appendix A: Transport Alternatives Considered

Five MeshCore facilities can in principle carry arbitrary binary data to a peer.
The choice materially affects both security posture and architecture, so the
reasoning and the measured limits are recorded here. All figures derive from the
firmware guards cited in Appendix C.

| | `RAW_CUSTOM` **(chosen)** | `GRP_DATA` | `REQ` | `ANON_REQ` | `TXT_MSG` |
|---|---|---|---|---|---|
| Companion send cmd | `CMD_SEND_RAW_DATA` (25) | `CMD_SEND_CHANNEL_DATA` (62) | `CMD_SEND_BINARY_REQ` (50) | `CMD_SEND_ANON_REQ` (57) | `CMD_SEND_TXT_MSG` (2) |
| Wire payload type | `0x0F` | `0x06` | `0x00` | `0x07` | `0x02` |
| Usable app bytes | **172** send / 170 recv (zero-hop) | 165 | 164 | 132 | 160 |
| Addressing | node identity | shared channel | node identity | node identity | node identity |
| Shared secret with third parties | **none** | **channel key** | none | none | none |
| Stock firmware can send | yes | yes | yes | yes | yes |
| Stock firmware can receive | **yes** | yes | **no** | **no** | yes |
| Binary-safe | **yes** | yes | yes | yes | **no** |
| Multi-hop along known path | **yes** | yes | yes | yes | yes |
| Flood-routable (discovery) | **no** | yes | yes | yes | yes |
| Survives BLE disconnect | **no** | yes (16 frames) | no | no | yes |
| Concurrent requests | unlimited | unlimited | **1** | **1** | unlimited |
| Transport encryption | none | channel key | per-contact ECDH | ephemeral ECDH | per-contact ECDH |

**`RAW_CUSTOM` was chosen.** It addresses the gateway directly by identity,
requires no secret shared with anyone but the gateway, is symmetric on stock
firmware in both directions, and offers the largest payload of any option. Its
lack of transport encryption is immaterial because L2 (§4) is mandatory and
provides stronger guarantees than a channel key would; arguably it is an
advantage, since a channel key offers false comfort while being known to every
channel member.

Its two genuine costs are accepted and mitigated in the body of this spec:

- **No offline queue** (§2.5). Inbound frames are dropped while BLE is
  disconnected. Mitigated by making the §11 recovery procedures mandatory, so
  every operation is resumable from a state query.
- **No flood routing** (§2.6), so a path must be established first. Mitigated by
  the zero-hop → advert-cache → trace escalation.

**`GRP_DATA` was rejected** on security grounds despite being the only option
with an offline queue. A MeshCore channel key is shared by every member of the
channel, so all Meshu traffic would sit inside a blast radius shared with
unrelated users, and any channel member could observe every wallet's message
sizes and timing. Direct addressing eliminates this. `GRP_DATA` remains the
natural fallback should the offline-queue limitation prove decisive in practice;
the L1 and L2 layers are transport-agnostic and would port unchanged, at a cost
of 7 bytes of payload.

**`REQ` (`CMD_SEND_BINARY_REQ`) was rejected** despite being the semantically
natural request/response primitive with free per-contact ECDH. Stock
`MyMesh::onContactRequest()` answers only `REQ_TYPE_GET_TELEMETRY_DATA`, and no
companion command exists to emit an arbitrary `PAYLOAD_TYPE_RESPONSE`, so the
gateway would require custom firmware. It is also strictly one-request-at-a-time
(`pending_req` is a single `uint32_t`, and `clearPendingReqs()` discards any
prior request), so a 22-frame restore would need 22 sequential round trips.

**`ANON_REQ` (`CMD_SEND_ANON_REQ`) was rejected** even though it addresses a raw
32-byte pubkey with no contact entry required, which is attractive for a
zero-configuration wallet. `Mesh.h` declares `onAnonDataRecv()` as an empty
default and **nothing in the companion firmware overrides it**, so inbound
anonymous requests are silently discarded. It also carries the smallest payload
of any option — 132 bytes, because the sender's full 32-byte public key travels
in every packet.

**`TXT_MSG` was rejected as not binary-safe.** `BaseChatMesh::composeMsgPacket()`
computes length with `strlen(text)` and `MyMesh::onChannelMessageRecv()` does the
same on receipt, so any payload containing a `0x00` byte is truncated at the
first NUL. Base64 or similar armouring would restore safety at a ~33% payload
cost, negating the point of a compact binary protocol.

### A.1 Correction to an earlier draft

An earlier version of this appendix asserted that `RAW_CUSTOM` "cannot reach a
gateway more than one hop away." **That was wrong.** The claim was based on the
comment `// don't flood route these (yet)` in `Mesh.cpp`, which disables only
*flood* routing of raw custom packets. Direct multi-hop forwarding is handled
earlier in `Mesh::onRecvPacket()`, in the `isRouteDirect() && getPathHashCount()
> 0` branch, which is payload-type-agnostic and returns
`ACTION_RETRANSMIT_DELAYED` for any type before the payload-type switch is
reached. Ordinary repeaters therefore do relay `RAW_CUSTOM` along a supplied
path. The practical consequence is only that a path must be discovered by other
means (§2.6).

## Appendix B: Configuration Parameters

| Parameter | Default | §|
|---|---|---|
| `MESHU_MTU_FLOOR` | 165 B | 2.7 |
| `MESHU_PATH_RETRY` | 3 | 2.6 |
| `MESHU_MAX_MSG` | 40 000 B | 3.2 |
| `MESHU_REASM_TIMEOUT` | 600 s | 3.5 |
| `MESHU_MAX_REASM` | 4 | 3.5 |
| `MESHU_MIN_RTO` | 15 000 ms | 3.7 |
| `MESHU_MAX_RETRY` | 4 | 3.7 |
| `MESHU_REPLAY_WINDOW` | 256 | 4.7 |
| `MESHU_MAX_WALLETS` | 64 | 4.2.1 |
| `MESHU_CACHE_TTL` | 24 h | 11.1 |
| `MESHU_MELT_RETENTION` | 24 h | 8.6 |
| `MESHU_BURST` | 5 frames | 12.3 |
| `MESHU_WINDOW` | 6 frames | 12.3 |
| `MESHU_DUTY_CYCLE` | 0.10 | 12.2 |
| `MESHU_POLL_BASE` | 60 s | 12.4 |
| `MESHU_POLL_MAX` | 900 s | 12.4 |

---

## Appendix C: Source References

MeshCore, `github.com/meshcore-dev/MeshCore`:

| Constant / behaviour | Location |
|---|---|
| `MAX_PACKET_PAYLOAD 184`, `MAX_GROUP_DATA_LENGTH`, `MAX_PATH_SIZE 64` | `src/MeshCore.h` |
| `MAX_FRAME_SIZE 176` | `src/helpers/BaseSerialInterface.h` |
| `PAYLOAD_TYPE_*`, header bit layout | `src/Packet.h`, `docs/packet_format.md` |
| `CMD_*`, `RESP_CODE_*`, `PUSH_CODE_*`, `ERR_CODE_*` | `examples/companion_radio/MyMesh.cpp` |
| `CMD_SEND_RAW_DATA` handling, direct-only, flood rejected | `examples/companion_radio/MyMesh.cpp` |
| `MyMesh::onRawDataRecv()` — no offline queue, drops when BLE down | `examples/companion_radio/MyMesh.cpp` |
| `createRawData()` payload limit | `src/Mesh.cpp` |
| `RAW_CUSTOM` inbound requires `isRouteDirect()`; flood disabled | `src/Mesh.cpp` |
| Payload-type-agnostic direct multi-hop forwarding | `src/Mesh.cpp`, `onRecvPacket()` |
| `onAnonDataRecv()` empty default, never overridden | `src/Mesh.h` |
| `onContactRequest` telemetry-only behaviour | `examples/companion_radio/MyMesh.cpp` |
| `sendRequest` 168-byte guard, `pending_req` single slot | `src/helpers/BaseChatMesh.cpp` |
| `createAnonDatagram` 136-byte guard | `src/Mesh.cpp` |
| `composeMsgPacket` uses `strlen()` — not binary-safe | `src/helpers/BaseChatMesh.cpp` |
| `hasSeen()`, `MAX_PACKET_HASHES = 128+32` | `src/helpers/SimpleMeshTables.h` |
| `calculatePacketHash()` hashes payload bytes | `src/Packet.cpp` |
| `CMD_GET_ADVERT_PATH`, advert path cache | `examples/companion_radio/MyMesh.cpp` |
| Raw custom payload type, packet framing | `docs/packet_format.md`, `docs/payloads.md` |
| Default radio preset | `platformio.ini` |

Cashu, `github.com/cashubtc/nuts`:

| Topic | NUT |
|---|---|
| Models, V4 CBOR token, short keyset ID | 00 |
| Keys | 01 |
| Keysets, keyset ID V2 (33 B), fees | 02 |
| Swap | 03 |
| Mint, UUIDv7 quotes, `amount_paid`/`amount_issued` | 04 |
| Melt, async, `prefer_async` | 05 |
| Mint info | 06 |
| Token state check | 07 |
| Melt change | 08 |
| Restore signatures | 09 |
| Well-known secrets, P2PK, DLEQ, HTLC | 10, 11, 12, 14 |
| Deterministic secrets, gap limit | 13 |
| WebSockets | 17 |
| Cached responses | 19 |
| Mint quote signature | 20 |
| BOLT11 | 23 |
| Batched minting | 29 |
| Error codes | `error_codes.md` |
