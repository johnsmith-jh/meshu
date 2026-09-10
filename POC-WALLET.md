# Meshu PoC — Emergency Ecash-Only Wallet

**Status:** Draft — scoped derivative of `PROTOCOL.md` v1
**Date:** 2026-09-10

An "emergency" PWA Cashu wallet that operates over the Meshu transport but
handles **ecash tokens only — no Lightning, no minting, no melting**. Value
enters the wallet exclusively by receiving a token from a peer and leaves
exclusively by producing a token for a peer.

The gateway daemon is operated **by the mint itself**, on the same host or LAN
segment. This collapses the gateway and the mint into a single counterparty,
which is the same trust position as ordinary Cashu: you trust the mint, and
nothing else in the path learns anything the mint doesn't already know.

Everything not redefined here is inherited from `PROTOCOL.md`: the transport
binding (§2), L1 segmentation (§3), L2 encryption including the TOFU bootstrap
(§4, §4.2.1), L3 encoding (§5–6), airtime governance (§12), and idempotency
(§11) apply unchanged. `TESTVECTORS.md` conformance applies to the operation
subset below.

---

## 1. Scope

### 1.1 Features

| Feature | User action | Mint contact | Mechanism |
|---|---|---|---|
| Create wallet | Seed backup, scan gateway QR | Yes — first contact | `HELLO`, `KEYSETS`, `KEYS` |
| Sync proofs | Automatic on session start | Yes | `CHECKSTATE`, `KEYSETS` |
| Receive ecash | Paste / camera-scan a token string | Yes — re-issue | `SWAP` |
| Send ecash | Enter amount, show QR / copy string | Yes — split | `SWAP` |
| Restore | Enter seed on a new install | Yes — expensive | `RESTORE` |

### 1.2 Explicit non-goals

- No `MINT_QUOTE` / `MINT` / `MELT_QUOTE` / `MELT` — no Lightning anywhere.
  The mandatory NUT-20 profile (`PROTOCOL.md` §9) is therefore **not needed**:
  there are no quotes to lock.
- No BOLT11 handling, no bech32 repacking (`PROTOCOL.md` §6.3 unused).
- No P2PK / HTLC / well-known-secret tokens (NUT-10/11/14). Only plain 32-byte
  NUT-13 secrets are supported; anything else is rejected on receipt (§5.3).
- No multi-mint. One gateway = one mint, `mint_handle` 0.
- No wallet-to-wallet token transfer over the mesh (a token arrives by QR,
  camera, or paste — never by radio). Natural later addition.
- No fiat/LN top-up. There is no way to bring value in except a token from a
  peer who themselves has mint access.
- No direct-to-mint mode. When the wallet has internet it still talks to the
  gateway daemon over HTTPS (§9), never Cashu JSON to the mint directly.

### 1.3 Why this is much smaller than full Meshu

The two most dangerous operations in the full protocol disappear:

- **Minting** required NUT-20 quote locking because the gateway learned quote
  IDs (T1). No quotes exist here.
- **Melting** required sending bearer proofs to a *third-party* gateway (T2)
  and async reconciliation. Here the only operations that transmit proofs are
  `SWAP` and `CHECKSTATE`, both same-mint, and the gateway *is* the mint — the
  exposure is identical to a normal online Cashu wallet doing a swap.

What remains hard is everything the radio imposes: minute-scale operations,
lost replies, and the requirement that every state-changing operation be
recoverable (`PROTOCOL.md` §11 is still the most safety-critical section).

---

## 2. Trust model delta

`PROTOCOL.md` §1.3 applies with the following amendments:

| Entry | Status in this PoC |
|---|---|
| T1 (mint front-running / NUT-20) | **Vacated** — no mint quotes exist |
| T2 (melt proofs exposed to gateway) | **Collapsed to standard Cashu** — the gateway is run by the mint, so `SWAP` inputs are exposed exactly as they would be in any Cashu swap. No additional counterparty |
| T3 (metadata exposed) | **Unchanged** — radio observers see sizes/timing; the bootstrap `HELLO` exposes the wallet's long-term L2 pubkey (T7). The mint/gateway additionally sees proofs, amounts, and timing — as any mint does |
| T4 (ecash at rest) | **Unchanged** — wallet SHOULD encrypt IndexedDB |
| T5 (denial of service) | **Unchanged** |
| T6 (inbound frames lost while offline) | **Unchanged** — §11 recovery remains mandatory |
| T7 (TOFU bootstrap) | **Sharpened** — see S2 in §7: the gateway QR *is* the mint choice |

**The one new trust property:** because the mint operates the gateway, the
gateway cannot be "a malicious proxy in front of an honest mint." The failure
modes that remain are the failure modes of the mint itself (inflation, freeze,
rug) plus radio-layer attacks (jamming, metadata). This is deliberately the
standard Cashu posture, and the UI should say so.

---

## 3. Operation subset

| Op | Used for | Wire format | Required |
|---|---|---|---|
| `HELLO` `0x0D`/`0x8D` | Bootstrap (§4.2.1), session setup, capability check | §8.1 | MUST |
| `KEYSETS` `0x0A`/`0x8A` | Keyset handles, `active`, `input_fee_ppk`, `final_expiry` | §8.10 | MUST |
| `KEYS` `0x0B`/`0x8B` | Mint public keys; fetch once per keyset, cache forever, range-request | §8.11 | MUST |
| `CHECKSTATE` `0x09`/`0x89` | Sync, claim confirmation, send-claim detection | §8.9 | MUST |
| `SWAP` `0x08`/`0x88` | Receive (re-issue) and send (split) | §8.13 | MUST |
| `RESTORE` `0x07`/`0x87` | Seed recovery | §8.8 | MUST |
| `MINT_INFO` `0x0C`/`0x8C` | Amount limits, supported units | §8.12 | SHOULD |
| `ERROR` `0xFE` | — | §8.14 | MUST |

Per §13.3, the gateway advertises exactly this subset in `HELLO`, and the
wallet MUST NOT send anything else. A full Meshu gateway and a PoC wallet
interoperate without special-casing; a PoC gateway is simply a full gateway
with most ops unimplemented.

The gateway daemon still needs, from the full spec: the pairing table
(§4.2.1), the replay cache (§11.1 — `SWAP` is state-changing), melt retention
(**not needed** — no melts), the airtime governor (§12), and NUT-19 awareness
for safe swap replay (§11.3).

All of the above also runs unchanged over HTTPS when the wallet has internet
access (§9); only the transport differs.

---

## 4. Wallet data model

Everything is derived from or anchored to a single BIP39 seed (12 words,
shown once at creation, paper backup — see S6).

```
seed (BIP39, 128-bit)
├── L2 X25519 keypair            seed-derived (§4.2.1 MUST here, not SHOULD)
├── per-keyset NUT-13 counters   secrets + blinding factors, gap-limit scanning
└── persistent state (IndexedDB, encrypted at rest per T4)
    ├── gateway config           Ed25519 node id + X25519 key (from QR)
    ├── pinned session           epoch, msg_id counter, handles, path cache
    ├── keysets                  full IDs, keys (cached forever, §8.11), fees,
    │                            active flags, final_expiry
    ├── proofs[]                 { amount, secret, C, keyset_id, state }
    │                            state ∈ available | reserved_out | claiming_in
    ├── pending_ops[]            §11.2 intent records: msg_id, op, exact bytes
    └── sent_tokens[]            { token, amount, created_at, state }
                                 state ∈ reserved | claimed | reclaimed
```

Balance shown to the user has **three buckets**, never one number:

- **Available** — proofs in state `available`.
- **Incoming (claiming)** — a received token whose re-issue `SWAP` has not
  confirmed. Not spendable. See S1.
- **Outgoing (reserved)** — proofs backing a sent-but-unclaimed token. Not
  selectable for new operations. See S4.

---

## 5. Flows

### 5.1 Create wallet (first contact)

1. Generate the seed; show the 12-word mnemonic; require confirmation. Derive
   the L2 keypair and prepare (empty) NUT-13 counters.
2. Import the **gateway QR**: the mint's gateway node Ed25519 identity +
   X25519 key (+ optional radio preset hint), generated per §8. This QR is the
   root of trust (S2); the UI MUST show the mint URL and a key fingerprint for
   out-of-band comparison.
3. Connect to the companion node over BLE and establish a path to the gateway
   (zero-hop → advert cache → trace, `PROTOCOL.md` §2.6) — or, when online,
   skip BLE entirely and use the HTTPS transport (§9).
4. Send bootstrap `HELLO` (plaintext, §4.2.1). On the sealed response, the
   session is established; the gateway has pinned the wallet's key.
5. `KEYSETS(mint_handle 0)` → handles, `active`, `input_fee_ppk`,
   `final_expiry`. Persist.
6. `KEYS` per active keyset, range-requested to the exponents the wallet will
   use (e.g. 0–16 covers < 65 536). Cache permanently, keyed by full keyset
   ID, and **verify the keyset ID by recomputing it per NUT-02** — cheap, and
   it catches a misconfigured or hostile gateway serving wrong keys.
7. `CHECKSTATE` on any local proofs (none on first run). Done.

### 5.2 Sync proofs (session start / after reconnect)

1. Sealed `HELLO` if the session lapsed (epoch change, gateway restart, or
   `NACK DECRYPT_FAILED` → re-bootstrap, §4.2.1).
2. `KEYSETS` if handles are stale (`MC_STALE_HANDLE`) or periodically — this
   is how keyset rotation and `final_expiry` are noticed (S8).
3. `CHECKSTATE` over every local proof not in a final state:
   - `UNSPENT` → keep.
   - `SPENT` → delete; if it was `reserved_out`, mark the sent token
     **claimed** (the recipient swapped it).
   - `PENDING` → leave; re-check with §12.4 backoff.
4. Reconcile `pending_ops`: any interrupted `SWAP` is retried **byte-identical
   with the same `msg_id`** per §11.2/§11.4 before any new operation starts.

### 5.3 Receive ecash (claim a token)

The receive flow is a **re-issue**: the token's proofs are bearer instruments
the sender still knows, so the wallet swaps them for fresh outputs immediately.

1. **Ingress.** Paste or camera-scan a token. Accept Cashu **V4** (`cashuA`,
   CBOR) only; bound the input (reject > 8 KB) and parse defensively (S15).
2. **Validate.**
   - Mint URL matches the configured gateway's mint; foreign-mint proofs are
     rejected with an explicit message (S9) — they cannot be claimed here.
   - Keyset IDs known; unknown → refresh `KEYSETS`/`KEYS` once, then reject.
   - Every secret is a plain 32-byte value. Reject NUT-10 JSON secrets
     (`["P2PK",…]`, `["HTLC",…]`) — this wallet cannot re-issue them (S10).
3. **Persist intent (§11.2):** allocate the next NUT-13 counters, build the
   fresh outputs (same total, powers of two), record `msg_id` + exact request
   bytes + the token's proofs — *before transmitting*.
4. `SWAP(inputs = token proofs, outputs = fresh)`. Unblind the signatures with
   the stored blinding factors and verify each against the mint's public key
   for its amount (catches a corrupt or hostile response; nearly free).
5. On success: store the new proofs as `available`, discard the token's
   proofs, credit the balance. Net amount is `sum(inputs) − input_fees`
   (`input_fee_ppk`, S7) — show the net, not the gross.
6. **Failure handling.**
   - `11001` (already spent): the sender double-spent, or the token was
     already claimed. The token is worthless; say so plainly (S1).
   - `11002` (pending): wait, poll `CHECKSTATE` with §12.4 backoff.
   - Interrupted (any transport failure): retry the identical request
     (§11.4); on `11003` recover via `RESTORE` at the same counters.

The UI MUST label these funds **"incoming — claiming"** until step 5
completes. They are not the user's money yet (S1).

### 5.4 Send ecash (make a token)

1. User enters an amount. **Coin selection:** pick the fewest `available`
   proofs covering `amount + input_fees`; prefer proofs from inactive keysets
   (§8.10, S8).
2. Build outputs: a **send set** (the amount decomposed into powers of two,
   §6.1) plus a **change set** (the remainder), all from fresh NUT-13
   counters. Persist intent per §11.2 — counters, outputs, `msg_id` — before
   transmitting.
3. `SWAP(inputs = selected proofs, outputs = send set + change set)`. Unblind
   and verify.
4. Serialize the send set as a **V4 token** (`cashuA` + base64url CBOR: mint
   URL, full keyset ID, `{amount, secret, C}` per proof). Show as QR and as a
   copyable string. Store it in `sent_tokens` as `reserved`; the backing
   proofs become `reserved_out` and MUST NOT be selected again (S4).
5. **Claim detection:** on sync, `CHECKSTATE` shows the reserved proofs
   `SPENT` → the recipient claimed; mark the token `claimed`, finalize.
6. **Reclaim (cancel a send):** the wallet still knows these secrets — the
   token is only *reserved*, not gone. To cancel, `CHECKSTATE` first:
   - `UNSPENT` → mark the proofs `available` again. No mint call needed, but
     the token string is still out there; warn the user it becomes worthless
     only because the wallet will now race any presenter (and, being online
     first, wins).
   - `SPENT` → too late; the recipient claimed.
7. Interruption handling is identical to receive: byte-identical retry,
   `11003` → `RESTORE` (§11.4). Never re-derive fresh outputs on retry (S14).

**Rejected alternative:** handing over existing proofs without a swap. It
saves a round trip but the sender then can't cleanly reclaim, the receiver
races the sender's *whole wallet state*, and change handling disappears. One
`SWAP` round trip (~4–6 frames, ~4–6 s airtime) is the right price.

### 5.5 Restore

Per `PROTOCOL.md` §8.8 exactly: NUT-13 derivation (HMAC-SHA256 for V2
keysets), batches of 50–100 counters, gap limit 3 consecutive empty batches,
advance counters past the highest hit. Budget the user's expectations: a
200-counter scan is ~46 frames of pure upload, minutes of wall-clock (§12.5).
Restore is the only operation where this wallet feels the radio's weight;
everything else is seconds.

---

## 6. Error-code subset

From `PROTOCOL.md` §10, this PoC will realistically encounter:

| Code | Context here | Wallet action |
|---|---|---|
| 11001 | Receive: token already spent | Report double-spend; token worthless |
| 11002 | Proofs pending | Wait; `CHECKSTATE` backoff |
| 11003 | Swap outputs already signed | Retry identical / `RESTORE` (§11.4) |
| 11005 | Swap unbalanced | Recompute fees (bug) |
| 11007/11008 | Duplicate inputs/outputs | Bug; regenerate with fresh counters |
| 11014/11015 | Too many inputs/outputs | Split the operation |
| 12001–12003 | Keyset unknown/inactive/expired | Refresh `KEYSETS`; migrate balance (S8) |
| `0xF003` `MC_STALE_HANDLE` | Handle invalidated | Re-run `KEYSETS` |
| `0xF004`/`0xF005` | Mint unreachable/timeout | **Indeterminate** — resolve via §11, never assume failure |
| `0xF006` `MC_RATE_LIMITED` | Over-eager polling | Increase backoff |

---

## 7. Security considerations

This is the section to read twice. Ordered by how likely each is to bite.

**S1 — The receive double-spend race is the core flow, not an edge case.**
A received token is spendable by the sender until the wallet's re-issue `SWAP`
lands at the mint. Over LoRa that window is tens of seconds, occasionally
minutes — versus sub-second for an online wallet. A sender can reclaim or
double-spend during it. This is inherent to bearer ecash (Cashu warns about it
for *any* token in flight), but the radio stretches the window by two orders
of magnitude. Non-negotiable mitigations: funds are "incoming — claiming,"
never spendable, until the swap confirms; `11001` is surfaced as "this token
was already spent — the sender may have cheated you," not as a generic error.
Face-to-face rule of thumb for users: **don't consider a payment received
until the app says so.**

**S2 — The gateway QR is the mint choice, and it's a TOFU moment.**
Because the mint runs the gateway, importing a gateway config *is* choosing a
mint. A phishing QR points the wallet at an attacker's mint-and-gateway:
received "ecash" is issued by the attacker and is worthless, and every
subsequent session is protected (L2, pinned keys) — protected *with the
attacker*. The bootstrap analysis of `PROTOCOL.md` §4.2.1/T7 applies, but the
real defense is operational: distribute gateway QRs through trusted channels,
show the mint URL and key fingerprint prominently, and treat first contact as
an auditable event. This is the single most dangerous moment in the wallet's
life.

**S3 — The token string is the money.**
A shown QR or copied string is a bearer instrument: anyone who photographs
the QR or reads the clipboard can claim it first, and *first claim wins*.
Warn before displaying; prefer QR display over clipboard where possible;
mobile PWAs cannot reliably clear the clipboard — say so after copy. The same
applies in reverse: a token pasted into the wallet was visible wherever it
came from.

**S4 — Reserved-send hygiene.**
Until claim is confirmed, the wallet holds valid proofs backing the sent
token. It MUST NOT: select them for another operation, delete the record
before `CHECKSTATE` confirms `SPENT`, or re-spend them without a `CHECKSTATE`
first (the recipient may have just claimed). Sloppiness here produces either
accidental double-spend attempts (11001/11002 loops) or lost track of real
funds.

**S5 — Deterministic everything, persisted before transmit.**
NUT-13 outputs, seed-derived L2 key, monotonic `msg_id`, per-keyset counters
— all persisted *before* any state-changing frame is sent (§11.2, §11.5).
Counter reuse → `11008` at best; re-deriving fresh outputs on retry is the
classic way to lose funds (§11.4). This PoC has exactly one state-changing
operation (`SWAP`), which makes getting this right easier — and therefore
inexcusable to get wrong.

**S6 — The seed is the whole wallet.**
Paper backup of the 12 words is the only real backup; IndexedDB is a cache
that avoids an expensive `RESTORE`, nothing more. Encrypt IndexedDB (T4),
but assume a stolen unlocked phone = stolen balance, as with any hot wallet.

**S7 — Fees and dust.**
Every `SWAP` pays `input_fee_ppk`, rounded up per transaction (NUT-02).
Small balances erode on every receive and every send; below some threshold a
proof's fee approaches its value. Show net amounts, and consider warning when
a receive's net is materially less than its gross.

**S8 — Keyset rotation and expiry.**
`active=false` keysets can't receive new outputs; `final_expiry` (NUT-02)
means old proofs can *expire*. Wallets MUST prioritize spending inactive
proofs, SHOULD surface a "migrate your balance" prompt when a held keyset
nears expiry, and MUST refresh `KEYSETS` periodically. In an emergency
deployment with a long-lived offline wallet, this is a real, silent way to
lose funds.

**S9 — Foreign tokens are useless here.**
Single-mint by design: a token from another mint cannot be claimed and MUST
be rejected with a clear message. In an emergency mesh this will happen
(constantinople-effect: whatever mint the local community runs is the only
one that matters). Better to say "wrong mint" than to fail obscurely.

**S10 — No locked-secret tokens.**
P2PK/HTLC tokens are rejected on receipt (§5.3 validation). That's a feature
boundary, not a bug — but a user who *accepts* such a token outside the app
and then can't claim it will be confused. The rejection message must name the
reason.

**S11 — Metadata.**
The mint/gateway sees proofs, amounts, timing — ordinary Cashu mint
visibility. Radio observers see frame sizes and timing, and the bootstrap
`HELLO` exposes the wallet's long-term L2 pubkey, linkable to the 1-byte
`src` hash thereafter (T3/T7). No anonymity is provided or implied. When the
wallet is online, the metadata picture changes rather than disappears (S16).

**S12 — Denial of service and lost replies.**
Jamming wins (T5); BLE disconnects drop replies (T6). No funds are lost by
either *if and only if* §11 recovery is implemented faithfully: persist
intent, retry byte-identical, resolve indeterminate outcomes via
`CHECKSTATE`, never assume failure. In this PoC the entire indeterminacy
surface is one operation: "did my `SWAP` land?" — answered by `CHECKSTATE`
on the inputs and, if needed, `RESTORE` on the outputs.

**S13 — Standard Cashu mint trust.**
The mint can inflate, freeze, or disappear; ecash is a claim on the mint, not
on bitcoin. The emergency framing doesn't change this; it argues for a
community-run mint whose operators are known, and for sweeping value out
whenever internet access returns.

**S14 — `11003` is a recovery path, not an error.**
"Outputs already signed" after an interrupted swap means the mint did the
work and the response was lost. Retry the identical request (ideally against
a NUT-19 cached endpoint, §11.3) or `RESTORE` at the same counters. Treating
it as fatal loses the received funds (§10.2).

**S15 — Defensive token parsing.**
The token input is attacker-controlled CBOR reaching the wallet's parser.
Bound size (8 KB), reject indefinite-length items (§5.2), cap proof counts,
and treat any parse failure as "invalid token," never crash. A malicious
peer is a plausible threat model in an emergency context.

**S16 — Online mode trades radio metadata for IP metadata.**
On the HTTPS transport (§9), the gateway/mint — and the wallet's ISP — see
the wallet's IP address linked to its L2 identity and timing. That is neither
better nor worse than the radio exposure of T3/T7, but it is *different*, and
the toggle is therefore also a privacy choice the UI should state plainly:
"mesh" hides your IP from the mint; "internet" hides nothing from your ISP
but is much faster.

**S17 — TLS is a hard deployment requirement, and there is no insecure
fallback.**
The browser path only works with a CA-signed cert on a real domain (§9.3).
A wallet that cannot reach the HTTPS endpoint falls back to **mesh**, never
to plain HTTP, and MUST NOT expose a "disable TLS" setting. An operator who
cannot obtain a domain and certificate simply runs a mesh-only gateway; that
is a supported configuration, not a failure.

---

## 8. Gateway provisioning: the connection QR

The wallet's entire configuration is one connection string carrying two public
keys, which come from **two different places**:

| Field | Size | Source |
|---|---|---|
| version tag | 1 B (`0x01`) | hardcoded |
| gateway Ed25519 pubkey | 32 B | **the MeshCore radio** — node addressing (§2.2) |
| gateway X25519 pubkey | 32 B | **the gateway daemon** — L2 key agreement (§4.2) |
| optional TLVs | var | `0x01` = human label (UTF-8 ≤ 32 B), `0x02` = expected mint URL (UTF-8), `0x03` = gateway HTTPS URL (UTF-8, §9) |
| CRC16 | 2 B | computed over all preceding bytes |

```
payload  = version ‖ ed25519_pubkey ‖ x25519_pubkey ‖ tlvs ‖ crc16
string   = "meshu1:" ‖ base32(payload)      # uppercase, no padding
```

Base32 keeps the payload in QR **alphanumeric mode** (smallest, most robust
code; ~110–160 characters, QR version ≈ 6–8) and makes the pasted string
case-insensitive. The `meshu1:` prefix makes the format self-identifying
when it travels as text instead of an image.

### 8.1 Key origins

1. **Ed25519: read, not generated.** Stock MeshCore firmware creates the node
   identity on first boot, and it never changes. The daemon (or its setup
   tool) reads it over the companion protocol — `RESP_CODE_SELF_INFO` carries
   the 32-byte public key at bytes 4–35. The node's private key never leaves
   the radio.
2. **X25519: generated once by the daemon.** This is the daemon's own L2
   long-term keypair, generated from a CSPRNG at first run and persisted with
   the pairing table (§4.2.1). It cannot be derived from the node's seed —
   the daemon does not hold the node's private key. **Back this key up like
   the mint's own keys.**

### 8.2 Fingerprint

Both the gateway and the wallet (after import) display

```
fingerprint = SHA256(ed25519_pubkey ‖ x25519_pubkey)[0:8]
```

as 4 groups of 4 hex chars. It binds both keys in one 19-character readback,
so a swapped QR is detectable over a voice call or against the mint's info
page. The wallet MUST show it, and the expected-mint-URL TLV if present, and
require explicit user confirmation on import (S2).

TLVs are advisory: the fingerprint binds only the two public keys. A tampered
URL or label degrades to denial of service, because the gateway must still
prove possession of the pinned X25519 key (§9.2).

### 8.3 Rotation implications

The string binds node identity and daemon identity as one logical gateway, so
replacing **either** the radio (new Ed25519) or the daemon key (new X25519)
produces a new connection string that must be redistributed through the same
trusted channel. Daemon-key rotation additionally invalidates every pinned
wallet session: wallets re-bootstrap automatically (§4.2.1), but they cannot
distinguish a planned rotation from an attack except via the fingerprint —
so rotations MUST be announced out of band before they happen.

### 8.4 Publication as a fixed PNG

The daemon SHOULD regenerate the QR **at every startup** — generation is
deterministic given the keys, so this is cheap and guarantees the published
image always matches the current keys. It writes two files to a fixed
location:

```
/var/lib/meshu/gateway-qr.png    # the QR, error-correction level ≥ M,
                                    #   fingerprint printed beneath the code
/var/lib/meshu/gateway-qr.txt    # the connection string + fingerprint,
                                    #   for copy/paste and headless terminals
```

A fixed path and fixed name means the mint's info page (or any static page on
the same host) can simply link it — `<img src="/meshu/gateway-qr.png">` —
and after a rotation the linked image updates itself with no web content
changes. Printing the fingerprint beneath the code inside the PNG lets the
same linked image serve the S2 out-of-band verification.

## 9. Dual transport (HTTPS alongside mesh)

When the wallet has ordinary internet access, it MAY use it instead of the
radio. This is a transport swap only: the wallet talks to the **same gateway
daemon**, operated by the mint, speaking the **same protocol**. Talking Cashu
JSON directly to the mint is explicitly out of scope — it would fork the
wallet into two API clients with different identity and retry semantics.

### 9.1 Layer mapping

| Layer | Mesh transport | HTTPS transport |
|---|---|---|
| L3 messages (§5–6) | unchanged | unchanged — same ops, same bytes |
| L2 encryption (§4) | unchanged | unchanged — same keys, same nonce rules |
| L1 segmentation (§3) | active | bypassed — HTTP is reliable and ordered; only `msg_id` is retained (below) |
| Airtime governor (§12) | active | bypassed (polling backoff §12.4 still applies) |
| Addressing | node hashes, paths (§2) | URL from the connection string (§8) |

The daemon exposes a single endpoint at the provisioned URL. The wallet sends
`POST {https_url}` with `Content-Type: application/octet-stream`; the body is

```
msg_id (2 bytes, big-endian) ‖ sealed L2 message (§4.4)
```

and the response body has the same form, reusing the request's `msg_id`
(§3.3). No L1 header, no flags, no `dst`/`src` prefix — the HTTP round trip
replaces routing and reliability, while `msg_id` keeps its two security roles:
idempotency key (§11) and AEAD nonce input (§4.5). Its allocation rules are
unchanged, and a byte-identical body is a byte-identical retry that hits the
same replay-cache entry (§11.1) on either transport.

### 9.2 Why L2 stays on

- **Identity continuity.** The wallet's X25519 key is its identity on both
  transports; the gateway's pairing table (§4.2.1) and replay cache apply
  unchanged. A `SWAP` interrupted on one transport is retried byte-identical
  on the other.
- **Authentication without certificates.** The gateway proves itself by the
  pinned X25519 key (§4.2.1); a spoofed or hijacked URL degrades to denial of
  service, never to impersonation. TLS is defense in depth, not a
  load-bearing requirement — except for the browser constraint below.

### 9.3 TLS is mandatory in practice

The wallet is a PWA served over HTTPS, and browsers block `fetch()` to
plain-HTTP or self-signed endpoints (mixed content, and there is no cert
pinning for `fetch`). The gateway daemon MUST therefore serve its endpoint
over **TLS with a CA-signed certificate on a real domain** (e.g. Caddy/nginx
or Let's Encrypt in front), with CORS enabled for the wallet's origin. This
is a deployment requirement, not a protocol one — but it is not optional for
the browser path, and the wallet MUST NOT offer an insecure-HTTP fallback.

### 9.4 The toggle

- A user-facing **"use mesh"** toggle selects the transport. Off (default):
  HTTPS, with automatic mesh fallback if the endpoint is unreachable. On:
  mesh only. The active transport is always visible in the UI.
- Switching happens only between operations: in-flight jobs finish or are
  aborted first; `pending_ops` then retry on the new transport — safe by
  construction (§9.2).
- First contact and bootstrap `HELLO` work identically on either transport;
  a wallet configured once (§8) can use both forever.
- Polling backoff (§12.4) applies on both transports; online speed is not a
  reason to hammer the mint.

### 9.5 What changes and what doesn't

- Latency drops from minutes to sub-second; the async-job UX (progress,
  interruption, §11 recovery) stays identical.
- Metadata shifts rather than disappears: on mesh, observers see radio timing
  and sizes; on HTTPS, the gateway/mint and the wallet's ISP see the wallet's
  **IP address** linked to its L2 identity (S16).
- Mint URL, keys, keysets, proofs, balances, and all §11 recovery procedures
  are transport-independent.

## 10. Implementation checklist

Ordered, mirroring `README.md`'s implementation order:

1. **Codecs** — exponents (§6.1), CBOR envelope (§5), packed blobs (§6.7),
   V4 token parse/serialize (NUT-00). Validate against `TESTVECTORS.md`
   vectors 1, 4, 5, 6, 8 and the §12 checklist rows for the ops used here. Skip
   vectors 2, 3, 7 (UUID, bech32, NUT-20 — unused).
2. **L1 over a fake transport** — loss, reordering, the window/`REQ_ACK`
   rule (§3.4, §12.3).
3. **L2** — X25519 + ChaCha20-Poly1305, implicit nonce, **bootstrap form**
   (§4.2.1): first `HELLO` plaintext, never-replace pinning.
4. **Wallet core** — data model (§4), the three-bucket balance, coin
   selection, the four flows (§5) as async jobs with progress (§12.5).
5. **Gateway daemon** — pairings, replay cache, governor, and proxying of the
   §3 operation subset to a localhost mint (Nutshell or CDK).
6. **HTTPS transport** — daemon: TLS (CA-signed, real domain), CORS, and the
   single POST endpoint (§9). Wallet: the "use mesh" toggle behind a transport
   abstraction that feeds one shared message pipeline.
7. **Bench, then mesh** — two nodes zero-hop, then multi-hop.

The PoC deliberately reuses every byte of the L1/L2/L3 stack so that
graduating to the full protocol later is additive: implement `MINT_QUOTE`,
`MINT`, `MELT_QUOTE`, `MELT` (+ NUT-20) on top of a stack that already works.
