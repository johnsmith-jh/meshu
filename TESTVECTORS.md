# Meshu Test Vectors

Byte-exact conformance vectors for `PROTOCOL.md` v1.

Every vector here was produced by executing the transform and verifying the
round trip. Implement against these before connecting a radio: a codec bug found
at 16 bytes per second is expensive to diagnose.

Where a vector shows zeroed cryptographic material, that is noted explicitly and
means "structure is normative, bytes are placeholder".

---

## 1. Exponent amount codec (§6.1)

`amount = 1 << exponent`. A target amount decomposes into the set bits of its
binary representation, emitted ascending.

| Amount | Exponents | Encoded | Verification |
|---|---|---|---|
| 1 | `[0]` | `00` | 1 = 1 |
| 2 | `[1]` | `01` | 2 = 2 |
| 8 | `[3]` | `03` | 8 = 8 |
| 1000 | `[3,5,6,7,8,9]` | `030506070809` | 8+32+64+128+256+512 = 1000 |
| 100000 | `[5,7,9,10,15,16]` | `0507090a0f10` | 32+128+512+1024+32768+65536 = 100000 |

Reference decomposition:

```python
def to_exponents(amount):
    return [i for i in range(64) if amount >> i & 1]

def from_exponents(exps):
    return sum(1 << e for e in exps)
```

Conformance: `from_exponents(to_exponents(n)) == n` for all `n` in
`1..2**63-1`.

**Hamming weight drives cost.** 1024 needs 1 output; 1023 needs 10. A wallet
choosing amounts should prefer low weight where the user has latitude.

---

## 2. UUIDv7 quote ID packing (§6.2)

```
string : "019e6d5a-2347-7000-8322-05d51d498303"   36 bytes UTF-8
packed : 019e6d5a23477000832205d51d498303          16 bytes
```

Round trip verified lossless. Version nibble (high nibble of byte 6) is `7`,
confirming UUIDv7.

Saving: **20 bytes on every quote-bearing message.**

```python
import uuid
packed  = uuid.UUID(s).bytes          # 36 -> 16
restored = str(uuid.UUID(bytes=packed))
assert restored == s
```

> Reminder: NUT-20 signing (§9.2, vector 7) commits to the **36-character
> string**, not these 16 bytes.

---

## 3. BOLT11 bech32 5-bit repack (§6.3)

### 3.1 Worked example

```
invoice : lnbc100n1p3kdrv5sp5lpdxzghe5j67qqpzry9x8gf2tvdw0s3jn54khce6mua7lqpzry9x8gf2tvdw0s3jn54khce6mua7l
chars   : 96
hrp     : "lnbc100n"   (8 bytes)
nvals   : 87
packed  : 0c6cd1b2900d3e169848be692d780008864298e84a96c6b9f08ca74adaf8ceb7
          cefbe008864298e84a96c6b9f08ca74adaf8ceb7cefbe0
          (55 bytes)
wire    : 1 + 8 + 2 + 55 = 66 bytes
saving  : 31.2%
```

Round trip verified exact.

### 3.2 Scaling on realistic invoice lengths

| Invoice chars | Packed | Wire total | Saving |
|---|---|---|---|
| 267 | 162 | 173 | 35.2% |
| 300 | 182 | 193 | 35.7% |
| 400 | 245 | 256 | 36.0% |
| 500 | 307 | 318 | 36.4% |
| 700 | 432 | 443 | 36.7% |

### 3.3 Reference implementation

```python
CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
INV = {c: i for i, c in enumerate(CHARSET)}

def pack5(invoice):
    hrp, _, data = invoice.rpartition('1')
    vals = [INV[c] for c in data]
    acc = bits = 0
    out = bytearray()
    for v in vals:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits:
        out.append((acc << (8 - bits)) & 0xFF)   # pad bits MUST be zero
    return hrp.encode(), len(vals), bytes(out)

def unpack5(hrp, nvals, packed):
    acc = bits = 0
    vals = []
    for byte in packed:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5 and len(vals) < nvals:
            bits -= 5
            vals.append((acc >> bits) & 0x1F)
    return hrp.decode() + '1' + ''.join(CHARSET[v] for v in vals)
```

Conformance requirements:

- `unpack5(*pack5(inv)) == inv` MUST hold; verify before transmitting.
- Trailing pad bits MUST be zero.
- `rpartition('1')` is correct because the bech32 separator is the **last** `1`;
  the HRP itself may contain `1` (as in `lnbc100n`).
- A character outside `CHARSET` means the invoice is not valid bech32 — reject
  rather than transmit.

---

## 4. L3 `MINT_QUOTE` request, single frame (§8.2)

Structure: `[opcode, mint_handle, amount, unit, quote_pubkey]`

```
[ 0x01, 1, 1000, 0, h'02a1a1…a1' ]
```

CBOR, 42 bytes:

```
8501011903e800582102a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1
```

Byte-by-byte:

| Bytes | Meaning |
|---|---|
| `85` | array(5) |
| `01` | opcode `0x01` `MINT_QUOTE` |
| `01` | mint_handle 1 |
| `19 03e8` | uint 1000 (amount) |
| `00` | unit 0 = `sat` |
| `58 21` | byte string, length 0x21 = 33 |
| `02a1…a1` | quote_pubkey, 33 bytes |

Note `amount` here is an ordinary integer, not an exponent — §6.1 applies to
output denominations, not aggregate amounts.

### 4.1 Wrapped as an L1 frame

With `msg_id = 0x1234`, epoch 0, single frame (`MULTI` clear):

```
10 00 1234 00 8501011903e8005821…a1 0000000000000000000000000000000
│  │  │    │  │                     └─ Poly1305 tag (16 B, zeroed here)
│  │  │    │  └─ L3 CBOR (42 B; shown as plaintext, would be ciphertext)
│  │  │    └─ L2 epoch = 0
│  │  └─ msg_id = 0x1234
│  └─ flags = 0x00 (single frame, no ACK requested)
└─ 0x10 = version 0b00, kind DATA
```

Total 63 bytes of L1 frame. With the 2-byte `dst`/`src` routing prefix (§2.3)
the on-air payload is 65 bytes, fitting the 172-byte zero-hop send-path
capacity (§2.7) with 107 bytes spare, and the conservative 165-byte floor with
100 bytes spare.

**The ciphertext and tag are zeroed for illustration.** A conforming
implementation produces real ChaCha20-Poly1305 output here; only the framing is
normative in this vector.

---

## 4.2 Full companion frames (§2.3–2.5)

Same message as vector 4, with real transport framing. Gateway MeshCore pubkey
begins `0x7f`, wallet's begins `0x3a`, so `dst = 0x7f` and `src = 0x3a`.

**Outbound** — `CMD_SEND_RAW_DATA`, zero-hop, written to the BLE RX
characteristic (67 bytes):

```
19 00 7f 3a 10 00 1234 00 8501011903e800582102a1…a1 00000000000000000000000000000000
│  │  │  │  └──────── L1 frame (63 B) ────────────────────────────────────────────┘
│  │  │  └─ src  = wallet_pubkey[0]
│  │  └─ dst  = gateway_pubkey[0]
│  └─ path_len = 0 (zero-hop direct)
└─ 0x19 = CMD_SEND_RAW_DATA
```

Full hex:

```
19007f3a10001234008501011903e800582102a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1
a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a100000000000000000000000000000000
```

**Inbound** — `PUSH_CODE_RAW_DATA` notification, SNR +10 dB (`10 × 4 = 40 =
0x28`), RSSI −60 dBm (`0xC4` as signed int8), 69 bytes:

```
84 28 c4 ff 7f 3a 10 00 1234 00 …
│  │  │  │  └─ payload begins at offset 4
│  │  │  └─ 0xFF reserved, MUST be ignored
│  │  └─ RSSI, signed int8
│  └─ SNR ×4, signed int8
└─ 0x84 = PUSH_CODE_RAW_DATA
```

Full hex:

```
8428c4ff7f3a10001234008501011903e800582102a1a1a1a1a1a1a1a1a1a1a1a1a1a1
a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a100000000000000000000000000000000
```

Note the asymmetry: the outbound frame has a `path_len` field at offset 1 and the
payload starts at offset 2 (+ path bytes), while the inbound frame has a fixed
4-byte prefix and **no length field** — the payload runs to the end of the BLE
frame. Sharing a parser between the two directions will corrupt frames.

Ciphertext and tag are zeroed here for illustration; only the framing is
normative.

---

## 5. `RESTORE` hit bitmap (§8.8)

100 counters probed, mint holds signatures at counters 3, 7, 64, 99.

```
bitmap (13 bytes): 88000000000000000100000008
```

Bit layout — bit `i` of byte `j` corresponds to counter `j*8 + i`, LSB first:

| Counter | Byte | Bit | Byte value |
|---|---|---|---|
| 3 | 0 | 3 | `0x08` |
| 7 | 0 | 7 | `0x80` → byte 0 = `0x88` |
| 64 | 8 | 0 | `0x01` |
| 99 | 12 | 3 | `0x08` |

Response `[0x87, bitmap, signatures_blob]` with those 4 hits, 151 bytes:

```
8318874d8800000000000000010000000858 84 <4 × 33 bytes of C_>
```

Header portion decoded:

| Bytes | Meaning |
|---|---|
| `83` | array(3) |
| `18 87` | uint 0x87 (response opcode) |
| `4d` | byte string, length 0x0d = 13 (bitmap) |
| `88…08` | bitmap |
| `58 84` | byte string, length 0x84 = 132 = 4 × 33 (signatures) |

`signatures_blob` holds 33-byte `C_` values for set bits only, ascending by
counter — here for counters 3, 7, 64, 99 in that order. 2 frames.

All-miss response `[0x87, zero_bitmap, empty]`, 18 bytes / 1 frame:

```
8318874d0000000000000000000000000040
```

The trailing `40` is a zero-length byte string.

Decode verified to recover exactly `[3, 7, 64, 99]`.

```python
def encode_bitmap(hits, count):
    bm = bytearray((count + 7) // 8)
    for c in hits:
        bm[c >> 3] |= 1 << (c & 7)
    return bytes(bm)

def decode_bitmap(bm, count):
    return [i for i in range(count) if bm[i >> 3] >> (i & 7) & 1]
```

**Why this matters:** an all-miss batch of 100 returns 18 bytes / 1 frame instead
of the ~3.3 KB / 21 frames that returning outputs and signatures would cost. At
the end of a gap scan most batches are all-miss.

**What it does not fix:** the *request* is 22 frames regardless, because each
probed output is 34 bytes and the wallet cannot delegate derivation without
handing over its seed. See §8.8 — the bitmap optimises the response only.

---

## 6. L1 ACK bitmap (§3.6)

A 9-frame message; frames 3 and 7 were lost.

```
total    = 9
received = [0,1,2,4,5,6,8]
missing  = [3,7]
```

`ACKBM` frame, 7 bytes:

```
12 00 1234 09 7701
│  │  │    │  └─ bitmap, 2 bytes
│  │  │    └─ total = 9
│  │  └─ msg_id = 0x1234
│  └─ flags = 0
└─ 0x12 = kind ACKBM
```

Bitmap derivation:

```
byte 0 = 0x77 = 0b01110111  → seq 0,1,2 set; 3 clear; 4,5,6 set; 7 clear
byte 1 = 0x01 = 0b00000001  → seq 8 set
```

The sender retransmits exactly seq 3 and 7, each with `ATTEMPT` incremented from
0 to 1 — that is, `flags` byte `0x04` rather than `0x00`. Incrementing is
mandatory: a byte-identical resend is silently discarded by every repeater's
duplicate-suppression table (§2.8).

Bitmap sizing: a 255-frame message needs 32 bytes, so an `ACKBM` always fits in
one frame.

---

## 7. NUT-20 `msg_to_sign` (§9.2)

The most error-prone construction in the protocol. Three independent traps.

Inputs:

```
quote   = "019e6d5a-2347-7000-8322-05d51d498303"    (UTF-8 STRING, not packed)
outputs = [ (amount=8, B_=02 11×32),
            (amount=2, B_=02 22×32) ]               in request order
```

Construction, `len32` = 4-byte big-endian:

```
"Cashu_MintQuoteSig_v1"          (21 bytes ASCII, NOT length-prefixed)
len32(36) ‖ quote                (4 + 36)
len32(1)  ‖ 08                   (amount 8, minimal big-endian)
len32(33) ‖ 02 11×32             (B_ 0)
len32(1)  ‖ 02                   (amount 2)
len32(33) ‖ 02 22×32             (B_ 1)
```

Result, 145 bytes:

```
43617368755f4d696e7451756f74655369675f7631
0000002430313965366435612d323334372d373030302d383332322d303564353164343938333033
0000000108
00000021021111111111111111111111111111111111111111111111111111111111111111
0000000102
00000021022222222222222222222222222222222222222222222222222222222222222222
```

SHA-256:

```
8012edd6136194417e02f18b5c3aad2d9bff8d611768b19d8fa1171ee2206f7a
```

Then BIP-340 Schnorr-sign that 32-byte digest. Signature is 64 bytes.

### 7.1 Traps

1. **Quote is the 36-char string.** Signing the 16-byte packed UUID of vector 2
   yields a signature the mint rejects. Re-expand first.
2. **Amounts are minimal big-endian, not exponents.** Amount 8 is `0x08`
   (1 byte), not exponent `0x03`. Amount 0 is the *empty* byte string with
   `len32 = 0`. Amount 256 is `0x0100` (2 bytes).
3. **Output order must match the request exactly** — the same order as
   `outputs_blob`, since NUT-20 says "in the order they appear in the request".

Reference:

```python
def len32(n):
    return n.to_bytes(4, 'big')

def minimal_be(a):
    return b'' if a == 0 else a.to_bytes((a.bit_length() + 7) // 8, 'big')

def msg_to_sign(quote_str, outputs):
    m = b'Cashu_MintQuoteSig_v1'
    q = quote_str.encode()
    m += len32(len(q)) + q
    for amount, B in outputs:
        ab = minimal_be(amount)
        m += len32(len(ab)) + ab
        m += len32(len(B)) + B
    return m
```

Verify against the digest above before attempting a real mint. Failure produces
Cashu error `20008`.

---

## 8. `ERROR` response (§10)

`[0xFE, 20001, 0]` — quote not paid, no detail:

```
8318fe194e2100
```

| Bytes | Meaning |
|---|---|
| `83` | array(3) |
| `18 fe` | uint 0xFE (ERROR) |
| `19 4e21` | uint 20001 |
| `00` | detail_kind 0 = none |

7 bytes total. Gateways SHOULD use `detail_kind = 0` on the radio path.

---

## 9. Measured operation sizes

Produced by encoding real CBOR with the packed blob formats of §6.7. "Frames"
includes L1 headers and the 17-byte L2 overhead. Airtime at SF8/BW62.5
(~1.025 s/frame).

| Operation | L3 bytes | Wire bytes | Frames | Airtime |
|---|---|---|---|---|
| `HELLO` | 41 | 62 | 1 | 1.0 s |
| `MINT_QUOTE` req | 42 | 63 | 1 | 1.0 s |
| `MINT_QUOTE` resp (300-char invoice) | 228 | 257 | 2 | 2.0 s |
| `MINT` req, 1 sat (1 output) | 122 | 143 | 1 | 1.0 s |
| `MINT` req, 1000 sat (6 outputs) | 292 | 321 | 2 | 2.0 s |
| `MINT` req, 255 sat (8 outputs) | 361 | 396 | 3 | 3.1 s |
| `MINT` req, 16777215 sat (24 outputs) | 905 | 958 | 6 | 6.1 s |
| `MINT` resp (6 signatures) | 203 | 232 | 2 | 2.0 s |
| `MELT_QUOTE` req (300-char invoice) | 200 | 229 | 2 | 2.0 s |
| `MELT_QUOTE` resp | 28 | 49 | 1 | 1.0 s |
| `MELT` req, 3 inputs | 495 | 536 | 4 | 4.1 s |
| `MELT` req, 8 inputs | 826 | 879 | 6 | 6.1 s |
| `MELT` req, 16 inputs | 1354 | 1425 | 9 | 9.2 s |
| `SWAP` req, 3 in / 8 out | 478 | 519 | 4 | 4.1 s |
| `SWAP` req, 8 in / 8 out | 809 | 862 | 6 | 6.1 s |
| `CHECKSTATE` req, 10 Ys | 335 | 370 | 3 | 3.1 s |
| `CHECKSTATE` resp, 10 | 7 | 28 | 1 | 1.0 s |
| `CHECKSTATE` req, 50 Ys | 1655 | 1738 | 11 | 11.3 s |
| `CHECKSTATE` resp, 50 | 17 | 38 | 1 | 1.0 s |
| `KEYSETS` resp, 3 keysets | 49 | 70 | 1 | 1.0 s |
| `KEYS` resp, 64 keys | 2127 | 2228 | 14 | 14.3 s |
| `RESTORE` req, 100 counters | 3409 | 3558 | 22 | 22.5 s |
| `RESTORE` resp, 0 hits | 18 | 39 | 1 | 1.0 s |
| `RESTORE` resp, 5 hits | 184 | 213 | 2 | 2.0 s |
| `RESTORE` resp, 20 hits | 680 | 727 | 5 | 5.1 s |
| `RESTORE` resp, 100 hits | 3320 | 3463 | 21 | 21.5 s |

The `HELLO` row assumes sealed form (41 + 17 + 4 = 62 B wire). A first,
bootstrap `HELLO` (PROTOCOL.md §4.2.1) carries no tag: 41 + 1 + 4 = 46 B wire.
Both fit one frame.

### 9.1 Frame arithmetic

```python
MTU = 165
L1_SINGLE, L1_MULTI, L2 = 4, 6, 17

def frames(l3_len):
    body = l3_len + L2
    if body <= MTU - L1_SINGLE:              # 161
        return 1, body + L1_SINGLE
    n = math.ceil(body / (MTU - L1_MULTI))    # 159 per frame
    return n, body + n * L1_MULTI
```

---

## 10. JSON baseline comparison

Same logical operations, Cashu HTTP JSON vs Meshu:

| Operation | JSON | Meshu | Reduction | Frames |
|---|---|---|---|---|
| `MINT` req, 6 outputs | 1064 B | 292 B | **73%** | 7 → 2 |
| `RESTORE` req, 100 counters | 16 713 B | 3409 B | **80%** | 106 → 22 |
| `RESTORE` resp, 100 hits | 33 429 B | 3320 B | **90%** | 211 → 21 |
| `RESTORE` resp, 0 hits | 33 429 B | 18 B | **99.9%** | 211 → 1 |
| `RESTORE` full round trip, all hit | 50 142 B | 6729 B | **87%** | 317 → 43 |
| `RESTORE` full round trip, all miss | 50 142 B | 3427 B | **93%** | 317 → 23 |

The NUT-09 response baseline is large because the spec returns both `outputs`
and `signatures` arrays, of equal length. Meshu replaces the echoed outputs
with a 13-byte bitmap.

At SF8/BW62.5 a full 100-counter restore round trip goes from ~325 s of airtime
to ~44 s when every counter hits, and to ~24 s when none do. The floor is set by
the 22-frame request, which cannot be reduced (§8.8).

JSON baselines use full 33-byte keyset IDs as 66-char hex, 36-char quote ID
strings, and hex-encoded curve points, per the Cashu HTTP API.

---

## 11. LoRa airtime reference

Semtech time-on-air formula, 181-byte raw packet, explicit header, CR 4/5,
8-symbol preamble, CRC enabled, low-data-rate optimisation on for SF ≥ 11. The
181-byte figure is a full-size Meshu frame plus MeshCore packet framing, and
is used consistently for all airtime figures in these documents.

| Preset | Airtime | Raw rate | @10% duty |
|---|---|---|---|
| SF7 / BW250 | 146.0 ms | 1129.8 B/s | 113.0 B/s |
| **SF8 / BW62.5** (MeshCore default) | **1025.0 ms** | **161.0 B/s** | **16.1 B/s** |
| SF10 / BW250 | 840.7 ms | 196.3 B/s | 19.6 B/s |
| SF11 / BW250 | 1681.4 ms | 98.1 B/s | 9.8 B/s |
| SF12 / BW125 | 6070.3 ms | 27.2 B/s | 2.7 B/s |

```python
def airtime(sf, bw_khz, payload, cr=1, preamble=8, crc=1, ih=0):
    bw = bw_khz * 1000.0
    de = 1 if sf >= 11 else 0
    tsym = (2 ** sf) / bw
    num = 8 * payload - 4 * sf + 28 + 16 * crc - 20 * ih
    den = 4 * (sf - de)
    n = 8 + max(math.ceil(num / den) * (cr + 4), 0)
    return (preamble + 4.25) * tsym + n * tsym
```

Implementations SHOULD read actual radio parameters from
`RESP_CODE_SELF_INFO` (bytes 48–57) and compute airtime at runtime rather than
assuming the default preset.

---

## 12. Conformance checklist

A codec implementation should pass all of these before radio integration:

- [ ] `from_exponents(to_exponents(n)) == n` for random `n` in `1..2**63-1`
- [ ] Non-power-of-two rejected as an output amount
- [ ] UUIDv7 pack/unpack round trip, and rejection of non-UUID quote IDs
- [ ] bech32 pack/unpack round trip on real invoices; pad bits zero
- [ ] Non-bech32 characters rejected
- [ ] `MINT_QUOTE` request encodes to the exact 42 bytes of vector 4
- [ ] L1 single-frame vs fragmented header selection at the 161-byte boundary
- [ ] Frame count matches §9.1 for every size in vector 9
- [ ] ACK bitmap encode/decode, including the 255-frame maximum
- [ ] Missing-frame computation from an ACK bitmap
- [ ] Restore bitmap encode/decode round trip
- [ ] NUT-20 digest matches `8012edd6…` for vector 7
- [ ] NUT-20 uses the 36-char quote string, not packed bytes
- [ ] NUT-20 amounts are minimal big-endian, with 0 → empty
- [ ] `ERROR` encodes to the exact 7 bytes of vector 8
- [ ] Unknown trailing CBOR array elements ignored, not rejected
- [ ] Indefinite-length CBOR rejected
- [ ] Outbound frame places payload at offset 2 + `path_len`
- [ ] Inbound frame reads payload from fixed offset 4, no length field
- [ ] `dst` mismatch discards the frame before any crypto
- [ ] `dst` match is never treated as authentication; AEAD still verified
- [ ] MTU computed from live `path_len`, not hardcoded
- [ ] `ATTEMPT` incremented on every retransmission, never a verbatim resend
- [ ] Duplicate `seq` handled idempotently
- [ ] Duplicate `msg_id` returns cached response, does not re-execute
- [ ] L2 nonce never reused across two distinct plaintexts
- [ ] Bootstrap form (epoch `0xFF`, plaintext, no tag) accepted only for opcode `HELLO`
- [ ] Wallet discards any inbound bootstrap-form frame
- [ ] Pinned wallet key is never replaced by a bootstrap `HELLO`
- [ ] No operation sent before the sealed `HELLO` response verifies
- [ ] Sealed `HELLO` `wallet_pubkey` matches the verified L2 identity
- [ ] Gateway state keyed by full `wallet_pubkey`, never by the `src` hash
