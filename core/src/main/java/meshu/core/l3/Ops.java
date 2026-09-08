package meshu.core.l3;

import java.util.ArrayList;
import java.util.List;

/**
 * Operation wire formats (PROTOCOL.md §8) — builders and parsers for the PoC
 * subset (POC-WALLET.md §3): HELLO, KEYSETS, KEYS, CHECKSTATE, SWAP, RESTORE,
 * MINT_INFO, ERROR.
 *
 * <p>Each op has a {@code request(...)} producing an {@link Envelope} and a
 * {@code parse(Response)} decoding the response {@link Envelope}. Decoders
 * ignore unknown trailing elements (§5.2) for forward compatibility.
 */
public final class Ops {

    private Ops() {
    }

    private static Cbor.Value.Uint u(Cbor.Value v, String what) {
        if (!(v instanceof Cbor.Value.Uint x)) {
            throw new IllegalArgumentException("expected uint for " + what);
        }
        return x;
    }

    private static byte[] b(Cbor.Value v, String what) {
        if (!(v instanceof Cbor.Value.Bytes x)) {
            throw new IllegalArgumentException("expected bytes for " + what);
        }
        return x.value();
    }

    private static List<Cbor.Value> arr(Cbor.Value v, String what) {
        if (!(v instanceof Cbor.Value.Array x)) {
            throw new IllegalArgumentException("expected array for " + what);
        }
        return x.items();
    }

    // ============================================================ HELLO (§8.1)

    /**
     * req: {@code [ 0x0D, l1_version, wallet_pubkey, [supported_ops...] ]}
     */
    public static Envelope helloRequest(int l1Version, byte[] walletPubkey32, int[] supportedOps) {
        if (walletPubkey32.length != 32) {
            throw new IllegalArgumentException("wallet_pubkey must be 32 bytes");
        }
        List<Cbor.Value> ops = new ArrayList<>();
        for (int op : supportedOps) {
            ops.add(Cbor.uint(op));
        }
        return Envelope.of(Op.HELLO,
                Cbor.uint(l1Version),
                Cbor.bytes(walletPubkey32),
                Cbor.array(ops));
    }

    /**
     * resp: {@code [ 0x8D, l1_version, gateway_pubkey, [mint_urls...],
     * [nut19_cached_paths...], max_msg, server_time ]}
     */
    public record HelloResponse(
            int l1Version,
            byte[] gatewayPubkey,
            List<String> mintUrls,
            List<String> nut19CachedPaths,
            long maxMsg,
            long serverTime) {
    }

    public static HelloResponse parseHelloResponse(Envelope env) {
        requireOp(env, Op.responseOf(Op.HELLO));
        List<Cbor.Value> f = env.fields();
        return new HelloResponse(
                u(f.get(0), "l1_version").intValue(),
                b(f.get(1), "gateway_pubkey"),
                textList(f.get(2), "mint_urls"),
                textList(f.get(3), "nut19_cached_paths"),
                u(f.get(4), "max_msg").longValue(),
                u(f.get(5), "server_time").longValue());
    }

    public static Envelope helloResponse(int l1Version, byte[] gatewayPubkey32,
                                         List<String> mintUrls, List<String> nut19CachedPaths,
                                         long maxMsg, long serverTime) {
        return Envelope.of(Op.responseOf(Op.HELLO),
                Cbor.uint(l1Version),
                Cbor.bytes(gatewayPubkey32),
                Cbor.array(mintUrls.stream().map(Cbor::text).map(v -> (Cbor.Value) v).toList()),
                Cbor.array(nut19CachedPaths.stream().map(Cbor::text).map(v -> (Cbor.Value) v).toList()),
                Cbor.uint(maxMsg),
                Cbor.uint(serverTime));
    }

    // ============================================================ KEYSETS (§8.10)

    /** req: {@code [ 0x0A, mint_handle ]} */
    public static Envelope keysetsRequest(int mintHandle) {
        return Envelope.of(Op.KEYSETS, Cbor.uint(mintHandle));
    }

    /**
     * resp: {@code [ 0x8A, [ [ s_id, unit, active, input_fee_ppk, final_expiry ], ... ] ]}
     * Response order defines the keyset handles: handle i is entry i.
     */
    public record KeysetEntry(
            byte[] shortId,
            String unit,
            boolean active,
            long inputFeePpk,
            long finalExpiry) {
    }

    public static List<KeysetEntry> parseKeysetsResponse(Envelope env) {
        requireOp(env, Op.responseOf(Op.KEYSETS));
        List<Cbor.Value> rows = arr(env.fields().get(0), "keysets");
        List<KeysetEntry> out = new ArrayList<>();
        for (Cbor.Value row : rows) {
            List<Cbor.Value> e = arr(row, "keyset entry");
            out.add(new KeysetEntry(
                    b(e.get(0), "s_id"),
                    Unit.fromCbor(e.get(1)),
                    u(e.get(2), "active").longValue() != 0,
                    u(e.get(3), "input_fee_ppk").longValue(),
                    u(e.get(4), "final_expiry").longValue()));
        }
        return out;
    }

    public static Envelope keysetsResponse(List<KeysetEntry> entries) {
        List<Cbor.Value> rows = new ArrayList<>();
        for (KeysetEntry e : entries) {
            rows.add(Cbor.array(
                    Cbor.bytes(e.shortId()),
                    Unit.toCbor(e.unit()),
                    Cbor.uint(e.active() ? 1 : 0),
                    Cbor.uint(e.inputFeePpk()),
                    Cbor.uint(e.finalExpiry())));
        }
        return Envelope.of(Op.responseOf(Op.KEYSETS), Cbor.array(rows));
    }

    // ============================================================ KEYS (§8.11)

    /** req: {@code [ 0x0B, keyset_handle, from_exp?, to_exp? ]} */
    public static Envelope keysRequest(int keysetHandle, Integer fromExp, Integer toExp) {
        List<Cbor.Value> fields = new ArrayList<>();
        fields.add(Cbor.uint(keysetHandle));
        fields.add(fromExp == null ? Cbor.Value.Null.INSTANCE : Cbor.uint(fromExp));
        fields.add(toExp == null ? Cbor.Value.Null.INSTANCE : Cbor.uint(toExp));
        return new Envelope(Op.KEYS, fields);
    }

    /** resp: {@code [ 0x8B, s_id, keys_blob ]} */
    public record KeysResponse(byte[] shortId, List<byte[]> keys) {
    }

    public static KeysResponse parseKeysResponse(Envelope env) {
        requireOp(env, Op.responseOf(Op.KEYS));
        List<Cbor.Value> f = env.fields();
        return new KeysResponse(
                b(f.get(0), "s_id"),
                PackedBlobs.unpackKeys(b(f.get(1), "keys_blob")));
    }

    public static Envelope keysResponse(byte[] shortId, List<byte[]> keys) {
        return Envelope.of(Op.responseOf(Op.KEYS),
                Cbor.bytes(shortId),
                Cbor.bytes(PackedBlobs.packKeys(keys)));
    }

    // ============================================================ CHECKSTATE (§8.9)

    /** req: {@code [ 0x09, y_blob ]} */
    public static Envelope checkstateRequest(List<byte[]> ys) {
        return Envelope.of(Op.CHECKSTATE, Cbor.bytes(PackedBlobs.packYs(ys)));
    }

    /** Proof states (§8.9): 2 bits per proof, LSB-first. */
    public static final int STATE_UNSPENT = 0;
    public static final int STATE_PENDING = 1;
    public static final int STATE_SPENT = 2;

    /** resp: {@code [ 0x89, packed_states ]} */
    public static int[] parseCheckstateResponse(Envelope env, int proofCount) {
        requireOp(env, Op.responseOf(Op.CHECKSTATE));
        byte[] packed = b(env.fields().get(0), "packed_states");
        return unpackStates(packed, proofCount);
    }

    public static Envelope checkstateResponse(int[] states) {
        return Envelope.of(Op.responseOf(Op.CHECKSTATE), Cbor.bytes(packStates(states)));
    }

    /** Pack 2-bit states, LSB-first (§8.9). */
    public static byte[] packStates(int[] states) {
        byte[] out = new byte[(states.length * 2 + 7) / 8];
        for (int i = 0; i < states.length; i++) {
            int s = states[i];
            if (s < 0 || s > 2) {
                throw new IllegalArgumentException("state out of range: " + s);
            }
            out[(i * 2) >> 3] |= (byte) (s << ((i * 2) & 7));
        }
        return out;
    }

    public static int[] unpackStates(byte[] packed, int count) {
        int[] out = new int[count];
        for (int i = 0; i < count; i++) {
            out[i] = (packed[(i * 2) >> 3] >> ((i * 2) & 7)) & 0x3;
        }
        return out;
    }

    // ============================================================ SWAP (§8.13)

    /**
     * req: {@code [ 0x08, keyset_handle, inputs_blob, outputs_blob ]}
     */
    public static Envelope swapRequest(int keysetHandle,
                                       List<PackedBlobs.Proof> inputs,
                                       List<PackedBlobs.Output> outputs) {
        return Envelope.of(Op.SWAP,
                Cbor.uint(keysetHandle),
                Cbor.bytes(PackedBlobs.packProofs(inputs)),
                Cbor.bytes(PackedBlobs.packOutputs(outputs)));
    }

    /** resp: {@code [ 0x88, signatures_blob ]} */
    public static List<byte[]> parseSwapResponse(Envelope env) {
        requireOp(env, Op.responseOf(Op.SWAP));
        return PackedBlobs.unpackSignatures(b(env.fields().get(0), "signatures_blob"));
    }

    public static Envelope swapResponse(List<byte[]> signatures) {
        return Envelope.of(Op.responseOf(Op.SWAP), Cbor.bytes(PackedBlobs.packSignatures(signatures)));
    }

    // ============================================================ RESTORE (§8.8)

    /**
     * req: {@code [ 0x07, keyset_handle, counter_start, count, outputs_blob ]}
     */
    public static Envelope restoreRequest(int keysetHandle, long counterStart, int count,
                                          List<PackedBlobs.Output> outputs) {
        return Envelope.of(Op.RESTORE,
                Cbor.uint(keysetHandle),
                Cbor.uint(counterStart),
                Cbor.uint(count),
                Cbor.bytes(PackedBlobs.packOutputs(outputs)));
    }

    /**
     * resp: {@code [ 0x87, hit_bitmap, signatures_blob ]}
     * hit_bitmap bit i set → counter (counter_start + i) was signed; signatures
     * for set bits only, ascending.
     */
    public record RestoreResponse(byte[] hitBitmap, List<byte[]> signatures) {
    }

    public static RestoreResponse parseRestoreResponse(Envelope env) {
        requireOp(env, Op.responseOf(Op.RESTORE));
        List<Cbor.Value> f = env.fields();
        return new RestoreResponse(
                b(f.get(0), "hit_bitmap"),
                PackedBlobs.unpackSignatures(b(f.get(1), "signatures_blob")));
    }

    public static Envelope restoreResponse(byte[] hitBitmap, List<byte[]> signatures) {
        return Envelope.of(Op.responseOf(Op.RESTORE),
                Cbor.bytes(hitBitmap),
                Cbor.bytes(PackedBlobs.packSignatures(signatures)));
    }

    // ============================================================ MINT_INFO (§8.12)

    /** req: {@code [ 0x0C, mint_handle ]} */
    public static Envelope mintInfoRequest(int mintHandle) {
        return Envelope.of(Op.MINT_INFO, Cbor.uint(mintHandle));
    }

    /**
     * resp: {@code [ 0x8C, name?, [ nut_numbers... ], min_amount, max_amount,
     * [ method_unit_pairs... ], nut19_ttl? ]}
     */
    public record MintInfoResponse(
            String name,
            List<Integer> nutNumbers,
            long minAmount,
            long maxAmount,
            List<String> methodUnitPairs,
            Long nut19Ttl) {
    }

    public static MintInfoResponse parseMintInfoResponse(Envelope env) {
        requireOp(env, Op.responseOf(Op.MINT_INFO));
        List<Cbor.Value> f = env.fields();
        String name = f.get(0) instanceof Cbor.Value.Text t ? t.value() : null;
        List<Integer> nuts = new ArrayList<>();
        for (Cbor.Value v : arr(f.get(1), "nut_numbers")) {
            nuts.add(u(v, "nut").intValue());
        }
        List<String> pairs = textList(f.get(4), "method_unit_pairs");
        Long ttl = f.size() > 5 && f.get(5) instanceof Cbor.Value.Uint t ? t.longValue() : null;
        return new MintInfoResponse(name, nuts,
                u(f.get(2), "min_amount").longValue(),
                u(f.get(3), "max_amount").longValue(),
                pairs, ttl);
    }

    // ============================================================ ERROR (§8.14, §10)

    /**
     * resp: {@code [ 0xFE, code, detail_kind, detail? ]}
     * detail_kind: 0 = none, 1 = text, 2 = bytes.
     */
    public record ErrorResponse(long code, int detailKind, byte[] detailBytes, String detailText) {
    }

    public static Envelope error(long code) {
        return Envelope.of(Op.ERROR, Cbor.uint(code), Cbor.uint(0));
    }

    public static Envelope errorText(long code, String detail) {
        return Envelope.of(Op.ERROR, Cbor.uint(code), Cbor.uint(1), Cbor.text(detail));
    }

    public static ErrorResponse parseError(Envelope env) {
        requireOp(env, Op.ERROR);
        List<Cbor.Value> f = env.fields();
        long code = u(f.get(0), "code").longValue();
        int kind = u(f.get(1), "detail_kind").intValue();
        byte[] bytes = null;
        String text = null;
        if (kind == 1 && f.size() > 2) {
            text = ((Cbor.Value.Text) f.get(2)).value();
        } else if (kind == 2 && f.size() > 2) {
            bytes = b(f.get(2), "detail");
        }
        return new ErrorResponse(code, kind, bytes, text);
    }

    // ============================================================ helpers

    private static void requireOp(Envelope env, int expected) {
        if (env.opcode() != expected) {
            throw new IllegalArgumentException(
                    "expected opcode 0x%02x, got 0x%02x".formatted(expected, env.opcode()));
        }
    }

    private static List<String> textList(Cbor.Value v, String what) {
        List<String> out = new ArrayList<>();
        for (Cbor.Value item : arr(v, what)) {
            if (!(item instanceof Cbor.Value.Text t)) {
                throw new IllegalArgumentException("expected text in " + what);
            }
            out.add(t.value());
        }
        return out;
    }
}
