package meshu.core.l3;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Op wire-format round trips (PROTOCOL.md §8) + vector 5 (restore bitmap).
 */
class OpsTest {

    private static byte[] fill(int len, int seed) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) {
            b[i] = (byte) (seed + i);
        }
        return b;
    }

    /** Encode → decode preserves opcode and fields. */
    private static Envelope roundTrip(Envelope env) {
        return Envelope.decode(env.encode());
    }

    @Test
    void helloRoundTrip() {
        Envelope req = Ops.helloRequest(1, fill(32, 0), new int[]{Op.HELLO, Op.KEYSETS, Op.SWAP});
        Envelope decoded = roundTrip(req);
        assertEquals(Op.HELLO, decoded.opcode());
        assertEquals(1, ((Cbor.Value.Uint) decoded.fields().get(0)).intValue());
        assertEquals(32, ((Cbor.Value.Bytes) decoded.fields().get(1)).value().length);

        Ops.HelloResponse resp = new Ops.HelloResponse(
                1, fill(32, 0), List.of("https://mint.minibits.cash/Bitcoin"),
                List.of("/v1/mint/bolt11"), 40000, 1750000000L);
        Ops.HelloResponse parsed = Ops.parseHelloResponse(roundTrip(
                Ops.helloResponse(1, fill(32, 0), resp.mintUrls(), resp.nut19CachedPaths(),
                        resp.maxMsg(), resp.serverTime())));
        assertEquals(1, parsed.l1Version());
        assertEquals(List.of("https://mint.minibits.cash/Bitcoin"), parsed.mintUrls());
        assertEquals(40000, parsed.maxMsg());
    }

    @Test
    void keysetsRoundTrip() {
        List<Ops.KeysetEntry> entries = List.of(
                new Ops.KeysetEntry(fill(8, 0), "sat", true, 0, 0),
                new Ops.KeysetEntry(fill(8, 8), "sat", false, 100, 1750000000L));
        Envelope resp = Ops.keysetsResponse(entries);
        List<Ops.KeysetEntry> parsed = Ops.parseKeysetsResponse(roundTrip(resp));
        assertEquals(2, parsed.size());
        assertTrue(parsed.get(0).active());
        assertFalse(parsed.get(1).active());
        assertEquals(100, parsed.get(1).inputFeePpk());
        assertArrayEquals(entries.get(1).shortId(), parsed.get(1).shortId());
    }

    @Test
    void keysRoundTrip() {
        List<byte[]> keys = new java.util.ArrayList<>();
        for (int i = 0; i < 64; i++) {
            keys.add(fill(33, i));
        }
        Ops.KeysResponse parsed = Ops.parseKeysResponse(roundTrip(
                Ops.keysResponse(fill(8, 0), keys)));
        assertEquals(64, parsed.keys().size());
        assertArrayEquals(keys.get(63), parsed.keys().get(63));

        // Range request encoding: from_exp/to_exp optional.
        Envelope req = Ops.keysRequest(0, 0, 16);
        assertEquals(3, req.fields().size());
        Envelope noRange = Ops.keysRequest(0, null, null);
        assertEquals(3, noRange.fields().size());
        assertInstanceOf(Cbor.Value.Null.class, noRange.fields().get(1));
    }

    @Test
    void checkstateRoundTrip() {
        List<byte[]> ys = List.of(fill(33, 0), fill(33, 33), fill(33, 66));
        Envelope req = Ops.checkstateRequest(ys);
        Envelope decoded = roundTrip(req);
        assertEquals(Op.CHECKSTATE, decoded.opcode());

        int[] states = {Ops.STATE_UNSPENT, Ops.STATE_PENDING, Ops.STATE_SPENT};
        int[] parsed = Ops.parseCheckstateResponse(roundTrip(Ops.checkstateResponse(states)), 3);
        assertArrayEquals(states, parsed);
    }

    @Test
    void packedStatesLsbFirst() {
        // 2 bits per proof, LSB-first: [UNSPENT(0), PENDING(1), SPENT(2), SPENT(2)]
        int[] states = {0, 1, 2, 2};
        byte[] packed = Ops.packStates(states);
        assertEquals(1, packed.length);
        // bits (LSB first): 00 01 10 10 → 0b10_10_01_00 = 0xA4
        assertEquals((byte) 0xA4, packed[0]);
        assertArrayEquals(states, Ops.unpackStates(packed, 4));
    }

    @Test
    void swapRoundTrip() {
        List<PackedBlobs.Proof> inputs = List.of(
                new PackedBlobs.Proof(3, fill(32, 0), fill(33, 32)));
        List<PackedBlobs.Output> outputs = List.of(
                new PackedBlobs.Output(2, fill(33, 65)),
                new PackedBlobs.Output(1, fill(33, 98)));
        Envelope req = Ops.swapRequest(0, inputs, outputs);
        Envelope decoded = roundTrip(req);
        assertEquals(Op.SWAP, decoded.opcode());

        List<byte[]> sigs = List.of(fill(33, 131), fill(33, 164));
        List<byte[]> parsed = Ops.parseSwapResponse(roundTrip(Ops.swapResponse(sigs)));
        assertEquals(2, parsed.size());
        assertArrayEquals(sigs.get(1), parsed.get(1));
    }

    @Test
    void restoreRoundTrip() {
        List<PackedBlobs.Output> outputs = List.of(new PackedBlobs.Output(0, fill(33, 0)));
        Envelope req = Ops.restoreRequest(0, 0, 100, outputs);
        Envelope decoded = roundTrip(req);
        assertEquals(Op.RESTORE, decoded.opcode());

        // Vector 5: hits at counters 3, 7, 64, 99 of 100 → bitmap 88 00…01 00…08.
        byte[] bitmap = new byte[13];
        bitmap[0] = (byte) 0x88;
        bitmap[8] = 0x01;
        bitmap[12] = 0x08;
        List<byte[]> sigs = List.of(fill(33, 0), fill(33, 1), fill(33, 2), fill(33, 3));
        Ops.RestoreResponse parsed = Ops.parseRestoreResponse(roundTrip(Ops.restoreResponse(bitmap, sigs)));
        assertArrayEquals(bitmap, parsed.hitBitmap());
        assertEquals(4, parsed.signatures().size());
    }

    /** Vector 5: restore hit bitmap byte layout (§8.8). */
    @Test
    void vector5RestoreHitBitmap() {
        // counters 3, 7, 64, 99 of a 100-count batch.
        byte[] bm = new byte[(100 + 7) / 8];
        for (int c : new int[]{3, 7, 64, 99}) {
            bm[c >> 3] |= (byte) (1 << (c & 7));
        }
        assertEquals(13, bm.length);
        assertEquals(java.util.HexFormat.of().formatHex(bm), "88000000000000000100000008");
    }

    @Test
    void mintInfoRoundTrip() {
        Envelope req = Ops.mintInfoRequest(0);
        assertEquals(Op.MINT_INFO, roundTrip(req).opcode());

        // Build a response via the parse path (no builder needed for PoC receive side).
        Cbor.Value resp = Cbor.array(
                Cbor.uint(Op.responseOf(Op.MINT_INFO)),
                Cbor.text("minibits"),
                Cbor.array(List.of(Cbor.uint(4), Cbor.uint(5))),
                Cbor.uint(1),
                Cbor.uint(100000),
                Cbor.array(List.of(Cbor.text("bolt11/sat"))),
                Cbor.uint(3600));
        Ops.MintInfoResponse parsed = Ops.parseMintInfoResponse(Envelope.decode(Cbor.encode(resp)));
        assertEquals("minibits", parsed.name());
        assertEquals(List.of(4, 5), parsed.nutNumbers());
        assertEquals(100000, parsed.maxAmount());
        assertEquals(3600, parsed.nut19Ttl());
    }

    @Test
    void errorRoundTrip() {
        Ops.ErrorResponse bare = Ops.parseError(roundTrip(Ops.error(20001)));
        assertEquals(20001, bare.code());
        assertEquals(0, bare.detailKind());
        assertNull(bare.detailText());

        Ops.ErrorResponse withText = Ops.parseError(roundTrip(Ops.errorText(11001, "proofs already spent")));
        assertEquals(11001, withText.code());
        assertEquals(1, withText.detailKind());
        assertEquals("proofs already spent", withText.detailText());
    }

    @Test
    void wrongOpcodeRejected() {
        Envelope hello = Ops.helloRequest(1, fill(32, 0), new int[]{Op.HELLO});
        assertThrows(IllegalArgumentException.class, () -> Ops.parseKeysetsResponse(hello));
    }
}
