package meshu.core.l3;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * TESTVECTORS.md §6.7: packed blob formats.
 */
class PackedBlobsTest {

    private static byte[] fill(int len, int seed) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) {
            b[i] = (byte) (seed + i);
        }
        return b;
    }

    @Test
    void outputsRoundTrip() {
        List<PackedBlobs.Output> outputs = List.of(
                new PackedBlobs.Output(3, fill(33, 0)),
                new PackedBlobs.Output(9, fill(33, 100)));
        byte[] blob = PackedBlobs.packOutputs(outputs);
        assertEquals(2 * 34, blob.length);
        List<PackedBlobs.Output> back = PackedBlobs.unpackOutputs(blob);
        assertEquals(2, back.size());
        assertEquals(3, back.get(0).exponent());
        assertArrayEquals(outputs.get(0).blindedMessage(), back.get(0).blindedMessage());
        assertEquals(9, back.get(1).exponent());
    }

    @Test
    void outputsRejectBadLength() {
        assertThrows(IllegalArgumentException.class,
                () -> PackedBlobs.unpackOutputs(new byte[35]));
        assertThrows(IllegalArgumentException.class,
                () -> new PackedBlobs.Output(0, new byte[32]));
    }

    @Test
    void signaturesRoundTrip() {
        List<byte[]> sigs = List.of(fill(33, 0), fill(33, 50), fill(33, 100));
        byte[] blob = PackedBlobs.packSignatures(sigs);
        assertEquals(99, blob.length);
        List<byte[]> back = PackedBlobs.unpackSignatures(blob);
        assertEquals(3, back.size());
        assertArrayEquals(sigs.get(2), back.get(2));
    }

    @Test
    void proofsRoundTrip() {
        List<PackedBlobs.Proof> proofs = List.of(
                new PackedBlobs.Proof(3, fill(32, 0), fill(33, 32)),
                new PackedBlobs.Proof(5, fill(32, 64), fill(33, 96)));
        byte[] blob = PackedBlobs.packProofs(proofs);
        assertEquals(2 * 66, blob.length);
        List<PackedBlobs.Proof> back = PackedBlobs.unpackProofs(blob);
        assertEquals(2, back.size());
        assertEquals(3, back.get(0).exponent());
        assertArrayEquals(proofs.get(0).secret(), back.get(0).secret());
        assertArrayEquals(proofs.get(1).c(), back.get(1).c());
    }

    @Test
    void proofsRejectBadSecretLength() {
        // NUT-10 well-known secrets (not 32 bytes) cannot use the packed blob (§6.7).
        assertThrows(IllegalArgumentException.class,
                () -> new PackedBlobs.Proof(0, new byte[40], fill(33, 0)));
    }

    @Test
    void keysBlobIs64Entries() {
        List<byte[]> keys = new java.util.ArrayList<>();
        for (int i = 0; i < 64; i++) {
            keys.add(fill(33, i));
        }
        byte[] blob = PackedBlobs.packKeys(keys);
        assertEquals(64 * 33, blob.length);
        assertEquals(64, PackedBlobs.unpackKeys(blob).size());

        assertThrows(IllegalArgumentException.class,
                () -> PackedBlobs.packKeys(keys.subList(0, 63)));
        assertThrows(IllegalArgumentException.class,
                () -> PackedBlobs.unpackKeys(new byte[64 * 33 - 1]));
    }

    @Test
    void ysShareSignatureLayout() {
        List<byte[]> ys = List.of(fill(33, 7), fill(33, 9));
        assertArrayEquals(PackedBlobs.packSignatures(ys), PackedBlobs.packYs(ys));
        assertEquals(2, PackedBlobs.unpackYs(PackedBlobs.packYs(ys)).size());
    }
}
