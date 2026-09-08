package meshu.core.l3;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/**
 * TESTVECTORS.md vector 3 (§6.3): BOLT11 bech32 5-bit repack.
 */
class Bech32RepackTest {

    private static final HexFormat HEX = HexFormat.of();

    private static final String INVOICE =
            "lnbc100n1p3kdrv5sp5lpdxzghe5j67qqpzry9x8gf2tvdw0s3jn54khce6mua7lqpzry9x8gf2tvdw0s3jn54khce6mua7l";

    @Test
    void vector3Packing() {
        Bech32Repack.Packed p = Bech32Repack.pack(INVOICE);
        assertEquals("lnbc100n", p.hrp());
        assertEquals(87, p.nvals());
        assertEquals(55, p.packed().length);
        String expected = "0c6cd1b2900d3e169848be692d780008864298e84a96c6b9f08ca74adaf8ceb7"
                + "cefbe008864298e84a96c6b9f08ca74adaf8ceb7cefbe0";
        assertEquals(expected, HEX.formatHex(p.packed()));
    }

    @Test
    void roundTripExact() {
        Bech32Repack.Packed p = Bech32Repack.pack(INVOICE);
        assertEquals(INVOICE, Bech32Repack.unpack(p.hrp(), p.nvals(), p.packed()));
        assertTrue(Bech32Repack.roundTrips(INVOICE));
    }

    @Test
    void separatorIsLastOne() {
        // HRP itself contains '1' ("lnbc100n"); rpartition semantics required (§6.3).
        Bech32Repack.Packed p = Bech32Repack.pack(INVOICE);
        assertEquals("lnbc100n", p.hrp());
        assertFalse(p.hrp().endsWith("1"));
    }

    @Test
    void rejectsNonBech32Character() {
        // '1', 'b', 'i', 'o' are excluded from bech32 charset.
        assertThrows(IllegalArgumentException.class,
                () -> Bech32Repack.pack("lnbc1p3kdrv5b"));  // 'b' not in data charset position
        assertThrows(IllegalArgumentException.class,
                () -> Bech32Repack.pack("lnbc1p3kdrv5i"));
        assertThrows(IllegalArgumentException.class,
                () -> Bech32Repack.pack("lnbc1p3kdrv5o"));
    }

    @Test
    void rejectsMissingSeparator() {
        // No '1' at all → no separator.
        assertThrows(IllegalArgumentException.class, () -> Bech32Repack.pack("lnbc000n"));
    }

    @Test
    void trailingPadBitsZero() {
        // nvals=87 → 87*5 = 435 bits → 55 bytes = 440 bits → 5 pad bits, must be zero.
        Bech32Repack.Packed p = Bech32Repack.pack(INVOICE);
        int padBits = 55 * 8 - 87 * 5;
        int last = p.packed()[54] & 0xFF;
        assertEquals(0, last & ((1 << padBits) - 1), "pad bits must be zero");
    }
}
