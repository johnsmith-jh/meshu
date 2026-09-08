package meshu.core.l3;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * TESTVECTORS.md vector 1 (§6.1): exponent amount codec.
 */
class ExponentsTest {

    @Test
    void vectorValues() {
        assertArrayEquals(new int[]{0}, Exponents.toExponents(1));
        assertArrayEquals(new int[]{1}, Exponents.toExponents(2));
        assertArrayEquals(new int[]{3}, Exponents.toExponents(8));
        assertArrayEquals(new int[]{3, 5, 6, 7, 8, 9}, Exponents.toExponents(1000));
        assertArrayEquals(new int[]{5, 7, 9, 10, 15, 16}, Exponents.toExponents(100000));
    }

    @Test
    void vectorSums() {
        assertEquals(1000, Exponents.fromExponents(new int[]{3, 5, 6, 7, 8, 9}));
        assertEquals(100000, Exponents.fromExponents(new int[]{5, 7, 9, 10, 15, 16}));
    }

    /** Conformance: from_exponents(to_exponents(n)) == n for random n in 1..2^63-1. */
    @Test
    void roundTripRandom() {
        Random rng = new Random(42);
        for (int i = 0; i < 10000; i++) {
            long n = rng.nextLong(1, Long.MAX_VALUE);
            assertEquals(n, Exponents.fromExponents(Exponents.toExponents(n)));
        }
    }

    @Test
    void rejectsNonPowerOfTwoAsOutput() {
        assertThrows(IllegalArgumentException.class, () -> Exponents.requirePowerOfTwo(3));
        assertThrows(IllegalArgumentException.class, () -> Exponents.requirePowerOfTwo(0));
        assertThrows(IllegalArgumentException.class, () -> Exponents.requirePowerOfTwo(1000));
        assertEquals(10, Exponents.requirePowerOfTwo(1024));
        assertEquals(0, Exponents.requirePowerOfTwo(1));
    }

    @Test
    void amountOfBigInteger() {
        assertEquals(BigInteger.valueOf(1), Exponents.amountOf(0));
        assertEquals(BigInteger.valueOf(512), Exponents.amountOf(9));
        assertThrows(IllegalArgumentException.class, () -> Exponents.amountOf(64));
    }
}
