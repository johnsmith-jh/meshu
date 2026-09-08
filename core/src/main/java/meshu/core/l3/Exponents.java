package meshu.core.l3;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Amounts as power-of-two exponents (PROTOCOL.md §6.1, TESTVECTORS.md vector 1).
 *
 * <p>Cashu denominations are always powers of two: {@code amount = 1 << exponent}.
 * A target amount decomposes into the set bits of its binary representation,
 * emitted ascending. Aggregate amounts (invoice totals, fees) are ordinary CBOR
 * integers and do not use this codec.
 */
public final class Exponents {

    private Exponents() {
    }

    /** Decompose an amount into its set-bit exponents, ascending. */
    public static int[] toExponents(long amount) {
        if (amount < 0) {
            throw new IllegalArgumentException("negative amount: " + amount);
        }
        List<Integer> out = new ArrayList<>();
        for (int i = 0; i < 63; i++) {
            if ((amount >> i & 1) != 0) {
                out.add(i);
            }
        }
        return out.stream().mapToInt(Integer::intValue).toArray();
    }

    /** Recompose an amount from exponents. */
    public static long fromExponents(int[] exponents) {
        long amount = 0;
        for (int e : exponents) {
            if (e < 0 || e > 62) {
                throw new IllegalArgumentException("exponent out of range: " + e);
            }
            amount += 1L << e;
        }
        return amount;
    }

    /**
     * Exponent for a single output amount, which MUST be a power of two
     * (§6.1: "Any amount that is not a power of two MUST be rejected as an
     * output amount").
     */
    public static int requirePowerOfTwo(long amount) {
        if (amount <= 0 || (amount & (amount - 1)) != 0) {
            throw new IllegalArgumentException("output amount not a power of two: " + amount);
        }
        return Long.numberOfTrailingZeros(amount);
    }

    /** Amount for an exponent as BigInteger (exponents up to 63 per spec). */
    public static BigInteger amountOf(int exponent) {
        if (exponent < 0 || exponent > 63) {
            throw new IllegalArgumentException("exponent out of range: " + exponent);
        }
        return BigInteger.ONE.shiftLeft(exponent);
    }
}
