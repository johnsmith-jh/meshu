package meshu.core.l3;

/**
 * BOLT11 invoice bech32 5-bit repacking (PROTOCOL.md §6.3, TESTVECTORS.md vector 3).
 *
 * <p>A BOLT11 invoice is bech32: every character after the separator carries
 * exactly 5 bits. Repacking to 5-bit groups saves 31–37%. The transform is a
 * pure bit repack — no checksum recomputation, no semantic parsing — and is
 * exactly reversible. Trailing pad bits are zero.
 *
 * <p>Wire form: {@code hrp (text) ‖ nvals (uint) ‖ packed (bytes)}.
 */
public final class Bech32Repack {

    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final int[] INV = new int[128];

    static {
        java.util.Arrays.fill(INV, -1);
        for (int i = 0; i < CHARSET.length(); i++) {
            INV[CHARSET.charAt(i)] = i;
        }
    }

    private Bech32Repack() {
    }

    /** Result of packing: hrp, number of 5-bit data chars, and packed bytes. */
    public record Packed(String hrp, int nvals, byte[] packed) {
        public Packed {
            packed = packed.clone();
        }

        @Override
        public byte[] packed() {
            return packed.clone();
        }
    }

    /**
     * Pack an invoice into (hrp, nvals, packed). The separator is the last '1'
     * (the HRP may itself contain '1', e.g. "lnbc100n").
     *
     * @throws IllegalArgumentException on non-bech32 characters or missing separator
     */
    public static Packed pack(String invoice) {
        int sep = invoice.lastIndexOf('1');
        if (sep < 0) {
            throw new IllegalArgumentException("no bech32 separator '1' in invoice");
        }
        String hrp = invoice.substring(0, sep);
        String data = invoice.substring(sep + 1);

        int nvals = data.length();
        byte[] out = new byte[(nvals * 5 + 7) / 8];
        int acc = 0, bits = 0, outPos = 0;
        for (char c : data.toCharArray()) {
            int v = c < 128 ? INV[c] : -1;
            if (v < 0) {
                throw new IllegalArgumentException("non-bech32 character: '" + c + "'");
            }
            acc = (acc << 5) | v;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                out[outPos++] = (byte) (acc >> bits);
            }
        }
        if (bits > 0) {
            out[outPos] = (byte) (acc << (8 - bits)); // pad bits MUST be zero
        }
        return new Packed(hrp, nvals, out);
    }

    /** Reconstruct the invoice from (hrp, nvals, packed). Exactly reversible. */
    public static String unpack(String hrp, int nvals, byte[] packed) {
        StringBuilder sb = new StringBuilder(hrp).append('1');
        int acc = 0, bits = 0, produced = 0;
        for (byte b : packed) {
            acc = (acc << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5 && produced < nvals) {
                bits -= 5;
                sb.append(CHARSET.charAt((acc >> bits) & 0x1F));
                produced++;
            }
        }
        if (produced != nvals) {
            throw new IllegalArgumentException("packed data too short for nvals=" + nvals);
        }
        return sb.toString();
    }

    /** Round-trip check (§6.3: implementations MUST verify before transmitting). */
    public static boolean roundTrips(String invoice) {
        try {
            Packed p = pack(invoice);
            return unpack(p.hrp(), p.nvals(), p.packed()).equals(invoice);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
