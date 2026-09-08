package meshu.core.l3;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * NUT-20 mint quote signature construction (PROTOCOL.md §9.2, TESTVECTORS.md
 * vector 7). The most error-prone construction in the protocol — three traps:
 *
 * <ol>
 *   <li><b>quote is the 36-char UTF-8 string</b>, not the 16-byte packed UUID.
 *       Re-expand before signing.</li>
 *   <li><b>amounts are minimal big-endian</b>, so 0 → empty, 1 → 0x01,
 *       256 → 0x0100. Expand the exponent to the amount first.</li>
 *   <li><b>output order must match the request exactly</b> — the same order as
 *       outputs_blob.</li>
 * </ol>
 *
 * <pre>
 * msg_to_sign = "Cashu_MintQuoteSig_v1"        (21 bytes ASCII, not length-prefixed)
 *             ‖ len32(quote) ‖ quote           (UTF-8 string)
 *             ‖ for each output, in request order:
 *                   len32(amount) ‖ amount     (minimal big-endian)
 *                 ‖ len32(B_)     ‖ B_         (33 raw bytes)
 * </pre>
 *
 * Then sign SHA-256(msg_to_sign) with BIP-340 Schnorr.
 */
public final class Nut20 {

    private static final byte[] PREFIX = "Cashu_MintQuoteSig_v1".getBytes(StandardCharsets.US_ASCII);

    private Nut20() {
    }

    /** One output for signing: amount (as absolute value) and blinded message. */
    public record SigningOutput(BigInteger amount, byte[] blindedMessage) {
        public SigningOutput {
            if (blindedMessage.length != 33) {
                throw new IllegalArgumentException("B_ must be 33 bytes");
            }
            blindedMessage = blindedMessage.clone();
        }

        @Override
        public byte[] blindedMessage() {
            return blindedMessage.clone();
        }
    }

    /**
     * Build {@code msg_to_sign} from the quote string and the outputs.
     *
     * @param quoteString the 36-char quote string (re-expanded from packed form)
     * @param outputs     the outputs in request order, amounts as absolute values
     */
    public static byte[] msgToSign(String quoteString, List<SigningOutput> outputs) {
        ByteArrayOutputStream m = new ByteArrayOutputStream();
        m.writeBytes(PREFIX);
        byte[] q = quoteString.getBytes(StandardCharsets.UTF_8);
        writeLen32(m, q.length);
        m.writeBytes(q);
        for (SigningOutput o : outputs) {
            byte[] amount = minimalBigEndian(o.amount());
            writeLen32(m, amount.length);
            m.writeBytes(amount);
            writeLen32(m, o.blindedMessage().length);
            m.writeBytes(o.blindedMessage());
        }
        return m.toByteArray();
    }

    /** Build msg_to_sign from packed-blob outputs, expanding exponents to amounts. */
    public static byte[] msgToSignFromOutputs(String quoteString, List<PackedBlobs.Output> outputs) {
        List<SigningOutput> so = outputs.stream()
                .map(o -> new SigningOutput(Exponents.amountOf(o.exponent()), o.blindedMessage()))
                .toList();
        return msgToSign(quoteString, so);
    }

    /** The 32-byte digest to BIP-340 sign. */
    public static byte[] digest(String quoteString, List<SigningOutput> outputs) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(msgToSign(quoteString, outputs));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Minimal big-endian encoding: 0 → empty, 1 → 0x01, 256 → 0x0100 (§9.2 trap 2). */
    static byte[] minimalBigEndian(BigInteger amount) {
        if (amount.signum() < 0) {
            throw new IllegalArgumentException("negative amount");
        }
        if (amount.signum() == 0) {
            return new byte[0];
        }
        // BigInteger.toByteArray() may add a leading zero for sign; strip it.
        byte[] b = amount.toByteArray();
        if (b.length > 1 && b[0] == 0) {
            byte[] out = new byte[b.length - 1];
            System.arraycopy(b, 1, out, 0, out.length);
            return out;
        }
        return b;
    }

    private static void writeLen32(ByteArrayOutputStream m, int len) {
        m.write((len >> 24) & 0xFF);
        m.write((len >> 16) & 0xFF);
        m.write((len >> 8) & 0xFF);
        m.write(len & 0xFF);
    }
}
