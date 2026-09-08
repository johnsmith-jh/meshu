package meshu.core.l3;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * TESTVECTORS.md vector 7 (§9.2): NUT-20 msg_to_sign — the three-trap construction.
 */
class Nut20Test {

    private static final HexFormat HEX = HexFormat.of();

    private static final String QUOTE = "019e6d5a-2347-7000-8322-05d51d498303";

    /** Vector 7: full msg_to_sign byte layout. */
    @Test
    void vector7MsgToSign() {
        byte[] b0 = new byte[33];
        b0[0] = 0x02;
        java.util.Arrays.fill(b0, 1, 33, (byte) 0x11);
        byte[] b1 = new byte[33];
        b1[0] = 0x02;
        java.util.Arrays.fill(b1, 1, 33, (byte) 0x22);

        List<Nut20.SigningOutput> outputs = List.of(
                new Nut20.SigningOutput(BigInteger.valueOf(8), b0),
                new Nut20.SigningOutput(BigInteger.valueOf(2), b1));

        byte[] msg = Nut20.msgToSign(QUOTE, outputs);
        assertEquals(145, msg.length);

        String expected =
                "43617368755f4d696e7451756f74655369675f7631"
                        + "0000002430313965366435612d323334372d373030302d383332322d303564353164343938333033"
                        + "0000000108"
                        + "00000021" + "02" + "11".repeat(32)
                        + "0000000102"
                        + "00000021" + "02" + "22".repeat(32);
        assertEquals(expected, HEX.formatHex(msg));
    }

    /** Vector 7: SHA-256 digest must match 8012edd6… */
    @Test
    void vector7Digest() {
        byte[] b0 = new byte[33];
        b0[0] = 0x02;
        java.util.Arrays.fill(b0, 1, 33, (byte) 0x11);
        byte[] b1 = new byte[33];
        b1[0] = 0x02;
        java.util.Arrays.fill(b1, 1, 33, (byte) 0x22);

        byte[] digest = Nut20.digest(QUOTE, List.of(
                new Nut20.SigningOutput(BigInteger.valueOf(8), b0),
                new Nut20.SigningOutput(BigInteger.valueOf(2), b1)));

        assertEquals("8012edd6136194417e02f18b5c3aad2d9bff8d611768b19d8fa1171ee2206f7a",
                HEX.formatHex(digest));
    }

    /** Trap 1: sign the 36-char string, not the 16-byte packed UUID. */
    @Test
    void trap1QuoteIsStringNotPacked() {
        byte[] b = new byte[33];
        b[0] = 0x02;
        // The quote must be embedded as its UTF-8 string form with len32 = 36.
        byte[] quoteBytes = QUOTE.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        assertEquals(36, quoteBytes.length);

        // Prefix (21) + len32(4) places the quote string at offset 25.
        byte[] withString = Nut20.msgToSign(QUOTE, List.of(
                new Nut20.SigningOutput(BigInteger.ONE, b)));
        // len32(36) = 0x00000024 at bytes 21..24.
        assertEquals(0x00, withString[21]);
        assertEquals(0x00, withString[22]);
        assertEquals(0x00, withString[23]);
        assertEquals(0x24, withString[24]);

        // A packed-UUID signer would embed 16 bytes (len32=16) — a different, rejected digest.
        byte[] packed = QuoteId.parse(QUOTE) instanceof QuoteId.Form.Packed p ? p.bytes() : null;
        assertNotNull(packed);
        assertEquals(16, packed.length);
    }

    /** Trap 2: amounts are minimal big-endian — 0→empty, 1→0x01, 256→0x0100. */
    @Test
    void trap2MinimalBigEndian() {
        assertArrayEquals(new byte[0], Nut20.minimalBigEndian(BigInteger.ZERO));
        assertArrayEquals(new byte[]{0x01}, Nut20.minimalBigEndian(BigInteger.ONE));
        assertArrayEquals(new byte[]{0x01, 0x00}, Nut20.minimalBigEndian(BigInteger.valueOf(256)));
        assertArrayEquals(new byte[]{0x08}, Nut20.minimalBigEndian(BigInteger.valueOf(8)));
        assertArrayEquals(new byte[]{(byte) 0xff}, Nut20.minimalBigEndian(BigInteger.valueOf(255)));
        // No leading zero byte for sign.
        assertArrayEquals(new byte[]{(byte) 0x80}, Nut20.minimalBigEndian(BigInteger.valueOf(128)));
    }

    /** msgToSignFromOutputs expands exponents to absolute amounts. */
    @Test
    void fromOutputsExpandsExponents() {
        byte[] b = new byte[33];
        b[0] = 0x02;
        List<PackedBlobs.Output> outputs = List.of(new PackedBlobs.Output(3, b)); // 2^3 = 8
        byte[] viaOutputs = Nut20.msgToSignFromOutputs(QUOTE, outputs);
        byte[] direct = Nut20.msgToSign(QUOTE, List.of(
                new Nut20.SigningOutput(BigInteger.valueOf(8), b)));
        assertArrayEquals(direct, viaOutputs);
    }
}
