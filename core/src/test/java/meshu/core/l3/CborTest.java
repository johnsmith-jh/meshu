package meshu.core.l3;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * TESTVECTORS.md vectors 4, 8 (§5, §8.2, §10): CBOR envelope + canonical form.
 */
class CborTest {

    private static final HexFormat HEX = HexFormat.of();

    /** Vector 4: MINT_QUOTE request must encode to exactly 42 bytes. */
    @Test
    void mintQuoteRequestEncodesToVector4() {
        // [ 0x01, 1, 1000, 0, h'02a1a1…a1' (33 bytes) ]
        byte[] quotePubkey = new byte[33];
        quotePubkey[0] = 0x02;
        java.util.Arrays.fill(quotePubkey, 1, 33, (byte) 0xa1);

        Envelope env = Envelope.of(Op.MINT_QUOTE,
                Cbor.uint(1),            // mint_handle
                Cbor.uint(1000),         // amount
                Cbor.uint(0),            // unit sat
                Cbor.bytes(quotePubkey)); // quote_pubkey

        byte[] encoded = env.encode();
        String expected = "8501011903e800582102" + "a1".repeat(32);
        assertEquals(expected, HEX.formatHex(encoded));
        assertEquals(42, encoded.length);
    }

    /** Vector 8: ERROR response must encode to exactly 7 bytes. */
    @Test
    void errorResponseEncodesToVector8() {
        // [0xFE, 20001, 0]
        Envelope env = Envelope.of(Op.ERROR, Cbor.uint(20001), Cbor.uint(0));
        byte[] encoded = env.encode();
        assertEquals("8318fe194e2100", HEX.formatHex(encoded));
        assertEquals(7, encoded.length);
    }

    /** Envelope decode recovers opcode as first array element. */
    @Test
    void envelopeRoundTrip() {
        Envelope env = Envelope.of(Op.HELLO,
                Cbor.uint(1), Cbor.bytes(new byte[32]), Cbor.array(Cbor.uint(0x0D)));
        Envelope decoded = Envelope.decode(env.encode());
        assertEquals(Op.HELLO, decoded.opcode());
        assertEquals(Op.HELLO, decoded.opcodeHint());
        assertEquals(3, decoded.fields().size());
    }

    /** §5.2: decoders ignore unknown trailing array elements. */
    @Test
    void ignoresUnknownTrailingElements() {
        // A v2 message with an extra field must still decode as a v1 envelope.
        byte[] v2 = Cbor.encode(Cbor.array(
                Cbor.uint(Op.KEYSETS), Cbor.uint(0), Cbor.uint(999) /* future field */));
        Envelope env = Envelope.decode(v2);
        assertEquals(Op.KEYSETS, env.opcode());
        assertEquals(2, env.fields().size()); // caller reads what it knows
    }

    /** §5.2: indefinite-length items MUST be rejected. */
    @Test
    void rejectsIndefiniteLength() {
        // 0x9F = indefinite-length array start
        assertThrows(IllegalArgumentException.class,
                () -> Cbor.decode(new byte[]{(byte) 0x9F, 0x01, (byte) 0xFF}));
    }

    /** §5.1: maps are forbidden. */
    @Test
    void rejectsMaps() {
        // 0xA1 = map(1)
        assertThrows(IllegalArgumentException.class,
                () -> Cbor.decode(new byte[]{(byte) 0xA1, 0x01, 0x02}));
    }

    /** §5.2: negative integers unsupported. */
    @Test
    void rejectsNegativeInt() {
        // 0x20 = negative int -1
        assertThrows(IllegalArgumentException.class, () -> Cbor.decode(new byte[]{0x20}));
    }

    @Test
    void canonicalMinimalIntEncoding() {
        // 1000 encodes as 19 03e8 (2-byte), not 1a 000003e8 (4-byte).
        assertArrayEquals(new byte[]{0x19, 0x03, (byte) 0xe8}, Cbor.encode(Cbor.uint(1000)));
        assertArrayEquals(new byte[]{0x17}, Cbor.encode(Cbor.uint(23)));
        assertArrayEquals(new byte[]{0x18, 0x18}, Cbor.encode(Cbor.uint(24)));
        assertArrayEquals(new byte[]{0x00}, Cbor.encode(Cbor.uint(0)));
    }

    @Test
    void decodeRejectsTrailingBytes() {
        assertThrows(IllegalArgumentException.class,
                () -> Cbor.decode(new byte[]{0x01, 0x02}));
    }

    // ---- adversarial: attacker-controlled lengths must not allocate (review C1)

    @Test
    void rejectsOversizedByteStringLength() {
        // 0x5A = byte string with 4-byte length claiming 0x10000000; input is tiny.
        byte[] frame = new byte[]{(byte) 0x5A, 0x10, 0x00, 0x00, 0x00, 0x41};
        assertThrows(IllegalArgumentException.class, () -> Cbor.decode(frame));
    }

    @Test
    void rejectsOversizedTextLength() {
        // 0x7A = text string with 4-byte length claiming 2 GB.
        byte[] frame = new byte[]{(byte) 0x7A, 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x61, 0x62};
        assertThrows(IllegalArgumentException.class, () -> Cbor.decode(frame));
    }

    @Test
    void rejectsHugeArrayCount() {
        // Array count claims ~2 billion items; input has 1 byte.
        byte[] frame = new byte[]{(byte) 0x9A, 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x01};
        assertThrows(IllegalArgumentException.class, () -> Cbor.decode(frame));
    }

    @Test
    void rejectsTruncatedLengthHeader() {
        // Claims a 4-byte length argument but only 1 byte is present.
        byte[] frame = new byte[]{(byte) 0x5A, 0x00};
        assertThrows(IllegalArgumentException.class, () -> Cbor.decode(frame));
    }

    @Test
    void byteStringAndTextRoundTrip() {
        byte[] data = {0x01, 0x02, 0x03};
        Cbor.Value v = Cbor.decode(Cbor.encode(Cbor.bytes(data)));
        assertArrayEquals(data, ((Cbor.Value.Bytes) v).value());

        Cbor.Value t = Cbor.decode(Cbor.encode(Cbor.text("meshu")));
        assertEquals("meshu", ((Cbor.Value.Text) t).value());
    }

    @Test
    void nestedArrayDecodes() {
        // KEYSETS response shape: [0x8A, [[s_id, unit, active, fee, expiry], ...]]
        Cbor.Value inner = Cbor.array(
                Cbor.bytes(new byte[8]), Cbor.uint(0), Cbor.uint(1), Cbor.uint(0), Cbor.uint(0));
        Cbor.Value outer = Cbor.array(Cbor.uint(Op.responseOf(Op.KEYSETS)), Cbor.array(List.of(inner)));
        Cbor.Value decoded = Cbor.decode(Cbor.encode(outer));
        assertInstanceOf(Cbor.Value.Array.class, decoded);
    }
}
