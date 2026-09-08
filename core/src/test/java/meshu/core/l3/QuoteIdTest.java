package meshu.core.l3;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/**
 * TESTVECTORS.md vector 2 (§6.2): UUIDv7 quote ID packing.
 */
class QuoteIdTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void vector2RoundTrip() {
        String s = "019e6d5a-2347-7000-8322-05d51d498303";
        QuoteId.Form form = QuoteId.parse(s);
        assertInstanceOf(QuoteId.Form.Packed.class, form);
        byte[] packed = ((QuoteId.Form.Packed) form).bytes();
        assertEquals("019e6d5a23477000832205d51d498303", HEX.formatHex(packed));
        assertEquals(16, packed.length);

        // Expand back to the canonical 36-char lowercase string (§9.2 trap 1).
        assertEquals(s, QuoteId.expand(packed));
    }

    @Test
    void vector2IsUuidV7() {
        QuoteId.Form form = QuoteId.parse("019e6d5a-2347-7000-8322-05d51d498303");
        byte[] packed = ((QuoteId.Form.Packed) form).bytes();
        // Version nibble (high nibble of byte 6) is 7 for UUIDv7.
        assertEquals(0x07, (packed[6] >> 4) & 0x0F);
    }

    @Test
    void nonUuidIdPassesThroughAsText() {
        QuoteId.Form form = QuoteId.parse("not-a-uuid-quote-id");
        assertInstanceOf(QuoteId.Form.Text.class, form);
        assertEquals("not-a-uuid-quote-id", ((QuoteId.Form.Text) form).value());
    }

    @Test
    void stringForSigningExpandsPacked() {
        String s = "019e6d5a-2347-7000-8322-05d51d498303";
        assertEquals(s, QuoteId.stringForSigning(QuoteId.parse(s)));
        assertEquals("verbatim-text", QuoteId.stringForSigning(QuoteId.parse("verbatim-text")));
    }

    @Test
    void cborFormBytesForUuidTextForNonUuid() {
        Cbor.Value packed = QuoteId.toCbor(QuoteId.parse("019e6d5a-2347-7000-8322-05d51d498303"));
        assertInstanceOf(Cbor.Value.Bytes.class, packed);
        Cbor.Value text = QuoteId.toCbor(QuoteId.parse("custom-id"));
        assertInstanceOf(Cbor.Value.Text.class, text);

        // Round trip through CBOR forms.
        assertEquals("019e6d5a-2347-7000-8322-05d51d498303",
                QuoteId.stringForSigning(QuoteId.fromCbor(packed)));
        assertEquals("custom-id",
                QuoteId.stringForSigning(QuoteId.fromCbor(text)));
    }
}
