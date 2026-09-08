package meshu.core.l3;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * NUT-00 V4 token round trip (POC-WALLET.md §5.3).
 */
class TokenV4Test {

    private static byte[] fill(int len, int seed) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) {
            b[i] = (byte) (seed + i);
        }
        return b;
    }

    private static TokenV4.Token sampleToken() {
        return new TokenV4.Token(
                "https://mint.minibits.cash/Bitcoin",
                "sat",
                null,
                List.of(new TokenV4.TokenGroup(
                        new KeysetId(fill(33, 1)),
                        List.of(
                                new TokenV4.TokenProof(8, "aa".repeat(32), fill(33, 0)),
                                new TokenV4.TokenProof(2, "bb".repeat(32), fill(33, 33))))));
    }

    @Test
    void roundTripPreservesAllFields() {
        TokenV4.Token token = sampleToken();
        String serialized = TokenV4.serialize(token);
        assertTrue(serialized.startsWith(TokenV4.PREFIX));

        TokenV4.Token parsed = TokenV4.parse(serialized);
        assertEquals("https://mint.minibits.cash/Bitcoin", parsed.mintUrl());
        assertEquals("sat", parsed.unit());
        assertNull(parsed.memo());
        assertEquals(1, parsed.groups().size());
        assertArrayEquals(token.groups().get(0).keysetId().bytes(),
                parsed.groups().get(0).keysetId().bytes());
        assertEquals(2, parsed.groups().get(0).proofs().size());
        assertEquals(8, parsed.groups().get(0).proofs().get(0).amount());
        assertEquals("aa".repeat(32), parsed.groups().get(0).proofs().get(0).secret());
        assertArrayEquals(token.groups().get(0).proofs().get(0).c(),
                parsed.groups().get(0).proofs().get(0).c());
    }

    @Test
    void totalAmount() {
        assertEquals(10, sampleToken().totalAmount());
    }

    @Test
    void memoRoundTrip() {
        TokenV4.Token withMemo = new TokenV4.Token(
                "https://mint.minibits.cash/Bitcoin", "sat", "for coffee",
                sampleToken().groups());
        TokenV4.Token parsed = TokenV4.parse(TokenV4.serialize(withMemo));
        assertEquals("for coffee", parsed.memo());
    }

    @Test
    void multiGroupRoundTrip() {
        TokenV4.Token multi = new TokenV4.Token(
                "https://mint.minibits.cash/Bitcoin", "sat", null,
                List.of(
                        new TokenV4.TokenGroup(new KeysetId(fill(33, 1)),
                                List.of(new TokenV4.TokenProof(1, "cc".repeat(32), fill(33, 0)))),
                        new TokenV4.TokenGroup(new KeysetId(fill(33, 2)),
                                List.of(new TokenV4.TokenProof(4, "dd".repeat(32), fill(33, 33))))));
        TokenV4.Token parsed = TokenV4.parse(TokenV4.serialize(multi));
        assertEquals(2, parsed.groups().size());
        assertEquals(5, parsed.totalAmount());
    }

    @Test
    void rejectsWrongPrefix() {
        assertThrows(IllegalArgumentException.class, () -> TokenV4.parse("cashuA" + "x".repeat(20)));
        assertThrows(IllegalArgumentException.class, () -> TokenV4.parse("notatoken"));
    }

    @Test
    void shortKeysetIdPreserved() {
        // V4 tokens may carry the 8-byte short keyset ID (NUT-00).
        TokenV4.Token shortId = new TokenV4.Token(
                "https://mint.minibits.cash/Bitcoin", "sat", null,
                List.of(new TokenV4.TokenGroup(
                        new KeysetId(fill(8, 9)),   // 8-byte short form
                        List.of(new TokenV4.TokenProof(1, "ee".repeat(32), fill(33, 0))))));
        TokenV4.Token parsed = TokenV4.parse(TokenV4.serialize(shortId));
        assertEquals(8, parsed.groups().get(0).keysetId().bytes().length);
        assertArrayEquals(shortId.groups().get(0).keysetId().bytes(),
                parsed.groups().get(0).keysetId().bytes());
    }

    @Test
    void cborBytesMatchStringForm() {
        TokenV4.Token token = sampleToken();
        byte[] cbor = TokenV4.serializeCbor(token);
        TokenV4.Token fromCbor = TokenV4.parseCbor(cbor);
        assertEquals(token.mintUrl(), fromCbor.mintUrl());
        assertEquals(token.totalAmount(), fromCbor.totalAmount());
    }

    // ---- adversarial: attacker-controlled token bytes must not allocate OOM (review C2)

    @Test
    void rejectsOversizedByteStringLength() {
        // 0x58 = byte string, 1-byte length claiming 0x7F bytes; input is tiny.
        byte[] evil = new byte[]{(byte) 0xA1, 'i', (byte) 0x58, 0x7F, 0x01};
        assertThrows(IllegalArgumentException.class, () -> TokenV4.parseCbor(evil));
    }

    @Test
    void rejectsOversizedTextLength() {
        // Map with "m" key whose text length claims far more than remains.
        byte[] evil = new byte[]{(byte) 0xA1, 'm', (byte) 0x7A,
                0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
        assertThrows(IllegalArgumentException.class, () -> TokenV4.parseCbor(evil));
    }

    @Test
    void rejectsHugeArrayCountInTokenField() {
        // "t" array claims ~2 billion groups; input is a handful of bytes.
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        o.write(0xA1);                 // map(1)
        o.write('t');                  // key "t"
        o.write(0x9A);                 // array, 4-byte count
        o.writeBytes(new byte[]{0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF});
        assertThrows(IllegalArgumentException.class, () -> TokenV4.parseCbor(o.toByteArray()));
    }

    @Test
    void rejectsTruncatedFrame() {
        // Valid map header but body cut off mid-field.
        byte[] truncated = new byte[]{(byte) 0xA3, 'm', 0x61, 'h'};
        assertThrows(IllegalArgumentException.class, () -> TokenV4.parseCbor(truncated));
    }
}
