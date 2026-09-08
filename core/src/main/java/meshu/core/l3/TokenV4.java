package meshu.core.l3;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * NUT-00 V4 token parse/serialize (POC-WALLET.md §5.3, NUT-00).
 *
 * <p>A V4 token is {@code cashuB} + base64url(CBOR) with single-char keys and
 * binary curve material. It holds proofs from a single mint. The PoC wallet
 * accepts V4 only and rejects locked (NUT-10) secrets on receipt.
 *
 * <p>Structure (JSON-equivalent):
 * <pre>
 * { "m": mintUrl, "u": unit, "d"?: memo,
 *   "t": [ { "i": keysetIdBytes, "p": [ { "a": amount, "s": secret, "c": sigBytes } ] } ] }
 * </pre>
 *
 * <p>Note: the PoC doc (POC-WALLET.md §5.3) says "cashuA", but per current
 * NUT-00 the V4 CBOR version flag is {@code B}; {@code cashuA} is deprecated V3
 * JSON. This implements {@code cashuB}. (Flagged for spec correction.)
 */
public final class TokenV4 {

    public static final String PREFIX = "cashuB";

    private TokenV4() {
    }

    /** One proof in a token: amount, secret (utf-8, 64-hex for 32-byte), C signature. */
    public record TokenProof(long amount, String secret, byte[] c) {
        public TokenProof {
            if (c.length != 33) {
                throw new IllegalArgumentException("C must be 33 bytes");
            }
            c = c.clone();
        }

        @Override
        public byte[] c() {
            return c.clone();
        }
    }

    /** Proofs grouped under one keyset ID. */
    public record TokenGroup(KeysetId keysetId, List<TokenProof> proofs) {
        public TokenGroup {
            proofs = List.copyOf(proofs);
        }
    }

    /** A parsed V4 token. */
    public record Token(String mintUrl, String unit, String memo, List<TokenGroup> groups) {
        public Token {
            groups = List.copyOf(groups);
        }

        /** Total value of all proofs. */
        public long totalAmount() {
            long sum = 0;
            for (TokenGroup g : groups) {
                for (TokenProof p : g.proofs()) {
                    sum += p.amount();
                }
            }
            return sum;
        }
    }

    // ------------------------------------------------------------ serialize

    /** Serialize to the {@code cashuB…} string form. */
    public static String serialize(Token token) {
        return PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(serializeCbor(token));
    }

    /** Serialize to the raw CBOR bytes (no prefix). */
    public static byte[] serializeCbor(Token token) {
        // { "m":…, "u":…, "d"?:…, "t":[…] } — a CBOR map with single-char keys.
        // Our Cbor class forbids maps (§5.1 applies to Meshu L3, not NUT-00),
        // so build the map bytes directly.
        ByteWriter w = new ByteWriter();
        int mapSize = token.memo() != null ? 4 : 3;
        writeMapHeader(w, mapSize);

        writeText(w, "m");
        writeText(w, token.mintUrl());
        writeText(w, "u");
        writeText(w, token.unit());
        if (token.memo() != null) {
            writeText(w, "d");
            writeText(w, token.memo());
        }
        writeText(w, "t");
        writeArrayHeader(w, token.groups().size());
        for (TokenGroup g : token.groups()) {
            writeMapHeader(w, 2);
            writeText(w, "i");
            writeBytes(w, g.keysetId().bytes());
            writeText(w, "p");
            writeArrayHeader(w, g.proofs().size());
            for (TokenProof p : g.proofs()) {
                writeMapHeader(w, 3);
                writeText(w, "a");
                writeUint(w, p.amount());
                writeText(w, "s");
                writeText(w, p.secret());
                writeText(w, "c");
                writeBytes(w, p.c());
            }
        }
        return w.bytes();
    }

    // ------------------------------------------------------------ parse

    /** Parse a {@code cashuB…} string. */
    public static Token parse(String serialized) {
        if (!serialized.startsWith(PREFIX)) {
            throw new IllegalArgumentException("not a V4 token (expected " + PREFIX + " prefix)");
        }
        byte[] cbor = Base64.getUrlDecoder().decode(serialized.substring(PREFIX.length()));
        return parseCbor(cbor);
    }

    /** Parse raw CBOR bytes into a Token. */
    public static Token parseCbor(byte[] cbor) {
        ByteReader r = new ByteReader(cbor);
        int mapSize = r.readMapHeader();
        String mint = null, unit = null, memo = null;
        List<TokenGroup> groups = new ArrayList<>();
        for (int i = 0; i < mapSize; i++) {
            String key = r.readText();
            switch (key) {
                case "m" -> mint = r.readText();
                case "u" -> unit = r.readText();
                case "d" -> memo = r.readText();
                case "t" -> groups = readGroups(r);
                default -> r.skip(); // unknown fields ignored (forward compat, NUT-00)
            }
        }
        if (mint == null || unit == null) {
            throw new IllegalArgumentException("V4 token missing required m/u field");
        }
        return new Token(mint, unit, memo, groups);
    }

    private static List<TokenGroup> readGroups(ByteReader r) {
        int n = r.readArrayHeader();
        List<TokenGroup> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            int gs = r.readMapHeader();
            byte[] keysetId = null;
            List<TokenProof> proofs = new ArrayList<>();
            for (int j = 0; j < gs; j++) {
                String key = r.readText();
                switch (key) {
                    case "i" -> keysetId = r.readBytes();
                    case "p" -> proofs = readProofs(r);
                    default -> r.skip();
                }
            }
            out.add(new TokenGroup(new KeysetId(keysetId), proofs));
        }
        return out;
    }

    private static List<TokenProof> readProofs(ByteReader r) {
        int n = r.readArrayHeader();
        List<TokenProof> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            int ps = r.readMapHeader();
            long amount = -1;
            String secret = null;
            byte[] c = null;
            for (int j = 0; j < ps; j++) {
                String key = r.readText();
                switch (key) {
                    case "a" -> amount = r.readUint();
                    case "s" -> secret = r.readText();
                    case "c" -> c = r.readBytes();
                    default -> r.skip(); // d (DLEQ), w (witness), unknown — ignored
                }
            }
            out.add(new TokenProof(amount, secret, c));
        }
        return out;
    }

    // ------------------------------------------------------------ minimal CBOR map reader/writer
    // (Meshu L3 forbids maps, but NUT-00 V4 tokens require them, so a tiny
    //  separate codec lives here rather than weakening the L3 Cbor class.)

    private static final class ByteWriter {
        private final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();

        byte[] bytes() {
            return out.toByteArray();
        }

        void write(int b) {
            out.write(b);
        }

        void write(byte[] b) {
            out.writeBytes(b);
        }
    }

    private static void writeMapHeader(ByteWriter w, int size) {
        writeTypeAndValue(w, 5, size);
    }

    private static void writeArrayHeader(ByteWriter w, int size) {
        writeTypeAndValue(w, 4, size);
    }

    private static void writeUint(ByteWriter w, long v) {
        writeTypeAndValue(w, 0, v);
    }

    private static void writeText(ByteWriter w, String s) {
        byte[] utf8 = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        writeTypeAndValue(w, 3, utf8.length);
        w.write(utf8);
    }

    private static void writeBytes(ByteWriter w, byte[] b) {
        writeTypeAndValue(w, 2, b.length);
        w.write(b);
    }

    private static void writeTypeAndValue(ByteWriter w, int major, long v) {
        int mt = major << 5;
        if (v < 24) {
            w.write(mt | (int) v);
        } else if (v <= 0xFF) {
            w.write(mt | 24);
            w.write((int) v);
        } else if (v <= 0xFFFF) {
            w.write(mt | 25);
            w.write((int) (v >> 8));
            w.write((int) v);
        } else {
            w.write(mt | 26);
            for (int s = 24; s >= 0; s -= 8) {
                w.write((int) (v >> s));
            }
        }
    }

    private static final class ByteReader {
        private final byte[] data;
        private int pos = 0;

        ByteReader(byte[] data) {
            this.data = data;
        }

        private int remaining() {
            return data.length - pos;
        }

        private void ensureAvailable(int n) {
            // Lengths are attacker-controlled (token input, POC-WALLET.md S15):
            // verify before allocating or reading.
            if (n < 0 || n > remaining()) {
                throw new IllegalArgumentException(
                        "truncated token: need " + n + " bytes, have " + remaining());
            }
        }

        int readMapHeader() {
            return readHeader(5);
        }

        int readArrayHeader() {
            return readHeader(4);
        }

        long readUint() {
            ensureAvailable(1);
            int initial = data[pos++] & 0xFF;
            if (initial >> 5 != 0) {
                throw new IllegalArgumentException("expected uint");
            }
            return readArgument(initial & 0x1F);
        }

        String readText() {
            int len = readHeader(3);
            ensureAvailable(len);
            String s = new String(data, pos, len, java.nio.charset.StandardCharsets.UTF_8);
            pos += len;
            return s;
        }

        byte[] readBytes() {
            int len = readHeader(2);
            ensureAvailable(len);
            byte[] out = new byte[len];
            System.arraycopy(data, pos, out, 0, len);
            pos += len;
            return out;
        }

        private int readHeader(int expectedMajor) {
            ensureAvailable(1);
            int initial = data[pos++] & 0xFF;
            int major = initial >> 5;
            if (major != expectedMajor) {
                throw new IllegalArgumentException(
                        "expected CBOR major type %d, got %d".formatted(expectedMajor, major));
            }
            long v = readArgument(initial & 0x1F);
            if (v < 0 || v > remaining()) {
                // Every item/entry needs at least one byte; a count larger than
                // the remaining input is impossible for well-formed tokens.
                throw new IllegalArgumentException("CBOR length/count exceeds remaining input");
            }
            return (int) v;
        }

        private long readArgument(int ai) {
            if (ai < 24) {
                return ai;
            }
            int bytes = switch (ai) {
                case 24 -> 1;
                case 25 -> 2;
                case 26 -> 4;
                case 27 -> 8;
                default -> throw new IllegalArgumentException("bad additional info: " + ai);
            };
            ensureAvailable(bytes);
            long v = 0;
            for (int i = 0; i < bytes; i++) {
                v = (v << 8) | (data[pos++] & 0xFFL);
            }
            return v;
        }

        /** Skip one arbitrary item (for unknown-field forward compatibility). */
        void skip() {
            ensureAvailable(1);
            int initial = data[pos++] & 0xFF;
            int major = initial >> 5;
            int ai = initial & 0x1F;
            switch (major) {
                case 0, 7 -> readArgument(ai);
                case 2, 3 -> {
                    long len = readArgument(ai);
                    if (len > remaining()) {
                        throw new IllegalArgumentException("truncated token");
                    }
                    pos += (int) len;
                }
                case 4 -> {
                    int n = (int) readArgument(ai);
                    for (int i = 0; i < n; i++) {
                        skip();
                    }
                }
                case 5 -> {
                    int n = (int) readArgument(ai);
                    for (int i = 0; i < n * 2; i++) {
                        skip();
                    }
                }
                default -> throw new IllegalArgumentException("cannot skip major type " + major);
            }
        }
    }
}
