package meshu.core.l3;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal, hand-rolled CBOR reader/writer honouring the L3 disciplines of
 * PROTOCOL.md §5:
 *
 * <ul>
 *   <li>positional definite-length arrays, never maps (§5.1)</li>
 *   <li>integers in canonical minimal form (§5.2)</li>
 *   <li>indefinite-length items MUST be rejected (§5.2)</li>
 *   <li>unknown trailing array elements are ignored by message decoders (§5.2)</li>
 * </ul>
 *
 * Only the types Meshu uses are supported: uint, byte string, text string,
 * array, and null. Encoding is canonical (RFC 8949 §4.2 minimal form); decoding
 * accepts any well-formed definite-length form, per §5.3.
 */
public final class Cbor {

    private Cbor() {
    }

    /** Decoded CBOR value: one of uint / bytes / text / array / null. */
    public sealed interface Value {
        record Uint(BigInteger value) implements Value {
            public long longValue() {
                return value.longValueExact();
            }

            public int intValue() {
                return value.intValueExact();
            }
        }

        record Bytes(byte[] value) implements Value {
        }

        record Text(String value) implements Value {
        }

        record Array(List<Value> items) implements Value {
        }

        enum Null implements Value {
            INSTANCE
        }
    }

    // ---------------------------------------------------------------- encode

    public static byte[] encode(Value v) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeValue(out, v);
        return out.toByteArray();
    }

    private static void writeValue(ByteArrayOutputStream out, Value v) {
        switch (v) {
            case Value.Uint u -> writeTypeAndValue(out, 0, u.value());
            case Value.Bytes b -> {
                writeTypeAndValue(out, 2, BigInteger.valueOf(b.value().length));
                out.writeBytes(b.value());
            }
            case Value.Text t -> {
                byte[] utf8 = t.value().getBytes(java.nio.charset.StandardCharsets.UTF_8);
                writeTypeAndValue(out, 3, BigInteger.valueOf(utf8.length));
                out.writeBytes(utf8);
            }
            case Value.Null n -> out.write(0xF6);
            case Value.Array a -> {
                writeTypeAndValue(out, 4, BigInteger.valueOf(a.items().size()));
                for (Value item : a.items()) {
                    writeValue(out, item);
                }
            }
        }
    }

    /** Write a major-type/argument pair in canonical minimal form (RFC 8949 §4.2). */
    private static void writeTypeAndValue(ByteArrayOutputStream out, int majorType, BigInteger value) {
        int mt = majorType << 5;
        long v = value.longValueExact();
        if (v < 24) {
            out.write(mt | (int) v);
        } else if (v <= 0xFF) {
            out.write(mt | 24);
            out.write((int) v);
        } else if (v <= 0xFFFF) {
            out.write(mt | 25);
            out.write((int) (v >> 8));
            out.write((int) v);
        } else if (v <= 0xFFFF_FFFFL) {
            out.write(mt | 26);
            for (int s = 24; s >= 0; s -= 8) {
                out.write((int) (v >> s));
            }
        } else {
            out.write(mt | 27);
            for (int s = 56; s >= 0; s -= 8) {
                out.write((int) (v >> s));
            }
        }
    }

    // ---------------------------------------------------------------- decode

    /** Decode one CBOR item. Indefinite-length items and maps are rejected (§5.2). */
    public static Value decode(byte[] data) {
        int[] pos = {0};
        Value v = readValue(data, pos);
        if (pos[0] != data.length) {
            throw new IllegalArgumentException("trailing bytes after CBOR item");
        }
        return v;
    }

    private static Value readValue(byte[] data, int[] pos) {
        int initial = data[pos[0]++] & 0xFF;
        int major = initial >> 5;
        int ai = initial & 0x1F;
        switch (major) {
            case 0 -> {
                return new Value.Uint(readArgument(data, pos, ai));
            }
            case 2 -> {
                int len = readBoundedLength(data, pos, ai);
                byte[] out = new byte[len];
                System.arraycopy(data, pos[0], out, 0, len);
                pos[0] += len;
                return new Value.Bytes(out);
            }
            case 3 -> {
                int len = readBoundedLength(data, pos, ai);
                String s = new String(data, pos[0], len, java.nio.charset.StandardCharsets.UTF_8);
                pos[0] += len;
                return new Value.Text(s);
            }
            case 4 -> {
                // Each item occupies at least one byte, so count > remaining is
                // impossible for well-formed input — reject before allocating.
                BigInteger c = readArgument(data, pos, ai);
                if (c.bitLength() > 31 || c.longValue() > data.length - pos[0]) {
                    throw new IllegalArgumentException("CBOR array count exceeds input size");
                }
                int count = c.intValueExact();
                List<Value> items = new ArrayList<>(count);
                for (int i = 0; i < count; i++) {
                    items.add(readValue(data, pos));
                }
                return new Value.Array(List.copyOf(items));
            }
            case 7 -> {
                if (ai == 22) {
                    return Value.Null.INSTANCE;
                }
                throw new IllegalArgumentException("unsupported simple/float CBOR value: 0x%02x".formatted(initial));
            }
            default -> throw new IllegalArgumentException(
                    "unsupported CBOR major type %d (maps are forbidden, §5.1)".formatted(major));
        }
    }

    /**
     * Read a length argument for major types 2/3 and verify it fits the
     * remaining input BEFORE the caller allocates. Lengths are attacker-
     * controlled; a 5-byte header claiming 4 GB must fail here, not in
     * {@code new byte[len]}.
     */
    private static int readBoundedLength(byte[] data, int[] pos, int ai) {
        BigInteger l = readArgument(data, pos, ai);
        if (l.bitLength() > 31) {
            throw new IllegalArgumentException("CBOR length out of range: " + l);
        }
        int len = l.intValueExact();
        if (len < 0 || len > data.length - pos[0]) {
            throw new IllegalArgumentException(
                    "CBOR length " + len + " exceeds remaining input " + (data.length - pos[0]));
        }
        return len;
    }

    private static BigInteger readArgument(byte[] data, int[] pos, int ai) {
        if (ai == 31) {
            throw new IllegalArgumentException(
                    "indefinite-length CBOR item rejected (§5.2)");
        }
        if (ai < 24) {
            return BigInteger.valueOf(ai);
        }
        int bytes = switch (ai) {
            case 24 -> 1;
            case 25 -> 2;
            case 26 -> 4;
            case 27 -> 8;
            default -> throw new IllegalArgumentException("bad additional info: " + ai);
        };
        if (pos[0] + bytes > data.length) {
            throw new IllegalArgumentException("truncated CBOR length header");
        }
        long v = 0;
        for (int i = 0; i < bytes; i++) {
            v = (v << 8) | (data[pos[0]++] & 0xFFL);
        }
        return BigInteger.valueOf(v);
    }

    // ---------------------------------------------------------------- builders

    public static Value.Uint uint(long v) {
        if (v < 0) {
            throw new IllegalArgumentException("CBOR uint cannot be negative: " + v);
        }
        return new Value.Uint(BigInteger.valueOf(v));
    }

    public static Value.Bytes bytes(byte[] v) {
        return new Value.Bytes(v);
    }

    public static Value.Text text(String v) {
        return new Value.Text(v);
    }

    public static Value.Array array(Value... items) {
        return new Value.Array(List.of(items));
    }

    public static Value.Array array(List<Value> items) {
        return new Value.Array(List.copyOf(items));
    }
}
