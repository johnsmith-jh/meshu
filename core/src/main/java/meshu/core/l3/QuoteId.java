package meshu.core.l3;

import java.util.UUID;

/**
 * Quote ID packing (PROTOCOL.md §6.2, TESTVECTORS.md vector 2).
 *
 * <p>NUT-04/05 quote IDs are UUIDv7, 36 bytes as a string but 16 packed.
 * The round trip is lossless. A mint is not strictly required to use UUID
 * quote IDs, so {@code quote_id} fields are typed bytes-or-text: pack a
 * UUID-form ID to 16 bytes, pass a non-UUID ID through as text.
 *
 * <p><b>Critical (§9.2):</b> NUT-20 signing commits to the 36-character UTF-8
 * string, not these 16 bytes. Re-expand before signing.
 */
public final class QuoteId {

    private QuoteId() {
    }

    /** Packed (16-byte) or text (non-UUID) quote ID form. */
    public sealed interface Form {
        /** A UUID quote ID, packed to 16 bytes. */
        record Packed(byte[] bytes) implements Form {
            public Packed {
                if (bytes.length != 16) {
                    throw new IllegalArgumentException("packed quote ID must be 16 bytes");
                }
                bytes = bytes.clone();
            }

            @Override
            public byte[] bytes() {
                return bytes.clone();
            }
        }

        /** A non-UUID quote ID, carried as text verbatim. */
        record Text(String value) implements Form {
        }
    }

    /** Parse a string quote ID: UUID → packed, otherwise → text form. */
    public static Form parse(String s) {
        try {
            UUID u = UUID.fromString(s);
            return new Form.Packed(toBytes(u));
        } catch (IllegalArgumentException e) {
            return new Form.Text(s);
        }
    }

    /** Expand a packed 16-byte form back to the 36-char canonical lowercase string. */
    public static String expand(byte[] packed16) {
        if (packed16.length != 16) {
            throw new IllegalArgumentException("packed quote ID must be 16 bytes");
        }
        long msb = 0, lsb = 0;
        for (int i = 0; i < 8; i++) {
            msb = (msb << 8) | (packed16[i] & 0xFFL);
        }
        for (int i = 8; i < 16; i++) {
            lsb = (lsb << 8) | (packed16[i] & 0xFFL);
        }
        return new UUID(msb, lsb).toString();
    }

    /** The string to sign for NUT-20: expand packed form, pass text verbatim. */
    public static String stringForSigning(Form form) {
        return switch (form) {
            case Form.Packed p -> expand(p.bytes());
            case Form.Text t -> t.value();
        };
    }

    /** CBOR value for a quote ID: byte string when packed, text string otherwise (§6.2). */
    public static Cbor.Value toCbor(Form form) {
        return switch (form) {
            case Form.Packed p -> Cbor.bytes(p.bytes());
            case Form.Text t -> Cbor.text(t.value());
        };
    }

    /** Parse a quote ID from its CBOR form (bytes → packed, text → text). */
    public static Form fromCbor(Cbor.Value v) {
        return switch (v) {
            case Cbor.Value.Bytes b -> new Form.Packed(b.value());
            case Cbor.Value.Text t -> new Form.Text(t.value());
            default -> throw new IllegalArgumentException("quote_id must be bytes or text");
        };
    }

    private static byte[] toBytes(UUID u) {
        byte[] out = new byte[16];
        long msb = u.getMostSignificantBits();
        long lsb = u.getLeastSignificantBits();
        for (int i = 7; i >= 0; i--) {
            out[i] = (byte) msb;
            msb >>= 8;
        }
        for (int i = 15; i >= 8; i--) {
            out[i] = (byte) lsb;
            lsb >>= 8;
        }
        return out;
    }
}
