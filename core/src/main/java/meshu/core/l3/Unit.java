package meshu.core.l3;

/**
 * Currency units (PROTOCOL.md §6.6). Values 0x00–0x7F are well-known;
 * 0x80+ means a text string follows for unknown units.
 */
public final class Unit {

    public static final int SAT = 0;
    public static final int MSAT = 1;
    public static final int USD = 2;
    public static final int EUR = 3;
    public static final int BTC = 4;

    private Unit() {
    }

    /** Well-known unit code, or -1 for a custom (text) unit. */
    public static int codeOf(String unit) {
        return switch (unit.toLowerCase()) {
            case "sat" -> SAT;
            case "msat" -> MSAT;
            case "usd" -> USD;
            case "eur" -> EUR;
            case "btc" -> BTC;
            default -> -1;
        };
    }

    public static String nameOf(int code) {
        return switch (code) {
            case SAT -> "sat";
            case MSAT -> "msat";
            case USD -> "usd";
            case EUR -> "eur";
            case BTC -> "btc";
            default -> throw new IllegalArgumentException("unknown unit code: " + code);
        };
    }

    /** CBOR value for a unit: uint when well-known, text when custom (§6.6). */
    public static Cbor.Value toCbor(String unit) {
        int code = codeOf(unit);
        return code >= 0 ? Cbor.uint(code) : Cbor.text(unit);
    }

    public static String fromCbor(Cbor.Value v) {
        return switch (v) {
            case Cbor.Value.Uint u -> nameOf(u.intValue());
            case Cbor.Value.Text t -> t.value();
            default -> throw new IllegalArgumentException("unit must be uint or text");
        };
    }
}
