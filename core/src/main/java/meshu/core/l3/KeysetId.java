package meshu.core.l3;

import java.util.HexFormat;

/**
 * Keyset IDs (PROTOCOL.md §6.4, NUT-00/02).
 *
 * <p>Keyset IDs V2 are 33 bytes ({@code 0x01 ‖ SHA-256}), 66 chars as hex.
 * Meshu never transmits hex. Two compact references exist:
 * <ul>
 *   <li><b>short keyset ID (s_id, 8 bytes)</b> — {@code id_bytes[:8]}, NUT-00</li>
 *   <li><b>keyset handle (1 byte)</b> — per-session index from KEYSETS (§8.10)</li>
 * </ul>
 */
public record KeysetId(byte[] bytes) {

    private static final HexFormat HEX = HexFormat.of();

    public KeysetId {
        bytes = bytes.clone();
    }

    @Override
    public byte[] bytes() {
        return bytes.clone();
    }

    /** Parse a full keyset ID from hex (66 or 16 chars). */
    public static KeysetId fromHex(String hex) {
        return new KeysetId(HEX.parseHex(hex));
    }

    /** The short keyset ID: first 8 bytes (NUT-00). */
    public byte[] shortId() {
        byte[] out = new byte[8];
        System.arraycopy(bytes, 0, out, 0, 8);
        return out;
    }

    /** Whether this is a V2 keyset ID (0x01 ‖ SHA-256). */
    public boolean isV2() {
        return bytes.length == 33 && bytes[0] == 0x01;
    }

    public String hex() {
        return HEX.formatHex(bytes);
    }

    public String shortHex() {
        return HEX.formatHex(shortId());
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof KeysetId k && java.util.Arrays.equals(bytes, k.bytes);
    }

    @Override
    public int hashCode() {
        return java.util.Arrays.hashCode(bytes);
    }

    @Override
    public String toString() {
        return hex();
    }
}
