package meshu.gateway.companion;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * PACKET_SELF_INFO (0x05) payload, per MeshCore docs/companion_protocol.md:
 *
 * <pre>
 * byte 0      0x05
 * byte 1      advert type
 * byte 2      TX power
 * byte 3      max TX power
 * bytes 4-35  Ed25519 public key (32 bytes)
 * bytes 36-39 advert latitude  (int32 LE, /1e6)
 * bytes 40-43 advert longitude (int32 LE, /1e6)
 * byte 44     multi ACKs
 * byte 45     advert location policy
 * byte 46     telemetry mode (bitfield)
 * byte 47     manual add contacts (bool)
 * bytes 48-51 radio frequency (uint32 LE, /1000.0 → MHz)
 * bytes 52-55 radio bandwidth  (uint32 LE, /1000.0 → kHz)
 * byte 56     radio spreading factor
 * byte 57     radio coding rate
 * bytes 58+   device name (UTF-8)
 * </pre>
 */
public record SelfInfo(
        int advType,
        int txPower,
        int maxTxPower,
        byte[] publicKey,
        double advLat,
        double advLon,
        int multiAcks,
        int advLocPolicy,
        int telemetryMode,
        boolean manualAddContacts,
        double radioFreqMhz,
        double radioBwKhz,
        int radioSf,
        int radioCr,
        String name) {

    private static final int MIN_LENGTH = 58;

    public static SelfInfo parse(byte[] payload) {
        if (payload == null || payload.length < 2 || (payload[0] & 0xFF) != PacketType.SELF_INFO) {
            throw new IllegalArgumentException("not a SELF_INFO payload");
        }
        if (payload.length < MIN_LENGTH) {
            throw new IllegalArgumentException("SELF_INFO too short: " + payload.length + " < " + MIN_LENGTH);
        }
        ByteBuffer b = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);
        b.position(1);
        int advType = b.get() & 0xFF;
        int txPower = b.get() & 0xFF;
        int maxTxPower = b.get() & 0xFF;
        byte[] pub = new byte[32];
        b.get(pub);
        double lat = b.getInt() / 1e6;
        double lon = b.getInt() / 1e6;
        int multiAcks = b.get() & 0xFF;
        int advLocPolicy = b.get() & 0xFF;
        int telemetryMode = b.get() & 0xFF;
        boolean manualAdd = b.get() != 0;
        double freqMhz = (b.getInt() & 0xFFFF_FFFFL) / 1000.0;
        double bwKhz = (b.getInt() & 0xFFFF_FFFFL) / 1000.0;
        int sf = b.get() & 0xFF;
        int cr = b.get() & 0xFF;
        String name = "";
        if (b.hasRemaining()) {
            byte[] rest = new byte[b.remaining()];
            b.get(rest);
            name = new String(rest, StandardCharsets.UTF_8).replace("\0", "").strip();
        }
        return new SelfInfo(advType, txPower, maxTxPower, pub, lat, lon,
                multiAcks, advLocPolicy, telemetryMode, manualAdd,
                freqMhz, bwKhz, sf, cr, name);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof SelfInfo s && Arrays.equals(publicKey, s.publicKey) && name.equals(s.name);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(publicKey);
    }

    @Override
    public String toString() {
        return "SelfInfo{name='%s', pubkey=%s, radio=%.3f MHz / %.1f kHz / SF%d / CR%d, txPower=%d/%d}"
                .formatted(name, HexFormat.of().formatHex(publicKey),
                        radioFreqMhz, radioBwKhz, radioSf, radioCr, txPower, maxTxPower);
    }
}
