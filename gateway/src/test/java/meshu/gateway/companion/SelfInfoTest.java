package meshu.gateway.companion;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SelfInfoTest {

    /** Build a SELF_INFO payload exactly per docs/companion_protocol.md layout. */
    private static byte[] selfInfoPayload(byte[] pubkey32, String name) {
        ByteBuffer b = ByteBuffer.allocate(58 + name.length()).order(ByteOrder.LITTLE_ENDIAN);
        b.put((byte) 0x05);          // packet type
        b.put((byte) 0x02);          // adv type: chat
        b.put((byte) 20);            // tx power
        b.put((byte) 30);            // max tx power
        b.put(pubkey32);             // bytes 4-35
        b.putInt(52351777);          // lat * 1e6
        b.putInt(13405222);          // lon * 1e6
        b.put((byte) 0);             // multi acks
        b.put((byte) 0);             // adv loc policy
        b.put((byte) 0);             // telemetry mode
        b.put((byte) 1);             // manual add contacts
        b.putInt(869525);            // freq *1000 → 869.525 MHz
        b.putInt(62500);             // bw *1000 → 62.5 kHz
        b.put((byte) 8);             // SF8
        b.put((byte) 5);             // CR 4/5
        b.put(name.getBytes(StandardCharsets.UTF_8));
        return b.array();
    }

    @Test
    void parsesAllFields() {
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) {
            key[i] = (byte) i;
        }
        SelfInfo info = SelfInfo.parse(selfInfoPayload(key, "meshu-gw"));

        assertEquals(2, info.advType());
        assertEquals(20, info.txPower());
        assertEquals(30, info.maxTxPower());
        assertArrayEquals(key, info.publicKey());
        assertEquals(52.351777, info.advLat(), 1e-6);
        assertEquals(13.405222, info.advLon(), 1e-6);
        assertTrue(info.manualAddContacts());
        assertEquals(869.525, info.radioFreqMhz(), 1e-9);
        assertEquals(62.5, info.radioBwKhz(), 1e-9);
        assertEquals(8, info.radioSf());
        assertEquals(5, info.radioCr());
        assertEquals("meshu-gw", info.name());
    }

    @Test
    void rejectsWrongPacketType() {
        byte[] payload = selfInfoPayload(new byte[32], "x");
        payload[0] = 0x0D; // DEVICE_INFO
        assertThrows(IllegalArgumentException.class, () -> SelfInfo.parse(payload));
    }

    @Test
    void rejectsTruncatedPayload() {
        byte[] payload = selfInfoPayload(new byte[32], "x");
        byte[] shortPayload = new byte[40];
        System.arraycopy(payload, 0, shortPayload, 0, 40);
        assertThrows(IllegalArgumentException.class, () -> SelfInfo.parse(shortPayload));
    }

    @Test
    void toleratesMissingName() {
        byte[] full = selfInfoPayload(new byte[32], "meshu-gw");
        byte[] noName = new byte[58];
        System.arraycopy(full, 0, noName, 0, 58);
        SelfInfo info = SelfInfo.parse(noName);
        assertEquals("", info.name());
    }
}
