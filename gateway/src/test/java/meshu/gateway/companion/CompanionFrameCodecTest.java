package meshu.gateway.companion;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CompanionFrameCodecTest {

    private static byte[] inboundFrame(byte... payload) {
        byte[] frame = new byte[3 + payload.length];
        frame[0] = CompanionFrameCodec.IN_MARKER;
        frame[1] = (byte) (payload.length & 0xFF);
        frame[2] = (byte) (payload.length >> 8);
        System.arraycopy(payload, 0, frame, 3, payload.length);
        return frame;
    }

    @Test
    void encodeProducesMarkerLittleEndianLengthAndPayload() {
        byte[] frame = CompanionFrameCodec.encode(new byte[]{0x01, 0x02, 0x03});
        assertArrayEquals(new byte[]{0x3C, 0x03, 0x00, 0x01, 0x02, 0x03}, frame);
    }

    @Test
    void encodeRejectsOversizedPayload() {
        assertThrows(IllegalArgumentException.class,
                () -> CompanionFrameCodec.encode(new byte[0x1_0000]));
    }

    @Test
    void deframerParsesSingleFrame() {
        var deframer = new CompanionFrameCodec.Deframer();
        List<byte[]> frames = deframer.feed(inboundFrame((byte) 0x05, (byte) 0xAA), 0, 5);
        assertEquals(1, frames.size());
        assertArrayEquals(new byte[]{0x05, (byte) 0xAA}, frames.getFirst());
    }

    @Test
    void deframerDiscardsLeadingJunk() {
        // Radios interleave console text on the UART; frames start at the marker.
        byte[] junk = "hello console\r\n".getBytes();
        byte[] frame = inboundFrame((byte) 0x01);
        byte[] stream = new byte[junk.length + frame.length];
        System.arraycopy(junk, 0, stream, 0, junk.length);
        System.arraycopy(frame, 0, stream, junk.length, frame.length);

        var deframer = new CompanionFrameCodec.Deframer();
        List<byte[]> frames = deframer.feed(stream, 0, stream.length);
        assertEquals(1, frames.size());
        assertArrayEquals(new byte[]{0x01}, frames.getFirst());
    }

    @Test
    void deframerHandlesByteByByteDelivery() {
        byte[] frame = inboundFrame((byte) 0x05, (byte) 0x10, (byte) 0x20, (byte) 0x30);
        var deframer = new CompanionFrameCodec.Deframer();
        int emitted = 0;
        for (byte b : frame) {
            emitted += deframer.feed(new byte[]{b}, 0, 1).size();
        }
        assertEquals(1, emitted);
    }

    @Test
    void deframerParsesBackToBackFrames() {
        byte[] f1 = inboundFrame((byte) 0x01, (byte) 0x00);
        byte[] f2 = inboundFrame((byte) 0x05, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04);
        byte[] stream = new byte[f1.length + f2.length];
        System.arraycopy(f1, 0, stream, 0, f1.length);
        System.arraycopy(f2, 0, stream, f1.length, f2.length);

        var deframer = new CompanionFrameCodec.Deframer();
        List<byte[]> frames = deframer.feed(stream, 0, stream.length);
        assertEquals(2, frames.size());
        assertArrayEquals(new byte[]{0x01, 0x00}, frames.get(0));
        assertArrayEquals(new byte[]{0x05, 0x01, 0x02, 0x03, 0x04}, frames.get(1));
    }

    @Test
    void deframerRecoversFromBogusLength() {
        // A junk '>' followed by an absurd length must not wedge the stream.
        byte[] stream = new byte[]{
                0x3E, 0x7F, 0x7F,              // bogus: claims ~32 KB payload
                0x3E, 0x02, 0x00, 0x09, 0x08   // real frame: payload {0x09, 0x08}
        };
        var deframer = new CompanionFrameCodec.Deframer();
        List<byte[]> frames = deframer.feed(stream, 0, stream.length);
        assertEquals(1, frames.size());
        assertArrayEquals(new byte[]{0x09, 0x08}, frames.getFirst());
    }

    @Test
    void deframerWaitsForIncompleteFrame() {
        byte[] frame = inboundFrame((byte) 0x05, (byte) 0xAA, (byte) 0xBB);
        var deframer = new CompanionFrameCodec.Deframer();
        assertTrue(deframer.feed(frame, 0, 4).isEmpty()); // header + 1 payload byte
        List<byte[]> frames = deframer.feed(frame, 4, frame.length - 4);
        assertEquals(1, frames.size());
        assertArrayEquals(new byte[]{0x05, (byte) 0xAA, (byte) 0xBB}, frames.getFirst());
    }
}
