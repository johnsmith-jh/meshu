package meshu.core.l2;

import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Arrays;

/**
 * L2 AEAD and message layout (PROTOCOL.md §4.3–§4.5).
 *
 * <p>Sealed message layout (§4.4):
 * <pre>
 * byte 0      epoch        key epoch; 0xFF = bootstrap form (§4.2.1)
 * bytes 1..n  ciphertext   ChaCha20-Poly1305 of the L3 message
 * last 16     tag          Poly1305 authenticator
 * </pre>
 *
 * <p>Implicit nonce (§4.5): {@code epoch ‖ dir ‖ msg_id(BE) ‖ 0x00 × 8}.
 * Associated data: {@code version_byte ‖ opcode_hint ‖ dir ‖ epoch ‖ msg_id}.
 *
 * <p>Bootstrap form (§4.2.1): byte 0 = 0xFF, remaining bytes are L3 plaintext,
 * no tag. Accepted only for opcode HELLO, and only by the gateway.
 */
public final class L2 {

    /** Epoch value marking bootstrap form; not a valid epoch (§4.6). */
    public static final int EPOCH_BOOTSTRAP = 0xFF;

    /** Direction: wallet → gateway. */
    public static final int DIR_W2G = 0x00;
    /** Direction: gateway → wallet. */
    public static final int DIR_G2W = 0x01;

    /** L2 overhead: 1-byte epoch + 16-byte Poly1305 tag (§4.4). */
    public static final int OVERHEAD = 17;

    private L2() {
    }

    /**
     * Seal an L3 message. Returns {@code epoch ‖ ciphertext ‖ tag}.
     *
     * @param key        the 32-byte directional key (k_w2g or k_g2w)
     * @param epoch      key epoch, 0x00–0xFE
     * @param dir        DIR_W2G or DIR_G2W
     * @param msgId      16-bit message id (§3.3); never reuse for two plaintexts (§4.5)
     * @param opcodeHint the message's opcode (first L3 array element)
     * @param plaintext  the L3 CBOR bytes
     */
    public static byte[] seal(byte[] key, int epoch, int dir, int msgId, int opcodeHint, byte[] plaintext) {
        validateEpoch(epoch);
        ChaCha20Poly1305 aead = init(true, key, epoch, dir, msgId, opcodeHint);
        byte[] out = new byte[1 + plaintext.length + 16];
        out[0] = (byte) epoch;
        int n = aead.processBytes(plaintext, 0, plaintext.length, out, 1);
        try {
            aead.doFinal(out, 1 + n);
        } catch (Exception e) {
            throw new IllegalStateException("AEAD seal failed", e);
        }
        return out;
    }

    /**
     * Open a sealed message. Returns the L3 plaintext.
     *
     * @throws AeadException if the tag does not verify
     */
    public static byte[] open(byte[] key, int dir, int msgId, int opcodeHint, byte[] sealed) {
        if (sealed.length < 1 + 16) {
            throw new AeadException("sealed message too short: " + sealed.length);
        }
        int epoch = sealed[0] & 0xFF;
        if (epoch == EPOCH_BOOTSTRAP) {
            throw new AeadException("bootstrap form is not a sealed message (§4.2.1)");
        }
        ChaCha20Poly1305 aead = init(false, key, epoch, dir, msgId, opcodeHint);
        byte[] out = new byte[sealed.length - 1 - 16];
        int n = aead.processBytes(sealed, 1, sealed.length - 1, out, 0);
        try {
            aead.doFinal(out, n);
        } catch (org.bouncycastle.crypto.InvalidCipherTextException e) {
            throw new AeadException("tag verification failed", e);
        }
        return out;
    }

    /** Build bootstrap form: {@code 0xFF ‖ L3 plaintext}. Gateway HELLO only (§4.2.1). */
    public static byte[] bootstrap(byte[] l3Plaintext) {
        byte[] out = new byte[1 + l3Plaintext.length];
        out[0] = (byte) EPOCH_BOOTSTRAP;
        System.arraycopy(l3Plaintext, 0, out, 1, l3Plaintext.length);
        return out;
    }

    /**
     * Parse a bootstrap-form message. Returns the L3 plaintext.
     *
     * @throws AeadException if not bootstrap form
     */
    public static byte[] parseBootstrap(byte[] message) {
        if (message.length < 1 || (message[0] & 0xFF) != EPOCH_BOOTSTRAP) {
            throw new AeadException("not bootstrap form");
        }
        return Arrays.copyOfRange(message, 1, message.length);
    }

    public static boolean isBootstrap(byte[] message) {
        return message.length >= 1 && (message[0] & 0xFF) == EPOCH_BOOTSTRAP;
    }

    // ------------------------------------------------------------ internals

    private static ChaCha20Poly1305 init(boolean forEncryption, byte[] key,
                                         int epoch, int dir, int msgId, int opcodeHint) {
        ChaCha20Poly1305 aead = new ChaCha20Poly1305();
        aead.init(forEncryption, new AEADParameters(
                new KeyParameter(key), 128, nonce(epoch, dir, msgId), aad(opcodeHint, dir, epoch, msgId)));
        return aead;
    }

    /** Implicit nonce (§4.5): {@code epoch ‖ dir ‖ msg_id(BE) ‖ 0x00 × 8}. */
    static byte[] nonce(int epoch, int dir, int msgId) {
        byte[] n = new byte[12];
        n[0] = (byte) epoch;
        n[1] = (byte) dir;
        n[2] = (byte) (msgId >> 8);
        n[3] = (byte) msgId;
        return n; // bytes 4..11 stay zero
    }

    /** Associated data (§4.5): {@code version_byte ‖ opcode_hint ‖ dir ‖ epoch ‖ msg_id}. */
    static byte[] aad(int opcodeHint, int dir, int epoch, int msgId) {
        return new byte[]{
                0x00,               // L1 version 0 (§13.1)
                (byte) opcodeHint,
                (byte) dir,
                (byte) epoch,
                (byte) (msgId >> 8),
                (byte) msgId
        };
    }

    private static void validateEpoch(int epoch) {
        if (epoch < 0 || epoch >= EPOCH_BOOTSTRAP) {
            throw new IllegalArgumentException("epoch must be 0x00–0xFE, got " + epoch);
        }
    }

    /** L2 authentication/usage failure (maps to NACK DECRYPT_FAILED, §3.8). */
    public static final class AeadException extends RuntimeException {
        public AeadException(String message) {
            super(message);
        }

        public AeadException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
