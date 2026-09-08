package meshu.core.l2;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/**
 * L2 AEAD and key agreement (PROTOCOL.md §4.2–§4.5).
 */
class L2Test {

    private static final HexFormat HEX = HexFormat.of();

    /** RFC 8439 §2.8.2 ChaCha20-Poly1305 AEAD test vector. */
    @Test
    void rfc8439AeadVector() throws Exception {
        byte[] key = HEX.parseHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce = HEX.parseHex("070000004041424344454647");
        byte[] aad = HEX.parseHex("50515253c0c1c2c3c4c5c6c7");
        byte[] plaintext = HEX.parseHex(
                "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
        byte[] expectedCt = HEX.parseHex(
                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116");
        byte[] expectedTag = HEX.parseHex("1ae10b594f09e26a7e902ecbd0600691");

        org.bouncycastle.crypto.modes.ChaCha20Poly1305 aead = new org.bouncycastle.crypto.modes.ChaCha20Poly1305();
        aead.init(true, new org.bouncycastle.crypto.params.AEADParameters(
                new org.bouncycastle.crypto.params.KeyParameter(key), 128, nonce, aad));
        byte[] out = new byte[plaintext.length + 16];
        int n = aead.processBytes(plaintext, 0, plaintext.length, out, 0);
        aead.doFinal(out, n);

        byte[] ct = new byte[plaintext.length];
        byte[] tag = new byte[16];
        System.arraycopy(out, 0, ct, 0, ct.length);
        System.arraycopy(out, ct.length, tag, 0, 16);
        assertArrayEquals(expectedCt, ct);
        assertArrayEquals(expectedTag, tag);
    }

    /** Both sides of an X25519 exchange derive identical directional keys (§4.2). */
    @Test
    void bothSidesDeriveIdenticalDirectionalKeys() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("X25519");
        KeyPair wallet = gen.generateKeyPair();
        KeyPair gateway = gen.generateKeyPair();

        byte[] walletPubRaw = rawPublic(wallet);
        byte[] gatewayPubRaw = rawPublic(gateway);

        KeyAgreement.DirectionalKeys walletSide = KeyAgreement.derive(wallet.getPrivate(), gatewayPubRaw);
        KeyAgreement.DirectionalKeys gatewaySide = KeyAgreement.derive(gateway.getPrivate(), walletPubRaw);

        assertArrayEquals(walletSide.walletToGateway(), gatewaySide.walletToGateway());
        assertArrayEquals(walletSide.gatewayToWallet(), gatewaySide.gatewayToWallet());
        // Directional keys differ from each other (reflection protection, §4.2).
        assertFalse(java.util.Arrays.equals(walletSide.walletToGateway(), walletSide.gatewayToWallet()));
    }

    /** Seal then open recovers the plaintext; nonce and AAD bind context (§4.5). */
    @Test
    void sealOpenRoundTrip() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("X25519");
        KeyPair a = gen.generateKeyPair();
        KeyPair b = gen.generateKeyPair();
        KeyAgreement.DirectionalKeys keys = KeyAgreement.derive(a.getPrivate(), rawPublic(b));

        byte[] plaintext = "meshu L3 message".getBytes();
        int epoch = 0, msgId = 0x1234, opcode = 0x0D;

        byte[] sealed = L2.seal(keys.walletToGateway(), epoch, L2.DIR_W2G, msgId, opcode, plaintext);
        assertEquals(1 + plaintext.length + 16, sealed.length); // 17-byte overhead (§4.4)
        assertEquals(0, sealed[0]); // epoch 0

        byte[] opened = L2.open(keys.walletToGateway(), L2.DIR_W2G, msgId, opcode, sealed);
        assertArrayEquals(plaintext, opened);
    }

    /** Wrong opcode_hint in AAD fails verification (§4.5: binds opcode). */
    @Test
    void wrongOpcodeHintFailsVerification() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("X25519");
        KeyPair a = gen.generateKeyPair();
        KeyPair b = gen.generateKeyPair();
        KeyAgreement.DirectionalKeys keys = KeyAgreement.derive(a.getPrivate(), rawPublic(b));

        byte[] sealed = L2.seal(keys.walletToGateway(), 0, L2.DIR_W2G, 1, 0x0D, "x".getBytes());
        assertThrows(L2.AeadException.class,
                () -> L2.open(keys.walletToGateway(), L2.DIR_W2G, 1, 0x08 /* wrong op */, sealed));
    }

    /** Wrong msg_id fails (nonce mismatch, §4.5). */
    @Test
    void wrongMsgIdFailsVerification() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("X25519");
        KeyPair a = gen.generateKeyPair();
        KeyPair b = gen.generateKeyPair();
        KeyAgreement.DirectionalKeys keys = KeyAgreement.derive(a.getPrivate(), rawPublic(b));

        byte[] sealed = L2.seal(keys.walletToGateway(), 0, L2.DIR_W2G, 0x1234, 0x0D, "x".getBytes());
        assertThrows(L2.AeadException.class,
                () -> L2.open(keys.walletToGateway(), L2.DIR_W2G, 0x1235, 0x0D, sealed));
    }

    /** Wrong direction fails (AAD + directional key, §4.2/§4.5). */
    @Test
    void wrongDirectionFailsVerification() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("X25519");
        KeyPair a = gen.generateKeyPair();
        KeyPair b = gen.generateKeyPair();
        KeyAgreement.DirectionalKeys keys = KeyAgreement.derive(a.getPrivate(), rawPublic(b));

        byte[] sealed = L2.seal(keys.walletToGateway(), 0, L2.DIR_W2G, 1, 0x0D, "x".getBytes());
        assertThrows(L2.AeadException.class,
                () -> L2.open(keys.gatewayToWallet(), L2.DIR_G2W, 1, 0x0D, sealed));
    }

    /** Bootstrap form: 0xFF ‖ plaintext, no tag (§4.2.1). */
    @Test
    void bootstrapForm() {
        byte[] l3 = {0x0D, 0x01, 0x02};
        byte[] boot = L2.bootstrap(l3);
        assertEquals((byte) 0xFF, boot[0]);
        assertEquals(1 + l3.length, boot.length);
        assertTrue(L2.isBootstrap(boot));
        assertArrayEquals(l3, L2.parseBootstrap(boot));

        // A sealed message is not bootstrap form.
        assertFalse(L2.isBootstrap(new byte[]{0x00, 0x01}));
        assertThrows(L2.AeadException.class, () -> L2.parseBootstrap(new byte[]{0x00, 0x01}));
    }

    /** Opening a bootstrap-form message as sealed is rejected (§4.2.1). */
    @Test
    void bootstrapRejectedAsSealed() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("X25519");
        KeyPair a = gen.generateKeyPair();
        KeyPair b = gen.generateKeyPair();
        KeyAgreement.DirectionalKeys keys = KeyAgreement.derive(a.getPrivate(), rawPublic(b));

        byte[] boot = L2.bootstrap(new byte[]{0x0D});
        assertThrows(L2.AeadException.class,
                () -> L2.open(keys.walletToGateway(), L2.DIR_W2G, 1, 0x0D, boot));
    }

    /** Epoch must be 0x00–0xFE; 0xFF is bootstrap-only (§4.6). */
    @Test
    void epochValidation() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("X25519");
        KeyPair a = gen.generateKeyPair();
        KeyPair b = gen.generateKeyPair();
        KeyAgreement.DirectionalKeys keys = KeyAgreement.derive(a.getPrivate(), rawPublic(b));

        assertThrows(IllegalArgumentException.class,
                () -> L2.seal(keys.walletToGateway(), 0xFF, L2.DIR_W2G, 1, 0x0D, "x".getBytes()));
        // 0xFE is valid.
        assertDoesNotThrow(() ->
                L2.seal(keys.walletToGateway(), 0xFE, L2.DIR_W2G, 1, 0x0D, "x".getBytes()));
    }

    /** The implicit nonce is epoch ‖ dir ‖ msg_id(BE) ‖ zeros (§4.5). */
    @Test
    void implicitNonceLayout() {
        byte[] n = L2.nonce(0x05, 0x01, 0x1234);
        assertEquals(12, n.length);
        assertArrayEquals(new byte[]{0x05, 0x01, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0}, n);
    }

    /** AAD is version ‖ opcode_hint ‖ dir ‖ epoch ‖ msg_id (§4.5). */
    @Test
    void aadLayout() {
        byte[] aad = L2.aad(0x0D, 0x00, 0x00, 0x1234);
        assertArrayEquals(new byte[]{0x00, 0x0D, 0x00, 0x00, 0x12, 0x34}, aad);
    }

    private static byte[] rawPublic(KeyPair kp) {
        byte[] enc = kp.getPublic().getEncoded();
        return java.util.Arrays.copyOfRange(enc, enc.length - 32, enc.length);
    }
}
