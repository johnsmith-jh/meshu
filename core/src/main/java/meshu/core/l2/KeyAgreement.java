package meshu.core.l2;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * L2 key agreement and derivation (PROTOCOL.md §4.2).
 *
 * <pre>
 * shared    = X25519(own_private, peer_public)
 * prk       = HKDF-Extract(salt = "meshu/v1/salt", ikm = shared)
 * k_w2g     = HKDF-Expand(prk, "meshu/v1/w2g", 32)
 * k_g2w     = HKDF-Expand(prk, "meshu/v1/g2w", 32)
 * </pre>
 *
 * HKDF is HMAC-SHA256 (RFC 5869). Separate directional keys prevent reflection.
 */
public final class KeyAgreement {

    private static final byte[] SALT = "meshu/v1/salt".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final byte[] INFO_W2G = "meshu/v1/w2g".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final byte[] INFO_G2W = "meshu/v1/g2w".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    private KeyAgreement() {
    }

    /** The two directional session keys derived from one static-static ECDH. */
    public record DirectionalKeys(byte[] walletToGateway, byte[] gatewayToWallet) {
        public DirectionalKeys {
            if (walletToGateway.length != 32 || gatewayToWallet.length != 32) {
                throw new IllegalArgumentException("directional keys must be 32 bytes");
            }
            walletToGateway = walletToGateway.clone();
            gatewayToWallet = gatewayToWallet.clone();
        }
    }

    /**
     * Derive directional keys from own X25519 private key and the peer's raw
     * 32-byte X25519 public key.
     */
    public static DirectionalKeys derive(PrivateKey ownPrivate, byte[] peerPublicRaw32) {
        try {
            byte[] shared = x25519(ownPrivate, peerPublicRaw32);
            byte[] prk = hkdfExtract(SALT, shared);
            return new DirectionalKeys(
                    hkdfExpand(prk, INFO_W2G, 32),
                    hkdfExpand(prk, INFO_G2W, 32));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("X25519/HKDF failed", e);
        }
    }

    /** Raw X25519 Diffie-Hellman shared secret. */
    static byte[] x25519(PrivateKey ownPrivate, byte[] peerPublicRaw32) throws GeneralSecurityException {
        // The JDK wraps a raw X25519 public key in a fixed 12-byte X.509 prefix.
        byte[] x509 = new byte[44];
        System.arraycopy(X25519_PUBLIC_PREFIX, 0, x509, 0, X25519_PUBLIC_PREFIX.length);
        System.arraycopy(peerPublicRaw32, 0, x509, X25519_PUBLIC_PREFIX.length, 32);
        KeyFactory kf = KeyFactory.getInstance("X25519");
        PublicKey peer = kf.generatePublic(new X509EncodedKeySpec(x509));
        javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("XDH");
        ka.init(ownPrivate);
        ka.doPhase(peer, true);
        return ka.generateSecret();
    }

    /** X.509 SubjectPublicKeyInfo DER prefix for X25519 (RFC 8410). */
    private static final byte[] X25519_PUBLIC_PREFIX = {
            0x30, 0x2a,                         // SEQUENCE, 42 bytes
            0x30, 0x05,                         // SEQUENCE, 5 bytes (AlgorithmIdentifier)
            0x06, 0x03, 0x2b, 0x65, 0x6e,       // OID 1.3.101.110 (X25519)
            0x03, 0x21, 0x00                    // BIT STRING, 33 bytes, 0 unused bits
    };

    static byte[] hkdfExtract(byte[] salt, byte[] ikm) throws GeneralSecurityException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(salt, "HmacSHA256"));
        return hmac.doFinal(ikm);
    }

    static byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws GeneralSecurityException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(prk, "HmacSHA256"));
        byte[] okm = new byte[length];
        byte[] t = new byte[0];
        int produced = 0;
        for (int counter = 1; produced < length; counter++) {
            hmac.reset();
            hmac.update(t);
            hmac.update(info);
            hmac.update((byte) counter);
            t = hmac.doFinal();
            int n = Math.min(t.length, length - produced);
            System.arraycopy(t, 0, okm, produced, n);
            produced += n;
        }
        Arrays.fill(t, (byte) 0);
        return okm;
    }
}
