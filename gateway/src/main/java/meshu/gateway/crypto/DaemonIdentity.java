package meshu.gateway.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

/**
 * The daemon's long-term L2 X25519 keypair (POC-WALLET.md §8.1): generated from
 * a CSPRNG on first run and persisted in the daemon_state table. This key is one
 * half of the connection QR and MUST be backed up like the mint's own keys —
 * rotating it invalidates every pinned wallet session (§8.3).
 */
@Component
public class DaemonIdentity {

    private static final Logger log = LoggerFactory.getLogger(DaemonIdentity.class);
    private static final String PRIV_KEY = "x25519_private_pkcs8";
    private static final String PUB_KEY = "x25519_public_x509";

    private final JdbcTemplate db;

    public DaemonIdentity(JdbcTemplate db) {
        this.db = db;
    }

    /** Load the persisted keypair, or generate and persist a fresh one on first run. */
    public KeyPair loadOrCreate() {
        List<byte[]> priv = query(PRIV_KEY);
        List<byte[]> pub = query(PUB_KEY);
        if (!priv.isEmpty() && !pub.isEmpty()) {
            try {
                KeyFactory kf = KeyFactory.getInstance("X25519");
                return new KeyPair(
                        kf.generatePublic(new X509EncodedKeySpec(pub.getFirst())),
                        kf.generatePrivate(new PKCS8EncodedKeySpec(priv.getFirst())));
            } catch (Exception e) {
                throw new IllegalStateException("corrupt daemon key in daemon_state — restore from backup", e);
            }
        }
        try {
            KeyPair kp = KeyPairGenerator.getInstance("X25519").generateKeyPair();
            db.update("INSERT INTO daemon_state(key, value) VALUES (?, ?)",
                    PRIV_KEY, kp.getPrivate().getEncoded());
            db.update("INSERT INTO daemon_state(key, value) VALUES (?, ?)",
                    PUB_KEY, kp.getPublic().getEncoded());
            log.warn("generated NEW daemon X25519 keypair — back up the daemon_state table, "
                    + "this key is in every connection QR (POC-WALLET.md §8.1)");
            return kp;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("X25519 not available", e);
        }
    }

    private List<byte[]> query(String key) {
        return db.query("SELECT value FROM daemon_state WHERE key = ?",
                (rs, i) -> rs.getBytes(1), key);
    }

    /** Raw 32-byte X25519 public key (the last 32 bytes of its X.509 encoding). */
    public static byte[] rawPublicKey(KeyPair kp) {
        byte[] enc = kp.getPublic().getEncoded();
        if (enc.length != 44) {
            throw new IllegalStateException("unexpected X25519 X.509 length: " + enc.length);
        }
        return Arrays.copyOfRange(enc, enc.length - 32, enc.length);
    }

    /**
     * Connection-string fingerprint (POC-WALLET.md §8.2):
     * {@code SHA256(ed25519_pubkey ‖ x25519_pubkey)[0:8]} as 4 dash-separated
     * groups of 4 hex chars, for out-of-band verification.
     */
    public static String fingerprint(byte[] ed25519Pub, byte[] x25519Pub) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(ed25519Pub);
            byte[] digest = sha.digest(x25519Pub);
            String hex = HexFormat.of().formatHex(digest, 0, 8);
            return String.join("-",
                    hex.substring(0, 4), hex.substring(4, 8),
                    hex.substring(8, 12), hex.substring(12, 16));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
