package meshu.gateway.session;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.util.List;

import meshu.core.l2.KeyAgreement;

/**
 * TOFU pairing table (PROTOCOL.md §4.2.1).
 *
 * <p>The gateway learns a wallet's L2 X25519 key from the wallet's first HELLO,
 * sent in plaintext bootstrap form. On an unknown key the gateway derives the
 * directional keys and <b>pins</b> the pairing durably; a pinned key is
 * <b>never replaced</b> via bootstrap — that rule is what makes first-contact
 * TOFU safe (§1.3 T7).
 *
 * <p>All state is keyed by the full 32-byte wallet_pubkey, never by the 1-byte
 * src hash (which belongs to the companion node, §2.3).
 */
@Component
public class PairingService {

    private static final Logger log = LoggerFactory.getLogger(PairingService.class);

    /** MESHU_MAX_WALLETS (§4.2.1): bound the pairing table against abuse. */
    public static final int MAX_WALLETS = 64;

    private final JdbcTemplate db;
    private final KeyPair daemonKey;

    public PairingService(JdbcTemplate db, meshu.gateway.crypto.DaemonIdentity daemonIdentity) {
        this.db = db;
        this.daemonKey = daemonIdentity.loadOrCreate();
    }

    /** The daemon's raw 32-byte X25519 public key (for HELLO responses). */
    public byte[] daemonPublicKey() {
        return meshu.gateway.crypto.DaemonIdentity.rawPublicKey(daemonKey);
    }

    /** Whether a wallet key is already pinned. */
    public boolean isPinned(byte[] walletPubkey) {
        Integer n = db.queryForObject(
                "SELECT COUNT(*) FROM pairing WHERE wallet_pubkey = ?",
                Integer.class, walletPubkey);
        return n != null && n > 0;
    }

    /**
     * Pin a new wallet key from a bootstrap HELLO. Never replaces an existing
     * pairing (§4.2.1). Returns the directional keys for this wallet.
     *
     * @throws PairingException if the table is full
     */
    public KeyAgreement.DirectionalKeys pinIfNew(byte[] walletPubkey) {
        if (walletPubkey.length != 32) {
            throw new IllegalArgumentException("wallet_pubkey must be 32 bytes");
        }
        if (isPinned(walletPubkey)) {
            // Replays of a bootstrap HELLO are harmless: reply under the pinned key.
            return keysFor(walletPubkey);
        }
        Integer count = db.queryForObject("SELECT COUNT(*) FROM pairing", Integer.class);
        if (count != null && count >= MAX_WALLETS) {
            throw new PairingException("pairing table full (" + MAX_WALLETS + ")");
        }
        db.update("INSERT INTO pairing(wallet_pubkey) VALUES (?)", walletPubkey);
        log.info("pinned new wallet {}… ({} paired)", hexPrefix(walletPubkey), count == null ? 1 : count + 1);
        return keysFor(walletPubkey);
    }

    /** Derive the directional keys for a pinned wallet. */
    public KeyAgreement.DirectionalKeys keysFor(byte[] walletPubkey) {
        return KeyAgreement.derive(daemonKey.getPrivate(), walletPubkey);
    }

    /** Touch last_seen for audit. */
    public void seen(byte[] walletPubkey) {
        db.update("UPDATE pairing SET last_seen_at = unixepoch() WHERE wallet_pubkey = ?", walletPubkey);
    }

    /** All pinned wallet pubkeys (for src-hash collision resolution, §2.3). */
    public List<byte[]> allWallets() {
        return db.query("SELECT wallet_pubkey FROM pairing", (rs, i) -> rs.getBytes(1));
    }

    private static String hexPrefix(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            sb.append(Character.forDigit((b[i] >> 4) & 0xF, 16)).append(Character.forDigit(b[i] & 0xF, 16));
        }
        return sb.toString();
    }

    /** Pairing table exhausted (§4.2.1: gateways MUST bound it). */
    public static final class PairingException extends RuntimeException {
        public PairingException(String message) {
            super(message);
        }
    }
}
