package meshu.gateway.session;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

/**
 * Replay cache (PROTOCOL.md §11.1), persisted in SQLite.
 *
 * <p>Keyed by {@code (wallet_pubkey, epoch, msg_id)}. On a request whose
 * SHA-256(L3 plaintext) matches a stored entry, the cached response is replayed
 * and the operation is <b>not</b> re-executed — for MINT/MELT/SWAP this is the
 * difference between idempotence and losing funds. A {@code msg_id} collision
 * with a <b>different</b> L3 hash is MC_MALFORMED (a bug or an attack).
 *
 * <p>The cache survives restart (entries for state-changing ops MUST, §11.1),
 * which is why it lives in the database rather than memory.
 */
@Component
public class ReplayCache {

    private final JdbcTemplate db;

    public ReplayCache(JdbcTemplate db) {
        this.db = db;
    }

    /** Outcome of a cache lookup. */
    public sealed interface Lookup {
        /** No prior entry — proceed to execute and then {@link #store}. */
        record Miss() implements Lookup {
            static final Miss INSTANCE = new Miss();
        }

        /** Exact retry — replay the stored response without re-executing. */
        record Hit(byte[] sealedResponse) implements Lookup {
        }

        /** Same (wallet, epoch, msg_id) but a different payload — MC_MALFORMED. */
        record Conflict() implements Lookup {
            static final Conflict INSTANCE = new Conflict();
        }

        /** Entry exists but has no stored response yet (a prior attempt crashed mid-op). */
        record Incomplete() implements Lookup {
            static final Incomplete INSTANCE = new Incomplete();
        }
    }

    /**
     * Look up a request. Call before executing the op.
     */
    public Lookup lookup(byte[] walletPubkey, int epoch, int msgId, byte[] l3Plaintext) {
        List<Row> rows = db.query(
                "SELECT l3_hash, response FROM replay_cache WHERE wallet_pubkey=? AND epoch=? AND msg_id=?",
                (rs, i) -> new Row(rs.getBytes(1), rs.getBytes(2)),
                walletPubkey, epoch, msgId);
        if (rows.isEmpty()) {
            return Lookup.Miss.INSTANCE;
        }
        Row row = rows.getFirst();
        if (!Arrays.equals(row.l3Hash, sha256(l3Plaintext))) {
            return Lookup.Conflict.INSTANCE;
        }
        return row.response == null ? Lookup.Incomplete.INSTANCE : new Lookup.Hit(row.response);
    }

    /** Record a request before executing (crash-safe intent), with no response yet. */
    public void recordIntent(byte[] walletPubkey, int epoch, int msgId, byte[] l3Plaintext) {
        db.update(
                "INSERT OR IGNORE INTO replay_cache(wallet_pubkey, epoch, msg_id, l3_hash) VALUES (?,?,?,?)",
                walletPubkey, epoch, msgId, sha256(l3Plaintext));
    }

    /** Store the sealed response for a recorded request. */
    public void store(byte[] walletPubkey, int epoch, int msgId, byte[] sealedResponse) {
        db.update(
                "UPDATE replay_cache SET response=? WHERE wallet_pubkey=? AND epoch=? AND msg_id=?",
                sealedResponse, walletPubkey, epoch, msgId);
    }

    private record Row(byte[] l3Hash, byte[] response) {
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
