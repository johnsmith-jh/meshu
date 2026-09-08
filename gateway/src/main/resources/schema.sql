-- Meshu gateway daemon state (POC-WALLET.md §3, §8.1; PROTOCOL.md §4.2.1, §11.1)

-- Key-value store for daemon-level state, including the long-term X25519
-- keypair (rows 'x25519_private_pkcs8' / 'x25519_public_x509'). Back this up
-- like the mint's own keys: rotation invalidates the connection QR and every
-- pinned wallet session (§8.3).
CREATE TABLE IF NOT EXISTS daemon_state (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

-- Pairing table (PROTOCOL.md §4.2.1): wallets introduce their L2 key in a
-- plaintext first HELLO; the gateway pins it and never replaces it.
CREATE TABLE IF NOT EXISTS pairing (
    wallet_pubkey BLOB PRIMARY KEY,          -- 32-byte X25519
    first_seen_at INTEGER NOT NULL DEFAULT (unixepoch()),
    last_seen_at  INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Replay cache (PROTOCOL.md §11.1): idempotent retry of state-changing ops.
-- Keyed by (wallet_pubkey, epoch, msg_id, l3_hash). A cache hit replays the
-- stored response without re-executing; a msg_id collision with a DIFFERENT
-- l3_hash is MC_MALFORMED (a bug or an attack).
CREATE TABLE IF NOT EXISTS replay_cache (
    wallet_pubkey BLOB    NOT NULL,
    epoch         INTEGER NOT NULL,
    msg_id        INTEGER NOT NULL,
    l3_hash       BLOB    NOT NULL,          -- SHA-256 of the L3 plaintext
    response      BLOB,                      -- sealed response; NULL until completed
    created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (wallet_pubkey, epoch, msg_id)
);
