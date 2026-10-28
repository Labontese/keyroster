-- Host agents (03-07). Nothing here is authority: a join token only lets
-- one agent record itself as pending, and an agent is approved only while
-- the admin-signed directory the signer installed holds an active host
-- entry whose keys equal the agent's enrolled host keys.
--
-- join_tokens: one row per minted join token, stored only as the SHA-256
-- of its 32 raw bytes (token_hash), with the host name the admin expects
-- and the expiry (microseconds since the epoch, a whole second). The one
-- use sets used_at_us in the same transaction that records the agent.
CREATE TABLE join_tokens (
    token_hash BLOB PRIMARY KEY CHECK (length(token_hash) = 32),
    expected_name TEXT NOT NULL,
    expires_at_us INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    used_at_us INTEGER
);

-- agents: one row per enrolled agent, keyed by the SHA-256 of its TLS
-- identity's SubjectPublicKeyInfo. host_keys is the JSON array of its
-- sorted host keys (trust.FormatKey form) and facts the JSON object of
-- its facts, both as the agent sent them and the proof of possession
-- covered. token_hash is the join token that enrolled it, so a retry of
-- that same enrollment is recognised (PR #71 review F11).
-- approved_at_us is set on the first state answer the agent got while the
-- directory approved it; from then on it keeps getting signed state after
-- its host entry is disabled or removed, so the removal and later
-- revocations reach the host, until an admin forgets the row (keyroster
-- host forget; PR #71 review D-R1).
CREATE TABLE agents (
    id INTEGER PRIMARY KEY,
    identity_spki_sha256 BLOB NOT NULL UNIQUE CHECK (length(identity_spki_sha256) = 32),
    token_hash BLOB NOT NULL CHECK (length(token_hash) = 32),
    expected_name TEXT NOT NULL,
    host_keys TEXT NOT NULL,
    facts TEXT NOT NULL,
    enrolled_at_us INTEGER NOT NULL,
    last_seen_us INTEGER,
    approved_at_us INTEGER
);
