-- Revocation state (Phase 3, REVOKE-01..03). Every row commits in the same
-- transaction as the revoke and krl_publish log leaves that record it.
--
-- revocation: one row per revoked entry. Kind serial names a certificate by
-- its CA key (SSH wire format) and serial; key_id and key arrive with 03-03.
-- valid_before_us is the revoked certificate's valid_before (whole seconds)
-- times 10^6, NULL when not known. request_id is the revoke request that
-- added the row; it is not unique, because one request may resolve to
-- several entries or to none.
CREATE TABLE revocation (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('serial', 'key_id', 'key')),
    ca_key BLOB,
    serial INTEGER CHECK (serial IS NULL OR serial > 0),
    key_id TEXT,
    key BLOB,
    valid_before_us INTEGER,
    request_id BLOB NOT NULL CHECK (length(request_id) = 16),
    leaf_index INTEGER NOT NULL,
    revoked_at_us INTEGER NOT NULL
);

-- krl_state: the KRL version in force, its canonical manifest and the ops
-- key's detached signature over it. Exactly one row once a KRL is
-- published; none before.
CREATE TABLE krl_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL CHECK (version >= 1),
    krl BLOB NOT NULL,
    manifest BLOB NOT NULL,
    sig BLOB NOT NULL,
    published_at_us INTEGER NOT NULL
);

-- revoke_request: one row per accepted revoke request, also when it
-- resolved to no entry, so a replayed request ID is refused
-- (duplicate_request) before any state changes.
CREATE TABLE revoke_request (
    request_id BLOB PRIMARY KEY CHECK (length(request_id) = 16),
    leaf_index INTEGER NOT NULL
);
