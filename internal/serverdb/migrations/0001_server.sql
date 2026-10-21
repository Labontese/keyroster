-- keyroster-server's state. NOTHING HERE IS AUTHORITY: no row lets anyone
-- sign in or obtain a certificate. Only the admin-signed directory that
-- the signer has installed binds credentials to users, and only the
-- signer decides what to sign (D-03, AUTH-01). A server compromise can
-- rewrite this file; the worst it achieves is a bogus invite, which
-- still needs an admin signature to become a bound credential.

-- Accounts an admin started with `keyroster user add`, waiting for a
-- passkey and an admin-signed directory version that binds it. The
-- invite token is stored only as its SHA-256 (invite_hash); the token
-- itself is never stored or logged. user_handle is the WebAuthn user
-- handle for registration; it never takes part in authentication.
CREATE TABLE pending_users (
    name TEXT PRIMARY KEY,
    user_handle BLOB NOT NULL UNIQUE,
    invite_hash BLOB NOT NULL UNIQUE,
    invite_expires_us INTEGER NOT NULL,
    created_us INTEGER NOT NULL,
    created_by TEXT NOT NULL
);

-- Nonces of admin API requests already used, kept until expires_us (the
-- first use plus nonceRetention), which outlives the window in which
-- their signature could still be accepted. A second use is a replay.
CREATE TABLE admin_nonces (
    nonce TEXT PRIMARY KEY,
    expires_us INTEGER NOT NULL
);
