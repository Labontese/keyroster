-- Web sign-in (02-10). A session here grants nothing beyond reading the
-- signed-in user's own account page: it never authorizes a certificate
-- or a directory change, and every request that uses it is checked again
-- against the admin-signed directory the signer has installed.

-- One row per begun sign-in ceremony: the 32 random challenge bytes the
-- server chose, for the user named at begin, until expires_us. A row is
-- consumed once, with DELETE ... RETURNING.
CREATE TABLE web_challenges (
    id TEXT PRIMARY KEY,
    user_name TEXT NOT NULL,
    challenge BLOB NOT NULL,
    expires_us INTEGER NOT NULL
);

-- Signed-in web sessions. The session ID is stored only as its SHA-256
-- (id_hash); the ID itself is never stored or logged. cred_id is the
-- credential whose assertion opened the session: the session ends as
-- soon as that credential is no longer bound to user_name. A session
-- also ends after an idle or absolute limit, which TouchSession enforces
-- in the statement that extends it.
CREATE TABLE sessions (
    id_hash BLOB PRIMARY KEY,
    user_name TEXT NOT NULL,
    cred_id BLOB NOT NULL,
    created_us INTEGER NOT NULL,
    last_seen_us INTEGER NOT NULL
);
