-- Passkey registration (02-08). NOTHING HERE IS AUTHORITY EITHER: a
-- pending credential is a proposal the admin compares out of band and
-- signs into a directory version (02-09). Until the signer has installed
-- such a directory, the credential lets nobody sign in.

-- One row per begun registration ceremony: the go-webauthn session data
-- the server wrote itself (it never decodes session bytes a client sent),
-- keyed by the invite and the ceremony's challenge, so concurrent
-- ceremonies on one invite never overwrite each other's session. A row is
-- consumed once, with DELETE ... RETURNING (02-08-F1).
CREATE TABLE registration_sessions (
    invite_hash BLOB NOT NULL,
    challenge TEXT NOT NULL,
    session BLOB NOT NULL,
    expires_us INTEGER NOT NULL,
    PRIMARY KEY (invite_hash, challenge)
);

-- Credentials registered through an invite and not yet bound by an
-- admin-signed directory. id is the unpadded base64url of the credential
-- ID go-webauthn verified (never the client's id string), alg the COSE
-- algorithm and spki the public key as SPKI DER, accepted by the same
-- internal/webauthn.ParsePublicKey rule the signer applies.
CREATE TABLE pending_credentials (
    id TEXT PRIMARY KEY,
    user_name TEXT NOT NULL REFERENCES pending_users(name),
    alg INTEGER NOT NULL,
    spki BLOB NOT NULL,
    backup_eligible INTEGER NOT NULL CHECK (backup_eligible IN (0,1)),
    backed_up INTEGER NOT NULL CHECK (backed_up IN (0,1)),
    registered_us INTEGER NOT NULL
);

-- At most one pending credential per user: an invite registers exactly
-- one passkey (02-08-F1).
CREATE UNIQUE INDEX pending_credentials_one_per_user ON pending_credentials(user_name);

-- When the current invite registered its credential; NULL while unused.
-- A reinvite resets it.
ALTER TABLE pending_users ADD COLUMN invite_used_us INTEGER;
