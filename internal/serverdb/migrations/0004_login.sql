-- CLI login sessions (02-12): one row per keyroster login begun through
-- the browser-loopback flow. A row is never authority. The signer
-- re-verifies the stored request and assertion when the CLI redeems the
-- code, and nothing is minted for a row that is never redeemed.
--
-- request is the LoginIssueRequest as the CLI built it, without evidence;
-- the approval page's fingerprint and the WebAuthn challenge both come from
-- these bytes. code_challenge is the CLI's PKCE S256 challenge and state
-- its loopback state; both travel back only to 127.0.0.1:redirect_port.
-- The single-use code is stored only as its SHA-256 (code_hash), set when
-- the passkey approves the row. A redeemed row is deleted by the next
-- CreateLogin: the signer's log is the record.
CREATE TABLE login_sessions (
    id TEXT PRIMARY KEY,
    user_name TEXT NOT NULL,
    request BLOB NOT NULL,
    code_challenge TEXT NOT NULL,
    state TEXT NOT NULL,
    redirect_port INTEGER NOT NULL CHECK (redirect_port BETWEEN 1024 AND 65535),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'redeemed')),
    assertion BLOB,
    code_hash BLOB UNIQUE,
    code_expires_us INTEGER,
    created_us INTEGER NOT NULL,
    expires_us INTEGER NOT NULL
);
