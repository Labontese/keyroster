-- Every installed admin-signed directory version (D-01): the canonical
-- directory document with the admins' detached SSHSIG signatures under
-- keyroster/directory/v1, and the policy version it was verified under.
-- The highest version is in force. Each row commits in the same
-- transaction as its directory_install log leaf.
CREATE TABLE directory (
    version INTEGER PRIMARY KEY CHECK (version >= 1),
    doc BLOB NOT NULL,
    sigs BLOB NOT NULL,
    policy_version INTEGER NOT NULL,
    installed_at_us INTEGER NOT NULL
);
