-- The keystore backend the CA keys were selected or provisioned in by
-- ca-init. Exactly one row; opts_json is the canonical JSON of the backend
-- options (sorted keys).
CREATE TABLE backend_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    name TEXT NOT NULL,
    opts_json TEXT NOT NULL
);

-- The five online keys chosen at ca-init (CA-01): one per role, and no key
-- serves two roles. pubkey is the SSH wire encoding.
CREATE TABLE ca_keys (
    role TEXT PRIMARY KEY CHECK (role IN ('user', 'host', 'machine', 'ops', 'log')),
    pubkey BLOB NOT NULL UNIQUE,
    alg TEXT NOT NULL,
    custody TEXT NOT NULL
);

-- Every installed root-signed trust bundle with its policy, both canonical
-- documents with their detached root signatures (KEY-07). The highest
-- version is in force.
CREATE TABLE trust_bundle (
    version INTEGER PRIMARY KEY CHECK (version >= 1),
    bundle BLOB NOT NULL,
    bundle_sigs BLOB NOT NULL,
    policy BLOB NOT NULL,
    policy_sigs BLOB NOT NULL,
    installed_at_us INTEGER NOT NULL
);
