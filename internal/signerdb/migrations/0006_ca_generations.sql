-- Every CA key generation of every role (03-12, D-14): generation 1 is the
-- ca-init key of ca_keys, and each later generation is created by
-- keyroster-signer ca-rotate prepare together with a ca_generation log
-- entry in the same transaction. pubkey is the SSH wire encoding, and no
-- key serves two generations or two roles. location is a backend's handle
-- for the key (the PIV slot of a later plan); it is empty for the software,
-- agent and memory backends.
CREATE TABLE ca_key_generations (
    role TEXT NOT NULL CHECK (role IN ('user', 'host', 'machine', 'ops', 'log')),
    generation INTEGER NOT NULL CHECK (generation >= 1 AND generation <= 4294967295),
    pubkey BLOB NOT NULL UNIQUE,
    alg TEXT NOT NULL,
    custody TEXT NOT NULL,
    location TEXT NOT NULL DEFAULT '',
    created_at_us INTEGER NOT NULL,
    PRIMARY KEY (role, generation)
);

-- A database that ca-init already initialised gets generation 1 of each
-- of its five keys.
INSERT INTO ca_key_generations (role, generation, pubkey, alg, custody, location, created_at_us)
SELECT role, 1, pubkey, alg, custody, '', 0 FROM ca_keys;
