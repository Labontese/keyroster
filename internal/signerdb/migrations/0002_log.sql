-- Merkle log (VIS-01). One row per leaf, in index order without gaps; the
-- leaf bytes are the canonical tlog encoding and leaf_hash their RFC 6962
-- leaf hash.
CREATE TABLE log_leaf (
    idx INTEGER PRIMARY KEY CHECK (idx >= 0),
    leaf BLOB NOT NULL,
    leaf_hash BLOB NOT NULL CHECK (length(leaf_hash) = 32)
);

-- One signed C2SP checkpoint per log size. Every append writes the
-- checkpoint for the new size in the same transaction as the leaf.
CREATE TABLE checkpoint (
    size INTEGER PRIMARY KEY CHECK (size > 0),
    note BLOB NOT NULL
);
