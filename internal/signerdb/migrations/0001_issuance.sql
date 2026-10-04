-- Serial high-water mark (CA-03). Exactly one row.
CREATE TABLE serial_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_serial INTEGER NOT NULL CHECK (last_serial >= 0)
);
INSERT INTO serial_state (id, last_serial) VALUES (1, 0);

-- One row per issued certificate. The serial is the primary key, so a
-- serial can never be recorded twice, and a request id can be used once.
CREATE TABLE issuance (
    serial INTEGER PRIMARY KEY CHECK (serial > 0),
    request_id BLOB NOT NULL UNIQUE CHECK (length(request_id) = 16),
    ca_role TEXT NOT NULL,
    key_id TEXT NOT NULL,
    cert BLOB NOT NULL,
    issued_at_us INTEGER NOT NULL
);
