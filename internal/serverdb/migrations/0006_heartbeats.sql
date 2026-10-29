-- Host agent operations (03-08, AGENT-07).
--
-- heartbeats: the newest heartbeat of each enrolled agent, by its seq. A
-- heartbeat replaces the stored one only when its seq is greater, so a
-- replayed or reordered heartbeat never replaces a newer one. body is the
-- canonical JSON the agent posted, every field validated before it was
-- stored; received_at_us is the server's clock at receipt. Nothing here is
-- authority: it is the host's own word, shown by keyroster host status.
CREATE TABLE heartbeats (
    agent_id INTEGER PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    body BLOB NOT NULL,
    received_at_us INTEGER NOT NULL
);

-- removed_dir_version: for an agent approved once, the directory version
-- the server first served it under that no longer approves it (its entry
-- removed, disabled or re-keyed), recorded on the agent's first request
-- under such a version and cleared when a directory approves it again.
-- keyroster host forget waits until the host's heartbeat shows a
-- committed directory version at or above it (host_removal_not_applied,
-- owner decision 2026-10-28), unless the admin passes --host-gone.
ALTER TABLE agents ADD COLUMN removed_dir_version INTEGER;

-- clock_offset_s: the clock offset of the agent's newest heartbeat that
-- authenticated and parsed, stored or refused (a stale or a future seq
-- included), so clock_skew in keyroster host status never lags behind
-- the fetcher (owner decision D-R2, PR #72 review). NULL: none yet.
ALTER TABLE agents ADD COLUMN clock_offset_s INTEGER;

-- seq_regressed_at_us: when a heartbeat with a seq below the stored one
-- was last refused and logged (at most once an hour per agent). It is
-- later than heartbeats.received_at_us while the host still sends lower
-- seqs, which keyroster host status flags seq_regressed (D-R2).
ALTER TABLE agents ADD COLUMN seq_regressed_at_us INTEGER;
