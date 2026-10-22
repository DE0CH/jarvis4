-- machines' snapshots (docs/STATE.md 2.2): the tarball is an object (object_key in jarvis4-snapshots-de0ch); the row
-- says what it is. pending: streamed, its hash known, not yet signed; committed: the machine signed its sha256 (sig).
-- A booting machine's carried-over snapshot names its predecessor's object (no copy). facts: what the router reads
-- out of it (transcripts, the conversation's tail, the repos' changes), taken while it streams in.
CREATE TABLE snapshots (
  machine_id   text PRIMARY KEY,
  object_key   text NOT NULL,
  sha256       text NOT NULL,
  sig          text NOT NULL DEFAULT '',
  bytes        bigint NOT NULL,
  state        text NOT NULL CHECK (state IN ('pending', 'committed')),
  facts        jsonb,
  committed_at timestamptz
);
CREATE INDEX snapshots_object ON snapshots (object_key);
