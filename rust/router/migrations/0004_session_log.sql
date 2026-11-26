-- each session's lifecycle log and its machines' supervisor lines, and the old core's input log (session ''),
-- (docs/STATE.md step 4): what were lifecycle/<session>.jsonl, supervisor-log/<session>.jsonl and input-log.jsonl on the
-- volume, one row per line, in order (n)
CREATE TABLE session_log (
  n          bigserial PRIMARY KEY,
  session_id text NOT NULL,
  kind       text NOT NULL CHECK (kind IN ('lifecycle', 'supervisor', 'input')),
  line       jsonb NOT NULL
);
CREATE INDEX session_log_by_session ON session_log (session_id, kind, n);
