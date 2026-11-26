-- the pane each session's machine pushes itself every 2 s when it changed (machine/screen.go; router/screens.go): the
-- read-only terminal, the autopilot's dialog check and a stuck harness's reason read it, from any replica. Apart from
-- the versioned records, so a push doesn't make every replica read them all again.
CREATE TABLE session_screens (
  session_id text PRIMARY KEY,
  machine_id text NOT NULL,
  snap       jsonb NOT NULL,
  at         timestamptz NOT NULL DEFAULT now()
);
