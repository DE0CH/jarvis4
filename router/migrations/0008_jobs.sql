-- a session's lifecycle action as a job (docs/STATE.md 3, step 7): at most one running per session (the 409 "in the
-- middle of another action"), held by one replica under a lease it renews; a replica that dies leaves the lease to run
-- out, and another replica carries the job on (jobs.go)
CREATE TABLE jobs (
  id          text PRIMARY KEY,
  session_id  text NOT NULL,
  kind        text NOT NULL,
  args        jsonb NOT NULL DEFAULT '{}',
  state       text NOT NULL CHECK (state IN ('running', 'done', 'failed')),
  owner       text NOT NULL,
  lease_until timestamptz NOT NULL,
  attempts    int NOT NULL DEFAULT 1,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  error       text NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX jobs_one_running ON jobs (session_id) WHERE state = 'running';
CREATE INDEX jobs_lease ON jobs (lease_until) WHERE state = 'running';
