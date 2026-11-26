-- what waits for a machine (docs/STATE.md 5, step 6): supervisor commands, holder-signed execs and attested deliveries,
-- taken by its long poll (GET /m/commands) on whichever router replica it reaches; an exec's or a delivery's answer
-- comes back on the same row (ref = its id). Writers NOTIFY mq (payload m:<machine> / a:<ref>) in the same transaction.
CREATE TABLE machine_queue (
  id          bigserial PRIMARY KEY,
  machine_id  text NOT NULL,
  kind        text NOT NULL CHECK (kind IN ('command', 'exec', 'delivery')),
  ref         text NOT NULL DEFAULT '',
  body        jsonb NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  taken_at    timestamptz,
  answered_at timestamptz,
  answer      jsonb
);
CREATE INDEX machine_queue_untaken ON machine_queue (machine_id, id) WHERE taken_at IS NULL;
CREATE INDEX machine_queue_ref ON machine_queue (ref) WHERE ref <> '';
-- the final snapshot a pause or destroy waits for (snapwait.go): its progress and how it ended, seen by every replica
CREATE TABLE snapshot_waits (
  machine_id text PRIMARY KEY,
  token      text NOT NULL,
  moved_at   timestamptz NOT NULL,
  progress   jsonb,
  done       boolean NOT NULL DEFAULT false,
  error      text NOT NULL DEFAULT ''
);
