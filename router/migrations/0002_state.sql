-- the router's records (docs/STATE.md step 3): what state.json held, one table per collection, each row the record's
-- JSON as the router's Go types write it (doc). A few hot columns are generated from doc for queries; the rest of the
-- schema outline (STATE.md 2.1) reshapes these as later steps need queries on them. Singletons are settings rows.
CREATE TABLE sessions (
  id         text PRIMARY KEY,
  doc        jsonb NOT NULL,
  state      text GENERATED ALWAYS AS (doc->>'state') STORED,
  machine_id text GENERATED ALWAYS AS (nullif(doc->>'machineId', '')) STORED
);
CREATE INDEX sessions_machine ON sessions (machine_id);
CREATE TABLE records (
  ord        int PRIMARY KEY,           -- the order destroyed sessions were recorded in
  doc        jsonb NOT NULL,
  session_id text GENERATED ALWAYS AS (doc->>'id') STORED
);
CREATE TABLE approvals (
  id         text PRIMARY KEY,
  doc        jsonb NOT NULL,
  kind       text GENERATED ALWAYS AS (doc->>'kind') STORED,
  session_id text GENERATED ALWAYS AS (doc->>'session') STORED
);
CREATE TABLE machines        (id text PRIMARY KEY, doc jsonb NOT NULL);  -- what each machine's start reported: its keys
CREATE TABLE machine_certs   (id text PRIMARY KEY, doc jsonb NOT NULL);  -- machine → its latest old-core succession cert
CREATE TABLE machine_sessions(id text PRIMARY KEY, doc jsonb NOT NULL);  -- machine → session id
CREATE TABLE session_certs   (id text PRIMARY KEY, doc jsonb NOT NULL);  -- session → its line's latest old-core cert
CREATE TABLE grants          (id text PRIMARY KEY, doc jsonb NOT NULL);
CREATE TABLE schedules       (id text PRIMARY KEY, doc jsonb NOT NULL);  -- session → wakeups, crons, watches, resume prompt
CREATE TABLE devices         (id text PRIMARY KEY, doc jsonb NOT NULL);
CREATE TABLE uploads         (id text PRIMARY KEY, doc jsonb NOT NULL);
CREATE TABLE inbox           (id text PRIMARY KEY, doc jsonb NOT NULL);
CREATE TABLE batches         (id text PRIMARY KEY, doc jsonb NOT NULL);
CREATE TABLE call_results    (id text PRIMARY KEY, doc jsonb NOT NULL);
CREATE TABLE outcomes        (id text PRIMARY KEY, doc jsonb NOT NULL);  -- session → its undelivered outcomes
CREATE TABLE messages        (id text PRIMARY KEY, doc jsonb NOT NULL);
CREATE TABLE message_rules   (id text PRIMARY KEY, doc jsonb NOT NULL);
