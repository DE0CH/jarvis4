-- the router's secrets (docs/STATE.md 2.3): the Claude accounts' OAuth pairs and its holder keys, AES-256-GCM under
-- the router's seal key (Secret router-seal, never in the database or its backups); key_id names the key a row is
-- sealed under (a rotation reseals row by row)
CREATE TABLE sealed_docs (
  name       text PRIMARY KEY,
  key_id     text NOT NULL,
  nonce      bytea NOT NULL,
  body       bytea NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
