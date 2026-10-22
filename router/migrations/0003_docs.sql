-- the router's small documents that were files on its volume (docs/STATE.md step 4): store-docs.json, repos.json,
-- claim-device.json, core-certs.json, line-state.json, kernel-line-state.json; one row each, the file's bytes
CREATE TABLE router_docs (
  name       text PRIMARY KEY,
  body       bytea NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
