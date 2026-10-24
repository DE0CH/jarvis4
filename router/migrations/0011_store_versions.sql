-- each store's earlier versions on a box with no core (router/storeversions.go, DECISIONS 232): the kernel's secrets
-- keeps no history, so the router keeps each version's keys — every entry it saw written (sealed to P + K, so it
-- reveals nothing), secrets' signed key-written receipt for it and its backup object — and a restore writes an
-- earlier entry back with its receipt (writer "replay"). keys: name → entry, or null for a key the router never saw
-- written (a Recover's); version: secrets' store version after the change.
CREATE TABLE store_versions (
  store   text NOT NULL,
  seq     int NOT NULL,
  at      timestamptz NOT NULL DEFAULT now(),
  version text NOT NULL,
  cause   jsonb NOT NULL,
  keys    jsonb NOT NULL,
  PRIMARY KEY (store, seq)
);
