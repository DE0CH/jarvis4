-- the records' version (docs/STATE.md step 10): every State.Do takes this row FOR UPDATE (Do's are serialised across
-- the replicas, as the one process's mutex did before) and a replica whose copy is older reloads it first
CREATE TABLE state_version (
  id int PRIMARY KEY CHECK (id = 1),
  v  bigint NOT NULL
);
INSERT INTO state_version (id, v) VALUES (1, 0);
