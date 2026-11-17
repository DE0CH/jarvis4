-- which records each change of the records touched (statedb.go catchUp): a replica whose copy is older reads only
-- those again, not all of them. One row per record a Do wrote or deleted, under the state_version it made (tbl: the
-- record's table, '' = a settings row), and one marker row per version (tbl '*'): a version with no marker (a router
-- from before this table) is one whose records nobody listed, and the reader takes all the records again.
CREATE TABLE state_changes (
  v   bigint NOT NULL,
  tbl text NOT NULL,
  id  text NOT NULL
);
CREATE INDEX state_changes_v ON state_changes (v);
