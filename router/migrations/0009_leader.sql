-- the scheduler lease (docs/STATE.md 4, step 8): the replica named here for the next 30 s runs the periodic loops
CREATE TABLE leader (
  name   text PRIMARY KEY,
  holder text NOT NULL,
  until  timestamptz NOT NULL
);
