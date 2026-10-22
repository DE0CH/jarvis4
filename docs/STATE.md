# STATE: the router's state apart from its compute (docs/PLAN-cluster.md step 6)

Step 6 makes the router stateless: any number of replicas behind a rolling update, every record in Postgres
(CloudNativePG on the cluster), large blobs in Hetzner Object Storage, long actions as durable jobs any replica can
carry on, and one database lease for the few things that must run once (the scheduler's tick). This file is the audit
of where the router's state lives today (file:line references are to `router/` at the time of writing), the target
for each piece, the schema, the job model, how the machines' `/m` traffic works with several replicas, the order of
the migration, and what is deleted at the end. The database itself is already deployed (below, "The database").

## 1. Where the state lives today

The router is one process that owns everything; a second process may only proxy to it.

### 1.1 state.json (router/state.go)

`State` (state.go:147) holds `persisted` (state.go:116) in memory under one mutex; `State.Do` (state.go:207) runs a
closure under the lock and rewrites the whole file `DATA_DIR/state.json` atomically (state.go:214, tmp + rename) after
every change. Fields of `persisted`:

| field | type (file) | what |
|---|---|---|
| `Sessions` | `map[id]*Session` (state.go:16) | every live session: machine, state, error, label, model, mode, size, harness, stores, Claude account, repos, content, image, titles, liveness, ops settings, kernel line (`Kernel *KernelLine`, kernelline.go:40), waiting text, disk size |
| `Approvals` | `map[id]*Approval` (state.go:71) | phone approvals waiting (challenge docs, options, origin, batch) |
| `Records` | `[]*Record` (state.go:96) | destroyed sessions (a Session plus archive info, restore marks) |
| `Started` | `map[machine]*Started` (state.go:106) | each machine's keys as the core/spawner reported them (the `/m` auth keys), its volume, its kernel predecessor and cert |
| `Certs`, `SessCerts` | `map[machine]*Doc`, `map[session]*Doc` | old-core succession certs (SessCerts is a save-time copy of `Session.Cert`, state.go:216) |
| `Machines` | `map[machine]session` | machine → session index |
| `Grants` | `map[id]*StoredGrant` (grants.go:31) | phone-signed grants and standing rules |
| `Schedules` | `map[session]*Schedule` (schedule.go:69) | wakeups, crons, resume prompt, watches (schedule.go:73) |
| `Budget`, `BBBudget` | budget.go:220, bbbudget.go | this month's Fly spend estimate and DM flags; Browserbase DM flags |
| `Devices` | `map[id]*Device` (devices.go:53) | paired OpenClaw/Paseo apps |
| `Uploads` | `map[id]*Upload` (uploads.go:43) | first-prompt attachment metadata (the bytes are files, 1.2) |
| `Tasks` | `*TaskState` (tasks.go:572) | task instances, runs, daily schedules |
| `Inbox`, `Batches`, `CallResults`, `Outcomes` | inbox.go:86, batches.go:29, apicalls.go:46, outcomes.go:58 | Inbox requests, batches, approved/denied API calls, per-session outcomes to deliver |
| `Leases` | `*LeaseState` (leases.go:104) | shared-device leases: holder and queue per device |
| `Messages`, `MessageRules` | messages.go:54, :74 | peer messages held for Deyao, his per-kind rules |
| `CoreKey`, `ActiveCore` | corechange.go, nextcore.go | the old core's identity and the blue/green core URL |
| `KernelRoot`, `KernelSecrets` | kernelline.go, kernel.go | the root key's ⊤ on the sink; which secrets colour serves |

### 1.2 Other files on the router's volume (`DATA_DIR`, main.go:20)

| path | written by | what |
|---|---|---|
| `snapshots/<machine>.tar.gz` + `.sig` | http.go:610 (`POST /m/snapshot`), snapstream.go (stream + commit), read by http.go:562 (`GET /m/snapshot`), kernelline.go:268, archive.go:173/291 | paused sessions' final snapshots, several GB each |
| `line-state.json` | linestate.go:59 | the old core's sealed line state (also copied to the backup bucket, linestate.go:28) |
| `kernel-line-state.json` | kernel.go:303 | the same for the kernel's secrets |
| `claude-accounts/accounts.json`, `claude-accounts/claude-<name>.json` | claudeaccounts.go:116, :119, :162 | the Claude accounts and each account's OAuth pair (refresh token: secret) |
| `holders/<name>.key` | grants.go:73 | the router's holder private keys (ECDH), kept so standing rules naming them survive restarts (secret) |
| `uploads/<id>/<name>` | uploads.go:90 | staged first-prompt attachments |
| `task-runs/<run>.log`, `.output` | tasks.go:644 | task run logs and outputs |
| `input-log.jsonl` | vouch.go:567 | the core's input log, mirrored |
| `store-docs.json` | storedocs.go:89 | what each store and key is for |
| `repos.json` | repos.go:76 | the repo picker's list |
| `claim-device.json`, `core-certs.json` | claimdevice.go:25, :66 | the app's claim countersignatures; the master's cert on each core |
| `lifecycle/<session>.jsonl` | lifecycle.go:121 | each boot/pause/resume/destroy operation's log |
| `supervisor-log/<session>.jsonl` | supervisorlog.go:47 | the machines' supervisor lines |
| `restores/<session>/` | restore.go:42 | a restoring line's archived snapshot, fetched from the Storage Box |
| `jarvis1-imports/<id>/` | jarvis1import.go:110 | Jarvis 1 import files |
| backup fallback file | backups.go:248 | a key-backup export kept when the bucket was unreachable |
| `core-final.json` | nextcore.go:283, move.go:729 | the old core's final state across a flip or move |
| `tmp/` | archive.go:307, livearchive.go:90 | scratch for archives |
| `router.leader`, `router.leader.addr` | leader.go:49, :74 | the flock and the leader's address |
| `wg.conf`, moved/moved-in markers | wg.go, move.go:329, :734 | the WireGuard peer config; a box move's markers |

backup.go (439 lines) tars all of this, age-encrypted, to the Storage Box every few minutes and at drain
(backup.go:76, :91; main.go:244), and each snapshot once (backup.go:143); `ROUTER_RESTORE=1` rebuilds a volume from it
(backup.go:406, main.go:147).

### 1.3 In-process memory (the `Router` struct, flows.go:23)

| field | what | lost on a restart today |
|---|---|---|
| `commands` (flows.go:35, queue at flows.go:1479) | per-machine channel of supervisor commands (`snapshot`, `free`, …) | yes |
| `execs`, `results` (flows.go:36-37, grants.go:331-365) | holder-signed shell commands for a machine and the callers waiting for their results | yes |
| `deliveries` (vouch.go:318-330) | per-machine channel of attested deliveries (wakeups, messages) and their result waiters | yes |
| `snapped` (flows.go:39, snapwait.go:24) | the final snapshot a pause/destroy waits for, with its last progress | yes |
| `locks` (flows.go:41, lock at flows.go:85) | one lifecycle action per session (409 on a clash) | yes |
| `drain` (flows.go:42, drain.go:44) | running lifecycle goroutines; refuses new ones after SIGTERM | n/a |
| `gate` (flows.go:43, movegate.go:28) | requests and deliveries in flight at a handover | n/a |
| `ops` (flows.go:44, sessionops.go:65) | busy marks, the last permission-mode/restart/account-switch job (`wakeJob`, sessionops.go:80) | yes |
| `spares` (flows.go:61, handover.go:49) | the next machine started while the old one stops | yes (the spare is killed later or leaks) |
| `lc` (flows.go:59, lifecycle.go:87) | open lifecycle operations and their Fly pollers | closed as "cut off" (lifecycle.go:323) |
| `sup` (flows.go:58) | supervisor-log sequence numbers | re-read from the files |
| `claude` (flows.go:51) | login hubs: long polls of `GET /m/claude-login`, the refresh in flight | the refresh is let finish at drain (main.go:245) |
| `setupSeen`, `hk`, `kernelTokenDMed` | setup-session last seen, holder keys loaded, a DM sent once | harmless |

A running action is a goroutine of the leader. A crash or a rollout past the grace period cuts it off, and
`endCutOff` (drain.go:201) turns what it left into a plain failed or paused session for Deyao to run again.

### 1.4 The machinery that exists only because of the single owner

- **leader.go** (224 lines): an flock on the shared volume (leader.go:49-72, main.go:79, :113). The new pod of a
  rollout is a standby that reverse-proxies everything to the leader (leader.go:107-190); the old leader drains, then
  hands over (leader.go:196, main.go:259) and the standby loads state.json (main.go:163).
- **drain.go** (226 lines): SIGTERM → new lifecycle actions get 503 "router updating" (drain.go:56, :84), running ones
  finish up to `DRAIN_SECONDS` (default 1740 s, main.go:175; drain.go:145).
- **movegate.go** (285 lines): at a handover, deliveries stop (movegate.go:97), long polls (`/m/commands`,
  `/m/claude-login`, movegate.go:233) end with "nothing", other requests in flight are handed to the next leader
  (movegate.go:123).
- **move.go** (820 lines): moving the router and its volume between boxes.
- **backup.go** (439 lines): the volume's tarball to the Storage Box.
- **wg.go**: the router itself is the Fly org's WireGuard peer (userspace wireguard-go); only the leader runs it
  (main.go:150-160, :184-215), so the machines' `/m` reaches exactly one process.

## 2. The target

Every piece above lands in one of four places:

- **Postgres** (database `jarvis4`, role `router`): every record, every job, every queue. Writes are transactions,
  so a replica that dies mid-request leaves either the old or the new state.
- **Object storage** (Hetzner, fsn1): blobs. `jarvis4-snapshots-de0ch` for snapshots and the other large files
  (uploads, restores, imports, task outputs); `jarvis4-db-de0ch` for the database's WAL and base backups.
- **Derived cache**: in-memory copies any replica rebuilds from Postgres or the Fly/kernel APIs (budget numbers,
  the GitHub repo cache, Fly event pollers, kernel identities).
- **Gone**: what only served the single owner (state.json, the flock, the drain, the move gate, the box move, the
  volume backup, `wg.conf` on the router's volume).

| today | target |
|---|---|
| `Sessions` | `sessions` (hot columns + `doc jsonb` for the rest) |
| `Approvals`, `Inbox`, `Batches`, `CallResults`, `Outcomes` | `approvals`, `inbox`, `batches`, `call_results`, `outcomes` |
| `Records` | `records` |
| `Started`, `Machines`, `Certs`, `SessCerts` | `machines` (keys, volume, kernel cert, session, state); old-core certs as columns there while old-core lines exist |
| `Grants` | `grants` |
| `Schedules` | `wakeups`, `crons`, `watches` (one row each, `due_at` indexed) and `sessions.resume_prompt` |
| `Budget`, `BBBudget`, `KernelRoot`, `KernelSecrets`, `CoreKey`, `ActiveCore`, line-state docs | `settings` (key → jsonb) |
| `Devices` | `devices` |
| `Uploads` | `uploads` (metadata) + objects `uploads/<id>/<name>` |
| `Tasks` | `task_instances`, `task_runs`; run logs/outputs as objects `task-runs/<run>.{log,output}` |
| `Leases` | `leases` (device, holder, queue position, last seen) |
| `Messages`, `MessageRules` | `messages`, `message_rules` |
| `snapshots/*.tar.gz` + `.sig` | objects `snapshots/<session>/<machine>.tar.gz` + row in `snapshots` (sha256, sig, size, state pending/committed) |
| `claude-accounts/*` | `claude_accounts` (name, uuid, default flag, OAuth pair sealed, see 2.3) |
| `holders/*.key` | `holder_keys` (name, private key sealed) |
| `input-log.jsonl` | `input_log` (seq, entry jsonb) |
| `store-docs.json`, `repos.json`, `claim-device.json`, `core-certs.json` | `store_docs`, `repos`, `settings` rows |
| `lifecycle/*.jsonl` | `ops` (one row per operation) + `op_events` (seq, source, machine, at, text) |
| `supervisor-log/*.jsonl` | `supervisor_lines` (session, seq, machine, at, text), pruned to the newest N per session |
| `restores/`, `jarvis1-imports/`, `tmp/` | objects (`restores/<session>/…`, `imports/<id>/…`); `tmp` is the pod's emptyDir |
| `commands`, `execs`, `deliveries`, `results` channels | `machine_queue` rows + `LISTEN/NOTIFY` (section 5) |
| `snapped` | `snapshots` row state + `snapshot_progress` columns, waited for by the job (section 4) |
| `locks`, `ops.busy`, `wakeJob` | the session's active `jobs` row (one running job per session, a unique partial index) |
| `spares` | a step of the job, its machine id in `jobs.data` |
| `drain`, `gate`, leader flock | gone (section 7) |

### 2.1 Schema outline

All ids are text (the router's existing ids). `doc jsonb` keeps the long tail of fields that no query filters on,
so the Go types move over without a column per field; a field becomes a column the day a query needs it.

```sql
sessions      (id pk, state, machine_id, label, claude_account, harness, size, disk_gb, image, kernel jsonb,
               waiting, error, paused_at, created_at, updated_at, resume_prompt, doc jsonb, version int)
machines      (id pk, session_id fk, signing_key, encryption_key, image, volume jsonb, kernel_pred, kernel_cert jsonb,
               state /* created|certified|booted|killed */, created_at, killed_at)
records       (session_id pk, destroyed_at, archive jsonb, archive_error, live_kept, doc jsonb)
approvals     (id pk, kind, session_id, machine_id, batch_id, created_at, expires_at, doc jsonb)
inbox         (id pk, kind, session_id, batch_id, created_at, expires_at, doc jsonb)
batches       (id pk, created_at, doc jsonb)
call_results  (id pk, session_id, created_at, doc jsonb)
outcomes      (id pk, session_id, created_at, delivered_at, doc jsonb)
grants        (id pk, holder, session_id, created_at, expires_at, doc jsonb)
wakeups       (session_id, name, due_at, prompt, doc jsonb, pk(session_id, name))          -- index on due_at
crons         (session_id, name, next_at, spec, doc jsonb, pk(session_id, name))         -- index on next_at
watches       (session_id, name, next_check_at, doc jsonb, pk(session_id, name))
leases        (device pk, holder_session, since, last_seen, queue jsonb)
devices       (id pk, kind, created_at, doc jsonb)
uploads       (id pk, owner, bound_session, created_at, doc jsonb)
task_instances(id pk, task, session_id, doc jsonb)   task_runs (id pk, instance_id, phase, slot, started_at, doc jsonb)
messages      (id pk, from_session, to_session, kind, state, created_at, doc jsonb)   message_rules (kind pk, doc jsonb)
snapshots     (machine_id pk, session_id, object_key, sha256, sig, bytes, state /* pending|committed|failed|none */,
               progress jsonb, moved_at, committed_at)
claude_accounts (name pk, uuid, is_default, sealed_pair bytea, updated_at, refresh_holder, refresh_until)
holder_keys   (name pk, sealed_key bytea)
input_log     (seq bigint pk, entry jsonb)
store_docs    (store pk, doc jsonb)          repos (repo pk, doc jsonb)
settings      (key pk, value jsonb, updated_at)
ops           (id pk, session_id, kind, state, started_at, ended_at, result, error)
op_events     (op_id, seq, source, machine_id, at, text, pk(op_id, seq))
supervisor_lines (session_id, seq, machine_id, at, text, pk(session_id, seq))
machine_queue (id bigserial pk, machine_id, kind /* command|exec|delivery */, body jsonb, created_at,
               taken_at, answered_at, answer jsonb)                                        -- index (machine_id, taken_at)
jobs          (id pk, session_id, kind, state /* queued|running|waiting|done|failed */, step, data jsonb,
               attempts, lease_owner, lease_until, next_run_at, created_at, updated_at, error)
               -- unique (session_id) where state in ('queued','running','waiting'): one action per session
leader        (name pk, holder, until)                                                     -- the scheduler lease
schema_migrations (version pk, applied_at)
```

Concurrency: a request that changes a session does `UPDATE sessions … WHERE id = $1 AND version = $2` (optimistic,
retried) or `SELECT … FOR UPDATE` inside its transaction; the 409 "in the middle of another action" (flows.go:80)
becomes the unique index on active jobs.

### 2.2 Snapshots in object storage

- **Upload** (`POST /m/snapshot-stream`, snapstream.go): the replica that takes the request streams the body into an
  S3 multipart upload at `snapshots/<session>/<machine>.tar.gz` (5 MiB parts, so no local copy and no memory
  growth), hashing on the way, and records `snapshots(state=pending, sha256, bytes)`. Progress reports update
  `snapshots.progress/moved_at` (what snapwait.go:24 keeps in memory today).
- **Commit** (`POST /m/snapshot-commit`): any replica checks the machine's signature against the row's sha256 and
  sets `state=committed, sig`. Carry (`/m/snapshot-carry`) records the predecessor's object key for this machine;
  nothing is copied.
- **Restore** (`GET /m/snapshot`): the replica streams the object to the machine with `X-Snapshot-Sig` from the row.
  The machine checks the hash the cert names, as now, so the bucket is not trusted for integrity.
- **Confidentiality**: the bucket is private and its credential is only in the router's Secret, the same trust the
  router's volume has today. Encrypting each snapshot to a key the line holds (so the router can't read it) is a
  separate design change, not part of step 6.
- **Lifetime**: a session keeps only its newest committed snapshot; older ones are deleted by the job that commits
  the newer one (after the kill's cert names it). Destroy deletes the session's prefix after the archive.

### 2.3 Secrets in the database

The Claude OAuth pairs (claudeaccounts.go) and the holder private keys (grants.go:73) are on the volume in plain
files today. In Postgres they are sealed with a data key the router gets from its own Secret (`ROUTER_DB_SEAL_KEY`,
SOPS, never in the database or its backups), so the WAL archive and base backups in object storage hold only
ciphertext. The Claude refresh stays single-flight: the refresh takes `SELECT … FOR UPDATE` on the account's row (or
`pg_advisory_xact_lock(hash(name))`), refreshes, writes the new pair and commits; a second replica waits on the lock
and reads the new pair. The rule "a refresh in flight finishes" (main.go:245) becomes the transaction itself.

## 3. Long actions as durable jobs

### 3.1 The model

A job is a row: `kind`, `session_id`, `step` (name of the next step), `data jsonb` (what earlier steps produced:
machine ids, docs, the spare, the snapshot key), `state`. Every replica runs a worker loop:

```sql
UPDATE jobs SET lease_owner = $me, lease_until = now() + interval '60 seconds', state = 'running', attempts = attempts + 1
WHERE id = (SELECT id FROM jobs
            WHERE state IN ('queued','running','waiting') AND next_run_at <= now()
              AND (lease_until IS NULL OR lease_until < now())
            ORDER BY next_run_at FOR UPDATE SKIP LOCKED LIMIT 1)
RETURNING *;
```

The holder renews `lease_until` every 20 s while a step runs. A step ends by writing, in one transaction, its outputs
into `data`, the session/machine rows it changes, and the next `step` (or `done`/`failed`). If the replica dies, the
lease runs out and another replica runs the same step again: so **every step is idempotent**, or records that it
began before its side effect and checks for that effect when it runs again. A step that waits (for a machine's keys,
a snapshot, Fly's destroy) sets `state=waiting, next_run_at=now()+backoff` and frees the lease, or is woken by a
`NOTIFY job_<id>` from the request that makes progress (a snapshot commit, a status report). A rollout then never
cuts an action off: SIGTERM stops the worker from claiming, the step in progress either finishes within the grace
period or its lease lapses and the new pod carries on. No drain, no 503.

`ops`/`op_events` (the lifecycle log the app shows) are written by the steps, so the log is continuous across
replicas.

### 3.2 The jobs and their steps

Kernel lines (kernelline.go). "Idempotent" says why a repeat is safe; **bold** marks a prerequisite change.

**start** (a new session after the phone's approval: flows.go:684 Respond → kernelline.go:123 respondKernel,
kernelline.go:167 kernelSpawn):
1. `notarize-new`: notarize the phone-signed (sink, source-x) cert and move the root's ⊤ onto source-x. Idempotent:
   notarizing the same cert answers the same; the mover holds no state, the moved grant is stored with the step.
2. `spawn`: spawner `POST /spawn` from source-x. **Not idempotent today**: `Spawner.Spawn` (kernel/spawner/spawner.go:163)
   makes a new Fly machine on every call. Prerequisite: the spawner answers a second spawn from the same source with
   the live machine it already made for it (it keeps `machines` with their `Source`, spawner.go:58), so the step can
   simply be repeated. Writes `machines(id, state=created)`.
3. `init`: spawner `GET /init` until the machine gave its keys (409 = waiting). Idempotent (a read).
4. `notarize-machine`: notarize (source, fly-M), move the grant onto M; `machines.state=certified`. Idempotent as 1.
5. `await-boot`: waiting until the machine's first status report (`machines.state=booted`), up to 15 min
   (lifecycle.go `lcBootMax`). Woken by `NOTIFY` from `/m/status`.
6. `done`: `sessions.state=started`.

**pause** (flows.go:951, snapsafe.go `finalSnapshotAndKillNext`):
1. `ask-snapshot`: enqueue the `snapshot` command in `machine_queue` (once: the step records the queue row id).
2. `await-snapshot`: waiting until `snapshots.state` is committed/none/failed, with the stall rules of snapwait.go
   (10 min without progress, 3 min silent) evaluated from `snapshots.moved_at` and the machine's last status.
3. `kill`: spawner `/kill` with the snapshot's sha256 and sig (kernelline.go:266). Idempotent: the spawner answers a
   repeated kill with the same cert (spawner.go:284), notarize and move as above; 409 "not destroyed yet" = waiting.
4. `done`: `sessions.state=paused, machine_id=null, paused_at`; delete the session's older snapshot objects.

**resume** (flows.go:994, kernelline.go:447): `spawn` from the source the kill made (its snapshot), then steps 3-6 of
start. A resume that needs the phone (an upgrade of the image) files the approval and ends `waiting` on it; the
approval's response re-queues it.

**destroy** (flows.go:1235):
1. the pause steps if a machine runs (`force` skips a failed snapshot, as now);
2. `archive`: archive.go to the Storage Box (snapshot object + live transcripts + logs). Idempotent: livearchive.go
   already skips files whose sums it holds (`held`/`taken`), and the archive dir is fixed in `sessions.doc`
   (`ArchiveDir`) by the first attempt;
3. `burn`: (source, sink) by the gullible signer, notarized (kernelline.go:321). Idempotent once the burn cert is kept
   in `data` (a repeat with the cert in hand only notarizes again);
4. `on-destroy` hooks (Discord channel export etc.; each records its own done flag in `data`);
5. `finish`: in one transaction the session row becomes a `records` row; delete the session's snapshot objects.

**upgrade** (memory.go:236), **restart** (sessionops.go:551), **more disk** (disk.go:190): one job each whose steps
are pause (with the spare, below) then resume, carrying the new size/env/disk in `data`. The handover's spare
(handover.go): at `ask-snapshot`, a `spawn-spare` step asks the spawner for the next machine and stores its id in
`data.spare`; resume's `spawn` takes it if it matches (same image, size, disk) and otherwise a `kill-spare` step kills
it. A crash no longer leaks a spare: the job's `data` names it.

**permission-mode switch** (sessionops.go:271) and **Claude account switch** (accountswap.go:146): running → enqueue
the holder-signed exec in `machine_queue`, step `await-exec` until its answer row (woken by `NOTIFY`), then verify
(`waitReg`, accountswap.go:271, as a polling step). Paused → only a row update, no job. A switch waiting on a terminal
grant (`ModeAfterGrant`) is a job `waiting` on the grant's Inbox row.

**approved flows** (Respond, flows.go:684; add-store, flows.go:744; batches): the HTTP request stores the phone's
signature and creates the job in the same transaction, answering at once; the job does the kernel calls. A repeated
Respond with the same signature finds the job and answers its state.

**task runs** (tasks.go:1106 StartRun): a job of kind `task-run` whose steps are start/resume, deliver the prompt,
await the result (`/m/task-result`), pause.

## 4. Scheduler leader lease

Only the periodic ticks need exactly one runner: scheduleLoop, leaseLoop, watchLoop, archiveLoop, budgetLoop,
bbBudgetLoop, uploadsLoop, inboxLoop, outcomeLoop, messageLoop, tasksLoop, inputLogLoop, coreChangeLoop, loginLoop,
volSweepLoop, autopilot and the Discord tick (features.go:51-71). They run on the replica holding the lease:

```sql
INSERT INTO leader (name, holder, until) VALUES ('scheduler', $me, now() + interval '30 seconds')
ON CONFLICT (name) DO UPDATE SET holder = $me, until = excluded.until
WHERE leader.until < now() OR leader.holder = $me
RETURNING holder;  -- = $me: this replica leads for 30 s; renewed every 10 s
```

Each tick's effect is still a transaction (a wakeup row deleted in the same transaction that enqueues its delivery,
a cron's `next_at` advanced with it), so a lost lease mid-tick at worst runs one tick twice on rows already advanced,
never delivers twice. Long actions a tick starts (auto-pause, a task run) are jobs, so they don't depend on the
leader staying. The movegate's "no delivery lost or made twice" (movegate.go:1-20) comes from those transactions
instead of from stopping deliveries.

## 5. The machines' `/m` traffic with several replicas

**Reachability.** Today the router process is the Fly org's WireGuard peer (wg.go) and only the leader runs it. One
WireGuard peer can't be active in two processes (the endpoint would flap between them), and a peer per router
replica would give each replica its own `_peer.internal` name. So the peer moves out of the router into its own small
Deployment, **`m-gateway`** (namespace jarvis4-router): the same userspace wireguard-go + netstack code, one replica
per peer, forwarding each TCP connection on :8081 to the `router` Service (all replicas). Two peers
(`jarvis4-gw-a`, `jarvis4-gw-b`, each `fly wireguard create`), two single-replica Deployments, and the spawner gives
machines both addresses (`KERNEL_MACHINE_URL` becomes a list); the machine's client tries the other on a failed dial.
A gateway's rollout is then a gap only for that gateway; the router's rollouts never touch the peer.

**Authentication** stays as it is: every `/m` request is signed by the machine's key, checked against
`machines.signing_key` in Postgres, so any replica can serve any machine.

**Long polls** (`GET /m/commands`, http.go:677; `GET /m/claude-login`): the replica that holds the poll does
`LISTEN m_<machine>` on a dedicated connection (one pgx connection multiplexes every channel a replica listens to),
then reads `machine_queue` for untaken rows of that machine; if none, it waits for a notification or the 50 s
timeout. A writer (a pause job enqueueing `snapshot`, an exec, a delivery) inserts the row and `NOTIFY m_<machine>`
in the same transaction. Taking a row is `UPDATE … SET taken_at = now() WHERE id = (… FOR UPDATE SKIP LOCKED)`, so
two polls of the same machine (one lingering on an old replica) never take the same command. A command taken but not
acknowledged within a timeout is offered again (the supervisor's commands are idempotent: snapshot, free). Exec
results (`POST /m/exec-result`) and delivery results (`POST /m/delivery-result`) write `answer` and
`NOTIFY q_<row>`; the waiting caller (an HTTP request or a job step on any replica) LISTENs for it. The Claude login
long poll LISTENs on `claude_<account>`, notified by the refresh's transaction.

**Rollouts.** A replica that gets SIGTERM stops claiming jobs, leaves the Service (readiness fails first), answers
its open long polls with "nothing" (the machine re-polls through the gateway and lands on another replica), lets
uploads in progress finish within the grace period and exits. Nothing is handed over because nothing is owned.

**Streams** (`POST /m/snapshot-stream`, live transcripts): served by whichever replica the connection lands on,
straight into object storage (2.2). The app's event stream (sessionevents.go) reads `op_events`/`supervisor_lines`
and LISTENs on `ev_<session>`.

## 6. Migration order (each a deployable step)

Each step ships alone, keeps the router working, and is a clean cut for what it moves (no dual reads).

1. **The database** (done: k8s/cluster/postgres, below).
2. **Schema + connection**: the router gets `DATABASE_URL` (Secret `router-db` in jarvis4-router, written with
   `JARVIS4_DB_ROUTER_PASSWORD` from the infra store) and a migrations runner (embedded SQL files, applied under
   `pg_advisory_lock` at start); `/healthz` and the status page show the database (primary reachable, schema
   version, replication lag). Nothing moves yet. Done: router/db.go (pgx), router/migrations/, `infra/router-secrets.py
   --box cluster --part db DATABASE_URL=dburl:JARVIS4_DB_ROUTER_PASSWORD`; the router's tests run against a real
   Postgres (`TEST_DATABASE_URL`, a schema per test; CI's test job has a postgres:18 service container).
3. **state.json → Postgres in one cut**: `State.Do` keeps its signature but loads from and writes to the tables
   (inside a transaction, the rows its closure touched); a one-shot import reads the volume's state.json into the
   tables at the first start of that version and renames the file. Still one replica, still the flock: this step is
   only the storage. The volume backup (backup.go) stops including state.json. Done: router/statedb.go,
   migrations/0002_state.sql. For this step each collection of `persisted` is its own table `(id, doc jsonb)` (records
   `(ord, doc)`), with generated hot columns where a query already wants them (sessions.state, sessions.machine_id,
   approvals.kind/session_id); the other fields are `settings` rows `state.<json key>`. Do still runs under one lock
   on an in-memory copy and writes only the rows its closure changed, in one transaction; a failed write is retried
   and shows in /healthz and /setup/status. The tables take the outline's shape (2.1: `machines` merging Started,
   Certs and Machines; `wakeups`/`crons`/`watches` rows; `version` columns) as the jobs of steps 6-8 need queries on
   them. Every router outside the cluster (CI's stand-ins, the replica, e2e) gets a database from
   `infra/test-postgres.sh fresh NAME`.
4. **The other volume files**: logs (`lifecycle/`, `supervisor-log/`), small JSON files (store-docs, repos,
   claim-device, core-certs, line-state, input-log), Claude accounts and holder keys (sealed) into tables; uploads,
   task-run outputs, restores and imports into object storage.
5. **Snapshots into object storage** (2.2), with a one-shot copy of the existing `snapshots/` for paused sessions.
   After this the volume holds only `wg.conf`, the flock and scratch.
6. **The machine queue** (section 5) replaces the `commands`/`execs`/`deliveries`/`results` channels and the
   `snapped` waits, still on one replica.
7. **Durable jobs** (section 3), one action at a time: pause, destroy, start/resume, upgrade/restart/disk, the switches,
   approved flows, task runs. Each action's goroutine and its `lock`/`begin` go as it moves. Prerequisite for start:
   the spawner's idempotent spawn.
8. **The scheduler lease** (section 4) replaces "the leader runs the loops".
9. **m-gateway** (section 5): the WireGuard peer leaves the router; the router listens on :8081 in the pod network.
10. **Stateless replicas**: the router Deployment becomes 2 replicas, RollingUpdate `maxUnavailable: 0`, readiness on
    the database, a PodDisruptionBudget, no volume (scratch is an emptyDir). This is the step that deletes the old
    machinery (section 7).

## 7. What is deleted

- `router/state.go`'s file storage (`save`, state.json, `snapshotPath`) and the `persisted` in-memory copy.
- `router/leader.go` (the flock, the standby proxy, `handOver`), and main.go's leader/standby/handover sequence
  (main.go:79-145, :231-262).
- `router/drain.go` (begin/drain/endCutOff: a cut-off action is now a job another replica carries on) and the
  `errDraining` 503.
- `router/movegate.go` (stopDeliveries/freezeRequests: nothing is handed over).
- `router/move.go` and the moved/moved-in markers (a box move is a database restore elsewhere plus a Flux sync).
- `router/backup.go` (the volume tarball: the database has its own backups; key backups in the bucket stay).
- `router/handover.go`'s in-memory `spares` (the spare becomes a job step) and `snapwait.go`'s in-memory waits.
- The router's PersistentVolumeClaim and `ROUTER_RESTORE`.
- The RUNBOOK and DESIGN sections about the drain, the leader and box moves are rewritten in the same commits.

## 8. The database (deployed)

- **k8s/cluster/postgres/**: three Flux Kustomizations in a row (flux.yaml): `db-cert-manager` (cert-manager 1.21.2,
  needed by the Barman Cloud plugin's mTLS), `db-operator` (CloudNativePG 1.30.1 + plugin-barman-cloud 0.15.1;
  CloudNativePG's in-tree barmanObjectStore is removed in 1.31, so backups use the plugin from the start), `db` (the
  Cluster). Release manifests are vendored with their sha256 in flux.yaml; every image is pinned by digest. `db` has
  `prune: false`: deleting the database is never a side effect of a git change.
- **Cluster `jarvis4-db`** (namespace jarvis4-db): 2 instances of PostgreSQL 18.6, database `jarvis4` owned by role
  `router` (password: Secret `jarvis4-db-router`, `infra/router-secrets.py --box cluster --part postgres-app`; the same
  value is `JARVIS4_DB_ROUTER_PASSWORD` in the infra store for the router's own Secret), one synchronous standby with
  `dataDurability: preferred` (writes wait for the replica while it is up and go on without it when it is down), data
  checksums, 5 GiB each on local-path. The router connects to `jarvis4-db-rw.jarvis4-db.svc:5432` (the primary);
  `-ro` is the replica.
- **Backups**: the plugin archives every WAL segment (at least every 5 min, `archive_timeout`) and a base backup daily
  at 03:00 UTC (and one at once) to `s3://jarvis4-db-de0ch/jarvis4-db/` on fsn1.your-objectstorage.com, kept 30 days
  (Secret `postgres-s3`, part `postgres`). The credential is the Object Storage project's (`HETZNER_S3_*`), which also
  reaches the project's other buckets.
- **Restore** (a lost cluster or node): a new Cluster with `bootstrap.recovery` from the ObjectStore
  `jarvis4-db-store` (any point in the last 30 days), pushed to git; the router's `DATABASE_URL` stays the same.
- **NetworkPolicy**: Postgres takes connections only from namespace jarvis4-router (5432), from its own instances
  (replication, the instance manager :8000) and from cnpg-system (the operator).
- **Buckets** (made 2026-10-22 in the Object Storage project with `HETZNER_S3_*`, private): `jarvis4-db-de0ch` (the
  database's backups) and `jarvis4-snapshots-de0ch` (section 2.2; unused until migration step 5).

### 8.1 How to see that it is up

There is no kube API from a session. What shows it:
- after a push, Flux reports the Kustomizations `db-cert-manager`, `db-operator`, `db` Ready; `db` waits on the
  Cluster's own Ready condition, so `db` Ready = Postgres healthy;
- objects appear under `s3://jarvis4-db-de0ch/jarvis4-db/wals/` within minutes of the first start and under
  `base/` after the first backup: listing the bucket from a session with `HETZNER_S3_*` proves the primary runs
  and archives;
- Grafana: `container_memory_working_set_bytes{box="cluster",namespace="jarvis4-db"}` shows the instances;
- from migration step 2 on, the router's `/healthz` and status page report the database.

### 8.2 Memory on the cx23 (jarvis2-cluster-1)

Measured on 2026-10-22 (Grafana): the node has 3,820 MiB; with only Flux, kube-system and the edge running,
2,498 MiB are available, so the base (k3s server with embedded etcd, containerd, the OS, Alloy, Flux 80 MiB,
kube-system 43 MiB) uses about 1,290 MiB. Planned requests on top (MiB; limits in brackets):

| component | requests | limits |
|---|---|---|
| cloudflared ×2 + kernel-id | 136 | 272 |
| router ×2 (peak seen on the control box: 680 MiB with standby + leader) | 1,024 | 2,048 |
| kernel: notary, notarizer, mover, merger, spawner, identity, gullible, secrets-blue, secrets-green | 288 | 800 |
| cert-manager ×3 (no upstream requests; measured elsewhere about 100) | ~100 | none |
| CloudNativePG operator + Barman plugin | 148 | 328 |
| Postgres ×2 (512 each) + Barman sidecars ×2 | 1,152 | 1,536 |
| **total with the base** | **about 3,840** | **about 6,270** |

It does not fit: the requests alone reach the node's 3,820 MiB before any burst, and the services that step 5 moves
onto the cluster need far more (on the services box: search peaked at 1,060 MiB, icloud-index at 3,607 MiB). Today
(before the router, the kernel and the services land) the database fits and comes up: it uses about 1.5 GiB of the
2.5 GiB available.

Verdict, per Deyao's rule (add machines, never throttle): before the router and the kernel move onto the cluster
(step 5), add a second node, **a cx43 (8 vCPU, 16 GiB) joined as a k3s agent** in fsn1 on the private network,
IPv6-only with WARP like the first. The two Postgres instances then run one per node (switch
`podAntiAffinityType` to `required`), the router's two replicas spread over both, and the services (search,
icloud-index) fit on it. A third server node is the separate question of control-plane HA (etcd needs three).
