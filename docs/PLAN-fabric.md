# Plan: sessions on aviary's fabric (runner `fabric`)

Deyao, 2026-11-17: a third kind of session beside Fly and AWS machines: the session runs as a gVisor sandbox on
autoscaled AWS hosts with its files on a network filesystem, on the fabric YYC AI's sandboxes run on (DE0CH/aviary:
sandboxd, the AMI recipe, hermit's scaler and placement), unmodified. What differs from YYC AI is one layer up: the
session's git repository and its own CLAUDE.md, skills and settings, not a managed CLAUDE.md. The existing kinds
(Fly machines, AWS machines, every harness on them) keep their code paths and tests; nothing of theirs changes.

Status (2026-11-17): design confirmed with Deyao. Built and pushed, all inert until infra and a kernel release
turn them on:

| Part | State |
|---|---|
| aviary: spec `mounts`, `sandbox.mounts`, `directEgress`, live console tail | pushed (DE0CH/aviary d417d225) |
| kernel/spawner: the fabric runner (`fabric.go`), objects `fabric-x<32 hex>` | pushed, tests pass; ships with a kernel release (Deyao's OK) |
| machine: `JARVIS2_RUNNER=fabric` (object, keys line, records-only snapshot) | pushed, tests pass |
| router: runner `fabric` (offered with `FABRIC_HERMIT_URL`), the session's conversation, the spawn, `GET /fabric/env` | pushed, tests pass |
| router: a destroy asks a fabric machine for its whole state (`snapshot-full`, so the archive holds the files), then deletes the conversation's files at hermit (`DELETE /v1/workspaces/{cid}`, `FABRIC_HERMIT_MAGPIE_TOKEN`) | pushed, tests pass |
| the source image: a fabric session's sources name `FABRIC_SESSION_IMAGE` with `FABRIC_SESSION_IMAGE_SIG` (router), the iPhone app accepts the fabric repo (`KernelChecks.fabricImageRepo`) | pushed; the app needs a TestFlight build; CI pins and signs it (images.yml `fabric-pin`) once the router's manifest has `FABRIC_SESSION_IMAGE` |
| image `jarvis4-session-fabric` (images.yml job `fabric`, `session-image/fabric/`), `aviary-sandbox`'s bind mode, the env-fetching entrypoint | pushed; bind mode tested (`session-image/tools/tests/aviary_sandbox.rs`); the new GHCR package must be made public (github-web) before hosts can pull it |
| hermit-jarvis: the fabric hermit's control hashes in the descriptor (`aviary/src/fabric.rs`, `FABRIC_HERMIT_URL`, `FABRIC_HERMIT_GATEWAY_TOKEN`) | pushed, tests pass (the flow unchanged). No activity forwarding: the fabric hermit's janitor keeps a sandbox whose supervisor answers its health (`silence_check`), and its `idleMinutes`/`maxLifetimeHours` are set past any session |
| infra: AWS eu-central-1 (AMI, launch template, scaler and AMI-CI users, image bucket, `fabric-ami.yml`), the gateway server, the fabric bucket and its fenced key, the fabric hermit with its database and JuiceFS on the cluster | done 2026-11-17; smoke test passed (`k8s/cluster/fabric/smoke.yaml`: a sandbox asked as the spawner asks, an AWS host in about a minute, the fabric image under gVisor, the console read live, released) |
| the kernel release (the spawner's fabric runner, its env and network rule), then the router's `FABRIC_HERMIT_URL` and the first fabric session | waiting on Deyao's OK |

This file is the plan and becomes the description as the parts land.

## Decisions (Deyao, 2026-11-17)

| Topic | Decision |
|---|---|
| Fabric | aviary's as is: the same sandboxd, AMI recipe, scaler and placement that YYC AI runs |
| Who runs it | aviary's own `hermit` binary (YYC AI's build) as an internal service of Jarvis 4's cluster, the **fabric hermit**: its own database and `hermit.json`, no chat site. hermit-jarvis stays the one hermit of chat.deyaochen.com |
| In the sandbox | the whole session machine, as on Fly: the keeper, aviary-gateway, the tunnel agent, and inside it aviary's sandbox image entered as today |
| Secrets | the keeper runs in the sandbox and holds the session's stores; `session-secret` works as today |
| Key path | the kernel's spawner gets a third runner: it asks the fabric hermit for a sandbox and reads the keeper's keys through it. hermit and its hosts are trusted the way Fly and AWS are. A kernel release (Deyao's OK and re-signature at release time) |
| Hosts | Deyao's AWS account, Frankfurt (eu-central-1), m7i.xlarge; a sandbox is 1 CPU / 3.5 GiB with 50 GiB of scratch, four per host (Deyao, 2026-11-18; 4 × 3.5 GiB in 15.5 GiB less 1 GiB reserved, 4 × 50 GiB + 16 GiB of system on the 220 GiB disk) |
| What lasts | `/workspace` (the session's repository) and the home; everything else is the sandbox's scratch |
| Mounts | the fabric mounts the list the deployment names (volume folder → path) and knows nothing of what a path means |
| Storage | JuiceFS: metadata in Postgres on Jarvis 4's cluster, data in Hetzner Object Storage |
| Network | direct egress, an optional host setting of the fabric: a sandbox reaches the internet from its host's public address, as a machine does |
| Engineering choices | Claude's from here on (Deyao: "You can make engineering decisions from now on") |

## What reading the code settled

- **The fabric cannot be linked alone.** `hermit::fabric::gvisor::Gvisor` works on hermit's whole `Core` (its
  database, sandbox rows, task claims), so the fabric is run by the hermit binary, and the spawner is a client of its
  HTTP contract.
- **No overlay inside gVisor on a host-backed directory** (runsc `precopy-20261102.1`: `mount -t overlay` works with
  the upper directory on tmpfs only; a PID namespace, `proc`, `pivot_root` and `/dev/fuse` work). `aviary-sandbox`'s
  overlay over the unpacked aviary image therefore cannot run there. The fabric's image carries aviary's sandbox
  image as a directory, which sandboxd's own root overlay makes writable, and `aviary-sandbox` binds it as the
  agent's root.
- **A fabric sandbox's only way out is the proxy at the egress address** (sandboxd's per-sandbox nft table), hence the
  direct egress setting.
- **hermit marks a sandbox ready through the supervisor contract on `:7070`** with its control token, and releases
  it there. A session has one supervisor (aviary's, booted against hermit-jarvis as today); its descriptor's
  `control.tokenSha256` list also carries the fabric hermit's token hash for that sandbox, so the fabric hermit's
  health and release calls are answered by the real supervisor.

## The parts

```
Jarvis 4 app ─▶ router ─▶ kernel spawner ──(caller magpie: PUT/release …/sandbox; caller admin: …/log)──▶ fabric hermit
                                                                                                    │ scaler, placement
chat.deyaochen.com ─▶ pigeon ─▶ magpie ─▶ hermit-jarvis ──(caller gateway: descriptor, activity)────┤
                                              ▲                                                     ▼
                                              │ chat-gw (as today)                        AWS hosts (sandboxd, gVisor)
 gVisor sandbox = the session machine ────────┘                                             │ JuiceFS: /workspace, /home/claude
   keeper (PID 1) · aviary-gateway · tunnel agent · aviary's sandbox (supervisor → Claude Code)
```

### DE0CH/aviary (all optional; YYC AI names none of them)

| Change | Where |
|---|---|
| A sandbox spec's `mounts`: `[{folder, path}]`, folders of the host's shared filesystem bound at paths in the sandbox | `sandboxd-api` `Spec.mounts`, sandboxd `config.rs`, `runsc.rs`, `storage.rs` |
| hermit.json `sandbox.mounts`: `[{name, path, quotaGiB, quotaInodes}]`: each conversation's folder `<name>/<conversation>`, made with its quota when the workspace is ensured, removed with it | hermit `config.rs`, `workspaces.rs`, `fabric/gvisor.rs` |
| host.json `directEgress` and hermit.json `fabric.directEgress` | sandboxd `net.rs`, hermit `fabric/scaler.rs` |
| `GET /v1/admin/sandboxes/{id}/log` answers a live sandbox's console as its host has it now | hermit `admin.rs`, `console.rs` |

### The runner (kernel/spawner; a kernel release)

The spawner's `Runner` interface, as for AWS:

| Call | Fabric |
|---|---|
| Create | `PUT /v1/conversations/{cid}/sandbox {"person"}` as caller `magpie`, `cid` a new uuid per machine; the machine id names it |
| Inspect | `GET …/sandbox`: starting → created, ready → started, gone → destroyed; the image hermit started it on |
| Init | the keeper writes `JARVIS2-KEYS {…}` to its stdout, the sandbox's console, as on AWS's serial console; the spawner reads it with `GET /v1/admin/sandboxes/{id}/log` |
| Destroy | `POST …/sandbox/release {"reason": "deleted"}` (forced) |
| DeleteVolume | `DELETE /v1/workspaces/{cid}` when the session is destroyed (the workspace and the home go); a pause keeps them |

The machine's environment: hermit's contract passes no per-sandbox environment, so the spawn's answer carries it
(`env`: `JARVIS2_SOURCE`, the roster, the root key, `JARVIS2_URL`) and the router serves it to the machine. The
fabric image's entrypoint reads its sandbox token from the boot environment's proxy URL (hermit's `hst1`, Ed25519,
naming the sandbox), asks the router at the fabric's egress address (`KERNEL_FABRIC_MACHINE_URL`, the gateway's
DNAT to the router's fabric listener) with that token, and gets the env plus `JARVIS2_RUNNER=fabric` and
`JARVIS2_MACHINE_ID=x<sandbox id>`. The router checks the token with hermit's `GET /v1/sandbox-token-keys`. Nothing
in the env is secret; the keys line and the cert are the trust path, as on the other runners.

The one image: hermit.json's `sandbox.image` and the router's `FABRIC_SESSION_IMAGE` name the same
`jarvis4-session-fabric:sha-…@sha256:…`, and images.yml `fabric-pin` moves both in one commit; `fabric-ami.yml` then
publishes it to the hosts' bucket and bakes the AMI. A source made before hermit sees the new image published starts on
nothing (the spawner's `wrong-image`) for those minutes.

The image check: hermit starts the one image its `hermit.json` names, and the spawner's init refuses a sandbox on
another digest than the source's (`wrong-image`), so a session's sources name the fabric image hermit runs, and a
resume after a pin moved starts on the new image (the router writes the new source on the current pin, as for Fly).

The snapshot on the fabric holds only the small files (`rust/machine/src/snapshot.rs` `fabric_state_paths`): the Jarvis records
(grants, the line's keys, deliveries) keep travelling signed, the directories stay on JuiceFS. So hermit, its hosts,
the JuiceFS metadata database and the bucket are trusted with the session's files between machines, as Deyao
accepted hermit and its hosts as trusted like Fly.

### hermit-jarvis (DE0CH/jarvis4 aviary/), only for sessions whose runner is `fabric`

- the descriptor's `control.tokenSha256` also holds the fabric hermit's hash for the session's sandbox (read from
  the fabric hermit's `GET /v1/sandbox/self` as caller `gateway`);
- nothing else: the fabric hermit's janitor keeps a sandbox whose supervisor answers its health, and its idle and
  lifetime limits are past any session's, so Jarvis 4's own pause stays the one that ends a sandbox.

The fabric hermit's `hermit.json` leaves pausing to Jarvis 4: `idleMinutes` and `maxLifetimeHours` past any session,
long `supervisorWaitSeconds` and `startDeadlineSeconds` (the supervisor comes up only after the machine's cert), and
a `fabric.migration.minAgeSeconds` no sandbox reaches (a direct connection does not survive a move).

### The image

`ghcr.io/de0ch/jarvis4-session-fabric`: the session image plus aviary's sandbox image as a directory. The keeper is
its first process. `aviary-sandbox` binds the directory as the agent's root instead of unpacking and overlaying.
The fabric mounts `/workspace` (the session's repository: JuiceFS `ws/<cid>`) and `/home/claude` (`home/<cid>`); the
image's `/etc/resolv.conf` names public resolvers.

### Infra

- AWS (Deyao's account, eu-central-1): the VPC and security group, the launch template `hermit-host`, the scaler's IAM
  user, the AMI (aviary's `hermit-ami` recipe run for this account), the image bucket. OpenTofu in `infra/aws`.
- Cluster: the fabric hermit (2 replicas) with its Postgres database and the JuiceFS metadata database, the gateway
  DaemonSet on one node (WireGuard hub), the Hetzner network route to it, the JuiceFS bucket in Hetzner Object
  Storage. Flux, as everything of Jarvis 4's.

### Infra in detail (from YYC AI's deployment, DE0CH/yyc-code yyc-ai/deploy/hermit and yyc-ai/infra/gateway.sh)

| Piece | Jarvis 4 |
|---|---|
| Addresses | sandboxes 10.205.0.0/16, hosts 10.204.0.0/24 (gateway 10.204.0.1), egress address 10.204.1.1; control = the Network jarvis2 10.77.0.0/16; pods 10.42.0.0/16 (k3s) |
| AWS (Deyao's account, eu-central-1, default VPC, subnet eu-central-1a) | aviary `fabric/aws/infra.sh` with `k8s/cluster/fabric/hermit.json`: `sg` and `ipv6` done (2026-11-17); `ami` (needs an aviary release with the fabric changes), `template`, `iam`/`iam-key` (scaler), `ci-iam`, `image-bucket`, `publish-image` |
| Gateway | a plain Hetzner server (not a cluster node: Deyao, 2026-11-16), fsn1, IPv6, on the Network jarvis2, its own firewall letting in udp 51821 only; sandboxd in gateway mode as a systemd unit (aviary `gateway-setup.sh`), installed by its cloud-init (Jarvis 4's boxes have no SSH); the Network's route 10.204.0.0/15 → its private address |
| Keys | the fabric CA, hermit's client cert, the hosts' cert, the gateway's cert and WireGuard key (aviary `fabric/host/make-certs.sh`), into the `infra` store |
| Cluster | namespace `fabric`: hermit (aviary's image, 2 replicas) with `hermit.json`, its database and the JuiceFS metadata database on the CloudNativePG cluster, `/jfs` through the JuiceFS CSI driver (bucket in Hetzner Object Storage); a DaemonSet that routes 10.204.0.0/15 via the Network's gateway on every node; the router's fabric listener and the metadata database reachable from the gateway at a node's private address on 3128 and 5432 (k3s ServiceLB: the gateway forwards to one address and keeps the port) |
| Wiring | router: `FABRIC_HERMIT_URL`, `FABRIC_HERMIT_TOOLS_TOKEN`, `FABRIC_HERMIT_MAGPIE_TOKEN`, `FABRIC_MACHINE_ADDR`, `FABRIC_SESSION_IMAGE(_SIG)`; spawner (kernel release): `KERNEL_FABRIC_HERMIT_URL`, `KERNEL_FABRIC_MACHINE_URL` = `http://10.204.1.1:3128`, then `POST /fabric-credentials`; hermit-jarvis: `FABRIC_HERMIT_URL`, `FABRIC_HERMIT_GATEWAY_TOKEN` |

### Tests

- aviary: unit and contract tests with each change (its CI gates the release Jarvis 4 pins).
- Jarvis 4: the spawner's fabric runner against a fake hermit (as `aws_test.go` against a fake EC2); hermit-jarvis's
  `tests/flow.rs` with a fake fabric hermit beside the existing flow, which must pass unchanged; `rust/e2e-kernel`
  (E2E_HARNESS=aviary) gains a fabric run on a replica (a throwaway kernel line, hermit and one real AWS host).
- A fabric host on a throwaway machine: aviary `testing/fabric-replica` (`up --hermit-json k8s/cluster/fabric/hermit.json`,
  `check`) builds it with the deployment's own recipe and these pins, stands in for the cloud (metadata service, S3
  with STS session tokens, JuiceFS stores, PKI) and checks egress by name, pause, freeze to S3 and thaw, and deleting
  a paused sandbox through sandboxd's API. A change to sandboxd or to the pins is checked there, never on production.
  A process `runsc exec` started does not survive a restore (gVisor): a freeze check follows the sandbox's init.

## Costs

AWS eu-central-1 on demand: m7i.xlarge USD 0.2415/h per host (two sessions), each host at least 15 min, plus its
public IPv4 USD 0.005/h and gp3 disk USD 0.0952 per GB-month while it runs; traffic out of AWS USD 0.09/GB (the
JuiceFS data written to Hetzner included).

## Freeze and the time machine (Deyao, 2026-11-17)

Built (2026-11-18), switched on per deployment:

| Part | Where |
|---|---|
| sandboxd `POST …/pause` and `…/resume` (runsc pause/resume), the eviction (`…/freeze`) of a paused sandbox, a memory check in every create/receive/thaw (paused sandboxes hold theirs) | DE0CH/aviary crates/sandboxd |
| hermit: the freeze task pauses in place (row `frozen`, host kept); the repacking evicts (`fabric/packing.rs` `place`, `evictions`; `placement.rs` `reclaim`; scaler step 10 `evict_lone_frozen`); a thaw resumes in place or restores from S3 (`Gvisor::thaw`); the janitor wakes a due `until`; a frozen row's release is forced and deletes its image | DE0CH/aviary crates/hermit (`fabric/pausing.rs`, `freezekey.rs`) |
| magpie: an answer to a question asks hermit for the conversation's sandbox (a use) | DE0CH/aviary 4d38eb57 |
| router: `POST/GET /m/api/time-machine`, state `frozen`, Resume and every delivery thaw it, `frozenLoop` (hermit thawed it at its time) | router/timemachine.go |
| hermit-jarvis: a frozen session's sandbox is kept, its chat open, a use thaws it | aviary/src/reconcile.rs, hermit.rs |
| the `time-machine` command | session-image/tools/src/timemachine.rs |
| the frozen state on the web page, the iPhone app and the live push | app/, ios/, router/livepush.go |
| AWS: managed policy `jarvis4-fabric-freeze` on hermit-scaler (STS federation token `hermit-freeze`; Put/Get/Delete on `frozen/*` of the image bucket) | infra/fabric-aws/freeze-policy.json (applied by hand: `aws iam create-policy` + `attach-user-policy`; the user's inline policies are at AWS's 2048-byte limit) |
| the key | `HERMIT_FREEZE_KEY` in Secret hermit (`FABRIC_HERMIT_FREEZE_KEY` in the infra store) |

A deployment freezes when hermit.json names `fabric.freeze.bucket` and hermit has `HERMIT_FREEZE_KEY`; YYC AI names
neither. The design below is what was built, with one change: a freeze no longer goes to S3 by itself (lazy eviction).

### The design (2026-11-17)

Two kinds of stopping in hermit's contract (DE0CH/aviary docs/CONTRACTS.md), both optional per deployment:

| Operation | What survives | What comes back |
|---|---|---|
| `release` (as today: YYC AI's pause) | `/workspace` and the deployment's mounts | a new sandbox; Claude Code resumes from its transcript |
| `freeze` (new) | everything: RAM, processes, scratch disk, the mounts | the same sandbox (same id, same machine for the kernel); its processes go on where they stopped |

`POST /v1/conversations/{cid}/sandbox/freeze {"until": optional}` and `…/thaw`; a new state `frozen`, distinct from `gone`;
the unused `pause`/`resume` routes go (a clean cut). magpie's get-or-start thaws a frozen sandbox. The idle default is
a `hermit.json` setting: YYC AI keeps release; Jarvis 4's fabric freezes at a turn's end.

Decisions (Deyao, 2026-11-17):
- The image (RAM and scratch) is encrypted by the fabric hermit with a key of its own (hermit and its hosts are
  trusted with the session's files already); no kernel change.
- Images live in AWS S3 in the hosts' region (eu-central-1): no traffic fee, the fastest thaw.
- `time-machine <duration> [--until-resolved ID …]` (the agent's tool) freezes with `until`; it returns at the first of:
  the time is up, a message (or any delivery) arrives, or one of the named pending items is resolved, and says which.
  A pending item is anything that waits on Deyao for as long as he takes (Deyao, 2026-11-18): an `ask` question (its
  answer) and an Inbox request (`jarvis-request`, its decision) are the same kind, each a blocking command that leaves
  an ID when cancelled (`ask wait ID`, `jarvis-request wait ID`), so the time machine knows one rule, not one per kind.
- A turn that ends with background tasks running keeps the sandbox running (today's `held`), and freezes when they end
  or when the agent calls the time machine.
- A thaw the hosts can't restore (a newer gVisor release than the image's, a lost image) falls back to what release
  gives: the files, a fresh sandbox, the transcript. Upgrades never wait on frozen sessions.
- Frozen images are kept until the session is thawed or destroyed.
- Scheduled wakeups and crons stay as they are, for every session, fabric ones included (Deyao, 2026-11-17: more
  options, and YYC AI keeps its existing logic): the time machine is one more way to wait, not a replacement. A
  wakeup or cron due for a frozen session thaws it, as a message does.
- What tells the agent which to use, in Jarvis 4 only (Deyao, 2026-11-17; YYC AI's prompts and skills don't change):
  the scheduled-wakeup docs (claude-env `schedule-wakeup` skill and CLAUDE.md "Waiting on events") say to prefer the
  time machine when waiting on CI or anything else outside, and to use a scheduled wakeup or cron when Deyao asked
  for a specific task at a specific time. That text ships with the tool, in the same change (docs describe the
  present: until then a session has no time machine to prefer).

Everywhere a session's state shows knows `frozen` (Deyao, 2026-11-17), as a state of its own (and "in the time machine
until T" when it froze with `until`): the router's session states and its live push (router/livepush.go) to the live
monitoring dashboard and its iPhone app, the Jarvis 4 iPhone app (ios/) and the web page (app/). A frozen session is
neither running nor paused there, and the apps' actions on it (Resume, Destroy) thaw or destroy it.

Known limits the tool's description states: frozen means frozen (a local build doesn't advance; the time machine is
for waiting on something outside), connections to the outside reset at a thaw (another host, another address), and
both wall time and monotonic time jump by the time spent frozen (measured).

Measured 2026-11-17 (eu-central-1, m7i.xlarge from the fabric AMI, gp3 120 GB at its default throughput, runsc
precopy-20261102.1; a sandbox with a 7 GiB limit holding N of memory, half random, half text; `runsc checkpoint
--image-path` to the disk, `aws s3 cp` up, deleted, down, `runsc restore`):

| Memory held | Freeze (checkpoint) | Image | Upload | Download | Thaw (restore) | After the thaw |
|---|---|---|---|---|---|---|
| 1.5 GiB | 4.6 s | 1.6 GB | 4.9 s | 2.4 s | 0.4 s | the process went on counting |
| 6 GiB | 53 s | 6.1 GB | 44 s | 30 s | 1.5 s | the process went on counting |

So a typical session freezes in about 10 s and thaws in about 3 s plus a host (seconds on a warm host, about a minute
from the AMI). What this shows for the build:
- The image is not compressed (6 GB held, 6.1 GB written): about 115 MB/s at 6 GB is the gp3 disk's default
  throughput. Streaming the checkpoint straight to S3 (multipart), as the fork already streams it to a peer for a
  live migration, skips the disk and the separate upload.
- Monotonic time did NOT stay continuous: inside the sandbox it ran on through the freeze (19.5 s after 8 ticks at
  1.5 GiB). Programs see both clocks jump; the tool's description says so.
- The restore loads the image eagerly and is fast; most of a thaw is the download.

### Frozen sandboxes in the repacking (Deyao, 2026-11-18)

A freeze does not go to S3 by itself. Freezing pauses the sandbox where it is (`runsc pause`: its memory stays on its
host, nothing is written), and a thaw of a sandbox still there is `runsc resume` on that host, at once. Evicting is
the push below (record the paused sandbox into S3, delete it there): the sandbox stays `frozen`, now with no host, and
its thaw is a placement and a restore. Which sandboxes are evicted, and when, is not a rule of its own: it follows
from the repacking below.

**The algorithm**: one pure function, the repacking (hermit's `fabric/packing.rs`, tested alone), from which
placement, launches, evictions and releases all follow (Deyao, 2026-11-18); no rule of its own for any of them.

- In: the hosts with their slots; the running sandboxes, each on its host; the sandboxes waiting for one (a start, a
  thaw of an evicted one) with no host yet; the frozen sandboxes, each on its host with its `until`.
- Out: the target, where each running and waiting sandbox is, on the existing hosts or on new ones, and for each frozen
  sandbox, still on its host or evicted.
- The rule: a frozen sandbox takes no capacity. The target is the fewest hosts that hold every running and waiting
  sandbox. Among targets with that many hosts, the one that leaves the most frozen sandboxes where they are, then the
  one with the fewest moves. On each host of the target, its running sandboxes plus the frozen ones it keeps fit its
  slots: the ones over that are evicted, most time left before their `until` first (no `until` = the most of all;
  ties: the oldest freeze). A host outside the target has no running sandbox; its frozen ones are evicted and it is
  released.

What follows from it: a new sandbox takes a free slot when there is one (that keeps every frozen sandbox). With none,
it takes the slot of the frozen sandbox with the most time left (that is still fewer hosts than a launch). Only when no
frozen sandbox is left is a host launched (the target needs one more). A host whose running sandboxes fit elsewhere
goes, and its frozen sandboxes are evicted with it. Nothing is evicted while its slot isn't needed.

**The effects** (the scaler's pass, as for migrations): it carries out the plan's evictions, moves, placements and
terminations. Their order is not logic of its own, it follows from capacity: sandboxd refuses a sandbox its memory
can't hold, so a move or start into a slot a frozen sandbox still holds waits for the next pass, after that eviction.
A host is terminated only once it holds no sandbox at all, so its evictions come first. A wakeup, message or condition
that comes for a frozen sandbox thaws it from wherever it is.

### How a frozen image travels (engineering design, 2026-11-17)

Hosts hold no standing AWS credentials and may only read `images/*` through the VPC endpoint; that stays. So:

- **Freeze:** hermit makes a fresh 256-bit key for this freeze and STS credentials (`GetFederationToken`, 1 hour) whose
  session policy allows only `s3:PutObject` on `frozen/<sandbox>/<freeze id>` in the hosts' bucket, and calls
  sandboxd `POST /v1/sandboxes/{name}/freeze` with both. sandboxd records the sandbox the way a migration sends it:
  `runsc checkpoint --migrate-to 127.0.0.1:<port>` streams its memory (the fork's pre-copy stream, which only ever
  flows one way) into `sandboxd stream-sink | sandboxd seal | aws s3 cp - <key>` (seal.rs: AES-256-GCM in 1 MiB
  frames, the frame index as the nonce, the last frame marked; a streamed multipart upload of unknown length). Nothing
  of the sandbox's memory touches the host's tmpfs or disk, and the 64 KiB request bound holds. Once it stopped, its
  scratch file follows as `tar --sparse | sandboxd seal | aws s3 cp - <key>.scratch`. It then deletes the sandbox. hermit keeps the key sealed under its own key in its database and marks the sandbox `frozen`
  (no host, no slot). This is the eviction of a paused sandbox (above), never the freeze itself.
- **Thaw:** hermit places the sandbox like a start (any host; its spec and address travel as in a migration) and calls
  `POST /v1/sandboxes/{name}/thaw` with the key and read-only credentials for those objects; sandboxd puts back the
  scratch file (`aws s3 cp <key>.scratch - | sandboxd open | tar -x`), starts `runsc restore --migrate-listen` as a
  migration's receive does, and replays the recorded stream into it (`aws s3 cp <key> - | sandboxd open | sandboxd
  stream-source`). A restore the host can't do
  (another gVisor release, a lost object) is a release instead: the files stay, a new sandbox starts, Claude Code
  resumes from its transcript.
- Checked 2026-11-17 with the fork (precopy-20261102.1, systrap): a container counting once a second was recorded by
  `runsc checkpoint --migrate-to` into `sandboxd stream-sink` (484 531 bytes, its End record seen), deleted, and
  replayed by `sandboxd stream-source` into `runsc restore --migrate-listen`: it went on counting from where it
  stopped.
- The object goes once the thaw succeeded or the session is destroyed; nothing else deletes it. The scaler's IAM user
  gets `sts:GetFederationToken` and `s3:PutObject`/`GetObject`/`DeleteObject` on `frozen/*` (the session policy narrows
  each token to one object); the AMI gets the AWS CLI.

## Next: asking Deyao is a command (Deyao, 2026-11-17; not built yet in aviary)

The rule (CLAUDE.md "Write the minimal algorithm"): asking is an ordinary command that blocks until Deyao answers and
prints the answer. Everything else follows from that, with no logic of its own:

- `jarvis-request` (Inbox requests: stores, repos, grants, new sessions, batches) already works so (jarvis4 3cc242e7).
- A question: `ask` shows a question card in the chat and blocks until the answer, which it prints. The card is a
  component a tool drives, like a page or an email a tool sends, not part of the agent loop (Deyao, 2026-11-17): the
  chat box steers the turn; the question card belongs to the command that made it. So it is not the harness's:
  the command talks to magpie through the sandbox's gateway (`POST` a question, a long poll for its answer), magpie
  keeps the question and its answer apart from turns, the app shows every open question of the conversation, turn
  or no turn, and neither the supervisor nor the harness takes part. aviary's build, so YYC AI's sessions too. Claude
  Code's native AskUserQuestion and ExitPlanMode, and Qwen Code's ask_user_question, are turned off (a clean cut).
- The harness never dismisses a question for the person: no timeout, no parked turn, no "asking" state. A long wait
  goes to the background like any long command; the chat keeps showing the question; the watchdog keeps firing.
- The only dismissal is the agent's: cancelling the command. It then has the question's id; `ask status ID` prints the
  answer or that it still waits.
- A message Deyao sends before answering does not dismiss the question: it is delivered as any message is during a
  command (at once when the ask runs in the background, after the answer while it runs in the foreground, or when the
  harness moves it to the background).
- Waiting long on an answer: the agent cancels the command and calls the time machine with a condition beside the
  duration (today one kind: the answer to question ID). The time machine's return says why it returned: the time
  was up, a message came, or the answer arrived.
