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
| router: the conversation's files deleted at hermit on Destroy (`DELETE /v1/workspaces/{cid}`) | to do |
| the source image: a fabric session's sources name `FABRIC_SESSION_IMAGE` with `FABRIC_SESSION_IMAGE_SIG` (router), the iPhone app accepts the fabric repo (`KernelChecks.fabricImageRepo`) | pushed; the app needs a TestFlight build; CI does not sign the fabric image yet (images.yml pin step: `jarvis2-session-image <ref>` with the CI key) |
| image `jarvis4-session-fabric` (images.yml job `fabric`, `session-image/fabric/`), `aviary-sandbox`'s bind mode, the env-fetching entrypoint | pushed; bind mode tested (`aviary-sandbox_test.sh`); the new GHCR package must be made public (github-web) before hosts can pull it |
| hermit-jarvis: the fabric hermit's control hashes in the descriptor (`aviary/src/fabric.rs`, `FABRIC_HERMIT_URL`, `FABRIC_HERMIT_GATEWAY_TOKEN`) | pushed, tests pass (the flow unchanged). No activity forwarding: the fabric hermit's janitor keeps a sandbox whose supervisor answers its health (`silence_check`), and its `idleMinutes`/`maxLifetimeHours` are set past any session |
| infra: AWS eu-central-1, AMI, hermit + gateway, JuiceFS, bucket | to do |
| replica end to end (`infra/e2e-aviary.sh` fabric run) | to do |

This file is the plan and becomes the description as the parts land.

## Decisions (Deyao, 2026-11-17)

| Topic | Decision |
|---|---|
| Fabric | aviary's as is: the same sandboxd, AMI recipe, scaler and placement that YYC AI runs |
| Who runs it | aviary's own `hermit` binary (YYC AI's build) as an internal service of Jarvis 4's cluster, the **fabric hermit**: its own database and `hermit.json`, no chat site. hermit-jarvis stays the one hermit of chat.deyaochen.com |
| In the sandbox | the whole session machine, as on Fly: the keeper, aviary-gateway, the tunnel agent, and inside it aviary's sandbox image entered as today |
| Secrets | the keeper runs in the sandbox and holds the session's stores; `session-secret` works as today |
| Key path | the kernel's spawner gets a third runner: it asks the fabric hermit for a sandbox and reads the keeper's keys through it. hermit and its hosts are trusted the way Fly and AWS are. A kernel release (Deyao's OK and re-signature at release time) |
| Hosts | Deyao's AWS account, Frankfurt (eu-central-1), m7i.xlarge; a sandbox is 1 CPU / 7 GiB, two per host |
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

The image check: hermit starts the one image its `hermit.json` names, and the spawner's init refuses a sandbox on
another digest than the source's (`wrong-image`), so a session's sources name the fabric image hermit runs, and a
resume after a pin moved starts on the new image (the router writes the new source on the current pin, as for Fly).

The snapshot on the fabric holds only the small files (`machine/main.go` `fabricStatePaths`): the Jarvis records
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

### Tests

- aviary: unit and contract tests with each change (its CI gates the release Jarvis 4 pins).
- Jarvis 4: the spawner's fabric runner against a fake hermit (as `aws_test.go` against a fake EC2); hermit-jarvis's
  `tests/flow.rs` with a fake fabric hermit beside the existing flow, which must pass unchanged; `infra/e2e-aviary.sh`
  gains a fabric run on a replica (a throwaway kernel line, hermit and one real AWS host).

## Costs

AWS eu-central-1 on demand: m7i.xlarge USD 0.2415/h per host (two sessions), each host at least 15 min, plus its
public IPv4 USD 0.005/h and gp3 disk USD 0.0952 per GB-month while it runs; traffic out of AWS USD 0.09/GB (the
JuiceFS data written to Hetzner included).
