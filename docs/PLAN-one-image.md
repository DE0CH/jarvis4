# Plan: one image, and the `fly-preload` runner

Deyao, 2026-11-20. Today a session involves two images: Jarvis 4's session image (`ghcr.io/de0ch/jarvis4-session`,
what Fly boots: Jarvis's machine side **and** the agent's tools) and aviary's sandbox image
(`ghcr.io/de0ch/hermit-sandbox`, which an aviary session fetches onto its volume, about 7 minutes on a new session,
and runs Claude in). The tools in the session image exist only for the harnesses that run on it directly, and they
are squeezed by Fly's 8 GB unpack limit (claude-env lessons/72). The goal: the agent's tools live in one image,
aviary's, which may grow (disk is cheap); every harness runs in it; and a new Fly session starts without the
download.

Status (2026-11-20): planned; local branches only (the session's stores never arrived: Inbox outcomes not delivered
to aviary sessions, a bug being fixed in another session). Nothing deployed; no kernel release without Deyao's
authorisation and signature.

## Decisions (Deyao, 2026-11-20)

| Topic | Decision |
|---|---|
| The image | aviary's sandbox image is the one image with the agent's tools; Jarvis adds only its own parts |
| Tools | everything the legacy session image carries goes into aviary's sandbox image (DE0CH/aviary `claude/sandbox-tools`) |
| Harnesses | every harness (aviary, plain Claude Code, dsh, OpenClaw) runs in it |
| Runners on it | `fly-preload`, `aws`, `fabric` |
| Legacy | the `fly` runner keeps today's `jarvis4-session` image, frozen, as the fallback |
| New runner | `fly-preload`: its own Fly app `jarvis4-sessions-preload`, a new kernel signer with its own key and a Fly token narrowed to that app, a new New session option |
| Preloading | each session's volume is a fork of a golden volume holding the image unpacked, made per region by the deploy's CI |
| Kernel | change OK'd (Deyao, 2026-11-20); released only with his authorisation, roster re-signed by him |

## What reading the code settled

- **Jarvis's parts cannot be layered *inside* aviary's image without breaking dogfooding or the machine.** The machine
  side (keeper, jarvis-machine, harness launchers) assumes Ubuntu, user `claude` and `/home/claude`; aviary's image is
  Debian trixie whose uid 1000 is `node` with home `/home/sandbox`, and its root is the agent's whole world (the
  sandbox must be aviary's image unmodified, `dogfood-aviary` skill). So "one image" is realised the way the fabric
  image already does it (`session-image/fabric/Dockerfile`): Jarvis's machine layer is a small image of its own (no
  agent tools), and aviary's image is carried *as a directory* and entered as the agent's root by `aviary-sandbox`.
  The agent's tools exist once, in aviary's layers; the machine layer stays Jarvis-only and invisible inside the
  sandbox. **To confirm with Deyao** (he approved "FROM hermit-sandbox plus Jarvis's layer"; this is the same idea
  with the layers side by side instead of stacked, for the reasons above).
- **`fly-preload` needs no loader and no change to `aviary-sandbox`.** `aviary-sandbox` already skips the fetch when
  `/data/aviary/image-<digest12>.ok` is on the volume, and `aviary-sandbox --fetch` already writes exactly that. A
  golden volume is a volume on which a machine of the session image ran `aviary-sandbox --fetch`; a session's volume
  forked from it starts with the image in place. With the agent's tools gone from the machine layer, the image Fly
  boots is small and well under 8 GB, so the pull is quick too.
- **A forked volume is not empty, and the machine tolerates that.** `rust/machine/src/volume.rs` assumes a new, empty
  volume but only writes `/data/home/…` and chowns `/data` itself (not recursively), so the preloaded
  `/data/aviary/…` is left alone and nothing walks its 10 GB.
- **Fly's forks are lazy.** Fly's volume-forking blueprint: a fork is usable at once, its blocks fetched from the
  source on first read (a network block device), the full copy in the background; cross-region forks hydrate more
  slowly. So a golden volume per region, and a session forks its region's. To measure before relying on it (a
  throwaway app): time to usable, read speed while hydrating, cross-region.
- **Objects.** A machine object is `<runner>-<id>` and `doc.Object.Runner()` splits at the first `-`, so the new
  runner's objects are `flypreload-<Fly machine id>` (the New session option is still called `fly-preload`).

## The parts

| Part | Where | State |
|---|---|---|
| The agent's tools in aviary's image, test first (`testing/sandbox-tools`, ci.yml `sandbox-tools`) | DE0CH/aviary `claude/sandbox-tools` | written, not pushed |
| Size the YYC AMI builder disk (bake.rs `VolumeSize=16`) and the hosts' "16 GiB for system and image" to the grown image, from CI's measurement | DE0CH/aviary | open |
| Fly fork measurement on a throwaway app | a session with `infra` | open |
| kernel: signer `preloader` (`doc.ByPreloader`, the notarizer's rows for `flypreload-*` objects, the spawner's rows exclude them), role in the roster, `kernel/cmd/preloader` | `kernel/` | written, tests pass (b17e113) |
| preloader: its Fly app and token (`POST /fly-token`), golden volumes per (region, session image digest), `POST /golden`, spawn = fork of the golden (an empty volume when none yet), init/kill/destroy as the spawner's Fly path | `kernel/spawner` (shared code), `kernel/cmd/preloader` | written, tests pass (b17e113); to merge with `wip/spawner-runner-record` (runner from the record: map `fly-preload` → object `flypreload`) |
| machine: `JARVIS2_RUNNER=fly-preload` → object `flypreload-<id>`, cert checked against the preloader | `rust/machine`, `rust/doc`, kerneltest vectors | written, tests pass (f2d839c) |
| the tenth component: k8s blue/green, edge route, roster role lists (Go and Rust router, setup.py, fake kernel, e2e-kernel), flip state, a first release of a new role (no handoff) | `k8s/`, `router/`, `rust/router`, `infra/` | written, tests pass (d0d1b1a) |
| setup: `kernel-fly-token` for the preloader (its identity and token relay in the router's setup routes), the app's Recover sealing it too; a Fly token narrowed to `jarvis4-sessions-preload` (a Rust tool: `infra/fly-token.sh` is shell and its callers too) | `infra/setup.py`, router, iOS, `session-image/tools` | open |
| Fly app `jarvis4-sessions-preload` | a session with `infra` | open |
| router: runner `fly-preload` (spawn and lifecycle through the preloader), offered in New session; golden volumes asked for after each session-image pin | `rust/router` (and the Go router while it lives), app, iOS | after the type split (session `s58796a552ddb338a`) lands |
| CI: after `images.yml` pins a session image, the preloader makes its golden volume in each region in use | `.github/workflows/images.yml` | open |
| The machine image (Deyao, 2026-11-20: side by side): `session-image/machine-base` (Jarvis's parts, no agent tools) under session-image/Dockerfile's machine side → `jarvis4-session:machine-sha-<commit>` (images.yml job `machine`); aviary's image comes as a folder: the preloaded volume (fly-preload), fetched onto the disk (aws), carried in the fabric image (fabric) | `session-image/machine-base`, `images.yml` | written, not built (d…) |
| Every harness inside the sandbox: plain Claude Code, Paseo, OpenCode, OpenClaw and dsh started in aviary's image by `aviary-sandbox` (their runtimes and launchers bound in like Jarvis's session commands; Claude Code is aviary's). Their launchers are shell, so each is rewritten in Rust as it moves | `session-image/` | next, one harness at a time, each with a replica run |
| Switching runners: fly-preload, aws and fabric name the machine image for a harness once that harness runs in the sandbox (the aviary harness first); until then they keep the legacy image for the others | router (after the type split), pins | after the harnesses |
| Replica runs: `rust/e2e-kernel` per runner and harness; a fly-preload replica (throwaway app) | `rust/e2e-kernel` | with each part |
| Kernel release | Deyao's authorisation and signature | last |

## Security notes

- The preloader holds the only token for `jarvis4-sessions-preload`; the spawner's token stays narrowed to
  `jarvis4-sessions`. Neither can touch the other's machines or volumes.
- A session's volume is forked only from a golden volume the preloader itself made and recorded (never a volume id
  from a request), so no session's files can be copied into another session.
- A golden volume holds only public data: aviary's sandbox image as `crane` fetched it by digest. The machine that
  made it ran the session image (by digest) with no secrets, no keys and no network beyond the registry.
