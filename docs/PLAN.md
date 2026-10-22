# Jarvis 4 — plan

Jarvis 4 is a second, independent Jarvis built on the secrets-controller design
(`docs/DESIGN.md`). It runs **side by side with Jarvis 1, which keeps running exactly as
it is**: nothing here touches Jarvis 1's box, cluster, repo paths, session image, Fly app or budget.

## Where things run

| Piece | Where |
|---|---|
| Boxes | Its own Hetzner Cloud project (`jarvis2`), two boxes (DESIGN "The boxes"), each a single-node **k3s** reconciled by its own **Flux** from this repo (public), joined by the Hetzner Network `jarvis2`: the control box (`jarvis2-control`, cx23: the cores, the router, cloudflared) and the services box (`jarvis2-services`, cx33: transcript search, the watch runner, the iCloud index, experiments). **Changes only through git** (Deyao, 2026-10-09): no SSH, no reachable k8s API, no inbound port; a box git can't fix is replaced (a control box: set up again with Recover) |
| Core (secrets controller) | Go, two pods on the control box, blue and green (DESIGN "Core continuity"): one serves, the other takes the next release and is Recovered alongside, then the router flips; minimal network surface; all state in memory |
| Router | The Jarvis 4 backend (API for the app and the web page) on the control box; outside the core; untrusted |
| Sessions | Fly Machines in a **new Fly organisation** (`jarvis2-370`), so Jarvis 1's budget scan never sees them |
| Public address | `jarvis4.deyaochen.com`, a Cloudflare Tunnel (cloudflared on the control box) behind its own Cloudflare Access app: Deyao's login; `/setup` admits only the setup session's service token. Session machines never come through Cloudflare: they reach the router over Fly's private network (the control box's router is a WireGuard peer of the org), because Jarvis 1's Access apps admit any service token of the account |
| iPhone app | "Jarvis 4" (`dev.de0ch.jarvis2`, its own TestFlight app): one native SwiftUI app for iPhone and iPad (`ios/`, Apple frameworks only) |
| CI | GitHub Actions (this repo is public, so macOS runners are free): images to GHCR, the app to TestFlight |

## Setting up (Deyao, 2026-10-10)

A new core is empty. Deyao sets it up in the app, with no one else involved: **Reset** (a new recovery kit, the
stores start empty; the setup session then fills them with `infra/fill-stores.sh`) or **Recover** (his kit brings
every store back from the backups). docs/DESIGN.md "Setting a core up".

## Milestone 1 (all of it)

1. Core in Go: the primitives of docs/DESIGN.md, signed answers, in-memory state, tests.
2. Infra: Hetzner box + k3s + Flux, cloudflared tunnel + Access app, Fly org + its token held by the core.
3. Router: Jarvis 1's backend adapted: sessions created / paused / resumed / destroyed through the core.
4. Session image: Jarvis 1's image adapted: an init entry point that pulls its cert and secrets.
5. App: the mock's shell + extension pointed at the router; TestFlight.

## Status

- Core: `core/`, tests pass; the per-key core (stores made of keys, store versions, the phone-signed restore: DECISIONS
  163, 165) serves on the control box (which colour: `/setup/status` → `core`).
- Infra: the control box and the services box (DESIGN "The boxes"); tunnel `jarvis2` + Access apps on
  `jarvis4.deyaochen.com`; Fly app `jarvis4-sessions` in org `jarvis2-370`; logs, metrics and alerts in Grafana Cloud.
- Router: `router/` (docs/API.md), deployed.
- Session image: `session-image/` (its base in `session-image/base/`) + `machine/`, built by CI.
- End-to-end test on real Fly with a software phone (`infra/e2e.sh`), the Recover rehearsal on a real throwaway control
  box (`infra/rehearse-recover.sh`), the phone replica in CI before every TestFlight build.
- iOS app: `ios/`; web page: `app/` — see app/DECISIONS.md.
- Decisions to review: docs/DECISIONS.md.

## Later (Deyao, 2026-10-09)

- **Before Jarvis 1 retires** (Deyao keeps using Jarvis 1 until Jarvis 4 is ready and polished, then retires it and
  handles the conflicts then): Jarvis 4 must stop depending on it. The Claude login (storage, the only refresher,
  Re-login, the usage quota) is the router's (DECISIONS 115-121; Jarvis 1 follows it through `/peer/claude-login`).
  Jarvis 1's paused sessions move with the Jarvis 1 import (RUNBOOK "Importing a paused Jarvis 1 session"; Jarvis 1's
  records stay on the Storage Box). Content stores, the paired OpenClaw/Paseo apps, the Browserbase budget DM and the
  Machines tab's org personal are the router's own (DECISIONS 132-139); the apps' server URL is this host since 2026-10-13 (PARITY "Device pairing"). Done 2026-10-13 (Deyao: "make sure Jarvis 4 runs fully without Jarvis 1"):
  nothing in the router, the machine or the session image calls Jarvis 1 any more (the login's `follow` mode and the
  image's jarvis.deyaochen.com defaults are gone), and the end-to-end test runs with every Jarvis 1 hostname
  unreachable (RUNBOOK "Testing", DECISIONS 155). Jarvis 1 → Jarvis 4 (its `/peer/claude-login` follower) stays until Deyao
  sets Jarvis 1 to 0.

