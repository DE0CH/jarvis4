# Feature parity with Jarvis 1 (inventory, updated 2026-10-13)

Deyao asked for full parity with Jarvis 1. This lists every Jarvis 1 feature against Jarvis 4. J1 = claude-env
`selfhost/` (line numbers in `jarvis/server.js` unless named). Dependencies: SB Storage Box creds, FX arbitrary
Fly exec into the machine, FT Fly token, DT Discord bot token, GH GitHub token, CF Cloudflare API, CFA an Access
service token on the machine, OR OpenRouter, AT the Claude OAuth pair, K8s the box's API.

Facts: the router has no Fly token (it calls the core's start/kill/certify). Its ways into a machine are the
`/m/commands` poll (`snapshot`, and shell commands signed by a holder that the machine runs only under a phone grant,
a standing rule or its own allow list — DESIGN.md "Grants") and what the machine sends by itself (status reports,
snapshots, live transcripts, task results).


## Session lifecycle
- **Create** (FT, AT): present. Idempotent `requestId`: present (a repeat answers the session it made). Lifecycle lock: 409 and `busy {kind, since}` in `/api/state`.
- **Pause / resume / resume on newer image**: present (snapshot on the router volume, machine-signed, not encrypted). The snapshot holds the transcripts, `~/.claude.json`, `~/workspace`, `~/artifacts` and, as in Jarvis 1, the Paseo (OpenCode, Claude Code) and OpenClaw harnesses' state (`~/.paseo`, `~/.claude/.paseo-agent`, `~/.local/share/opencode`, `~/.openclaw`, without their logs, pid files and caches: `machine/main.go` `snapshotPaths`/`snapshotSkip`), so their apps stay paired across a pause.
- **Resume prompt**: present (`POST /api/sessions/:id/resume {prompt}`, delivered as a peer message once started; router/schedule.go). Jarvis 1 typed it as a user prompt instead.
- **Start on another size / model**: present (`POST …/resume {size, model, apiProxy}`), unsigned: no phone step.
- **Wake job status**: present for permission-mode and restart (`wake {kind, phase, error, finishedAt}` in `/api/state`).
- **Restart / env patch / transcript rollback**: present (`router/sessionops.go`): restart = pause + resume on the same image; `env` takes NON-secret keys only and stays for later starts; the rollback is applied by the next machine after it verified the snapshot (`machine/rollback.go`). env-resync: every resume re-pulls the stores; re-pull without a restart exists only inside add-store and downgrade.
- **Permission-mode switch**: present. The mode is signed (DECISIONS 30): a resume in another mode needs the phone; raising a running session to bypass needs a fresh phone grant for `terminal`; lowering runs Jarvis 1's `set-permission-mode` in place.
- **Auto-pause + idle countdown**: present (machine-reported status, `POST /api/sessions/:id/auto-pause`, `pauseInMs`; the scheduler vetoes it before a due wakeup). Not ported: Jarvis 1's "don't release if it moved during the snapshot" check.
- **Destroy + archive + uncommitted-work check** (SB): present. Destroy pauses a running session first (its final signed snapshot), the router archives it to the Storage Box with its own creds as one streamed `.tar.gz` in Jarvis 4's own folder (`router/archivetar.go`: `claude-records/.jarvis4-records/<date> <title>.tar.gz` with the transcripts, artifacts, logs, Discord export and the `jarvis2/` signed snapshot, cert, core cert; index `.jarvis4-records/index.json`), burns, then runs `onDestroy` hooks (the Discord channel deleted, the live copies removed). A failed archive leaves it paused (`?force=1` destroys anyway). `GET /api/sessions/:id/changes`: running via the `archive` holder's grant, paused from the snapshot's `.jarvis2-changes.txt`.
- **One-shot sessions**: present (`oneShot` → `SESSION_ONE_SHOT=1`). On the supervisor's marker the router destroys with force (archived, a failed archive doesn't stop it) and DMs when work was lost: dirty repos from the final snapshot, an unchecked state, a failed archive (`router/oneshot.go`, DECISIONS 40).
- **First prompt**: present (unsigned env). **First-prompt attachments**: present on the router (`router/uploads.go`: staged on the router's volume, fetched by the first machine over `/m/attachments`); not in the app (a file picker the extension doesn't carry).

## Previous sessions
- List, transcript tail (paused: the volume's snapshot; destroyed: the archive), remove/purge: present. Restore a destroyed session: present as a NEW line (phone-approved like a new session) whose first machine restores the archived snapshot, checking the old core-signed cert and the snapshot's signature (`router/restore.go`, `machine/restore.go`). Not phone-signed: which old snapshot is restored.
- **Paused Jarvis 1 sessions → Jarvis 4** (no Jarvis 1 counterpart; for the retirement): present (`router/jarvis1import.go`, `machine/jarvis1import.go`): prepare (the router hashes the Storage Box files into an import manifest), import (a new line whose cert's restore names the Jarvis 1 id and the manifest's sha256, approved in the Inbox), the first machine restores transcripts, workspace, artifacts, `~/.claude.json`, fixes remotes, resumes the conversation and re-arms the wakeups and crons. Setup session and `/api/jarvis1/*`; no app UI (the Inbox approval is the app's part). Several imports can be filed as one Inbox batch (`infra/setup.py jarvis1 import ID… --summary`), allowed under one Face ID.
- **Batch approvals** (no Jarvis 1 counterpart; Deyao, 2026-10-13): present (`router/batches.go`, `ios/Jarvis4/Review/BatchReviewView.swift`): a caller files several Inbox items with a summary; one entry, one review page, one Face ID; `jarvis-request batch`, `infra/setup.py request batch`, `/m/api/actions/requests/batch`.
- **Request outcomes** (no Jarvis 1 counterpart; Deyao, 2026-10-13): present (`router/outcomes.go`, `machine/outcomes.go`): the session that filed an Inbox item hears whether it was approved, denied, lapsed, dropped or failed (a batch in one message), from its own signed filing plus image texts, approvals checked against their signed proof; a paused session at its next start; `jarvis-request outcomes` / `wait ID`.
- **Indexing an archive by hand** (J1 `POST /api/records`): absent: Jarvis 4's records are its own `.tar.gz` archives only (DECISIONS 227).

## Terminal, remote control, title
- Registry read: present (the machine reports it: `/m/status {raw}`, `router/registry.go`).
- Live terminal: present (`router/terminal.go`, holder `terminal`; the app draws tmux's capture, app/DECISIONS 27).
- **App title sync (AT)**: present. The machine reads the Claude app's title of its Remote Control entry with its own Claude login and reports it (`/m/status {appTitle}`, `machine/apptitle.go`); it names the card, the Discord channel and the archive folder first (Jarvis 1's pickTitle: app title → CLI-pinned name → label → AI title), is kept while paused, and a resume without a label passes it as `SESSION_RESUME_TITLE`. Not ported: Jarvis 1's rename-back of a fresh Remote Control entry after a Start (`keepAppTitle`; DECISIONS 39).
- Remote page for opencode/openclaw/paseo-claude/cloudcli: present (`GET /api/sessions/:id/remote`, `router/remote.go`, holder `remote`).
- `/api/remotes?harness=` and `POST /api/sessions/:id/start`: present (`router/devices.go`), for Deyao and his paired OpenClaw/Paseo apps ("Device pairing" below).
- Per-session tunnel origin (CFA): present — harnesses opencode/openclaw/paseo-claude/cloudcli bring the store `tunnel` (Access service token `jarvis2-tunnel`); the machine fetches a proof for its own session id (`GET /m/tunnel-proof`); the cf-tunnel Worker confines the token to `AGENT jarvis2` with that proof (claude-env `cf-tunnel/wrangler.toml` `CONFINED_TOKENS`). A paused Jarvis 4 session's link gives the Worker's bare 503 (its Unpause page is for Jarvis 1 ids only).

## Automatic behaviour
- Auto-pause, Escape-cancel of a stale prompt (holder `status`), "needs you"/idle/dead DMs (+ `notify-idle` mute), model-downgrade DM (holder `status`), one-shot destroy: present (`router/autopilot.go`, `router/oneshot.go`); the stall nudge is the supervisor's own watch (`machine/stall.go`). Refused commands set `needsGrant`.
- Claude credential refresh: present (`router/claudelogin.go`): the router keeps the one shared pair on its volume and is its only refresher (Jarvis 4 never calls Jarvis 1), with lessons/74's refresh lock as a long-poll protocol that every session machine with the store `claude` (and Jarvis 1, while it still runs and follows) takes part in. A paused session on an image from before this (whose machine fetched the login from Jarvis 1) resumes on the newest image (DECISIONS 154). Login repair + "continue": present (holder `login`, for a session without it).
- Fly budget cap and "Also on Fly": present (`router/budget.go`, read-only `FLY_READ_TOKEN`).
- Browserbase budget DM: present (`router/bbbudget.go`, Jarvis 1's lib/bbbudget.js: the month re-priced from the session list, one DM at USD 8 and one at USD 10 overage; `BROWSERBASE_API_KEY` in the router's SOPS part `browserbase`; `/api/state` `browserbaseBudget`).
- Discord channel per session (DT, SB): present (`router/discord.go`, lobster, category "Jarvis 4"), named by the title above and renamed as it changes (2 edits per 10 min), exported into the session's archive (`discord/`) and deleted on destroy. Topic has no Remote Control link.
- **Live transcript sync to SB**: present. The machine sends changed transcripts every 5 min (`machine/livesync.go`); the router writes `claude-records/.live/<session id>/` with its own creds, so transcript search indexes running Jarvis 4 sessions; on destroy each copy goes only once the archive holds it (router/livearchive.go). No grant (the machine pushes; DECISIONS 38).

## Scheduling and devices
- Wakeups, crons: present (router/schedule.go; Jarvis 1's shapes, under `/api` and `/m/api`; delivered as the session's own signed request, core-attested; into a sensitive session approved per message).
- Watches: present (`router/watches.go`, Jarvis 1's shapes): the check runs on the box's watch runner (`services/watch`, no secrets, public internet only), so a paused session's watch still fires; delivery is the session's own signed request, and the machine re-runs the check for the context. A check can't use a store's secret (DECISIONS 114).
- Device leases (iphone, mac, wechat-phone): present in the router (`router/leases.go`, Jarvis 1's rules and shapes; wake messages are machine-checked deliveries; DECISIONS 113). Jarvis 1's lease table is separate until the cutover.
- Tasks + schedules: present on the router (`router/tasks.go`, `machine/task.go`, templates in `tasks/`; DECISIONS 32–37) and in the app (Tasks and Schedules tabs, app/DECISIONS 35). Jarvis 1's content templates are ported (`tasks/encrypt-to-content`, `paraphrase-to-content`, `proton-send`: content fields `optionsFrom: "content"`, key store `optionsFrom: "stores"`); `new-session` isn't (a new line needs the phone; a session proposes one instead). Jarvis 1's instances and schedules (all three schedules disabled) aren't recreated: each instance is a new line approved on the phone, and no Jarvis 4 store holds their `AES_KEY` yet (DECISIONS 134).

## Stores, repos, content
- Store editor in the app: partial — the shell's Stores page creates, unlocks, locks and marks stores sensitive; values are written only by the setup session (`infra/setup.py`). Copy keys between stores: missing (design question 12).
- Restoring a store to an earlier version (no Jarvis 1 counterpart: its stores were plain SOPS files in git): present
  (`core/history.go`, `router/storerestore.go`, DECISIONS 165): the core keeps each store's last 50
  versions; a phone-signed restore (the app's Stores → a store → Versions → Restore…, or an Inbox request from the web
  page / the setup session) puts one back with no kit. Every write is one key, so none silently drops the store's others.
- Multi-store merge conflict file: unverified. Repo picker: present (`router/repos.go`, the app's Settings → Repos). Repo delivery: replaced by per-repo deploy keys (SSH).
- Content stores: present (`router/content.go`; DECISIONS 132-133): Jarvis 1's `claude-records/.content/<name>/` folders, used in place with the router's Storage Box creds; the app's Content tab (web) manages them; New session (web and iPhone) and task fields pick them, signed in the line's config (`content`); `content-sync` on the machine goes through the local proxy to `/m/api/sessions/:id/content…`, only for the cert's stores, each downloaded file with the core's attestation. Drop tokens: missing.

## Account and apps
- Re-login: present (Settings → Claude account in the web page and the app: the CLI's sign-in page, paste the code; `POST /api/claude-login/start|code`). Usage quota: present (the router reads it with its own pair). Device pairing for OpenClaw/Paseo apps: present (`router/devices.go`; "Device pairing" below); both apps name this host (DECISIONS 161).
- Dashboard (app/DECISIONS.md 23–38): Sessions (live status, auto-pause/idle switches, resume prompt, destroy with the changes check, transcript, Discord link, needsGrant one-tap, permission mode, copy id), Grants (secure page, phone-signed), Terminal, Remote (with copy), per-session wakeups/crons, **Search** (conversations of both Jarvises, iCloud files), Previous (restore/tail/remove/delete), Tasks, Schedules, Stores, Repos, Settings (usage, Fly spend, core keys with copy), New session (one-shot, auto-pause, repos, API proxy; the permission mode is always bypass, DECISIONS 219), banners, "Also on Fly": present. Paired apps (Settings, web), Content (web tab; iPhone Settings → Content without uploads), lease pills, first-prompt attachments, the per-tab transcript filter on Sessions/Previous: missing.

## Harnesses and image
- Claude: present. OpenCode + Paseo, OpenClaw + claw-code: present (policy: opencode brings `openrouter` + `tunnel`, openclaw brings `claude` + `tunnel`; `GET /api/models[?harness=]`; the harness is signed in the cert's options). `harness-send`: present (the machine's own delivery). API proxy: present.
- Claude Code + Paseo (`paseo-claude`): new in Jarvis 4 (Deyao, 2026-10-20; DECISIONS 204), no Jarvis 1 counterpart. Brings `tunnel`, runs on a Claude account; the only harness besides `claude` whose running session switches accounts (no restart: its API proxy sends the new pair). Differences from `claude`: no Remote Control (the Paseo app and web UI instead), no claude.ai MCP connectors, Jarvis messages wait for the agent to be idle.
- Claude Code + CloudCLI (`cloudcli`): new in Jarvis 4 (Deyao, 2026-10-25; DECISIONS 240), no Jarvis 1 counterpart. As
  `paseo-claude`, with Deyao's CloudCLI fork and the Jarvis 4 Chat app (YYC AI's app code) as its front end.
- Session image: Jarvis 4 builds all of it. The base (tools, harnesses, entrypoint, supervisor, workspace layer, api-proxy,
  content-sync, pull-secrets, session-secret) is `session-image/base/`, carried over from Jarvis 1's `selfhost/session-image/` (DECISIONS 100-102);
  Jarvis 1's image is no longer used. Fork pins (Jarvis 1's `fork-pin.yml`): present (`.github/workflows/fork-pin.yml`; the
  forks run it on every build, DECISIONS 156).
- Workspace layer: to verify. on-start hooks: present.
- Peer-message delivery: present (a core-attested `peer` delivery the machine sends in itself, router/peermsg.go, machine/deliver.go).
- Session-facing API (`$JARVIS_URL`): present — the machine's local proxy signs to `/m/api`; secrets (`pull-secrets` pulls, `session-secret` asks for named keys: the supervisor's socket) and changes answered on the machine; notify-idle and self-retire on the router; watches and leases on the router.
- Transcript search: moved out of Jarvis (DE0CH/services, search.deyaochen.com; Deyao, 2026-10-24). iCloud index: present, on the Jarvis 4 services box (`services/icloud-index`, k8s/services/apps/icloud-index, moved from Jarvis 1's box with their databases on 2026-10-13: embeddings and the iCloud AI-budget ledger carried over). The router forwards the app's `/api/search*`, `/api/icloud/*` and sessions' `/m/api/search*`, `/m/api/icloud/*` (`router/searchsvc.go`). The index covers both Jarvises' archives, Jarvis 1's `.paused/`, both `.live/` and the task records. The iCloud index is identity-level: sessions need the `identity` store (DECISIONS).

## Design questions parity raised
1. A command channel replacing Fly exec: answered — grants (DESIGN.md "Grants", DECISIONS 24).
2. Free text into machines (wakeup/cron/resume prompts, nudges): open — unsigned today (DESIGN.md "Open").
3. Where archives and transcripts live: answered — the Storage Box in Jarvis 1's layout with the router's creds, the signed snapshot alongside (DECISIONS 27, 38).
4. Restore after a burn: answered — the old core-signed cert + the snapshot's signature (DECISIONS 28).
5. Secrets outside sessions: tasks answered (DECISIONS 32–34); watches answered without secrets (DECISIONS 114); Discord and the budget cap use the router's own secrets (DECISIONS 25).
6. Fly read access for the budget cap: answered (`FLY_READ_TOKEN`, DECISIONS 17).
7. The Discord bot token: answered — lobster, in the router's SOPS secrets (DECISIONS 25–26).
8. Per-session tunnel origins: answered — the confined `jarvis2-tunnel` token + per-id proof.
9. Cross-Jarvis services: answered for now — Worker-confined Jarvis 1 tokens; each moves into Jarvis 4 before Jarvis 1 retires (PLAN.md "Later"). The Claude login has moved (DECISIONS 115-121): Jarvis 1 now reads it from Jarvis 4.
10. Which options are signed: answered — the harness and the permission mode (DECISIONS 30); size, model, one-shot, auto-pause, API proxy unsigned.
11. Arbitrary env injection: non-secret names only (DECISIONS 31).
12. Store authoring in the app (the app as trusted writer), copy between stores: open.
13. Attachments and content without SB on machines: answered (router-staged uploads; content through the router, DECISIONS 132).
14. Device pairing for OpenClaw/Paseo: answered (Jarvis 4 pairs them itself; DECISIONS 135-136).
15. A machine reporting "busy" forever defeats auto-pause and the budget: open (the budget cap still pauses it).

## Device pairing for OpenClaw/Paseo

Jarvis 4 answers the apps itself (`router/devices.go`), as Jarvis 1 did: `GET /api/devices/pair?state&name&model&app=openclaw|paseo`
(Deyao's Access login in the app's sign-in sheet) mints one Access service token per app with the Cloudflare token
`jarvis2-device-tokens` (Access: Service Tokens read/write only; router SOPS part `devices`) and answers
`openclaw-de0ch://paired?…` / `paseo-de0ch://paired?…`. `GET /api/remotes` and `POST /api/sessions/:id/start` sit behind the
path-scoped Access app "Jarvis 4 devices" (Deyao's email, or any service token; `ACCESS_DEVICES_AUD`), and the router admits
a service token only when its client id is a paired device's. The same token passes the session hosts' Access
(`<id>-s.deyaochen.com`). Settings → Paired apps lists and removes them. Both forks name jarvis4.deyaochen.com
(DE0CH/openclaw `apps/ios/Sources/Jarvis/JarvisModels.swift` `JarvisConfig.baseURL`, DE0CH/paseo `packages/app/app.config.js`
`jarvis.url`; 2026-10-13, DECISIONS 161): each app pairs once with Jarvis 4 (RUNBOOK "Paired apps").
