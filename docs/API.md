# Jarvis 4 — router API

The router (`router/`) is the only thing reachable from outside: `https://jarvis4.deyaochen.com`, through a
Cloudflare Tunnel behind Cloudflare Access. It is untrusted: everything security-relevant it relays is a
document signed by the core (`{payload, sig}`) or by the iPhone, and the receiving end checks the signature.

Formats (same as the core, `core/crypto.go`): a signed document is `{"payload": "<JSON text>", "sig":
"<base64 DER ECDSA-P256-SHA256 over the payload bytes>"}`; public keys are base64 of the 65-byte uncompressed
X9.63 point (CryptoKit `x963Representation`). Errors are JSON `{"error": "..."}` with an HTTP status; errors
that come from the core are relayed as the core's signed error document `{payload, sig}` whose payload is
`{"kind":"error","error":"..."}`.

## Who may call what

| Prefix | Caller | Access |
|---|---|---|
| `/api/*`, `/` (web page) | Deyao's app / browser | Access app `jarvis4.deyaochen.com`, Deyao's email only. The iPhone app sends the Access token in the `cf-access-token` header (got once from `/api/auth/start`). The router also verifies the `Cf-Access-Jwt-Assertion` header itself. |
| `/setup/*` | the trusted setup session | Access app `jarvis4.deyaochen.com/setup`, service token `jarvis2-setup` only (kept in Jarvis 1's `default` store, never on a machine). The router then checks the setup key's signature on each call (below). |
| `/m/*` | session machines | Not on the public hostname at all: the router serves `/m` on a second port (8081) that only Fly's private network reaches (the box is a WireGuard peer of org `jarvis2-370`). The router checks the machine's own signature on each request. |

## App sign-in

`GET /api/auth/start?redirect=jarvis2://auth` — Access makes Deyao log in first; the router then redirects to
`<redirect>#token=<the Access JWT>`. Only `jarvis2://` redirects are allowed. The app keeps the token in the
Keychain and sends it as `cf-access-token` on every request; when a request comes back 302/401/403 from
Access (token expired), it runs sign-in again.

## Sessions

A session's `id` is the router's (`s…`), stable for the session's life. `machineId` is the machine it is on now
(null before the first start and while paused). Session objects keep the Jarvis 1 shape where a field means the
same thing:

```
{ id, machineId, released, name, state, status, created, region, environment /* stores, comma-joined */,
  stores, harness /* claude | opencode | openclaw | paseo-claude */, label, model, permissionMode, guest, pausedAt, error,
  autoPause /* "on" | "off" */, notifyIdle /* "on" | "off" */, oneShot, needsGrant /* a holder the machine refused */,
  lastReport /* the machine's last status report */,
  // while started, from the machine's report (fresh within 3 min), as in Jarvis 1:
  status /* busy | idle | waiting | … */, aiTitle, liveName, nameSource, bgTasks, statusUpdatedAt, bridgeSessionId,
  sessionId /* claude's conversation id */, authFailed, credsExpiresAt, sessionsInside, oneShotDone,
  refusals: [{kind: "fallback" | "refusal", at, uuid, from, to, model, category}],
  workers /* {subagents, jobs: {<Claude Code's task type: shell | monitor | workflow | teammate | …>: n}, at (ms)}:
  what the host conversation's harness runs besides itself now, from Claude Code's hooks (machine/workers.go);
  absent on an image from before */,
  pauseInMs /* while the auto-pause countdown runs */,
  serverTitle /* the Claude app's own title of its Remote Control entry (the machine reads it; kept while paused) */,
  userTitle /* a name pinned in the CLI */, title /* what the card, channel and archive use: serverTitle → userTitle →
  label → aiTitle → id, Jarvis 1's pickTitle */, liveSync /* {at, files: {<name>: bytes}, stored, error} — the last live
  transcript copy (below) */,
  discordChannel /* the session's Discord channel id */, waiting /* what a pause or destroy waits on, plain words, or "", e.g. the final snapshot's progress: "uploading snapshot 1.2/3.4 GB (35%), 40 MB/s, 55 s left" (POST /m/snapshot-progress) */, lockedStore /* the store the machine waits on at boot: its secrets pull got the core's 423 "store X is locked"; cleared by the next pull that goes through */, oldCore /* its line is an earlier core's: destroyed (archived in Previous) once paused (DESIGN "Carried secrets") */, wakeups: [wakeup view], crons: [cron view], watches: [watch view] /* below */,
  resumePrompt /* a prompt queued for delivery once started */ }
```

What the router does by itself with a running session (`router/autopilot.go`, every 30 s), from that report:
auto-pause after 1 h plain idle (unless `autoPause` is off, the session is one-shot, or another feature vetoes);
destroy a one-shot session once `oneShotDone` — forcefully (a failed archive doesn't stop it) and with a DM when work
was lost: dirty repos as its final snapshot recorded them, a repo check that couldn't run, or a failed archive
(`router/oneshot.go`, Jarvis 1's finishOneShot); Escape a prompt left `waiting` for 1 h (holder `status`); DM
"needs you" / idle / dead after 5 min in that state (the idle one muted by `notifyIdle` off); DM new safeguard
refusals and the "switch model?" dialog (holder `status` reads the pane); a Jarvis watchdog peer message every
15 min while idle with background jobs; and "continue" to a session with a Claude account whose turn stopped on "Please run /login", once its
own pair is in step (it logs in and keeps in step by itself, machine/claudelogin.go; the router never writes a
login into a session); and the harness check: a `claude` session whose booted machine has reported for 4 min without
Claude Code ever showing a live Remote Control host (`bootedAt`, `hostUp` in its liveness) is set `failed` with the
reason and the last lines of its pane ("the harness didn't come up within 4 min of boot …; its screen ends: Settings
Error / … / 3. Continue without these settings. Resume starts it again on a new machine."), logged as a `harness-check`
operation and DMed once; Resume (which finishes its pause first) or Destroy go on from there. Such a Resume goes on the
newest session image when the session's own is older (the image its Claude never came up on would hang again): the
`resume-upgrade` approval in the Inbox, one Face ID. A command the machine
refuses sets `needsGrant` to that holder and the loop leaves it alone for 10 min, or until a phone grant for that
holder is saved.

`state`: `approval` (waiting for the iPhone; no machine yet) → `starting` (the core makes the machine) →
`initialising` → `started` (running) → `pausing` → `paused` (no machine) → `resuming` → … ; `destroying` →
gone (moved to records); `failed` (with `error`).

While the router drains for a rollout (`router/drain.go`), every call that starts a lifecycle action (create's first
start after the approval answer, `respond`, pause, resume, destroy, restart, upgrade, the permission-mode switch, and
the same calls under `/m/api`, `/setup` and `/actions`) answers **503 `{error: "router updating, try again shortly"}`**;
the apps show the text as is and the action can be retried a moment later. Everything else is served as usual. A
session a router crash left mid-action comes back `failed` with `error` "the … was cut off by a router crash: … again"
(a cut-off resume: `paused` with that error).

| Call | Does |
|---|---|
| `GET /api/state` | `{sessions, approvals, core: {up, signingKey, agreementKey}}` |
| `GET /api/sizes` | `{sizes: [{id, label}]}` (small / medium / large, the sizes a new session picks from; Upgrade goes on past them while the running core reports `sizeLadder` in its `/identity`, `router/sizes.go`) |
| `GET /api/models` | `?harness=` optional → `{models: [{id, label, harness}], default, defaults: {<harness>: id}, harnesses: {<harness>: {label, detail}}}` — Jarvis 1's list (Claude, OpenRouter via OpenCode, Claude via OpenClaw) plus Claude Code driven by Paseo (`paseo/<Claude model id>`, harness `paseo-claude`), only harnesses the policy has. In `POST /api/sessions` an empty model or one of another harness becomes the harness's default; an unknown one is refused (400). |
| `GET /api/stores` | Every store, its keys and what each is for (never a value): `{stores: [{name, sensitive, empty, unlocked, about, version, keys: [names] /* the shape every session image reads */, keyInfo: [{name, explanation, at, writer: {by /* setup \| machine \| core */, machine, line, session, sessionLabel}}], keysFrom /* "core" */}], signed /* the core's signed list it was built from */}`. The list, sensitivity, empty, unlocked, the key names, who wrote each key and when are the core's (`POST /stores`; a machine writer's line is named with its session here); `about` and each `explanation` are the router's own record (`store-docs.json`). Same answer at `GET /m/stores` and `GET /setup/stores/keys`. |
| `PUT /api/stores/{store}/docs` | `{about?, keys?: {KEY: text}}` → `{ok}`: what the store and its keys are for (plain text, ≤ 2000 characters each; `""` removes a key's explanation). Shown on the web page, in the app and by `jarvis2 stores --keys`. |
| `GET /api/policy` | `{harnesses: {<harness>: {stores: […]}}}` — the stores each harness brings (the router adds them; the app hides them) |
| `POST /api/sessions` | Body `{requestId, label, prompt, model, permissionMode /* "bypass" or omitted: the only start mode (DECISIONS 219); any other value is refused 400 */, size, harness, stores: [], account, oneShot, autoPause, apiProxy, attachments: {uploadId, files: [{name}]}}` (`account`: its Claude account, `claude-<name>` or `<name>`, kept for its life; "" = the default; "Claude accounts" below) (`apiProxy`: `SESSION_API_PROXY=1`, claude through Jarvis 1's api-proxy.js; `attachments`: files staged by `POST /api/uploads`, bound to this session) (`oneShot`: the machine gets `SESSION_ONE_SHOT=1` and the session is destroyed when its prompt is done; `autoPause` defaults to true, false for one-shot; both show in the approval's `options`). The router adds the harness's stores and asks the core for a challenge (`succession(null, …)`, before any machine); the approval (kind `new-session`) appears at once. Answers `{id, requestId}`; a repeat with a `requestId` already on a session answers that session and makes nothing. |
| `POST /api/sessions/:id/pause` | The machine snapshots itself (signed, streamed to the router: no free disk needed), then the core kills it (a machine with a volume: stopped, its volume backed up, then destroyed; `router/snapsafe.go`). When the snapshot fails (an error the machine reports, no progress for `SNAPSHOT_STALL_SECONDS`, or a machine silent for 3 min), the machine is **kept**, with its volume if it has one: the session goes `failed` (machine still there) with `snapshotFailed` and an `error` saying so, and Deyao gets a "needs you" DM; pause again to retry, or destroy with `?force=1` (Destroy anyway). A kill that can't finish (45 min) leaves it `failed` with its machine, DMed. A session already paused answers 200 with nothing done. |
| `POST /api/sessions/:id/resume` | Optional `prompt` (≤ 4000 chars): carried in the resume's phone-approved cert; one left for a session that is already running goes in as a `resume-prompt` message Deyao approves ("Message approvals") (dropped if the start fails or is rejected). Optional `size` (small, medium, large, or a doubling past it: `16gb`, `32gb`, …), `model`, `apiProxy` (bool): kept for this and later starts (not in the core's Options, so no approval). Body `{upgrade: false}`: the same image (the challenge names the cert's own image string, what Fly reported: `repo@digest`), `approve_by_dead_machine`, then start + certify — no approval. When the core refuses that (403 "store set, image or options differ from the predecessor's"), the resume becomes the `resume-upgrade` approval in the Inbox on the same image (named by CI's pinned ref, whose signature the phone checks): one Face ID resumes it, with no retry. Any other refusal leaves the session `paused` with `error`. A `failed` session with no machine (a start or certify that failed, a start cut off by a router restart) resumes the same way; one that never got a cert (a new line whose first start failed) gets its `new-session` approval again, built from the session as it is (Deny leaves it `failed`). A failed session that still has a machine (a pause or destroy whose kill failed, or one cut off) has its pause finished first on the same call: the final snapshot (the same one again if taken), the kill (a kill failing on the way, 502, is tried again 4 times), then the resume; a kill the core refuses leaves it `failed` with `error: "kill: …"` (DECISIONS 181). `{upgrade: true}`: the newest session image; an approval of kind `resume-upgrade` first (reject = stays paused), then start + certify. A session already running (or starting) answers 200 with nothing done; one waiting in the Inbox is refused with an error saying so. Size, model and apiProxy are taken for a `failed` session too. |
| `POST /api/sessions/:id/destroy` | A running session is paused first (the machine's final signed snapshot, then the core's kill; a failed snapshot keeps the machine as for a pause, unless `?force=1`); the snapshot is archived to the Storage Box (below); then a burn: a succession to the null image, approved by the dead-machine rule and certified. The session moves to `GET /api/records`. A failed archive leaves the session `paused` with `error: "archive: … — nothing was lost …"` (Destroy again, or Destroy anyway); `?force=1` destroys anyway (the record keeps `archiveError`). The kill: a refusal of the snapshot claim (a machine certified by an earlier core) is killed again without it, and the router's copy is archived as is, marked (`snapshotNote`, `archive.unverified`: "from an earlier core, not verified by this core"; its Restore is checked like any other: the archived cert by this core or an earlier core the master key claimed, the snapshot by the cert's machine, again on the restoring machine); a kill that still fails goes on when Fly has no such machine, else leaves the session `failed` with `error: "kill: … (Destroy anyway removes the session; the machine is then on the Machines tab)"`, and `?force=1` destroys it anyway (the router stops taking the machine's calls; it is an orphan on the Machines tab). |
| `GET /api/sessions/:id/changes` | Uncommitted / unpushed work per repo under `~/workspace`: `{checked, paused?, reason?, status?, repos: [{name, uncommitted, unpushed /* -1 = no upstream */}]}`. Running: a shell command under the `archive` holder (a grant, standing rule or the session's allow list); paused: as the last snapshot recorded it. |
| `GET /api/sessions/:id/cert` | The line's latest core-signed succession cert `{payload, sig}` (404 before the first certify). The app's grant page reads `line`, `phone`, `stores` and `sensitive` from it after checking the core's signature. |
| `GET /api/holders` | `{holders: {<name>: <public key>}}`: the router's features that may hold grants (terminal, status, archive, remote). |
| `POST /api/sessions/:id/grants/draft` | Body `{holder, kind: "grant" \| "rule", minutes /* grant: 1–10 */, until /* rule: RFC 3339 */}` → `{text}`: exactly what the phone signs, `{kind, holder /* its public key */, session /* the line */, scope: "shell", issued, expires \| until}`. |
| `POST /api/sessions/:id/grants` | Body `{payload: text, sig}` (the phone's signature) → the stored grant `{id, session, holder, kind, ends, doc}`; refused unless the cert's phone key signed it for this line. |
| `GET /api/sessions/:id/grants` | `{grants: [...]}` (live ones; ended ones are dropped). `DELETE /api/grants/:gid` forgets one (the router stops using it; the signed text stays valid on the machine until it ends). |
| `GET /api/sessions/:id/terminal` | `{screen /* tmux capture-pane -e */, cursor: "x,y,width,height,visible", at?}` — no grant: the pane the machine pushes itself every 2 s when it changes (`POST /m/screen`, `machine/screen.go`; `at` = when, fresh for 45 s); a machine without the push is read by an exec under holder `terminal`. `POST` `{text?, keys?: [tmux key names]}` types, `{cols, rows}` resizes the window. |
| `GET /api/sessions/:id/events?after=<cursor>&limit=<n>` | The session's one event stream (`router/sessionevents.go`): `{events: [{key, at /* RFC 3339 */, source: "supervisor" \| "router" \| "fly", machine?, op? /* the operation's kind */, opId?, mark?: "start" \| "end", state? /* an end's: done \| failed \| cut off */, text}], next /* the cursor */, running: {id, kind, started} \| null, more, machine /* the current machine, "" when paused */}`, oldest first. It holds every supervisor line of every machine the line had (below), and each operation of the lifecycle log: a `start` mark, its router steps and Fly entries, an `end` mark ("Pause done after 4 s", "… failed after 6 s: <error>"). Without `after`: the newest `limit` events (default and cap 2000; `more`: older ones were left out). With `after` (a previous answer's `next`): only what was written since, at most `limit` supervisor lines (`more`: ask again at once); a Fly event is read a few seconds after it happened, so a new event can sort before one already shown: the client keeps its list in time order (`key` is stable). Also for paused and failed sessions. 400 a bad cursor, 404 no such session. |
| (the supervisor log) | Every machine of the line writes its lines into the session's log (`POST /m/supervisor-log`, `router/supervisorlog.go`), kept on the router's volume for the session's life (cut to its newer half past 20 MB, with a line saying so) and archived on Destroy. |
| (the lifecycle log) | The session's operations (`router/lifecycle.go`), in the events above. `kind`: `boot` (a new session's start after the phone's approval), `pause`, `resume` (also a resume the phone approved, and a first start tried again), `upgrade` (the Upgrade job: free, pause and resume on the next size in one operation), `restart`, `destroy`, `harness-pause`, `harness-resume`, `harness-check` (the harness check above failed the session). `state`: `running`, `done`, `failed` (with the session's error), `cut off` (a router restart ended it; its log ends there). Kept for the session's life, archived on Destroy. |
| (an operation's entries) | The router's own steps; what Fly did, read by the router with its read-only `FLY_READ_TOKEN` every 2 s while the operation runs and for 30 s after (each Fly event of its machines once: launch, start, exit with its code and OOM flag, destroy; and Fly's platform log lines for the machine, such as the image pull, not the app's stdout; when Fly's logs API refuses the token, a router entry says so and only events follow); (in the archive's `lifecycle.json`, each operation also carries the supervisor lines of its machines from 5 s before it began to 30 s after it ended). |
| `POST /api/sessions/:id/harness` | `{action: "pause" \| "resume"}`: the supervisor SIGSTOPs or SIGCONTs the Claude process (`pause-harness` / `resume-harness` in `GET /m/commands`, not guarded, like `snapshot` and `free`); recorded as an operation `harness-pause` / `harness-resume` (its supervisor lines follow in its log). No app button. → `{ok, machine, command, op}`; 400 another action, 409 no machine. |
| `GET /term/:id` | The terminal as a web page (`router/web/terminal.html`, one self-contained file: no outside scripts, strict CSP, `no-store`): polls the snapshot above once a second, sends keys and text in order, fits the window to the screen. The iPhone app shows it in a WKWebView and listens on the message handler `jarvis2`: `{action: "grant", holder: "terminal"}` (open the app's Face ID grant review) and `{action: "signin"}` (the Access login expired); it calls `window.jarvis2Refresh()` once the grant is signed or the login renewed. In a plain browser the grant button files `POST /api/requests/grant` (minutes 10) and an expired login reloads the page once. The id must be `[A-Za-z0-9-]` (else 404). |
| `GET /api/sessions/:id/tail` | A paused session's conversation end, from its snapshot: `{title, sessionId, messages: [{role, text, at}], stale?}`; while it runs, its last pause snapshot's tail with `stale: true` (404 without a snapshot). |
| `GET /api/state` (extra fields) | `budget` (the Fly cap: `capUsd` 50 pauses every running session, `warnUsd` 45 sends one DM; `FLY_BUDGET_USD` / `FLY_BUDGET_WARN_USD` on the router): `{month, spentUsd, capUsd, warnUsd, warned, capped, cappedAt, ratePerHour, perMonth, running, volumes, snapshots, snapshotGb /* the volume snapshots Fly stores and bills, past 10 GB free, DECISIONS 180 */, sampledAt}` or null; `fly`: `{apps, app, machines, volumes, other: [{kind, app, id, name, state, region, created, detail}], error, checkedAt}` ("Also on Fly": machines in app jarvis4-sessions that are no running session of the router's, and volumes); `flyApp`. |
| `GET /api/state` (`browserbaseBudget`) | `{month, capUsd, warnUsd, overUsd, parts: {time, proxyMb, proxyBytes, total}, usage: {count, minutes, proxyMb, proxyBytes}, warned, capped, sampledAt}` or null (`router/bbbudget.go`: the month re-priced from Browserbase's session list every 10 min; one DM at the warn line, one at the cap; nothing is blocked). |
| `GET /api/machines` | The Machines tab (`router/machines.go`): every machine in Fly app jarvis4-sessions, live from Fly with the read-only `FLY_READ_TOKEN`, newest first: `{app, machines: [{id, name, state, region, size /* small\|medium\|large\|16gb\|32gb… or "" (a guest no size has) */, guest, image, created, updated, sessionId /* "" = no session */, current /* the session's machine now; false = an earlier one */, routerUrl /* its JARVIS2_URL */, test /* routerUrl isn't jarvis2-box's */, noDestroy /* why Destroy isn't offered, "" = it is */, attention /* why it stands out (stopped, failed, stuck, no session), "" = it doesn't */}], orgs: [{org, via /* "fly" */, error, checkedAt, apps: [{app, label /* "Jarvis 4 sessions"…, "" = an app no Jarvis uses */, own /* jarvis4-sessions */, status, error, machines: [same fields; other apps: no session/router, noDestroy "read-only", otherSession /* a Jarvis 1 session id */], volumes: [{id, name, state, region, sizeGb, attachedTo, created, attention}]}]}], attention /* how many things stand out */, configError, checkedAt}`. Every org Deyao has (`router/flyorgs.go`): jarvis2-370 and kamyee read from Fly with READ-ONLY org tokens (`FLY_ORG_READ_TOKENS`), personal with its own read-only token (`FLY_PERSONAL_READ_TOKEN`, DECISIONS 138). An org that can't be read comes back with `error`. 502 `{error}` when jarvis4-sessions can't be listed. |
| `POST /api/machines/:id/destroy` | Destroy a machine that belongs to NO session, re-checked on a fresh Fly list: no session names it (no live session's mapping; a machine the router started that no session names any more, such as a destroyed session's left behind by Destroy anyway, counts as an orphan) and it is at least 15 minutes old (a Start's machine exists before the router records it). The router asks the core's `kill` (the call a pause makes; the core alone holds a destroying Fly token). → `{ok, id}`; 409 `{error}` for a session machine or a too-new one; 400 for an unknown id; the core's signed error when the kill fails. |
| `GET /api/records` | Destroyed sessions `{records: [...]}`; each has `archive: {dir, title, transcripts, artifacts, signer, snapshotAt, last}` when it was archived, `archiveError`, `restored: [{sessionId, at}]`. |
| `POST /api/records` | Index an archive ALREADY on the Storage Box, by hand (Jarvis 1's call): `{archiveDir: "claude-records/<folder>", transcripts: [file…], artifacts?, title?, environment? \| stores?, repos?, permissionMode?, model?, size?, harness?, created?, destroyedAt?}` → `{ok, record}` (id `archive-<the first transcript's uuid prefix>`; one already on the list answers that record). The transcripts must exist; nothing is scanned. Such a record has no machine-signed snapshot (`archive.signer` empty), so its tail, Remove and Delete work and Restore is refused (400). |
| `GET /api/records/:id/tail` | The archived conversation's end (a Range read of its newest transcript), same shape as the session tail. |
| `DELETE /api/records/:id` | Off the list and the Storage Box index; `?purge=1` deletes its archive too (the whole dir, or only its own files when another record shares the dir). A record already gone answers `{ok, already: true}`. |
| `POST /api/records/:id/restore` | Body `{requestId?}` → `{id, requestId}`. A NEW session (new line) with the record's options, except the permission mode: bypass, the only start mode (DECISIONS 219); an approval of kind `new-session` with `options.restore` naming the record. Its first machine restores the archived snapshot (below). |
| `POST /api/sessions/:id/auto-pause` | Body `{on}` (Jarvis 1's `{enabled}` works too) → `{ok, autoPause: "on" | "off"}`; restarts the idle countdown. |
| `POST /api/sessions/:id/notify-idle` | Body `{on}` → `{ok, notifyIdle}`: mutes only the idle DM; "needs you", dead and downgrade DMs still come. |
| `GET /api/sessions/:id/remote` | Paseo (opencode, paseo-claude) and OpenClaw sessions only (400 otherwise; 409 unless `started`): `{webUrl, harness, pairUrl, relay}` (opencode, paseo-claude: the Paseo app's pairing link) or `{webUrl /* …#token= */, harness, url /* wss://<id>-s.deyaochen.com */, token}` (openclaw: the gateway token). Read in the machine as holder `remote` (a grant, standing rule or allow-list entry); refused → 403 `{error, needsGrant: "remote"}`; front end not up → 503 `{error}`. Cached 1 min per machine. `webUrl` = `https://<session id>-s.deyaochen.com/` (suffix: router env `SESSION_TUNNEL_SUFFIX`). |
| `GET /api/remotes?harness=openclaw\|opencode\|paseo-claude\|paseo` | Jarvis 1's shape: `{sessions: [{id, title, state, model, harness, + url, token, webUrl (openclaw) \| pairUrl (opencode, paseo-claude), or error (+ needsGrant)}]}`; `paseo` = every session a Paseo daemon fronts (opencode and paseo-claude); secrets only for a started session. Deyao, or a paired app's Access service token ("Paired apps" below). |
| `POST /api/sessions/:id/start` | The paired apps' Start of a paused session (Jarvis 1's call): a resume on the same image, no phone step → 202 `{ok}`. Deyao or a paired app. |
| `POST /api/sessions/:id/permission-mode` | Body `{mode: "auto" | "bypass"}`. Running → 202 `{started, inPlace}`: Jarvis 1's `set-permission-mode` under the `terminal` holder (claude relaunches `--resume` in the new mode; nothing else restarts); a refusal sets `needsGrant: "terminal"`. Raising a running session to bypass needs a fresh phone grant for `terminal`: without one, the iPhone app (its device login) gets 403 `{needsGrant: "terminal", phoneGrant: true}` and opens its own grant review; every other caller (the web page, an approved API call) gets 202 `{waiting: "inbox", inboxId, duplicate, needsGrant, phoneGrant, permissionMode}`: the router files a 10-minute `terminal` grant request in the Inbox as that caller's, keeps the switch as the session's `modeAfterGrant: {mode, inbox, until}` in `/api/state`, and runs it as soon as the phone signs that grant (its `wake` job then shows the outcome; a standing rule answering it switches nothing). An approved API call lists the grant request as its follow-up. Paused or failed with no machine → 200 `{nextStart: true}`. Same mode → `{unchanged: true}`. |
| `POST /api/sessions/:id/account` | Switch the session's Claude account (`router/accountswap.go`, DECISIONS 202). Body `{account /* claude-<name> or <name> */, continue?: bool}` ("Switch" / "Switch and continue"). Running (the claude harness, or Claude Code · Paseo) → 202 `{started, kind: "account", from, to}`: a job shown as the session's `wake` (`kind: "account"`, phases `switching` → `taking the login` → `checking the account` → `Remote Control` → `delivering continue` → `done` \| `failed` with `error`; `error` on a `done` job says what didn't come back, e.g. Remote Control), holding the session's lock. The session's account changes at once and its machine's `/m/claude-login` long poll is answered from the new account (the machine is a participant of the new account from then on). The switch is under the running claude, no restart: the supervisor replaces `~/.claude/.credentials.json` and `~/.claude.json`'s `oauthAccount` under the CLI's refresh lock (claude re-reads the credentials file before its next request), checks the installed token's account with Anthropic's profile endpoint (the status's `__ACCOUNT__`, which the job waits for), and starts Remote Control again (`/remote-control` → Enable; Claude Code stops it when the account changes; the new entry is in the new account's Claude app). Then, with `continue`, "continue" goes into the chat (the canned delivery). Claude Code · Paseo (`paseo-claude`) skips the Remote Control phase: its Claude Code reaches the API only through `api-proxy.js`, which sends the new pair from the next request (a turn in flight goes on under the new account); its "continue" goes in once the agent is idle. Other running harnesses → 409 (pause, switch, resume). A session image from before 2026-10-20 (no `__ACCOUNT__`) restarts its host on the new account instead (phase `restarting Claude`): by itself once idle; after 2 minutes the router kills the host's tmux session under the `terminal` holder (a refusal: `needsGrant: "terminal"`) and the harness relaunches it with `--resume`. Paused or failed → 200 `{ok, nextStart: true, from, to, continue}`: the next start takes the new account, and with `continue` "continue" goes in once its host is up and idle (`ops.continueAfterStart`; a resume onto the newest image keeps it). Same account → `{ok, unchanged: true}`. 400 unknown account, an account with no login, a harness with no Claude account; 409 running another harness or busy. With `CLAUDE_STORE_IN_CERT=1` a running session's switch also files the `add-store` of the new account's store (`addStore`: its approval id), and a paused one is refused (resume it first). Requestable as an API call; its Inbox item carries `does` ("Switch session “T” (id) from Claude account A to B …"). |
| `POST /api/sessions/:id/restart` | Body `{env?, rollback?: {dropFromMarker}, prompt?, size?, model?, apiProxy?, upgrade?}` → 202. Pause (if running) + resume on the same image; `upgrade: true` resumes on the newest session image instead, through its `resume-upgrade` approval (one Face ID; no spare machine is started ahead). `env`: `{NAME: value}` patch kept for later starts (`""`/null removes); names that look like secrets (TOKEN, SECRET, PASSWORD, API_KEY, `_KEY`, `_API`, AUTH, …) or Jarvis's own (`JARVIS*_`, `SESSION_`, `CLAUDE_`, `ANTHROPIC_`, `CF_ACCESS_`, `LOBSTER_`, `FLY_`, `LD_`, PATH, HOME…) → 400: secrets come only from stores. `rollback`: the next machine, after verifying the paused snapshot, drops every conversation-transcript line from the first containing the marker (env `JARVIS2_ROLLBACK` + `JARVIS2_ROLLBACK_PRED` = the paused machine; ignored by any other start). |
| `POST /api/sessions/:id/env` | Jarvis 1's shape `{env}` = a restart with only `env`. |
| `POST /api/sessions/:id/disk` | More disk (`router/disk.go`) → 202 `{started, kind: "disk", fromGb, toGb}`: the core extends the running machine's volume to twice its size (at most 500 GB; core `extend`), the session's `diskGb` becomes the new size (every later machine of the line gets a volume that big), and when Fly says the machine must restart to see it, a pause (its signed snapshot) and a resume. Job `wake: {kind: "disk", phase: extending → snapshotting → resuming → done \| failed}`, `busy: {kind: "growing-disk"}`. A failed session whose machine was kept (its snapshot ran out of space) is extended the same way, without the restart: then Pause again. With no machine (paused, failed) or a machine without a volume → 200 `{ok, kind: "disk", fromGb, toGb, nextStart: true}`: the next machine gets the bigger volume. 409 when busy, at 500 GB, or in another state (approval, pausing, …). |
| `POST /api/sessions/:id/upgrade` | The one tap out of a memory-starvation episode (`router/memory.go`) → 202 `{started, kind: "upgrade", from, to}`. A running session moves to the next size, twice the memory, with no last size (small → medium → large → 16gb → 32gb → 64gb → …; no size = medium; guests and prices: DECISIONS 167): the machine frees memory first (command `free`: the harness SIGSTOPped, every other process of the session user SIGKILLed, their list in `~/artifacts/jarvis2-upgrade-freed.txt`), then the usual pause (its signed snapshot) and resume on the bigger size (no approval: size isn't in the core's Options), then the canned `upgraded` delivery tells the session what was stopped. Job `wake: {kind: "upgrade", phase: freeing → snapshotting → resuming → done \| failed}`, `busy: {kind: "upgrading"}`. A start refused on the bigger size (Fly can't make the guest, or the core doesn't know the size) ends the job `failed` with that error word for word, and the session resumes on its old size. A failed session whose machine was kept is freed, paused and resumed bigger the same way; a paused one (or failed with no machine) → 200 `{ok, kind: "upgrade", from, to, nextStart: true}`: its next start is on the bigger size. 409 when busy or in another state. |
| `GET /api/state` (per session) | `busy: {kind: pausing | starting | destroying | mode | restarting | upgrading, since}` while a lifecycle action holds it (others 409); `wake: {kind, phase, error, startedAt, finishedAt}` for a permission-mode / restart job (kept 10 min after it ends); `apiProxy`, `envKeys`. A running session also carries `memory: {totalMb, availMb, at}` (its latest report, while fresh) and, during a memory-starvation episode, `memAlert: {since, reason, detail, nextSize /* the size Upgrade moves to; null when the running core can't start it (past large needs a core whose /identity says sizeLadder: 1), and then no Upgrade is offered, in the DM either */, nextGb, nextGuest /* "8×performance · 32 GB" */}` (`router/memory.go`: an OOM kill, PSI memory full avg60 ≥ 10 %, MemAvailable < 5 %, or no report for 90 s while under 15 % free; DMed once per episode, ends after 15 min healthy). Likewise `disk: {totalMb, availMb, at, volume /* the volume is the disk shown */, rootTotalMb?, rootAvailMb?}` and, while it has under 10 % or 1 GB free, `diskAlert: {since, reason, detail, canGrow, nextGb? /* what More disk gives */, why? /* why it can't grow */}` (DMed once per episode, ends at 20 % and 2 GB free; `router/disk.go`); `diskGb` (the volume size the next machine gets; 0 = the core's 10 GB). Every session: `noSnapshot` (the line's last machine left no signed snapshot, why: Resume refuses with an error naming the newest signed snapshot, and DMs once), `snapshotFailed` (the final snapshot failed and the machine is kept). Top level: `repos`. |
| `POST /api/uploads` | First-prompt attachments: one raw file per request, headers `x-upload-id` (`[A-Za-z0-9_-]{1,64}`, groups a form's files) and `x-upload-name` (URI-encoded; made a safe basename as in Jarvis 1) → `{name, size, isImage}`. ≤ 20 files, 25 MB each (413). Staged on the router's volume; unbound uploads go after 24 h, bound ones with their session. The app binds only its own uploads (not a session's, `PUT /m/api/sessions/:id/uploads/…`). Each bound file's sha256 and size go into the new line's signed config (`attachments: [{name, sha256, size}]`). |
| `GET /api/sessions/:id/attachments/:name` | The bytes of a file staged for that session (until its first machine has fetched them; 404 after): the app's approval page shows it and hashes it against the signed config. |
| `GET /api/repos` | Deyao's repo list, for Settings → Repos and New session's `repos`: `{repos: [{name, url /* https://github.com/<repo>.git */, repo /* owner/name */, store /* github-<repo> */, sensitive, fingerprint?, keyAt?}]}`. GitHub repos only; an entry is added or removed only by the core's answer to `POST /api/repos/key/finish` (below). |
| `POST /api/repos/key/begin {action: add \| remove, repo: owner/name \| GitHub URL, sensitive?, store, title, publicKey?, keys?}` | Relayed to the core's `deploy-keys/begin` (the repo normalised to `owner/name`; the app's store, title and key pair as sent): its signed begin document, which the shell's secure page checks and the phone answers. 400 for a non-GitHub repo or another action; 501 `{error}` from a core older than deploy keys. |
| `POST /api/repos/key/finish {pending, signature, share}` | Relayed to `deploy-keys/finish`; on the core's signed `deploy-key-added` the repo goes on the list (with `sensitive`, and `fingerprint` = SHA256 of the answer's `publicKey`, or the answer's own `fingerprint` from a core before R2), on `deploy-key-removed` it comes off. The answer is the core's, unchanged; `?inbox=ID` (the request the page answers): when sessions asked for this repo (`repo/add` from a session), each running one that doesn't hold `github-<repo>` gets an add-store approval at once, and the one for that request comes back beside the core's document as `{payload, sig, followups: [approvalId]}`, for the phone to check and sign under the same Face ID (DECISIONS 182). |
| `GET /api/github/repos` | `{repos: [{fullName, url, htmlUrl, private, fork, archived, description, language, pushedAt, owner}], cachedAt, configured}` (5 min cache, `?refresh=1`), listed with `GITHUB_READ_TOKEN` (router env; Metadata read picked explicitly, else GitHub lists public repos only — sessions push with their repos' deploy keys). 503 without it. |
| `GET /api/usage` | The default Claude account's quota (each account's: `GET /api/claude-accounts/{store}/usage`), read by the router with its stored access token (Jarvis 1's shape, `router/claudelogin.go`): `{fetchedAt, limits: [{kind, group, percent, severity, resetsAt, model, surface, active}], extraUsage: {enabled, monthlyLimit, usedCredits, utilization, currency, decimalPlaces, disabledReason, spendLimitReached} \| null, cached, stale?, error?}`; cached a minute (`?refresh=1` skips it); a failed fetch answers the last good reading with `stale`; 409 `{error, needLogin}` when Claude refuses the token. |
| `GET /api/claude-login` | The default Claude account's login ("Claude accounts" below), no secrets: `{hasLogin, expiresAt, expired, email, accountUuid, source, updatedAt, refreshedAt, participants: [{id, seen}], loginInProgress, preparing, error?, rejected?, needLogin?}` (below, "Claude accounts"). |
| `POST /api/claude-login/refresh` | Refresh now → `{ok, refreshed, expiresAt}`; 409 (no login stored) / 502 `{error, needLogin}`. |
| `POST /api/claude-login/start` | Re-login, step 1 → `{url}`: the CLI's sign-in page (claude.com/cai/oauth/authorize, PKCE, the manual redirect). The verifier is kept on the router's volume for 15 minutes, so a rollout doesn't lose it. |
| `POST /api/claude-login/code` | Re-login, step 2: `{code}` = the `code#state` the sign-in page shows → the CLI's token exchange and profile → stored into the default account (its own Claude account only, once it has one) → `{ok, email, expiresAt}`; sessions stuck on "Please run /login" get "continue" on the next tick. In mode `follow` the new pair also goes to Jarvis 1. |
| `GET /api/search`, `/api/search/context`, `/api/search/status`, `POST /api/search/reindex`; `GET /api/icloud/search`, `/api/icloud/file`, `/api/icloud/status`; `POST /api/icloud/relist`, `/api/icloud/retry` | The app's Search tab: forwarded to the box's own services (`router/searchsvc.go`; "Transcript search" and "iCloud index" below) with the query and body unchanged. 502 `{error: "… unreachable: …"}` when the service is down. |

### Archives (Storage Box, router env `STORAGEBOX_HOST/USER/PASSWORD`)

`claude-records/<yyyy-mm-dd> <title>/` (Jarvis 1's layout; ` 2`, ` 3`… when taken): `transcript-<id>.jsonl`, `artifacts/**`,
`session.json`, `restore-<session id>.json`, and `jarvis2/snapshot.tar.gz` + `snapshot.sig` (the machine's signature over the
sha256 hex) + `cert.json` (the signer's core-signed cert) + `core-cert.json` (the master-signed claim naming the core's key). Index:
`claude-records/.index/jarvis2-destroyed-sessions.json` (newest first). The destroy also writes `jarvis2/supervisor-log.jsonl` (the session's supervisor log, as the machines pushed it) and `jarvis2/lifecycle.json` (every operation with its merged log, oldest first, the destroy's own so far), then drops both from the router's volume. `RECORDS_OFF=1` (the e2e test) destroys without archiving.
While a session runs, its transcripts are also copied to `claude-records/.live/<session id>/<uuid>.jsonl` (`POST /m/live-transcript`
above). A destroy's archive first copies every live transcript the snapshot doesn't hold byte-identical into the record
(`transcript-<uuid>.jsonl`, or `transcript-<uuid>.live.jsonl` when the snapshot has another version; each read back and checked
by size and sha256), and a session with no snapshot but live copies gets a record of those alone (`session.json`
`snapshot: null` and `noSnapshot`, nothing to restore). Only then are the live copies the record holds deleted; any other (a
failed archive, even with `?force=1`; a file that came or changed since) stays, and the record says so (`liveKept`). The
record's `archive.live: [{name, size, sha256, in /* "snapshot" or the archive file */}]` lists them, `archive.noSnapshot` why
there is no snapshot or why it isn't the last machine's (a destroy never DMs about a missing snapshot: it isn't a resume;
`router/livearchive.go`).

Restore trust: the router passes the old cert to the new line's first machine in `JARVIS2_RESTORE_CERT`; the machine accepts
it only with no predecessor, checks it against the core key, the snapshot (`GET /m/restore-snapshot`) against the cert's
machine key, and refuses a sensitive line's snapshot into a line without a sensitive store. Which snapshot is restored is the
router's word, not the phone's (the core's options can't carry it).

### Jarvis 1 import (`router/jarvis1import.go`, `machine/jarvis1import.go`)

A paused Jarvis 1 session (`claude-records/.paused/<id>/` on the Storage Box: `<uuid>.jsonl`, `claude.json`,
`workspace.tar.gz`, `artifacts.tar.gz`, `harness.tar.gz`, `session.json`, `manifest.txt` written last) becomes a NEW
line, approved on the phone like a new session, whose first machine restores it and resumes the same conversation.

| Call | Does |
|---|---|
| `GET /api/jarvis1/paused` (`/setup/…` too) | `{sessions: [{id, title, pausedAt, size, model, environment, repos, prepare?, sha256?, sessions: [{id, state}], imported?}]}` from Jarvis 1's index `claude-records/.index/paused-sessions.json`, with each one's import state here. |
| `GET /api/jarvis1/paused/{id}` | That one's state: `prepare {state preparing\|ready\|failed, file, bytesDone, bytesTotal, error, sha256}`, `sha256` (the prepared manifest's), the Jarvis 4 sessions made from it, `imported {session, at}` once one came up. |
| `POST /api/jarvis1/paused/{id}/prepare` | 202: the router streams every file once (the names above; `changes.txt` and `artifacts-manifest.txt` are not taken) and hashes it, then writes the import manifest `{kind: "jarvis1-import", v: 1, session, files: [{name, sha256, size}]}` and Jarvis 1's record onto its volume (`jarvis1-imports/<id>/`). Refused without `manifest.txt` (an incomplete snapshot). |
| `POST /api/jarvis1/paused/{id}/import` | Body `{stores?: [...], explanation, prompt?, size?}` (the harness's stores come with it, so `stores` may be empty; `explanation` required from the setup session) → `{id, from, approval: true}`: a new session in `approval` (Inbox kind `new-session`, `options.restore` = "Jarvis 1 session “title” (id, paused date)"). Its cert's config: `label` = Jarvis 1's app title, `prompt` = a move notice typed into the resumed conversation (or the given one), Jarvis 1's model, repos, auto-pause, permission mode bypass (the only start mode, whatever Jarvis 1 ran in); `size` Jarvis 1's (`xlarge` → `large`); `restore = {machine: <Jarvis 1 id>, sha256: <the manifest's sha256>}`. The same import again answers the same session (`createRequestId` `jarvis1-import:<id>:<sha prefix>`). A session nobody prepared is prepared first (the call waits for it, up to 10 min). |

The machine (only the line's first, only when its cert names the restore) fetches the manifest (`GET /m/restore-snapshot`),
checks its sha256 against the cert, then each file (`GET /m/import-file/{name}`, streamed from the Storage Box: the machine
holds no Storage Box credential) against the manifest's sha256 and size, extracting tarballs into a staging dir while
hashing and moving them into place only once they match (entries outside `workspace/`, `artifacts/` or the harness roots, or
through a symlink, are skipped). The transcripts go to `~/.claude/projects/<slug of the working dir>/` after the repos are
cloned, `~/.claude.json` without `oauthAccount`/`userID`, GitHub remotes without embedded credentials (ending in `.git`, so
the deploy-key rewrites apply). Jarvis 1's armed wakeups and crons (`metadata.wake_*`, `cron_*`) are armed again as the
line's own signed requests: a passed wakeup 5 minutes after boot; a cron with its period, time zone and end, next run after
now, plus a one-off wakeup `missed-<name>` 5 minutes after boot when a run fell while paused. What was armed:
`~/artifacts/jarvis1-import/rearmed.txt` (beside Jarvis 1's `session.json`).

## The kernel (`kernel/`, `router/kernel.go`, `router/kernelline.go`; DESIGN "Target design", docs/PLAN-grants.md)

The kernel runs beside the old core with keys of its own (DECISIONS 216): eight components at `KERNEL_URL`
(`%s` = the role: notary, notarizer, mover, merger, spawner, identity, gullible, secrets; unset = no kernel on this
box). A session is a kernel line when its record has `kernel` (its source, the cert into it and its notarization, the
main grant, and while a machine runs the spawner's cert naming it); every lifecycle of it goes through the kernel.
New sessions start on the kernel once it is configured and the root's grant is in (`kernelServes`).

| Route | |
|---|---|
| `GET /api/kernel` | `{configured, serves, root, roster}`; `roster`: `{state: none\|pending\|current\|stale, rootKey, pending, copy, id, at, results, stale: ["roster stale: component X restarted (…)"]}` |
| `POST /api/kernel/root-key` | `{rootKey}` (base64 X9.63): the app's root key, kept until the setup session commits it (`keys/root.pub`, `k8s/cluster/kernel/root.pub`) |
| `GET /setup/kernel/root-key` | `{rootKey}`, setup-signed (`infra/setup.py kernel-root-key`) |
| `POST /setup/kernel/roster` | `{copy, payload, setupSig}`, setup-signed: `payload` exactly `sig.RosterPayload` of the 8 roles, `setupSig` the setup key's over it; kept as pending (`infra/setup.py kernel-roster`) |
| `GET /setup/kernel/roster` | `{current, secretsServing, status}`, setup-signed |
| `GET /api/kernel/roster/pending` | `{copy, payload, setupSig, at}`: what the app checks against `keys/setup.pub` and the root key signs |
| `POST /api/kernel/roster` | `{payload, rootSig}`: checked against the registered root key, posted as `{"roster": {payload, sig}}` to all 9 Deployments (notary, notarizer, mover, merger, spawner, identity, gullible, secrets-blue, secrets-green) → `{id, results}` (per Deployment `taken`, `standby, not named: …` for the next secrets, `refused: …`, `unreachable: …`); kept as current |
| `GET /api/kernel/roster` | the current `{copy, payload, sig, at, results, status}`; a component that answers it has no roster (a restart) gets it again, and refuses it (new keys): the roster is stale until a new one is signed (one DM) |
| `GET /api/kernel/root-grant/draft` | `{payload}`: ⊤ on the sink with the sink's (hash-to-curve) keys: what the root key signs once |
| `POST /api/kernel/root-grant` | `{grant: {payload, sig}}`: checked against the root key secrets names (`/keys`), then kept (`kernelRoot`) |
| `GET\|POST /api/kernel/secrets/{path}` | secrets' own API relayed as is (`identity`, `claim`, `store-key`, `stores`, `unlock/begin`, `unlock/finish`, `lock`, `unlocked`, `keys`, `wipe`, versions, restore, deploy keys): every answer is signed by secrets |
| `POST /setup/kernel/secrets/flip` | blue/green: the serving secrets hands off, the next (Recovered alongside with `?secrets=next`) takes over → `{serving}` |
| `GET /api/kernel/spawner/identity`, `POST /api/kernel/spawner/fly-token` | the app's Recover: the spawner's identity (the roster names its keys), and the Fly token from the core store's backup sealed to it |
| `GET /setup/kernel/spawner/identity`, `POST /setup/kernel/spawner/fly-token` | the setup session: the spawner's identity (checked against the root key's current roster), and the Fly token sealed to it (`infra/setup.py kernel-fly-token`) |
| `GET /m/kernel/boot` | a kernel machine's documents: `{grant, machineCert, machineNotarized, sourceCert, sourceNotarized, notary, notarizer, mover, merger, spawner, secrets (identities), keys (secrets' keys statement), stores (secrets' signed store list)}` (machine/kernelboot.go checks them) |
| `POST /m/kernel/downgrade` | `{keep: [stores]}`: the identity signer narrows the machine's grant (`jarvis2 downgrade` on a kernel machine) |
| `POST /m/pull-secrets` (kernel machine) | secrets' `/pull` with the line's grant: `{kind: secrets, machine: fly-<id>, grant, stores, versions, stale, sealed}`, signed by secrets |
| `GET /m/snapshot` (kernel machine) | the snapshot of the machine its source came from, or (a restoring line's first machine) the archived snapshot |

Approvals: `kernel-source` (a new source: a new session, a restore, a resume on another image): `challenge.payload` is
the cert (sink → source-x) the phone signs, the answer `{signature}`; `kernel-add-store`: two certs, `challenge` (sink
→ source-a, the one store) and `earlier[0]` (source-a → fly-M, ⊤), the answer `{signature}` = both signatures, one per
line. A delivered input (wakeup, cron, watch, outcome, content, attachment) to a kernel machine carries the log
notary's challenge (`about: input`) over sha256("jarvis2-input\n" + fly-M + "\n" + kind + "\n" + the input's sha256)
instead of the core's attestation.

## Approvals (the shell's secure pages)

```
approval = { id, kind: "new-session" | "resume-upgrade" | "add-store", created, session, machine /* add-store */,
             label, challenge /* the core-signed challenge doc */, options /* the form's fields, for display */,
             origin: {caller, call} /* who asked, from the credential (Requests) */, explanation /* a session's add-store */ }
```

| Call | Does |
|---|---|
| `GET /api/approvals` | `{approvals: [...]}` |
| `POST /api/approvals/:id/respond` | Body `{signature}` = base64 DER signature by the phone's signing key over **exactly** `challenge.payload`. Router → core `approve/by-phone` (for `add-store` with the machine's newest cert as `current`, and its carry). Answers `{answer, session}`: a core-signed `approval` (then the router starts and certifies the machine) or, for `add-store`, the new `succession-cert`: the machine's newest cert plus the store, so add-stores answered in any order all stay (DESIGN "A machine succeeding itself"). An answer that would lose a store the session holds (a core from before 2026-10-13) isn't stored: the approval is filed again from the newest cert and the respond fails with "approve it again". |
| `POST /api/approvals/:id/reject` | Drops it; a new session disappears, a resume-upgrade stays paused. |

The phone may approve anything; it shows exactly what it signs (`request.stores`, `request.sensitive`,
`request.options`, `request.image`, `request.addedStore`).

## Requests (the app's Inbox, `router/inbox.go`)

A request asks the phone for something that needs Face ID; it waits in the app's Inbox until Deyao reviews it on the
shell's secure page (docs/DESIGN.md "Requests"). The **intent endpoints** are the same under three prefixes, one per
kind of caller; the router records the caller from the credential (never from the body) and the call:

| Prefix | Caller | Credential |
|---|---|---|
| `/api/requests/…` | the web page, or the app (`cf-access-token` header) | Deyao's Access login |
| `/setup/requests/…` | Claude, the setup session | the setup key's signature (as every `/setup` call) |
| `/m/api/requests/…` | a session (`$JARVIS_URL/api/requests/…` through the machine's proxy; `jarvis2-request` in the image) | the machine key |

| Intent | Body (`explanation` in every one) | Who |
|---|---|---|
| `POST …/repo/add` | `{repo /* owner/name or a GitHub URL */, sensitive?, noStore?}`; from a session (its requests or actions) the request names that session (`params.session`, `open.options.into`/`intoLabel`/`store`), which gets the repo's store in the same approval; `noStore: true` only makes the key | anyone |
| `POST …/repo/remove` | `{repo}` | anyone |
| `POST …/grant` | `{session, holder, minutes /* 1–10, default 10 */}` or `{session, holder, days /* 1–365: a standing rule */}` | anyone, for any session (a session may leave `session` out: itself) |
| `POST …/unlock` | `{session}`: the locked stores that session waits on | anyone, for any session (a session may leave `session` out) |
| `POST …/restore` | `{store, seq}`: put version `seq` of a store back (below, "Store versions and restore"); opens the app's restore review | anyone; in a batch it is filed as a request of its own beside it (`own: true`) |
| `POST /m/api/requests/add-store` | `{store}` → the router's `add-store` approval (as `POST /m/add-store`) | a session, for itself |
| `PUT /m/api/sessions/:id/uploads/:upload/:name` | A session stages one file for a new session it will propose (`jarvis2-request new-session --attach FILE`): the raw bytes as the body, the upload id (`[A-Za-z0-9_-]{1,64}`, one per proposal) and the URI-encoded name in the path (made a safe basename) → `{name, size, isImage}`. The same limits as `POST /api/uploads` (≤ 20 files, 25 MB each, 413; unbound uploads go after 24 h, and with their session). The upload is the session's own: no other session or the app can add to it or bind it; a session holds at most 5 uploads no proposal uses yet (400); once a proposal binds it, it takes no more files. | a session |
| `POST /m/api/sessions` | `POST /api/sessions`'s body plus `explanation` (required); `attachments` (`{uploadId, files: [{name}]}`) names this session's own upload (above) and then goes exactly as the app's: each file's sha256 and size in the new line's signed config, the approval's `options.attachments` ("N file(s)") and its origin's `args.attachments` (the names), the bytes readable at `GET /api/sessions/:id/attachments/:name` for the approval page, fetched and checked by the new session's first machine (`GET /m/attachments`) → `{id, requestId, approval: true}`: a session PROPOSES a new session (`jarvis2-request new-session`). The same line and `new-session` approval as the app's New session (a succession from null, so it starts only on Deyao's Face ID); the approval's caller is the proposing session and it carries the explanation. `requestId` is scoped to the proposing session; at most 3 proposals wait per session (429). | a session |

`explanation`: the caller's reason, required from a session and the setup session (plain text; control and format
characters dropped; ≤ 600 characters, ≤ 8 lines; 400 otherwise). Answer `{id, duplicate, expires}`: the same kind and
arguments already pending answer that request (`duplicate: true`); 400 for bad arguments; at most 20 pending per caller (429: wait, or deny some). Every caller may ask every kind, for
any session (each waits for Deyao, and a session's actions could already ask them all). A request goes after 10 minutes, when its session is destroyed, when it is done
(a repo request when the core's deploy-key answer for that repo comes back by any path; a grant request when a grant
for that feature is stored), or on Deny.

```
item = { id, kind: "repo-key" | "grant" | "unlock" | "restore" | "peer-message" | "new-session" | "resume-upgrade" | "add-store", approval /* bool */,
         batch /* the batch it was filed in, if any */,
         params: {action, repo, sensitive, session, holder, minutes, days, store, seq}, session, sessionName,
         caller: {kind: "web" | "app" | "session" | "setup" | "router", session}, callerText /* "session “X” (s…)",
         "Deyao, from the web page", "Deyao, from the Jarvis 4 app", "Claude (setup session)" */, call: {method, path, args},
         explanation, created, expires, options /* an approval's form fields */,
         viaCall /* an approval an approved api-call brought about: that request's id */,
         does /* an api-call's effect in words where its path doesn't say it (an account switch: session, from → to) */,
         open: {kind /* the shell page, "api-call" for a call */, options /* its options, with inboxId */} }
```

| Call | Does |
|---|---|
| `GET /api/requests` | `{requests: [item]}`, newest first; also `inbox` in `GET /api/state` (the badge) |
| `GET /api/requests/:id` | one item (404 when answered, denied or expired); the shell reads the call and the reason here |
| `DELETE /api/requests/:id` | Deny: dropped (an approval is rejected, as `…/approvals/:id/reject`); one already gone answers 200 `{ok, gone: true}` |
| `POST /api/requests/:id/done` | the shell's page went through: the request leaves the Inbox |
| `POST /api/requests/:id/approve` | an `api-call` request (below, "Actions"): the router runs the call now as Deyao and keeps its outcome → `{ok, state: done \| failed, status, error, followups, awaiting}` (as below); 404 when gone. No Face ID: a step that needs the core's signature asks for its own afterwards, as a follow-up |
| `GET /api/requests/calls/:id` | an approved call's follow-ups → `{id, state: running \| done \| failed, status, error, followups: [{id, open, item /* the Inbox item while open */}], awaiting: {session, until} \| null}`; 404 when unknown or over 10 min old. A follow-up is an approval whose origin is the call (`viaCall`): a resume call's `resume-upgrade`, a `POST /api/sessions` call's `new-session`, a restore's. `awaiting`: the call started work that may still file one (a resume asking the core); it clears when one is filed or the work ends without one, and lapses at `until` (1 min). The review sheet (app and web page) shows these and waits on exactly this |
| `GET /setup/requests`, `GET /m/api/requests` | the same list for Claude; a session sees only its own |
| `GET /setup/repos` | the router's repo list (`infra/setup.py repos`) |
| `GET /setup/sessions` | `{sessions: [{id, machineId, state, title, image, stores, …}]}` (`infra/setup.py sessions`; the phone replica finds a session's machine here) |

### Batches (`router/batches.go`)

A caller files several items at once with one **summary** (its words, unverified, shown above the items); the Inbox
lists the batch as one entry and the phone allows every item under ONE Face ID, each signed and sent exactly as alone
(nothing new for the core to verify), or Deny drops them all.

| Call | Does |
|---|---|
| `POST …/requests/batch` (`/api`, `/setup`, `/m/api`, `/m/api/actions`) | Body `{summary /* required, as explanation */, items: [{intent, …that intent's body…, explanation?}]}`; intents: `repo/add`, `repo/remove`, `grant`, `unlock` (as above), `add-store` (`{store, session?}`; a session for itself unless it names another; the session must have a running machine with a cert: started, or initialising on a locked store), `new-session` (`POST /m/api/sessions`'s body, `attachments` included; two items can't bind the same upload), `jarvis1-import` (`{id, stores, size?, prompt?}`; setup session and Deyao only), `call` (`{method, path, body? | bodyText?, contentType?}`, as `POST /m/api/actions/requests/call`; any caller: an `api-call` request in the batch, approved with `POST /api/requests/:id/approve`, its result read at `GET /m/api/actions/requests/call/:id`; DECISIONS 183), `peer` (`{to, text}`, as `POST /m/api/requests/peer`, "Peer messages" below; a session only, 403 otherwise: an **upward** message is a `peer-message` request in the batch, its item `{intent, id, direction: "upward", to}`, delivered once approved with `POST /api/requests/:id/approve`; an **equal** or **downward** one is delivered at once when the batch is filed and waits for nothing, its item `{intent, direction, to, delivering: true}`; a batch of only those answers 200 with no `id`). 1–20 items. Every item is checked first, as its own endpoint checks it: one bad item (400/403, `item` = its index) or the same item twice and nothing is filed. → `{id: "b…", expires, items: [{intent, id?, session?, duplicate?, batch?, error?}]}`: an item that fails while being filed (the core refused its challenge) carries `error` and the rest stand. A request already waiting outside any batch joins this one (`duplicate`); one in another batch stays there (`batch`). Limits: a batch counts once toward the caller's 20 waiting requests and, when it proposes a session, once toward the 3 waiting proposals (429). |
| `GET /api/requests/batches/:id` (`/setup/…`; `/m/api/…` its own) | `{batch, items: [item]}`; 404 when gone |
| `DELETE /api/requests/batches/:id`, `POST /m/api/actions/requests/batches/:id/deny` | Deny all: its requests leave, its approvals are rejected (an approval still being made is rejected as it arrives); one already gone answers 200 `{ok, gone: true}` |

```
batch = { id, summary, caller, callerText, call: {method, path, args: {items}}, created, expires, items: [inbox ids, as filed],
          preparing /* approvals still being made: a new session's challenge; the phone waits for them */ }
```

`GET …/requests` and `GET /api/state` (`inboxBatches`) list the batches; each item carries `batch` and the batch's
`expires`. The whole batch goes 10 minutes after it was filed. An item can still be allowed or denied on its own (it
leaves the batch); a batch with nothing left goes. The app's batch page signs the items in order after the one Face ID
and shows each one's result; one that failed (the others went through and left the Inbox) is read again and signed on
Retry, with another Face ID.

### Outcomes (`router/outcomes.go`, `machine/outcomes.go`)

When an item a **session** filed (through `/m/api/requests/…`, `/m/api/sessions`, `/m/api/requests/batch` or the
`/m/api/actions/…` equivalents, incl. `requests/call`) is decided, the router tells that session with a delivery
(`/m/commands`, kind `request-outcome`, as wakeups and lease wakes are delivered). The outcome is one word:
`approved`, `denied` (Deny, Deny all, the actions' deny), `lapsed` (10 minutes without an answer), `dropped` (it left
without a decision: the session paused with an API call pending, the session it was about went away, an add-store
whose machine is gone) or `failed` (an approved API call that couldn't run). The delivery carries the session's own
signed filing, and per item `{item /* index in a batch, 0 otherwise */, outcome, ref /* the Inbox id; for add-store the
session's id; for new-session the new session's id */, status? /* an approved API call's HTTP status */, proof?}`. The
machine builds the text from its own filing and image texts, and checks the proof of an approval: the phone-signed
grant (grant), the machine's new core-signed cert naming the store (add-store), the core's approval by the phone with
the proposal's label and prompt (new-session), the core's signed key answer (repo add/remove); unlock and API calls
carry none and say they are Jarvis's report. A batch's items go together, once every item is decided or 30 s after the
last decision. A paused session is not started for it: the outcomes wait and go in at its next start; a destroyed
session's go with it. The core attests each delivery over `{request: <filing sig>, items: [{item, outcome, ref, status,
proof: sha256(payload "\n" sig)}]}` (origin `session-signed:<machine>`).

| Call | Does |
|---|---|
| `GET /m/api/requests/outcomes` | this session's recorded outcomes, newest first: `{outcomes: [{ref, batch?, item, kind, outcome, status?, at, delivered?, error?}]}` (`jarvis2-request outcomes`, `jarvis2-request wait ID`) |

The app never takes the title from the router: the list renders it from `kind` + `params` (`src/lib/inbox.ts`), and
the review page renders "What you sign (exact)" from the signed content (`Shell/SignedAction.swift`). The shell checks
that the item's `open.options` equal its own page's (repo, action, session, feature, length) and says so when not.

## The core, relayed (`/api/core/*`)

When the core can't be reached at all (its pod restarting, e.g. after a wipe) every one of these answers 503
`{error: "the core isn't running", coreDown: true}`; the app waits or shows it as a plain note.
Pass-through to the core's own endpoints, answers unchanged (signed): `GET identity`, `POST stores {nonce}`,
`POST stores/create {name}`, `POST stores/mark-sensitive {name}`, `POST unlock/begin
{store, for?}`, `POST unlock/finish {pending, shares}` (an unlock for one running session's cert also makes its machine
pull again: `refresh-secrets`), `POST lock {id}`, `POST unlocked {nonce}`, `POST store-key {phone, core?}`, `GET line-state` (the router's own copy, below), and
— from any of Deyao's logins (both are master-signed and checked by the core) — `POST claim {statement,
masterSig, bundle}` and `POST wipe {statement, masterSig}`. Formats: `docs/DESIGN.md`, `core/core.go`, the app's
`Shell/CoreSetup.swift`, and the reference client `e2e/main.go`. A claim the core accepts is kept by the router
(`DATA_DIR/core-certs.json`, the newest 10): the master-signed statement naming the core verifies on its own, so the
core keeps no copy; the router serves the running core's at `GET /setup/core-cert` and into each archive.

Setting the core up (Reset and Recover, the app's Reset or recover page):

- `GET identity` → `{signingKey, agreementKey, boxSig, state}`: `boxSig` = the box key's signature over
  `"jarvis2-core-identity <signingKey> <agreementKey>"` (checked against `keys/box.pub` from GitHub); `state` = a
  core-signed doc `{"kind":"core-state","master": <the master public key it was set up with, "" while empty>,
  "phone": {signingKey, agreementKey} | null}`.
- `claim`: `statement` = the JSON text `{"kind":"claim","master","core":{signingKey,agreementKey},"phone":{…},
  "bundleSha256"}`, `masterSig` = that master key's base64 DER ECDSA over it, `bundle` = `{"format":"keys",
  stores: [names], keys: [{store, key, wrapped: {e, wrapped}, data}], notSensitive: [names], owners: {store:
  "owner/name"}, flyToken}` sealed to the
  core's agreement key (ephemeral P-256, HKDF-SHA256 info `"jarvis2/claim"`, AES-256-GCM combined) → the core's
  signed `{"kind":"claimed","stores": n}`; 409 when the core is set up already, 400 "bad bundle" for any other bundle
  (any other `format` among them). Each key is wrapped by the app itself to the store key (`store-key`, below; the
  data under its own data key, `"<store>\n<key>"` as associated data), so the core never sees a store's plaintext; `owners` names each deploy-key store's
  repo (the app reads it from the store's `GITHUB_DEPLOY_REPO_*`); `flyToken` is the `core` store's `FLY_API_TOKEN`,
  which never becomes a store. Reset sends no stores; Recover every store from the backups.
- `wipe`: `statement` = `{"kind":"wipe","core": <the core's signing key>}`, signed by the master key the core was
  set up with → the core's signed `{"kind":"wiping","core"}`, then it exits; a new, empty core follows.

Core continuity (`core/continuity.go`, `router/linestate.go`; DESIGN "Core continuity"):

- `GET identity` also says `continuity: 1` (the core takes a seed and a line state in its claim bundle), and its
  signed state carries `lineSeq` (the newest line state's number, 0 for none), `derived` (its keys come from the master
  key's seed) and `serving` (`serving` | `standby` | `handed-off`).
- `claim` with continuity: the bundle (format `keys`) adds `coreSeed` = base64 of HKDF-SHA256(the master private
  scalar, no salt, info `"jarvis2/core-seed"`, 32 bytes) and optionally `lineState` = `{head, sealed}` as the router
  serves it; the statement adds `identity: {signingKey, agreementKey}` = the public keys the seed derives (each key's
  scalar = HKDF-SHA256(seed, no salt, info `"jarvis2/core/signing"` | `"…/agreement"`, 32 bytes), with `/1`, `/2`, … appended to
  the info until it is a valid P-256 scalar; carry, nonce and line-state keys = HKDF with info `"jarvis2/core/carry"` |
  `"…/nonce"` | `"…/line-state"`) and optionally `standby: true`. The core refuses (403) a claim whose identity isn't
  what its seed derives, and (400) an identity, line state or standby without a seed. From the claim on, the core
  signs and agrees with the derived keys (its identity and box signature change to them); its answer adds `derived`,
  `standby`, and with a line state `lineSeq` and `repoStores` (the deploy-key stores it took back). Each key of the
  bundle is wrapped to P + K for the DERIVED K: `POST store-key {phone, core}` (below).
- `GET /line-state` (the core's; relayed to the app as `GET /api/core/line-state`) → `{head, sealed}`: `head` = the
  core-signed `{"kind":"line-state-head", seq, final?, sha256 /* of base64-decoded sealed */, at}`, `sealed` = base64
  of a 12-byte nonce ‖ AES-256-GCM (line-state key, associated data `"jarvis2/line-state"`) of the line state (newest
  cert per machine, the machines created and initialised with their signing keys, killed, used, spent approvals, the
  input log's head and length, every store as the core holds it wrapped to P + K, the deploy-key stores' repos, the
  stores that aren't sensitive, the phone key they are wrapped for). 404 on a core without derived keys, 409 on one
  standing by. Every answer of a core with derived keys carries `X-Line-Seq: n`; the router fetches `/line-state`
  whenever `n` isn't the one it keeps, before it passes the answer on, and keeps it at `DATA_DIR/line-state.json` and,
  at most every 5 minutes and at its drain, in the backup bucket as `keys/_jarvis2/line-state.json` (left out of
  `GET /api/backups`). `GET /api/core/line-state` serves the kept one (`X-Line-Seq` names it), the bucket's when the
  volume has none; 404 when there is none.
- Blue/green (at most one core with these keys serves): `POST /handoff` (the core's; the router calls it, no body) →
  the FINAL line state `{head, sealed}` (`head.final: true`); from then on that core answers 409 "this core is
  handed-off" to everything but `GET identity`, `GET line-state` and `POST handoff` (the same final state again). A core
  claimed with `standby: true` answers 409 "this core is standby" to everything but `GET identity`, `POST store-key`,
  `POST wipe` and `POST /takeover {lineState: {head, sealed}}` → the core's signed `{"kind":"took-over", lineSeq,
  stores}`: only a FINAL state sealed by the same keys whose seq is at least the one the standby was claimed with
  (403 otherwise); it takes the lines and every store from it and serves. A claim whose `lineState` is already final
  serves at once from it (the old core handed off before the Recover). A kill of a machine the core doesn't know (an
  earlier core's) names no snapshot instead of refusing it, unless it comes with `legacy`.
- Taking over an earlier core's line (`core/legacy.go`): `POST /kill {machine, snapshot, legacy: {cert, coreCert:
  {statement, masterSig}}}` for a machine this core doesn't know: the claim signed by this core's master key, naming
  (as `core` or `identity`) the key that signed `cert`, a succession cert for that machine; `snapshot` signed by the
  cert's machine key (409 without one). The answer is the usual `killed` record plus `adopted` = the same cert signed by
  this core (also on a repeated kill). The router sends `legacy` for every machine whose cert the running key didn't
  sign and a kept claim names, replaces the session's cert with `adopted`, and marks the session `carryLost` (in
  `/api/state`) until its first pull goes through. Fly answering 404 for a machine counts as destroyed.
- `POST store-key {phone, core?}`: with `core` (an agreement public key, X9.63 base64) the answer is P + that point and
  names it (`core`); what a Recover wraps to before the claim gives the core its derived K.

## Store versions and restore (`core/history.go`, `router/storerestore.go`)

DESIGN "Restoring a store". A core from before stores kept versions answers 404.

- `POST /api/core/stores/versions {store, nonce}` (relayed; `/setup/stores/versions` the same) → the core's signed
  `{"kind":"store-versions", nonce, store, current /* the store's version now */, sensitive, versions: [{seq, at,
  version, cause: {kind: recover | created | write | delete | deploy-key | restore, key?, writer? {by, machine?, line?},
  from? /* restore: the version put back */}, keys: [{name, e, dataSha256, backupSha256?, at, writer}]}]}`, newest
  first, at most 50. 404 for a store that doesn't exist.
- `POST /api/core/stores/restore/begin {store, seq}` (relayed) → the core's signed `{"kind":"store-restore-begin",
  pending, store, sensitive, from: {seq, version}, to: {seq, version, at}, put: [{key, e, dataSha256, backupSha256, at,
  writer /* with a setup writer's sig */}], remove: [names], keep: [names], t}`. 404: no such store or version; 403: a
  repo's deploy-key store; 409: the store already is that version. A begin lapses after 10 min.
- `POST /api/stores/restore/finish {pending, signature, shares: {KEY: share}}` (the app, after Face ID): `signature` =
  the phone's base64 DER ECDSA over the begin's payload; one share per key in `put`, each the phone's x(p·E) sealed to
  `t` as an unlock's share. The router passes it to the core's `/stores/restore/finish` (403 another signature, 409 the
  store moved on, 400 a missing share; the begin is spent either way), writes the core's backups to the bucket
  (`keys/<store>/<key>.json`, below) and only then `/stores/restore/commit {pending}` → `{ok, restored /* the core's
  signed {"kind":"store-restored", pending, store, from, seq, version, keys, put, remove} */, refreshAsked: [session
  ids]}`. A backup the router can't write: nothing is committed (502). Every running session holding the store gets
  an unlock request (as after a key write), and a pending `restore` request for the store leaves the Inbox.

## Backups (`/api/backups`)

`GET /api/backups` → `{bucket, objects: [{key, body}]}`: every object under `stores/` and `sensitive/` in the
versioned bucket `jarvis2-backup-de0ch`, `body` its text unchanged — `stores/<name>.json` = `{doc, sig}` with `doc`
= `{"kind":"store-backup","name","sensitive","sealed":{e,data},"at"}` (the values sealed to the master key, HKDF info
`"jarvis2/backup"`, the store's name as associated data) and `sig` the setup key's ECDSA over `doc`;
`sensitive/<name>.json` = a signed `{"kind":"store-sensitive","name","at"}` marker. The router reads them with its
own read credential (router env `BACKUP_READ_ACCESS_KEY/SECRET_KEY`; `BACKUP_ENDPOINT`, `BACKUP_REGION`,
`BACKUP_BUCKET` default to the production bucket) and answers 503 without it, 502 when the bucket refuses. The app
checks each `sig` against `keys/setup.pub` (from GitHub) and opens each backup with the master key from the kit. A key
backup a restore wrote (`keys/<store>/<key>.json` with `writer: {by: "restore", receipt}`) is checked by its receipt: the
core's signed `{"kind":"store-restore-approved", pending, store, from, to, put: [{key, e, dataSha256, backupSha256}],
remove, begin, phoneSig, at}`, from a core whose identity (`core` in the object) the box key signed; it must name this
key's hashes (or list it as removed). Settings → Encrypted backup saves the same answer, checked but unopened, as one file for
`tools/decrypt-backup.py` (RUNBOOK "Offline copy of the stores").

Unlocks for one session (DESIGN "Carried secrets"): `unlock/begin {store, for}` with `for` = the nonce of the challenge
(New session's Start, an approval of a new line, an add-store) or of the session's cert (Unlock…) → the begin doc
carries `for`; only the cert with that nonce reads the store, its first pull that goes through locks it again, and an
unused one lapses after 30 min. No `for` = a standing unlock (the Stores page), open to every session until locked. The
signed `stores` list's `unlocked` means standing only; `unlocked` rows carry `for` ("" = standing). `for` that isn't a 64-hex nonce: 400.

Unlock, phone side: verify `unlock/begin`'s doc (kind `unlock-begin`, fields `pending, store, t, for, version, keys:
[{key, e, writer, dataSha256, backupSha256, at}]`) and every key's writer (`setup`: the setup key's signature over
`"jarvis2-store-key\n" store \n key \n e \n dataSha256 \n backupSha256`; `machine`: the core checked it, the app shows
which session wrote the key; `core`); one Face ID → for every key, Enclave key agreement of the phone's agreement key
with its `e` → the 32-byte x-coordinate, sealed to `t`: ephemeral P-256 key `r`, `x' = x(r·t)`, key =
HKDF-SHA256(ikm `x'`, salt empty, info `"jarvis2/unlock-share"`, 32 bytes), AES-256-GCM combined
(`nonce‖ciphertext‖tag`) → `{e: base64(r.pub x963), data: base64(combined)}` → `unlock/finish {pending, shares: {KEY:
share}}` (one share for each key the begin named).

## Deploy keys (the core: `deploy-keys/*`, `core/deploykeys.go`)

- `POST deploy-keys/begin {action: add | remove, repo: owner/name, sensitive, store, title, publicKey, keys}`: the
  app names the store (`github-<name>` for DE0CH, else `github-<owner>-<name>`) and the key's title on GitHub
  (`jarvis2 <store>`), and for an add makes the key pair: `publicKey` ("ssh-ed25519 <base64 wire>") and `keys`, the store's
  two keys `GITHUB_DEPLOY_REPO_<SLUG>` ("owner/name") and `GITHUB_DEPLOY_KEY_<SLUG>` (base64 of the OpenSSH private key
  file) (`<SLUG>` = `OWNER_NAME`, upper case, other characters `_`), each `{store, key, wrapped, data}` wrapped to the
  store key from `POST store-key` → the
  core's signed `{"kind":"deploy-key-begin", pending, action, repo, store, sensitive /* add: asked for, OR the store
  is sensitive already; remove: the store's */, replaces /* add: the store exists */, title, publicKey, keys: [{key,
  e, dataSha256}] /* add: each key's E and the sha256 hex of its data */, tokenStore: "github-deploy-keys", tokenKey,
  tokenWriter, tokenDataSha256, tokenBackupSha256, e /* the token key's E */, t /* a one-off key */}`, so the phone's
  signature covers the public key and the store's keys. The app keeps `DE0CH/jarvis2`'s store sensitive itself (it asks for it, and refuses a begin that isn't).
  400 for an add without the key pair, a key for another store or a repeated key, or a title that isn't one short line; 404
  while `github-deploy-keys` has no contents; 409 on an empty core; 409 `store github-x belongs to <owner/name>` when
  another repo owns that store name (names collide: `DE0CH/foo-bar` and `foo/bar`, `my.repo` and `My-Repo`; the owner
  is the repo whose add wrote the store, or after a Recover the bundle's `owners`; finish checks it again); 400 for a
  bad repo or store name (`github-deploy-keys` and `core` aren't allowed).
- `POST deploy-keys/finish {pending, signature, share}`: `signature` = the phone's base64 DER ECDSA over the begin
  document's payload (its signing key from the claim), `share` = x(p·E) of the token store sealed to `t` exactly as
  an unlock's share (HKDF info `"jarvis2/unlock-share"`); the shell makes both under one Face ID. One try per
  pending. The core opens `github-deploy-keys` for this call only (it never joins the unlocked set) and reads
  `GITHUB_DEPLOY_KEYS_TOKEN`; it deletes the repo's keys titled `jarvis2 <store>` on GitHub (`GET/DELETE
  /repos/{repo}/keys`), then — add — adds the app's public key (`POST /repos/{repo}/keys`, `read_only: false`) and
  stores exactly the app's keys (writer `core`) →
  `{"kind":"deploy-key-added", pending, repo, store, sensitive, title, publicKey, keyId}`; or —
  remove — deletes the store → `{"kind":"deploy-key-removed", pending, repo, store, deleted}`. 403 for a wrong
  signature or share; 502 `github: HTTP <status>: <GitHub's words>` when GitHub refuses (the router's
  `/api/repos/key/finish` turns a 403/404 into what the token needs: Repository "Administration: read and write").
- `POST store-key {phone}` → the core's signed `{"kind":"store-key", phone, storeKey}`: `storeKey` = P + K (X9.63
  base64) for that phone agreement key P. Open, also on an empty core: what the app wraps a data key to (one-off e,
  HKDF-SHA256 of x(e·storeKey) with info `"jarvis2/store-data-key"`, AES-256-GCM nonce‖ciphertext), since CryptoKit
  can't add points: a deploy key's store, and every store of a Recover's bundle (`claim`, above).

## Actions (`/m/api/actions/*`, `router/actions.go`)

A session's actions (Deyao, 2026-10-13): what a session may do to Jarvis 4 beyond its own business. Each session's key
is its own machine key (minted when the core starts the machine; the machine's local proxy signs every
`$JARVIS_URL/api/actions/…` call with it), so every action is that session's: Inbox entries name the caller "the
actions of session “title” (id)", and the router logs each non-GET action with its session. The key works only while
the session runs (`started`/`initialising`): from the moment it starts pausing or destroying every action is 403 and
its pending `api-call` requests leave the Inbox. Client: claude-env `scripts/jarvis2-actions.py`.

| Route | What |
|---|---|
| `GET /m/api/actions/sessions` | `{sessions: [{id, machineId, state, title, error, image, status?, needsGrant?}]}` |
| `GET /m/api/actions/requests` | The Inbox, as `GET /api/requests` |
| `POST /m/api/actions/sessions/:id/resume` | Resume a paused session: same image, no prompt, no option changes, so the core answers `approve_by_dead_machine` and the phone isn't asked. A line whose permission mode differs from its cert, or one the core refuses to resume by itself, gets its `resume-upgrade` approval instead (as `POST /api/sessions/:id/resume`, which also brings back a `failed` session with no machine). A failed session with a machine has its pause finished first (as the app's resume). 200 with nothing done when it already runs; 4xx when waiting in the Inbox, pausing or destroying |
| `POST /m/api/actions/sessions/:id/pause` | As the app's pause |
| `POST /m/api/actions/sessions/:id/upgrade` | As the app's Upgrade (next size up, `router/memory.go`) → 202 |
| `POST /m/api/actions/sessions/:id/destroy` | The app's Destroy, the same call: archived first, `?force=1` = its "destroy anyway" past a failed archive. |
| `POST /m/api/actions/requests/:id/deny` | An Inbox request leaves; an approval is rejected as the app's Deny; one already gone answers 200 `{ok, gone: true}` |
| `POST /m/api/actions/sessions` | Propose a new session (body as `POST /m/api/sessions` without `attachments`, `explanation` required): a `new-session` approval in the Inbox; at most 3 wait per session |
| `POST /m/api/actions/requests/{repo/add,repo/remove,grant,unlock}` | As `/setup/requests/*`: an Inbox request (any session, any repo) |
| `POST /m/api/actions/requests/batch`, `POST /m/api/actions/requests/batches/:id/deny` | A batch (Requests "Batches"); Deny all |
| `POST /m/api/actions/requests/call` | Ask for ANY app API call to be run as Deyao (`router/apicalls.go`). Body `{method, path /* with its query */, body? /* any JSON, sent as application/json */ \| bodyText? + contentType?, explanation /* required */}`, body at most 64 KB. The path must reach an app route that `callRules` allows (400 otherwise, e.g. the Inbox itself). → `{id, duplicate, expires}`: an `api-call` Inbox request with `params {method, path, body, contentType}` and `call.args.route` = the route's pattern |
| `GET /m/api/actions/requests/call/:id` | (A call waits in the Inbox while its session is paused, and runs when approved: it runs as Deyao; its outcome reaches the session at its next run. Only a destroyed session's call leaves.) That session's own call: `{state: "pending", expires}` while it waits, then `{state: done \| denied \| failed, status, contentType, body, withheld, error, approvedBy: app \| web, at}` for 10 min. `withheld`: the route's response carries a credential (`callStatus`), so only the status comes back. 404 for another session's |

Every app route is classified in `router/apicalls.go` `callRules` (`TestEveryAppRouteClassified` fails on one left
out): `callBody` (status and body go back), `callStatus` (status only: the response carries a credential) or `callNo`
(the Inbox and approvals, and calls that would hand out Deyao's login or can't run on the router). On approval the
router serves the call through its own public mux with the approving request's Access headers, so the route's own
`requireDeyao` checks Deyao himself.

## Setup (`/setup/*`)

Every call carries `X-Setup-Time` (unix seconds) and `X-Setup-Sig` = base64 DER ECDSA-P256-SHA256 signature
by the setup key over `"<METHOD> <path> <time> <sha256hex of body>"` (the router's path); the router checks it
against `SETUP_KEY` (`k8s/control/apps/router/router.yaml`), within ±2 min, each signature once. Client: `infra/setup.py`.

| Call | Core path |
|---|---|
| `GET /setup/identity` | `/identity` |
| `POST /setup/stores` | `/stores` |
| `POST /setup/stores/create` | `/stores/create` |
| `POST /setup/stores/versions` | `/stores/versions {store, nonce}` (below, "Store versions and restore"). `infra/setup.py versions STORE` |
| `POST /setup/stores/{store}/keys/{key}` | (the router's own, then `/stores/write-key`) one key written or deleted by the setup session, as `POST /m/stores/{store}/keys/{key}` with the setup key's signature over `WriterText`; its first key of a name the core doesn't have makes that store, sensitive. `infra/setup.py write\|delete` |
| `GET /setup/store-key` | (the router's own) as `GET /m/store-key` |
| `POST /setup/store-docs` | (the router's own) `{store, about?, keys: {KEY: text}}` → `{ok}`: as `PUT /api/stores/{store}/docs`. `infra/setup.py docs` |
| `POST /setup/stores/mark-sensitive` | `/stores/mark-sensitive` |
| `POST /setup/fly-token` | `/fly-token {sealed}`: `{"FLY_API_TOKEN"}` sealed to the core's agreement key (HKDF info `"jarvis2/fly-token"`) → the core's signed `{"kind":"fly-token-set"}`; 409 while the core is empty |
| `GET /setup/core-cert` | (the router's own) `{statement, masterSig}` of the claim it kept for the running core (matched by the core's signing key from `/identity`); 404 when none. A core claimed before the router kept claims (the running core until its release) is asked for its own `/core-cert`. |
| `GET /setup/stores/keys` | (the router's own) the store list with key names, as `GET /api/stores` |
| `GET /setup/jarvis1/paused[/{id}]`, `POST /setup/jarvis1/paused/{id}/prepare\|import` | (the router's own) as `/api/jarvis1/…` (Jarvis 1 import, above); the import's caller is `setup`. `infra/setup.py jarvis1 …` |
| `POST /setup/sessions/{id}/pause` | (the router's own) cancels the session's wakeups and crons, then pauses it (202; the snapshot if its machine answers within the wait, else none). `infra/setup.py pause` |
| `POST /setup/sessions/{id}/resume`, `POST /setup/sessions/{id}/restart` | (the router's own) the actions' resume (same image, no prompt) and the app's Restart (pause + that resume); wakeups and crons stay armed. A Claude line on an image from before the router's login gets a `resume-upgrade` approval instead (DECISIONS 154). 202. `infra/setup.py resume|restart` |
| `POST /setup/sessions/{id}/destroy` | (the router's own) the app's `POST /api/sessions/:id/destroy`: a running session is paused first (its final snapshot), then archived to the Storage Box, its line ended and its record kept; a failed archive leaves it paused with the error unless force (`?force=1`, or `{"force": true}` in the signed body). 202 `{ok, phase: "destroying"}`; follow it in `GET /setup/sessions` (gone) and the records. `infra/setup.py destroy SESSION [--force]` |

`GET /setup/status` — the router's health: the names of its secrets that are set (values never), the session
image, whether the core answers, and `githubRepos` — `{total, private}` repos the picker's `GITHUB_READ_TOKEN`
sees (or `{error}`; same 5-minute cache as `/api/github/repos`). `private: 0` = the token has no permission picked.
`flyOrgs` — the Machines view's orgs as counts only: `[{org, via, error, apps: [name…], machines, attention}]`.
`move` — the box move (`router/move.go`): `{role: sender|candidate|joined, phase, lastPrecopy, files, bytes, gapMs,
to, error}`. `backup` — the last state backup: `{at, path, size, snapshots, error}`. `core` — `{current: {url, serving,
identity}, next: {url, serving, identity, finalPending}}` (`serving`: empty | standby | serving | handed-off).

`POST /setup/core/flip` (setup-signed, empty body) — the next core serves from now on: drain → `POST /handoff` to the
serving core → `POST /takeover {lineState}` to the next → every later core call goes there. 409 with the reason when
the next core isn't a standby or refused the takeover (then no core serves until a retry; DECISIONS 179).

Every `/api/core/*` call takes `X-Jarvis2-Core: next` (or `?core=next`) to reach the next core (`NEXT_CORE_URL`)
instead of the serving one: "Recover alongside" sends it on identity, store-key and claim. `GET /api/state`'s `core`
has `next: {up, serving, signingKey}` when there is a next core.

The move's own listener (the sending box's router, `MOVE_ADDR` :8082, `Authorization: Bearer <MOVE_KEY>`): `GET /move/files`,
`GET /move/file?path=…`, `POST /move/freeze {finalizeCore}` → `{files, wg, coreFinal}`, `POST /move/done {url}`,
`POST /move/abort`.

## Claude accounts and their logins (`router/claudeaccounts.go`, `router/claudelogin.go`)

One Claude key store per Claude account, `claude-<name>` (DECISIONS 185, 190): a core store the router writes at every
change of the account's pair (`CLAUDE_CREDENTIALS`) or record (`CLAUDE_ACCOUNT`), as the core's writer `router` (no
approval, no bucket backup, no Inbox refresh; a core without them gets them within a minute), and the router's working
copy on its volume (`claude-accounts/<store>.json`, 0600; the default and Jarvis 1's account in
`claude-accounts/accounts.json`). With the router's env `CLAUDE_STORE_IN_CERT=1` a new session's cert names its
account's store, so the session gets its pair through that store at Start (the phone unlocks it with the rest). The router is the ONLY refresher of
each (when under 30 min are left; DECISIONS 115-121); it never calls Jarvis 1. A refresh revokes the previous access
token at once, so there is never a second refresher. A session's account is picked when it is made (`account` on
`POST /api/sessions`, `/m/api/sessions`, a batch's `new-session` item, `POST /api/tasks/instances` for a prompt
template, `POST /api/jarvis1/paused/{id}/import`; a record's restore takes the account it ran on while it exists) and
kept for its life unless switched (`POST /api/sessions/:id/account`, above) (`claudeAccount` in `GET /api/state`'s sessions and the `new-session` approval's options; in the
signed config too when the router runs with `SIGN_CLAUDE_ACCOUNT=1`). A harness
whose policy says `claudeAccount` (claude, openclaw, paseo-claude) and a prompt task get the default account when none is named; no
account at all (a new box): it starts logged out. `account` for a harness without one is ignored. The store `claude` (the
one shared login before accounts) is refused in `stores`; an add-store of it gives a session with no account the default
one (400 saying so).

| Call | Does |
|---|---|
| `GET /api/claude-accounts` | `{default, accounts: [{store, name, default, sessions: [ids], hasLogin, expiresAt, expired, email, accountUuid, source, updatedAt, refreshedAt, participants, loginInProgress, preparing, error?, rejected?, needLogin?}]}` (no secrets). `GET /setup/claude-accounts` the same for the setup session. |
| `POST /api/claude-accounts {name}` | A new account `claude-<name>` (lowercase letters, digits, single dashes; `name` may carry the prefix) → `{store, url}`: the sign-in page; then `…/code`. The first account becomes the default. An existing name starts that account's sign-in. 400 a bad name. |
| `POST /api/claude-accounts/{store}/login` | Re-login: `{store, url}` (the PKCE verifier is kept on the volume for 15 min). |
| `POST /api/claude-accounts/{store}/code {code}` | The pasted `code#state` → `{ok, store, email, expiresAt, note?}`. A sign-in of another Claude account than the store's is kept in that account's own store (made as `claude-<its email's name>` when there is none): `store` names it and `note` says so; the store asked for is unchanged. Stuck "Please run /login" sessions of the account get "continue" afterwards. |
| `POST /api/claude-accounts/{store}/refresh` | Refresh now → `{ok, refreshed, expiresAt}` (409 needLogin). |
| `POST /api/claude-accounts/{store}/default` | New session pre-picks it → `{ok, default}`. |
| `DELETE /api/claude-accounts/{store}` | Forget the account (its file goes, its core store loses its keys) → `{ok, default}` (the next account becomes the default when it was the default). 409 while any session uses it, naming them (switch them first: `POST /api/sessions/:id/account`). |
| `GET /api/claude-accounts/{store}/usage` | Its usage quota, as `/api/usage` was, plus `store` (`?refresh=1`). |

`GET /api/claude-login`, `POST /api/claude-login/{refresh,start,code}` and `GET /api/usage` act on the default account
(app builds from before accounts); 409 `needLogin` with no account.

Everyone who takes the pair long-polls `GET …/claude-login?have=<their expiresAt>&ack=<gen they hold a lock for, 0
none>&wait=<s, ≤ 55>` → `{credentials? (only when it expires later than have), account, expiresAt, gen, preparing}`. It answers at once when there is a newer pair, when a refresh is being prepared that the caller hasn't
acknowledged, or when the caller still holds a lock for a refresh that is over; else after `wait`. The refresh
protocol (lessons/74 over the network): the router sets `preparing` with a new `gen`; each participant takes the CLI's
refresh lock (`~/.claude/.oauth_refresh.lock`) and polls again with `ack=gen`; the router waits for every participant
seen in the last 2 minutes (at most 10 s), refreshes, writes the answer to its volume first, then answers every poll
with it; a participant writes its credentials file, then releases the lock. A failed refresh answers `preparing:
false` with no newer pair: participants release. A refused refresh (the grant is dead) DMs Deyao once.

`POST …/claude-login {credentials, account?}` offers a pair (a participant whose claude refreshed by itself): stored only
when it expires later and Anthropic's profile endpoint says it is the stored account's (403 otherwise) → `{stored,
expiresAt}`.

| Path | Who |
|---|---|
| `GET/POST /m/claude-login` | a session machine, for its session's account (404 `{noAccount: true}` when it has none); participant `m:<machine>` of that account. `GET/POST /m/api/credentials` (the push-claude-credentials script of session images from before 2026-10-13, through `$JARVIS_URL`) is the same pair and push. |
| `GET/POST /peer/claude-login`, `GET /peer/claude-login/status` | Jarvis 1 (one account: the one the shared login became, else the default): Access app `jarvis4.deyaochen.com/peer`, service token `jarvis1-claude-login` only (router env `ACCESS_PEER_AUD`, `JARVIS1_LOGIN_CLIENT_ID`; `infra/cloudflare.py --peer`); participant `jarvis1`. Its push may carry `relogin: true` (a Re-login in Jarvis 1's Settings), which may change the account. |
| `GET /setup/claude-login`, `GET /setup/claude-accounts` | the setup session (signed): the default account's status, every account's. |
| `/api/claude-accounts*`, `/api/claude-login*`, `/api/usage` | the app (above). |

## Machines (`/m/*`)

Every request carries `X-Machine: <fly machine id>`, `X-Time: <unix seconds>`, `X-Sig: <base64 DER signature
by the machine's signing key over "<method> <path> <time> <sha256 hex of body>">`; the router checks it
against the machine's current key (from `start`, or its latest downgrade) and refuses a time more than 120 s
off.

| Call | Does |
|---|---|
| `GET /m/cert` | `{cert, predecessorCert}` — this machine's latest succession cert and the predecessor's cert when it continues a real machine (the machine checks both against the core key the core put in its Fly config, `JARVIS2_CORE_KEY`). 404 until certified. |
| `GET /m/snapshot` | The predecessor's snapshot: body = tar.gz, header `X-Snapshot-Sig` = base64 signature by the predecessor's signing key over the sha256 of the body. 404 = none. |
| `POST /m/snapshot` | Upload this machine's snapshot (same format), streamed: the router writes the body to its volume while hashing it and checks `X-Sig` against that hash after (up to 32 GB; a machine the router doesn't know is refused before a byte is read). With header `X-Snapshot-None` and no body: nothing to snapshot (the machine is still booting; its agent answers every snapshot command from the first second of its life), and the waiting pause or destroy goes on at once. A pause or destroy doesn't ask a machine that never got past boot (no `/m/status` from it) at all. |
| `POST /m/snapshot-stream` | The final snapshot, streamed as the machine makes it (`machine/snapstream.go`, `router/snapstream.go`): no copy on the machine's disk. `X-Sig` covers `"POST /m/snapshot-stream <time> stream"` (the hash isn't known before the bytes), checked before a byte is read. The router keeps it as the machine's pending snapshot → `{sha256, bytes}`. |
| `POST /m/snapshot-commit` | `{sha256, sig}`: the machine's signature (its current key) over the hash the router answered, after checking it against its own → the pending file becomes its snapshot and the waiting pause goes on. 403 another key, 409 no pending snapshot with that hash. The machine signs one snapshot in its life: a later command commits the same one. |
| `POST /m/snapshot-progress` | `{phase: "measuring" \| "uploading" \| "writing", done, total /* uncompressed file bytes */, sent /* compressed bytes so far */, elapsedMs /* since the phase began */}`, every 3 s while the supervisor makes the final snapshot (`machine/snapprogress.go`: measured first, then counted as the tar.gz is made; "writing" = the whole-file path of an older router). Only while the router awaits that machine's snapshot: the router writes its own words from the numbers into the session's `waiting` ("measuring the snapshot (2.5 GB so far)", "uploading snapshot 1.2/3.4 GB (35%), 40 MB/s, 55 s left") and a line into the running operation's lifecycle log at most every 20 s. A report whose numbers moved keeps the pause waiting (`router/snapwait.go`, DECISIONS 214: the wait has no overall limit, it ends after `SNAPSHOT_STALL_SECONDS` with no progress; the body's bytes arriving at `/m/snapshot-stream` count too). → `{ok}` (`false`: nothing awaits it); 400 another phase or a negative number. The supervisor logs a line every 10 s and the last one ("snapshot: uploading done, … read, … compressed in N s"). |
| `POST /m/snapshot-failed` | `{error}`: the machine couldn't take its snapshot; the waiting pause stops waiting at once (and keeps a machine with no volume). |
| `POST /m/snapshot-carry` | `{sha256, sig}`: a machine asked while still booting signs the predecessor snapshot its cert names; the router links the predecessor's file as this machine's snapshot (409 for any other hash), and the machine never finishes booting. |
| `POST /m/disk` | `{root: {totalKb, availKb}, data?: {totalKb, availKb}}`: the root disk and the volume, every 30 s once booted (`machine/disk.go`), for the low-disk warning. 400 malformed. |
| `GET /m/restore-snapshot` | A restoring session's first machine only: the archived snapshot, same format, signed by the OLD machine named in `JARVIS2_RESTORE_CERT`; for a Jarvis 1 import, the import manifest (JSON). 404 otherwise. Streamed to disk by the machine. |
| `GET /m/import-file/{name}` | A Jarvis 1 import's first machine only: one file the manifest lists, streamed from the Storage Box with `Content-Length` = the manifest's size (the machine checks size and sha256). 404 for any other name or machine. |
| `POST /m/pull-secrets` | The router adds this machine's cert and the line's carried secrets (`snapshots/<machine>.carry`, else its predecessor's) and relays to the core; answers the core's signed `secrets` doc (sealed to the machine's key; its `carry` field, the next blob, is kept by the router; `stale`: stores whose values are behind a write; the router files no request for them, the session gets them at its next pull with a new cert). 423 `store X is locked` when no unlock is open to the cert and the blob doesn't hold the store. |
| `GET /m/commands` | Long poll (≤ 50 s): `{commands: ["snapshot"]}` or `{commands: []}`. `"refresh-secrets"` (an unlock for this machine's cert went through): the supervisor pulls again with its newest cert into its RAM copy (ignored while booting). `"free"` (an Upgrade, before its snapshot): the supervisor SIGSTOPs the harness and SIGKILLs every other process of the session user but itself (its worker and keeper), and writes their list to `~/artifacts/jarvis2-upgrade-freed.txt` (`machine/memory.go`; ignored while booting or frozen). `"pause-harness"` / `"resume-harness"` (`POST /api/sessions/:id/harness`): the supervisor SIGSTOPs / SIGCONTs the Claude process. |
| `POST /m/supervisor-log` | `{lines: [{at /* RFC 3339 */, text}]}` (≤ 500 lines; a line over 2000 bytes is clipped; an `at` more than a minute ahead or a day behind the router's clock becomes the router's): the supervisor's own log lines, pushed from its first second (also while the machine boots, before its first `/m/status`), written free of secrets by the machine. Appended to the session's supervisor log (`GET /api/sessions/:id/supervisor-log`). 400 malformed or too many lines, 404 a machine of no session. |
| `POST /m/memory` | Body `{totalKb, availKb, oomKills, psiFull60, top: [{rssKb, comm}]}` (≤ 10 processes): the machine's RAM, every 10 s once booted (`machine/memory.go`), for the starvation watch (`router/memory.go`). 400 for a malformed sample. |
| `GET /m/stores` | Every store (all of them, not only this session's) with its keys and what each is for, as `GET /api/stores`, so the session knows which one to ask for. `jarvis2 stores [--keys \| --json]` prints it, checks the list and the key names against the core's signature and marks this session's own stores. |
| `GET /m/store-key` | `{identity, storeKey}`: the core's identity (keys, box signature, its signed state naming the master key and the phone) and its signed `store-key` for that phone — what a writer seals to. The machine checks both against its core key. |
| `POST /m/stores/{store}/keys/{key}` | A running session writes or deletes one key, no approval (`jarvis2 put-key STORE KEY [--explain TEXT] < value`, `jarvis2 delete-key`): `{delete, wrapped: {e, wrapped}, data, backup: {e, data}, backupSha256, sig, explanation}` — the value sealed to the store key (AAD `store\nkey`), its backup sealed to the master key (HKDF info `"jarvis2/backup"`, the same AAD), `backupSha256 = sha256(backup.e + "\n" + backup.data)`, `sig` this machine's signature over `WriterText`. The router writes the backup first (`keys/<store>/<key>.json`), then the key into the core with the machine's newest cert (`/stores/write-key`, writer `machine`), keeps the explanation (required for a key name with none yet). No Inbox request: a session holding the store gets the key at its next pull with a new cert (an add-store, a resume; Deyao, 2026-10-22). → `{ok, receipt /* the core's key-written doc */}`. 400 malformed, missing explanation or backup; 403 the core or deploy-key token store, or a session that isn't running; the core's own refusals as they are (e.g. 403 a repo's deploy-key store, 404 no such store). |
| `POST /m/add-store` | Body `{store}`: asks Deyao (an `add-store` approval) to add one store to this session. With a reason: `POST /m/api/requests/add-store` (Requests). |
| `POST /m/downgrade` | Body `{stores, newEncryptionKey, newSigningKey}` → `{challenge}`, which the machine signs with its OLD key. |
| `POST /m/downgrade/finish` | Body `{challenge, signature}` → core `approve/by-old-key` → `{cert}`; from now on the router knows the machine by its new key. |
| `GET /m/tunnel-proof` | `{proof, id}`: hex HMAC-SHA256(`JARVIS2_TUNNEL_KEY`, `"jarvis2-tunnel:" + <this machine's session id>`), which the cf-tunnel Worker checks when the `jarvis2-tunnel` token registers that id. The machine puts it in `TUNNEL_AGENT_SECRET` at boot (never in the Fly config). 404 without the key; 403 for a machine with no running session. |
| `GET /m/config` | The values a machine takes from the router alone, each refused by the machine unless it matches its format (DESIGN "Inputs to a machine"): `{sessionId, discordChannel, liveSyncSeconds, taskRun, taskTrigger, tunnelProof}`. Everything else comes from the cert. |
| `GET /m/restore-cert` | `{cert, coreCert?, coreState?}`: the old line's cert a restoring new line checks (its machine must be the one the cert's config names). For a cert an earlier core signed: `coreCert` = the archive's `core-cert.json` (the master key's claim naming that core: `core` or, seeded, `identity`) and `coreState` = the running core's signed state naming its master key; the machine takes the cert when its own core key signed it, or that state's master signed that claim and the claimed key signed the cert. 404 without a restore. |
| `POST /m/delivery-result` | `{id, ok, error?}`: the machine's answer to a delivery. Deliveries arrive in `GET /m/commands` as `{deliveries: [{id, kind: wakeup\|cron\|nudge\|continue\|upgraded, request?, run?, minutes?, jobs?, from?, to?, attest}]}` (`upgraded`: a text built into the image from the two sizes, each small, medium, large or a doubling past it): a wakeup/cron is the session's own signed request, `attest` the core's input-log entry for it. |
| `GET /m/attachments` | `{files: [{name, size, isImage}], attest: {<name>: <core doc>}}`: the first-prompt attachments bound to this machine's session (404 none), each with the core's input-log entry for it (`/attest` machine, input `attachment`, origin `cert`, the sha256 of the file as it is on the volume; 502 when the core doesn't answer). The machine takes a file only when its bytes match the cert's sha256 + size AND its attestation. `GET /m/attachments/:name` the bytes; `DELETE /m/attachments` drops the router's copy once fetched. |
| `POST /m/task-result` | A task line's machine (harness `task:<template>`, below) after its run: `{run, exitCode, timedOut, error, startedAt, finishedAt, log /* tail ≤ 256 KB */, output /* ≤ 64 KB */}`, store values already redacted by the machine. `run: ""` = a boot with no run (the line's first machine). The router records the run and pauses the line. 403 for a machine that isn't a running task line. |
| `POST /m/status` | Body `{raw, appTitle}`: `raw` = the output of Jarvis 1's registry command (`machine/status.go`), sent by the supervisor when it changes and at least every 60 s; parsed by the router (`router/registry.go`); its last section, `__HARNESS__`, is the keeper's record of the harness (`machine/keeper.go`: starts on this machine, running, last end), the session's `registry.harness`. `appTitle` = the Claude app's title of the session's Remote Control entry, which the machine reads (at most once a minute) from `api.anthropic.com/v1/code/sessions/cse_<bridge>` with the session's own Claude login (`machine/apptitle.go`); "" keeps the last one. It becomes the session's `serverTitle`, and a resume without a label passes it on as `SESSION_RESUME_TITLE` (Jarvis 1's supervisor names a fresh Remote Control entry with it). |
| `POST /m/live-transcript` | Header `X-Name: <uuid>.jsonl`, body = the whole transcript (≤ 256 MB). The machine sends each conversation under `~/.claude/projects` that changed, every `JARVIS2_LIVE_SYNC_SECONDS` (default 300; router env `LIVE_SYNC_SECONDS` sets it), skipping Jarvis's delivery relays (`machine/livesync.go`). The router PUTs it to `claude-records/.live/<session id>/<name>` with its own Storage Box credentials — Jarvis 1's layout, which transcript search indexes — and records `liveSync` on the session; with no Storage Box (or `RECORDS_OFF=1`) it answers `{ok, stored: false}`. A destroy deletes only the copies its archive holds (Archives above). 403 for a machine with no running session. |

## The input log (`router/vouch.go`, `core/audit.go`)

`GET /api/input-log?last=N` (Access): the last N (≤ 2000, default 200) core-signed entries, each
`{kind: "input", seq, prev, at, machine, input, origin, sha256}` with `prev` = sha256 of the previous entry's payload.
The router appends each entry to `DATA_DIR/input-log.jsonl` as it arrives: attest's answer is the entry, and each
cert's entry comes beside the cert (`entry`, with the rebound `carry`, next to `payload`/`sig`). A new core's chain
starts again at seq 0. The core before R2 (the running one until its release) kept its entries for reading instead
(`POST /input-log`, `chain_from`): the router reads those while that core runs.

## Wakeups and crons (`router/schedule.go`)

Jarvis 1's shapes. The session arms them under `/m/api/sessions/:id/…` (through its machine's local proxy, below: its
own signed request is what vouches for the delivery); the app lists and cancels them under `/api/sessions/:id/…`, and
its `POST` (wakeup or cron) answers 400 saying the session arms them. At the due time the router hands the machine a
core-attested delivery of the session's own signed request, resuming a paused session first (straight in, whatever
stores the session holds: DECISIONS 210). A wakeup or cron belongs to its
session and ends with it.

| Call | Does |
|---|---|
| `GET …/wakeup` | `{wakeup /* the soonest or null */, wakeups}`; `GET …/wakeups` → `{wakeups}`. Wakeup view `{name, at /* ms */, atIso, prompt}`. |
| `POST …/wakeup` or `…/wakeups` | `{prompt, at? /* ISO or ms */, delaySeconds?, name? /* default "default" */}` → `{ok, wakeup}`. Arming a name again replaces it. ≤ 400 days (a time already past fires at once), prompt ≤ 3500 chars (whitespace collapses). 409 when the session is destroying. |
| `DELETE …/wakeup?name=X` (`?all=1`), `DELETE …/wakeups/:name` | `{ok, cancelled: [names]}` |
| `GET …/crons` | `{crons}`; view `{name, prompt, everySeconds, tz, nextAt, nextAtIso, until, untilIso, armedAtIso, runs, lastFiredIso}` |
| `POST …/crons` | `{name, prompt, everySeconds? /* 900–7776000, default 86400 */, time? "HH:MM" + tz?, at?, delaySeconds?, until?}` → `{ok, cron}` |
| `DELETE …/crons/:name` | `{ok}` |
| `POST …/notify-idle` | `{enabled}` → `{ok, notifyIdle: "on"|"off"}` (kept for the idle DMs) |

Delivery failures back off and, after 5 attempts, drop a wakeup (a cron skips that occurrence) with a DM. A message
held for Deyao counts as handed over: the wakeup is done (the cron advances), and the message queue delivers it once
approved or tells the session (an Inbox outcome of the request that armed it) when it is denied, lapses or fails.

## Message approvals (`router/messages.go`; docs/DESIGN.md "Message approvals")

An upward peer message into a session holding a sensitive store, and every resume prompt into a running session,
waits as a pending message until Deyao delivers (phone-signed) or denies it; Jarvis's own messages, the session's own
wakeups, crons and watches, and equal or downward peer messages go straight in (DECISIONS 210). Each pending one is also
an Inbox item (`kind: "message"`, `callerText` = who sends it, `explanation` = the plain headline "Message from session
“X” to session “Y”" (another kind: "<label> for session “Y”"), `params.text` = the exact text, `open: {kind:
"message", options: {messageId, sessionId}}`), and `/api/state` carries `messages` and `messageRules`, and per session
`pendingMessages` (a count) and `messageRules`.

| Call | Does |
|---|---|
| `GET /api/messages[?session=]` | `{messages: [{id, session, sessionName, kind, kindLabel, from, text, note, sha256, created, expires, state /* pending \| approved \| failed */, error, ruleable, ruleText}], rules: [{id, session, kind, kindLabel, text, until, created}]}` |
| `POST /api/messages/draft` | `{ids}` (pending, one session) → `{text, session, line}`: exactly what the phone signs, `{kind: "messages", session /* line */, items: [{id, delivery, sha256, from, text}], issued, expires /* +1 h */}` |
| `POST /api/messages/approve` | `{payload, sig}` → `{ok, delivering: [ids]}`; refused unless the cert's phone key signed it for that line and every item is that pending message unchanged. Each is delivered (a paused session is started; an Inbox outcome waits for it to run). |
| `POST /api/messages/deny` | `{ids}` → `{ok, denied}`; `DELETE /api/requests/{id}` denies one too |
| `POST /api/sessions/:id/message-rules/draft` | `{kind}` → `{text}`: `{kind: "message-rule", session, delivery, issued, until /* +1 year */}`; no rule for `peer` or `resume-prompt` |
| `POST /api/sessions/:id/message-rules` | `{payload, sig}` → the rule; that session's pending messages of the kind go in under it |
| `GET /api/sessions/:id/message-rules` | `{rules}`; `DELETE /api/message-rules/:rid` removes one (the router stops using it at once) |

Kinds that wait: `peer` (upward, into a sensitive session) and `resume-prompt`. A pending message lapses
after 24 h; a newer one of the same thing replaces one still waiting; Deyao gets one DM when a session's first one
waits.

## Tasks (`router/tasks.go`, `machine/task.go`, templates in `tasks/`)

Jarvis 1's Tasks and Schedules tabs, same shapes where the meaning is the same (`selfhost/jarvis/lib/tasks.js`). A task
**instance** is a session **line** whose signed harness is `task:<template>` (DECISIONS 32): creating one asks the phone
once (an ordinary `new-session` approval, label `Task: <name>`, stores = the template's + the ones picked in its store
fields). Each **run** resumes that line with no phone (`approve_by_dead_machine`); its machine runs the template from the
session image instead of a harness, reports to `/m/task-result`, and the router pauses the line again. Task lines also
show in `/api/state` `sessions` (harness `task:…`); the autopilot and Discord channels leave them alone.

**Template** (`tasks/<name>/task.json` + its files; the router image has a copy for the forms, the session image the copy
that runs — `/opt/jarvis2/tasks/<name>`, fixed by the line's image digest):

```
{ title, description?, run? /* "run.py" | "run.sh" | "run.js" | an executable; default: the first that exists */,
  prompt? /* "prompt.md": `claude -p` with {{field}} filled in, in the cert's permission mode (needs store claude) */,
  model? /* prompt only */, stores?: [store…], timeoutSeconds? /* 10–21600, default 600 */,
  size? /* small (default) | medium | large */,
  fields: [{ name /* [a-z][a-z0-9_]* */, label?, type: text|textarea|number|select|multiselect|checkbox, required?,
             default?, help?, placeholder?, options?: ["a", {value, label, sub?}], optionsFrom?: stores|sizes|models }] }
```

A (multi)select with `optionsFrom: "stores"` adds the picked store(s) to the line; `options` comes back empty for it —
the app fills the list from the core's store list (`/api/core/stores`). Jarvis 1's `secretKeys`, `image`, `memory` and
hidden values don't exist here (a picked store brings all its keys; secrets live only in stores).

**What a run sees** (machine/task.go): cwd `~/task-work` (fresh each run); env = PATH/HOME/LANG/…, `JARVIS_URL`,
`SESSION_ID`, `LOBSTER_CHANNEL`, the router's `TASK_PARAMS` (all values as JSON), `PARAM_<FIELD>` (lists comma-joined,
booleans `true`/`false`), `TASK_INSTANCE`, `TASK_NAME`, `TASK_RUN`, `TASK_TRIGGER` (manual | schedule), then `TASK_DIR`
(the template's files), `TASK_TEMPLATE`, `TASK_OUTPUT` (a file whose first 64 KB is the run's output in the app),
`TASK_STATE_DIR` (`~/workspace/task-state`, kept between runs by the snapshot), `TASK_WORK`, `TASK_TIMEOUT`, and last the
line's store values (the supervisor's RAM copy; nothing on disk). Parameters are NOT secret: they are in the machine's Fly config and unsigned,
so a script treats them as data. The log is `~/artifacts/task-runs/<run>.log` (20 kept, archived with the line); store
values of 6+ characters are replaced by `[secret NAME]` in the log and the output before they leave the machine.
A run past `timeoutSeconds` is killed with its process group (`timedOut`).

```
instance = { id, template, name, params, size, stores, session /* the line, null once gone */, createdAt, updatedAt,
             state: approval | ready | running | busy | failed | gone, detail, sessionState, image,
             lastRun /* the newest finished run */, activeRun, queued /* count */, schedules /* count */ }
run      = { id, name /* = id, Jarvis 1's Job name */, instance, instanceName, template, trigger: manual | schedule,
             schedule, slot, upgrade, phase: queued | starting | running | succeeded | failed | timedout | stopped | lost,
             createdAt, resumedAt, startedAt /* machine up, secrets pulled */, ranAt /* script start */, finishedAt, exitCode, reason,
             waiting /* e.g. the phone must approve a newer image */, tail /* last 15 lines */, logBytes, outputBytes,
             machine, image }
schedule = { id, instance, time "HH:MM", tz, enabled, since /* ms */, createdAt, nextAt /* ms or null */ }
```

| Call | Does |
|---|---|
| `GET /api/tasks` | `{sessionImage, templates /* parsed, broken ones with `error`; `source` = the run/prompt file */, instances, schedules}` |
| `POST /api/tasks/instances` | `{template, name, params, size?, requestId?}` → the instance (state `approval`); the phone's approval is in `/api/approvals`. 400 for bad values (`hide` is refused). |
| `PUT /api/tasks/instances/:id` | `{name?, params?, size?}` → the instance. Values that change the line's stores or content stores file a new line for the phone (as …/approve does); the instance, its schedules and runs stay, the old line goes. 409 while a run is in progress. |
| `DELETE /api/tasks/instances/:id` | Drops it with its schedules and runs; its line is destroyed (archived like any session) or its pending approval rejected. |
| `POST /api/tasks/instances/:id/approve` | A new line (phone approval) for an instance whose line is gone or failed; 409 otherwise. |
| `POST /api/tasks/instances/:id/run` | `{upgrade?}` → `{name, run}` (phase `queued`; it starts once the line is paused). `upgrade: true` resumes on the newest session image, which the phone approves first (`resume-upgrade`) — how a changed template reaches an existing task. A line waiting for the phone keeps the run queued until approved; a line gone or being destroyed gets its new line filed for the phone, and the run waits for it. 409 only with 3 runs queued. |
| `GET /api/tasks/instances/:id/runs` | `{runs}` newest first (20 finished kept). |
| `GET /api/tasks/runs/:id` | `{run, log, output}`. |
| `POST /api/tasks/runs/:id/stop` | Queued: dropped. Starting/running: `stopped`, the line is paused (a machine already up may have started the script). Finished: nothing to do, 200. |
| `POST /api/tasks/schedules` | `{instance, time, tz? /* default Europe/London */, enabled?}` → schedule. Daily at `time` in `tz`; a change never fires a slot already past; a slot missed by more than 2 h (router down) is skipped. |
| `PUT /api/tasks/schedules/:id` | `{time?, tz?, enabled?}` |
| `DELETE /api/tasks/schedules/:id` | `{ok}` |

DMs (lobster, as Jarvis 1): a scheduled run that failed, timed out or was lost (with the log's tail), and a scheduled
slot that could not start (line gone, waiting for approval, queue full). A run is `lost` when its line stopped (a manual
pause, the budget cap) before the machine reported, and `timedout` by the router when no result came 15 min past the
template's timeout. A run resumes its line with the secrets the line carries (DESIGN "Carried secrets"), no store
unlocked; a line without them (its blob lost, or first started under a core that predates them) waits on its locked
store like any start: a run whose machine isn't up 30 min after the resume (`waiting` says so) fails and the line is
paused.

## Device leases (`router/leases.go`)

Jarvis 1's lib/leases.js and shapes. One holder and a FIFO queue per device; `wechat-phone`, `iphone` and `mac` are
always listed. The session calls the `/m/api` paths through its machine's proxy (`scripts/lease.py`, which the device
helpers call); its path id must be its own. `/api/state` carries `leases` (the list below).

```
lease = { name, holder: null | {sid /* a session id, or "deyao" */, human, purpose, description, describedAt, note, since,
          expiresAt /* ms, null for Deyao */, expiresInSeconds}, queue: [{position, sid, purpose, description, describedAt,
          enqueuedAt, interrupted}], log /* last 20: {at, kind: granted|promoted|returned|force-returned|expired|taken-over|
          handed-back|note, sid, purpose?, note?, interrupted?} */ }
```

| Call | Does |
|---|---|
| `GET /api/leases`, `/m/api/leases` | `{leases}` |
| `GET /api/leases/:name`, `/m/api/leases/:name` | `{lease}` |
| `POST /m/api/sessions/:id/leases/:name` | `{purpose, description?, prompt? /* the wake note */, ttlSeconds? /* 60–21600, default 3600 */, lowPriority?}` → `{status: granted | renewed | queued | busy, position?, lease}`; `busy` (409) only for `lowPriority`. |
| `PUT /m/api/sessions/:id/leases/:name` | Renew (holder only) → `{status: "renewed", lease}`; 409 otherwise, `{takenOver: true}` with Deyao's note while he has it (and the session is told when he hands it back). |
| `PATCH /m/api/sessions/:id/leases/:name` | `{purpose?, description?}` (holder or waiter; no renew) → `{status: holder | queued | none, lease}` (`none`: this session neither holds nor waits for it, nothing changed) |
| `POST /m/api/sessions/:id/leases/:name/seen` | The session looked at a device Deyao has (lease.py status) → `{takenOver}`; it is told when he hands it back. |
| `DELETE /m/api/sessions/:id/leases/:name` | Return it (holder) or leave the queue → `{returned, left, next /* the woken session or null */}` |
| `POST /api/leases/:name/force-return` | The app: `{returned, previous, next}` |
| `POST /api/leases/:name/take-over` | The app: `{note?}` Deyao takes the device (never expires; agents' actions refused); the holder goes to the front of the queue and is told (`lease-taken`). While he has it, a note only replaces his note. → `{taken, interrupted, noteUpdated}` |
| `POST /api/leases/:name/hand-back` | The app: `{note?}` → `{handedBack, next, notified}`; the next waiter is woken, every other session that found it taken over is told (`lease-back`). |
| `POST /setup/leases/:name/take-over`, `…/hand-back` | The same, by the setup session for Deyao (setup-key signed; `infra/setup.py lease take-over DEVICE --note …`). |

Wake messages are deliveries (`/m/commands`, checked by the machine, attested by the core): `lease-granted` (the
waiter's own signed acquire request: its prompt, and the device in the signed path; `minutes`, `handover`,
`interrupted`), `lease-taken` and `lease-back` (image texts over `device`). A promoted holder that can't be woken is
retried every 30 s (20 tries). A destroyed session's holder or queue place goes at the next sweep.

## Watches (`router/watches.go`, `services/watch`)

Conditional wakeups, Jarvis 1's shapes. The session arms one (its own signed request); the router runs the check on the
watch runner (k8s/services/apps/watch/, on the services box: no secrets, public internet only) every `interval`, whether the session runs or is
paused. Exit 0 = met → `watch` delivery (the session's request: `[watch "<name>" met] <prompt>`); exit 3, or
`maxSeconds` past arming = give up → `watch-fail` (`failPrompt`, or a default). Any other exit, or a runner error =
not yet. The machine runs the check once more itself (its own env, 40 s) and appends that output; the runner's output
never reaches the session. A failed delivery backs off and after 5 attempts the watch is dropped with a DM.

```
watch view = { name, prompt, failPrompt, interval, maxSeconds, armedAt, armedAtIso, expiresAtIso, nextCheckIso, runs,
               lastExit /* null before the first run or when the runner failed */, lastRunIso, lastError /* the last stderr
               line, why it couldn't run, or why the delivery failed ("delivery: …") */, lastOutput /* the start of stdout */, outcome /* "" | met | gave-up */ }
```

| Call | Does |
|---|---|
| `POST /m/api/sessions/:id/watches` | `{name, script /* bash, ≤ 32 KB */, prompt, failPrompt?, interval? /* 30–3600 s, default 60 */, maxSeconds? /* ≤ 400 d, default 7 d */}` → `{ok, watch}`; the same name replaces. The app's `POST /api/sessions/:id/watches` → 400 (only the session's own request can be delivered). |
| `GET /api/sessions/:id/watches`, `/m/api/…` | `{watches}` (no script bodies) |
| `DELETE /api/sessions/:id/watches/:name`, `/m/api/…` | `{ok}` |

The runner (`POST http://10.77.0.3:30095/run {script, name, timeout}` on the services box →
`{exit, stdout, stderr, timedOut, ms}`, router env `WATCH_URL`): a check gets PATH, HOME and TMPDIR (a throwaway
directory), LANG and WATCH_NAME; bash, curl, python3, git, openssl, jq; 90 s; stdout capped at 16 KB.

## Content stores (`router/content.go`)

Named folders of files on the Storage Box, `claude-records/.content/<name>/` (Jarvis 1's, used in place), read and
written with the router's own Storage Box credentials. A name is `[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?`; a file path is
relative, `/`-separated, with no empty, `.` or `..` segment; a file is at most 25 MB.

| Path | Does |
|---|---|
| `GET /api/content[?fresh=1]` | `{stores: [{name, files, bytes}]}` (cached a minute; `fresh=1` walks the box). |
| `POST /api/content` | Body `{name}` → `{ok, name}`; 409 when it exists. |
| `DELETE /api/content/:name` | The store and every file in it. |
| `GET /api/content/:name/files` | `{name, files: [{path, size, modified}]}`, sorted by path; 404 for no store. |
| `GET /api/content/:name/file?path=` | The bytes (`application/octet-stream`). Jarvis 1's `x-content-path` header works in place of `path`. |
| `POST /api/content/:name/file?path=` | The raw body becomes that file (parent folders made) → `{path, size}`. |
| `DELETE /api/content/:name/file?path=` | The file, then the folders it leaves empty. |

A session's content stores are the cert's (`options.config.content`, signed with the line: New session's `content: [name…]`,
or a task's `optionsFrom: "content"` fields); `POST /api/sessions` refuses a name with no store. On the machine,
`SESSION_CONTENT` names them and the base image's `content-sync` (pull at every start, `push`, `status`) calls Jarvis 1's
session paths through the local proxy:

| Path (machine-signed, `/m/api/…`) | Does |
|---|---|
| `GET /m/api/sessions/:id/content` | `{ok, stores: {name: [{path, size, modified}]}}` for the cert's stores (a deleted store: `[]`). |
| `GET /m/api/sessions/:id/content/:name/file?path=` | The bytes, with header `X-Jarvis2-Attest`: the core's input-log entry (machine, `content`, origin `router`, sha256); the machine's proxy refuses the file (502) without a matching one. |
| `PUT` / `DELETE /m/api/sessions/:id/content/:name/file?path=` | Write or delete a file of one of the cert's stores; 403 for any other store. |

## Paired apps (`router/devices.go`)

Deyao's builds of the OpenClaw and Paseo apps pair once and then list and start sessions without a login of their own.

| Path | Does |
|---|---|
| `GET /api/devices/pair?state=&name=&model=&app=openclaw\|paseo` | Deyao's own Access login only (the app opens it in the system sign-in sheet). Mints one Access service token for that device (`CF_DEVICE_TOKENS_API`) → `302 openclaw-de0ch://paired?state&id&clientId&clientSecret` (or `paseo-de0ch://…`); an error comes back the same way as `error` + `status` (429 within 30 s of the last pairing). `state` is `[A-Za-z0-9_-]{16,64}`. |
| `GET /api/devices` | `{devices: [{id, name, model, app, createdAt, lastSeenAt}]}` (no token ids). |
| `DELETE /api/devices/:id` | Deletes its service token at Cloudflare and forgets it. |

`/api/remotes` and `/api/sessions/:id/start` are behind the Access app "Jarvis 4 devices" (`ACCESS_DEVICES_AUD`), which admits
Deyao's email or any service token of the account; the router then admits a token only when its client id (the JWT's
`common_name`) is a paired device's.

## Session-facing API (`/m/api/*`)

Jarvis 1's session scripts call `$JARVIS_URL/api/…`. A Jarvis 4 machine gets `JARVIS_URL=http://127.0.0.1:7171`
(plus placeholder `CF_ACCESS_CLIENT_ID/SECRET` and `SESSION_API_TOKEN`, which the scripts insist on; not for
OpenCode/OpenClaw, whose harness scripts read CF_ACCESS_* as "publish the web UI"). There `jarvis2-machine supervisor --worker`
serves a proxy that drops the scripts' headers and sends `/m/api/<rest>` (query kept, unsigned; the path is
signed as every `/m` call). Any `:id` in the path must be the calling machine's session (403 otherwise).

| Path | Served by |
|---|---|
| `GET /api/sessions/:id/secrets` | 410: the secrets don't travel over HTTP; they come from the supervisor's socket (below). |
| `GET /api/sessions/:id/changes` | The machine itself: `{checked, repos: [{name, uncommitted, unpushed /* -1 no upstream */}], status}`. |
| wakeups, crons, notify-idle | The router (above). Delivered as the session's own signed request; nothing is put on the allow list. |
| `DELETE /api/sessions/:id` | The router: the session retires itself (Destroy) → 202 `{started}`; 409 `{pending}` while it has wakeups, crons or watches. |
| leases, watches | The router (above). |
| search, iCloud index | `GET /m/api/search`, `/m/api/search/context`, `/m/api/search/status`, `POST /m/api/search/reindex` (any running session), `GET /m/api/icloud/search`, `/m/api/icloud/file`, `/m/api/icloud/status`, `POST /m/api/icloud/relist`, `/m/api/icloud/retry` (only a session whose cert holds the `identity` store; otherwise 403 `{error, needsStore: "identity"}`): the box's own services, as for the app. 403 for a machine with no running session. |
| device leases, content stores | The router (`router/leases.go`, `router/content.go`). |
| `GET/POST /api/credentials` | The session's Claude account's login ("Claude accounts" above). |
| `POST /api/requests/peer` | A peer message ("Peer messages" below; `jarvis2-message`). |
| anything else | 404 |

Nothing is forwarded to Jarvis 1.

### Peer messages (`router/peermsg.go`, `machine/peer.go`; DESIGN "Peer messages", DECISIONS 199)

The only way one session's words reach another. Claude Code's own cross-session messages (SendMessage over Remote
Control or a peer socket) are refused in every session (`/etc/claude-code/managed-settings.json`:
`crossSessionInbound: "refuse"`); the session image's `jarvis2-message SESSION "text"` calls:

| Path | Body → answer |
|---|---|
| `POST /m/api/requests/peer` (`$JARVIS_URL/api/requests/peer`) | `{to /* a session id, or its exact title */, text /* ≤ 8000 chars */}`. The sender is the calling machine's session. The direction, from the stores both machines' latest certs name and the router's permission modes: **equal** (same stores, same mode) and **downward** (the receiver holds no store the sender lacks, and bypasses only if the sender does) → 202 `{delivering: true, direction, to}`, delivered at once (a paused receiver is resumed); **upward** (the receiver holds a store the sender lacks, or bypasses while the sender doesn't) → 200 `{id, duplicate, expires, direction: "upward", waiting: "inbox", to}`: an Inbox request of kind `peer-message` (`params: {session /* the receiver */, text}`, the caller the sending session, an explanation by the router naming both sessions, their stores and modes and why it is upward). 400 for an unknown or ambiguous receiver, the sender itself, or an empty or too long text. |
| `POST /api/requests/:id/approve` (a `peer-message`) | Deyao's one tap (no Face ID: nothing is signed) → `{ok, state: "delivering", direction}`; the message goes with the session's current stores and `approved: true`. Deny is `DELETE /api/requests/:id`. |

The receiving machine gets a core-attested delivery of kind `peer` (`peer: {from, fromTitle, fromStores, fromMode, to,
toStores, toMode, direction, approved?, text}`, attested as that JSON with origin `session:<sender>`); it refuses an
`equal`/`downward` one when its own cert holds a store the sender lacks or it bypasses while the sender doesn't, and
an `upward` one without `approved`, and wraps the text with the verified sender, both sides' stores and modes and the
direction. The sender hears back like any request (`jarvis2-request outcomes`, kind `peer`): an upward message
approved, denied, lapsed or dropped, and any message whose delivery failed. A message can also be an item of a batch
(`{"intent": "peer", to, text}`, "Batches" above), so a session's asks and its upward messages go to Deyao as one Inbox
entry.

Jarvis's own messages (the watchdog, wakeups, outcomes, lease and upgrade notices, a resume prompt) reach claude through
the image's Jarvis channel (`jarvis-channel`, an MCP channel server; `jarvis-channel-send`), whatever the session's
permission mode. An image without the channel takes them on the peer socket as before.

### The supervisor's secrets socket (`/run/jarvis2/secrets.sock`)

Not HTTP: a unix socket on the machine (0600, the session user's; the supervisor serves the session user and root), one JSON request per connection,
one JSON answer `{ok, error?, locked?, names?, stores?, secrets?, n?}` (machine/secrets.go). Callers are identified by
SO_PEERCRED; every request is logged in the supervisor log with its op, the key names and the caller's pid and command,
never a value. Pulling and asking are separate: a pull never answers a value, and asking never pulls.

| Request | Who | Answer |
|---|---|---|
| `{"op":"names"}` | `session-secret --names` | `names`: the key names held now |
| `{"op":"get","keys":["K1","K2"]}` | `session-secret --keys K1,K2 --exec CMD \| --write FILE` | `secrets`: exactly those keys. Refused: no keys, a name that isn't an env name, a key not held (the error names it). There is no request for all keys. |
| `{"op":"reload"}` (`drop`, `held`: a downgrade's) | `pull-secrets`, add-store's waiter, `downgrade` | the router's newest cert, then a pull with it into RAM: `n`, `names`, `stores`; no value. `locked` when a store is locked. |
| `{"op":"pull"}` | boot | a pull with the cert on disk (waits for a locked store): `n`, `names`, `stores`; no value |
| `{"op":"boot-env"}` | the keeper; the boot steps | every held value, for the harness's env: answered to the keeper (root, the worker's parent) at each start of the harness, and to the boot steps (the pid in the keeper's root-owned `/run/jarvis2-keeper/harness.pid`) before `/run/jarvis2/booted` exists; refused to anyone else |

## Transcript search (`services/search`)

Two replicas (`k8s/services/apps/search/`, namespace jarvis2-services on the services box; any one answers, rolled one at a time with no gap), reached only through the router (above). One of them, the writer (a lease in the database), crawls; the other reloads when the index changes. It crawls
`claude-records/` on the Storage Box every 10 minutes (and when the router archives a session): archived sessions of
both Jarvises (`<dir>/transcript-<id>.jsonl`), Jarvis 1's pause snapshots (`.paused/<id>/`), running sessions of both
(`.live/<id>/`) and the text records in archive dirs (`.md .txt .html .log`, the task records). Other dot-dirs
(`.index/`, `.jarvis2-services/`) are skipped. Hybrid keyword (FTS5, 中文 as phrases/bigrams) + semantic
(`qwen/qwen3-embedding-8b` via OpenRouter) retrieval, reranked by `cohere/rerank-4-fast`.

| Call | |
|---|---|
| `GET /api/search?q=` | `&limit=` (1-50, 10), `&kind=msg,tool,doc`, `&after=`/`&before=` (YYYY-MM-DD), `&state=live,paused,archive` (the session's state now), `&archived=1` (only text read from an archive dir), `&session=` (id / dir / title fragment), `&mode=hybrid|keyword|semantic`, `&rerank=0`, `&group=1` (by session), `&full=1` (whole chunk text). `"quoted phrases"` must match. → `{query, mode, reranked, total, tookMs, timing, notes, terms, hits: [{id, score, via, kind, date, ts, title, sid, dir, state, machineId, file, lines, snippet, text?}]}` (or `sessions: [{title, sid, dir, state, machineId, date, score, count, hits}]` with `group=1`). |
| `GET /api/search/context?id=&before=3&after=3` | The chunks around a hit, in file order → `{session, file, chunks: [{id, kind, ts, lineFrom, lineTo, text, hit?}]}`; 404 for an unknown id. |
| `GET /api/search/status` | Counts (`chunks, sessions, files, vectors, kinds, sessions_by_state, span`), models and the indexer's state (`indexer: {state, lastRun, lastError, billing}`). Also, for the replica that answered: `replica: {pod, started, role: writer\|reader, draining, memory: {rssMB, peakRssMB, heapUsedMB, arrayBuffersMB, limitMB, ofLimit}, restartsInPod, restartedAfter, kubernetes: {restarts, containerStarted, lastTermination: {reason, exitCode, startedAt, finishedAt}}}`; `writer: {holder, since, until}`; `previousReplica` (the last copy that went away: `ended.how` = a clean SIGTERM, or killed with its `lastMemory`); `indexVersion`. |
| `POST /api/search/reindex` | Crawl now (the writer at once; a reader passes it to the writer's next 10 s tick) → 202 `{started, by}`. |

The index is one SQLite file on the pod's volume; a missing one is seeded from `claude-records/.jarvis2-services/search.db.gz`
on the Storage Box, which the pod rewrites daily.

## iCloud index (`services/icloud-index`)

Its own pod (`k8s/services/apps/icloud-index/`, namespace jarvis2-services on the services box), reached only through the router. It lists Deyao's
iCloud Drive daily (rclone, the saved login in `k8s/services/secrets/icloud-session.enc.yaml`) and reads each file: text,
OCR of scans and photos, video frames and speech (AI reading capped by `AI_BUDGET_USD`, a lifetime total kept in the
index), then embeds the text.

| Call | |
|---|---|
| `GET /api/icloud/search?q=` | `&limit=` (1-100, 10), `&kind=text,pdf,office,iwork,image,raw,audio,video,archive,other`, `&ext=`, `&under=<folder>`, `&after=`/`&before=`, `&mode=hybrid|keyword|semantic`, `&rerank=0`, `&full=1` → `{query, total, hits: [{path, kind, size, mtime, score, snippet, …}]}`. A hit's `path` is the iCloud path: `rclone copy "icloud:<path>" .` fetches it. |
| `GET /api/icloud/file?path=` | One file's record and all its extracted text, by part; 404 when it isn't indexed. |
| `GET /api/icloud/status` | Counts by state and kind, `aiSpentUsd`/`aiBudgetUsd`, `embedSpentUsd`, the last listing, the file being read, recent errors; `replica` (this copy: pod, start, `writer`/`reader`, draining, memory, restarts), `writer` (the lease: holder, since, until), `previousReplica` (the last copy that went and how). |
| `POST /api/icloud/relist` | List iCloud now → 202. |
| `POST /api/icloud/retry` | Give failed files another go → 202. |

Identity-level: sessions reach it only with the `identity` store (above). A missing index is seeded from
`claude-records/.jarvis2-services/icloud-index.db.gz.age` (age-encrypted, rewritten weekly); with no copy the pod refuses
to start (`SEED_REQUIRED=1`), so the budget is never spent twice.
