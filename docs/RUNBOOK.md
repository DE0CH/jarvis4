# Jarvis 4 — runbook

Everything here runs from a Jarvis 4 session holding the `infra` store (JARVIS2_* keys, HETZNER_JARVIS2_MOCK_API,
HETZNER_S3_*, CF tokens), with `JARVIS2_URL=https://jarvis4.deyaochen.com` for `infra/setup.py`. Jarvis 4 runs on two
Hetzner boxes (DESIGN "The boxes"): the control box (`jarvis2-control`: the blue and green cores, the router,
cloudflared) and the services box (`jarvis2-services`: the watch runner, the iCloud index). Neither
has SSH or a reachable k8s API: they change only through git, and a box git can't fix is replaced.

## Deploying

`git push` to main. The `images` workflow builds the core, router and session images, then pins them by digest in
`k8s/control/apps/` (and signs the session image for the phone, `SESSION_IMAGE_SIG`); `services.yml` builds and pins
the services box's images in `k8s/services/apps/`. Each box's Flux applies its own tree within a minute.
The session image stands on its base, `session-image/base/` (every tool, harness launcher and the entrypoint: add a
tool a session should always have to `session-image/base/Dockerfile` and push). The workflow's `base` job rebuilds the base
only when that directory changed since the base pinned in `session-image/Dockerfile` (`ARG BASE=…jarvis2-session:base-sha-<12>@sha256:…`),
or on `gh workflow run images -R DE0CH/jarvis2 -f base=true` (newer tools, the latest claude CLI); it takes 20-30 min,
and the pin job then moves `BASE` in the same commit as the k8s pins. Before pinning, the build job checks the session
image is anonymously pullable (Fly pulls without credentials) and needs at most 8.0e9 bytes on disk once unpacked
(`infra/image-unpacked-size.py`): Fly refuses a bigger one (it refused 8.380e9; 8.340e9 booted) and destroys the machine
before it boots, so every new session breaks. A failure there pins nothing. Its pin job
runs only for a commit on main, in the GitHub environment `release`, and pushes with its own deploy key
(`jarvis2-ci-pin`): main's ruleset lets only repo admins and deploy keys update main, so no workflow's GITHUB_TOKEN can.

Deyao's forks pin their builds themselves: on every push to its main, DE0CH/claw-code (`de0ch-latest.yml`) and
DE0CH/openclaw (`de0ch-package.yml`) publish release `de0ch-<sha12>` and run `gh workflow run fork-pin.yml -R
DE0CH/jarvis2 -f name=claw|openclaw -f url=… -f sha=…` with `JARVIS2_DISPATCH_TOKEN` (fine-grained PAT
`jarvis2-fork-dispatch`: Actions write on DE0CH/jarvis2 only). `fork-pin.yml` checks the inputs, pins the asset with its
sha256 (claw: `session-image/base/forks.json`, so the base rebuilds; OpenClaw: `session-image/openclaw-runtime.json`)
and pushes with its deploy key, which runs `images`. By hand: the same `gh workflow run` line (DECISIONS 156).

GitHub settings (R1 audit, 2026-10-11; `gh api`): ruleset "main: only admins and deploy keys update it" (deletion,
non_fast_forward, update; bypass: the admin role and deploy keys); environment `release` (deployment branches: main only)
with secrets ASC_KEY_ID / ASC_ISSUER_ID / ASC_PRIVATE_KEY (ios.yml's TestFlight job), CI_IMAGE_KEY (the private half of
`keys/ci.pub`), PIN_DEPLOY_KEY and FORK_PIN_DEPLOY_KEY (`fork-pin.yml`, deploy key `jarvis2-fork-pin`); environment `replica`
(main only) with REPLICA_FLY_TOKEN and REPLICA_REPO_TOKEN (ios.yml's phone replica, "The phone replica"). A workflow that must push to main gets its own deploy key in `release`, never
`contents: write` on GITHUB_TOKEN. Rotating the CI key: a new P-256 key into CI_IMAGE_KEY and its public half (base64
X9.63) into `keys/ci.pub` in one go, then run `images` so the router gets a fresh signature.

`k8s.yml` (every push touching `k8s/`) dry-runs each box's tree as its Flux applies it (`infra/flux-dryrun.sh`: on top of
the previous main, and on an empty cluster as a new box meets it) and checks every Deployment is there and pinned by
digest (Flux prunes what a commit drops, so an emptied file would delete the router and its volume).

### A core release: blue/green and the flip

The control box runs two cores, `core-blue` and `core-green` (`k8s/control/apps/core/core.yaml`, DESIGN "Core
continuity"). One serves (`k8s/control/apps/core/active.txt` names it; the router's `CORE_URL`), the other is the next
core (`NEXT_CORE_URL`): empty, or Recovered alongside as a standby. A core restart is a new, empty core, so:

1. CI moves a core only when `core/` changed (the CI-only fake and the tests don't count), and only the core that
   doesn't serve, never while that core's Deployment carries `jarvis2/core-pin: hold` (`metadata: { name: core-<colour>,
   namespace: jarvis2-core, annotations: { jarvis2/core-pin: hold } }`; a core change that waits for Deyao's go: delete
   the annotation, push, `gh workflow run images -R DE0CH/jarvis2`). The serving core is never restarted by CI. Even a
   comment in `core/` is a release (the next core restarts empty): keep such edits for a real core change.
   **A release holds the core it lands on** (the pin commit adds the annotation; DECISIONS 224): once pinned, that core
   may be Recovered alongside or mid-flip, which CI can't see, so a later core change is built but not pinned until the
   hold goes. Delete a hold only when `/setup/status` shows that core `empty` (a newer release then lands on it: push,
   or `gh workflow run images`), or in the commit after the flip (step 4). Never while it is a `standby`.
2. Deyao Recovers the new core alongside in the app (its Reset-or-Recover page reaches the next core with `?core=next`;
   `/setup/status` → `core.next.serving` = `standby`). Nothing waits on him meanwhile: the serving core goes on.
3. The router flips by itself (`FLIP_AUTO=1`), or `POST /setup/core/flip` (setup-signed): drain, `POST /handoff` to the
   serving core (its final line state), `POST /takeover` on the standby, every later core call to it. It records the
   flip in its state (`activeCore`), so a restarted router talks to the same core. `/setup/status` → `core.current` /
   `core.next` show each core's URL, `serving` and identity, and `core.activeCore`. A refused takeover leaves no core
   serving and DMs Deyao; run the flip again (it reuses the kept final state; a handed-off core stays handed off).
   The drain looks at the standby every 30 s and once more after it ends: a standby that went (restarted empty,
   Recovered with another kit) aborts the flip before anything is handed off; the serving core goes on and Deyao gets
   a DM. Recover the next core alongside again for a new flip.
   **A flip whose takeover already happened** (the current core `handed-off`, the next one Recovered with the kit and
   serving the final state its bundle carried) is finished by the same automatic tick or `POST /setup/core/flip`: the
   router checks the next core has the handed-off core's signing key and a line state at least as new as the kept final
   state, switches to it, records `activeCore` and drops `core-final.json`. Both cores `serving` changes nothing.
4. Then one commit: `active.txt` = the new serving colour, the router's `CORE_URL` / `NEXT_CORE_URL` swapped to
   match, and the `jarvis2/core-pin: hold` deleted from the new serving colour's Deployment, so the next release goes
   into the core that now doesn't serve. `CORE_URL` must be the `core.activeCore` that `/setup/status` shows: at
   start the router switches to `activeCore` whenever it equals `NEXT_CORE_URL` (`applyActiveCore`), so an env
   edit that names the serving core as the next one flips the router back to it. Never "flip" by editing the env alone.

`infra/setup.py identity` says which core is live and what it serves; the pin annotations and PLAN.md don't.

A router rollout replaces the two replicas one at a time (`maxUnavailable: 0`, readiness on `GET /readyz`, a
PodDisruptionBudget of 1; DESIGN "The router is two stateless replicas"): the stopping pod answers `/readyz` with 503 so
it leaves the Service (its log: `stopping: out of the Service, …`), hands the scheduler's lease on, lets its running
jobs end (`JOB_GRACE_SECONDS` 1740, under `terminationGracePeriodSeconds: 1800`), then exits (`stopped`); a job still
running then is carried on by the other replica once its lease lapses. Its log is in Grafana
(`namespace="jarvis4-router"`, "Logs and metrics"). After a crash (OOM, node reboot) the other replica serves
on and carries the crashed one's jobs on; a cut-off start may leave an uncertified machine that the Machines tab flags
with no session (Destroy it there). Moving the router to other nodes is a rollout like any other: the pods hold
nothing, the records are in Postgres (its own backups).

## The keys (`keys/`)

- `box.pub` — the control box's key. The app and `setup.py` check a core's keys against it (on GitHub's main).
  `infra/create.sh BOX_KIND=control` writes a new box's key to `box-next.pub`; it becomes `box.pub` (a commit) before
  Deyao sets that box's core up.
- `control-age.pub`, `services-age.pub` — each box's age key (SOPS recipient of its secrets), from `infra/create.sh`.
- `setup.pub` — the setup key (private half JARVIS2_SETUP_KEY); also `SETUP_KEY` in `k8s/control/apps/router/router.yaml`. It
  signs every `/setup` call, every store backup and every store blob (the writer signature the phone checks).
- `ci.pub` — CI's image key (private half: secret CI_IMAGE_KEY of the environment `release`): the phone shows a session
  image as a CI build only with its signature.

There is no master key in git: Deyao makes it in the app (Reset), and the core learns it from his claim.

## Setting the core up (Deyao, in the app — nothing for Claude to do)

A new core (after any restart, deploy of `core/`, or box rebuild) is empty. Deyao opens the app (it shows
Reset or recover by itself, or Settings → Reset or recover…):

- **Reset** — the app shows a new recovery kit (`jarvis2-kit:2:…`, Copy), he saves it in his password manager,
  taps "I've saved it", and the core is set up with no stores. Then "After a Reset" below.
- **Recover** — he pastes his kit; the app reads the backups and the router's copy of the core's line state, and the
  core is set up with every store. With the app and core from core continuity (DESIGN "Core continuity") it is the SAME
  core as before (its keys come from the kit): running and paused sessions go on, deploy-key stores come back (same
  phone), archives restore. Nothing else to do. Sessions made by a core from before continuity (random keys) end once.
  `infra/setup.py identity` shows `derived` in its state; the router logs `line state N` as it keeps each one, and
  `curl …/api/core/line-state` (Access login) shows the `X-Line-Seq` it holds.

`infra/setup.py identity` says whether the core is empty or set up (and with which master public key).

**The setup session's pins** (`pins.json` in the backup bucket, signed by the setup key): the master key the stores
belong to and the app's device key. `setup.py` writes, backs up or sends nothing to a core whose master isn't pinned,
unless its claim names the pinned device key and the app's countersignature is at the router (Deyao's Reset: the pin
moves by itself). A Recover keeps the master; a claim under the pinned master re-pins the device key it names. If
setup.py says REFUSED, the core was claimed by something other than his app: empty it from git ("Emptying the core
without its kit") and let him set it up again. `infra/setup.py pin-master` pins the current core's master by hand; use
it only when the core is known to be his (it holds the stores of a Recover, which only his kit opens) and nothing is
pinned yet (a new bucket, a rehearsal box).

### Store key names

The app, sessions (`jarvis stores`) and `infra/setup.py stores` list every store's key names (API.md `GET
/api/stores`), from the core's own signed list (`keysFrom: core`): a key is listed once it is written, and nothing at
the router records names. A new key in a store: add it to the layout file, then write it (`infra/setup.py write`).

### After a Reset (the setup session)

`infra/fill-stores.sh` — once the core is set up (and trusted: the pins above): creates the non-sensitive stores
(only those in `NOT_SENSITIVE` in `infra/setup.py`; a write marks any other store sensitive first if someone created it), writes every store to the core
and its backup (sealed to the new master key, read from the core's signed state), minting or rotating every token
whose value lived only in the old stores and backups, sends the core its Fly token (`backup-core` with a fresh
`infra/fly-token.sh`), and deletes the local copies. The stores and their keys: Deyao's own stores by kind, `default` (not sensitive), `identity`, `infra`,
`money`, `devices`, `work` and `jarvis1` (sensitive), whose key names are listed in the private claude-env repo
(`.claude/skills/jarvis2/stores.txt`, read by the script, which re-runs itself under `session-secret --keys …` with exactly
those names so it sees the setup session's live store values); `github-deploy-keys` (sensitive; GITHUB_DEPLOY_KEYS_TOKEN: a new fine-grained PAT
`jarvis2-deploy-keys`, all repositories, Repository "Administration: read and write" only, minted by `github-web
pat-create-all`, which deletes the same-name token first; its line is in the layout file too); the harness stores
`openrouter` (OPENROUTER_API), `claude` (no keys: a cert naming it gets the router's Claude login; made empty, not
sensitive), `tunnel` (CF_ACCESS_CLIENT_ID/SECRET: `jarvis2-tunnel`, rotated) and `core` (the Fly token). The narrowed
Fly token in an old `core` backup can't be revoked on its own (an attenuation of JARVIS2_FLY_TOKEN); it stays sealed
to the old master key. Old backup versions stay in the versioned bucket, sealed to their old key. Nothing needs
unlocking ahead (each Start unlocks what its session needs, for that session only); Deyao adds his repos again in
Settings → Repos (the repos' stores aren't backed up, below).

### Offline copy of the stores (Deyao, whenever he wants one)

A copy of the encrypted store backups that Deyao keeps himself and opens with his kit on his Mac, with no network:

1. **Download it in the app**: Settings → Encrypted backup → Download encrypted backup. The app reads every backup
   through the router (`GET /api/backups`), checks each signature against `keys/setup.pub` from GitHub as Recover does
   (any that fail are listed in red), and makes ONE file, `jarvis2-backup-<yyyy-mm-dd-hhmm>.json` (UTC): the objects
   exactly as served, the bucket, the fetch time and the setup public key. Save file… opens the share sheet (Save to
   Files, AirDrop to the Mac). The app never asks for the kit and never opens a backup; the file is as safe as the
   bucket itself (everything in it is sealed to the master key), and only the kit opens it.
2. **Decrypt it offline** with `tools/decrypt-backup.py` from a clone of DE0CH/jarvis2 (Python 3.9+ and
   `cryptography`; set up once, while online: `python3 -m venv ~/.jarvis2-venv && ~/.jarvis2-venv/bin/pip install
   cryptography`):

       ~/.jarvis2-venv/bin/python tools/decrypt-backup.py ~/Downloads/jarvis2-backup-2026-10-13-1015.json --setup-pub keys/setup.pub

   It asks for the kit without echoing it (or `--kit-file FILE`, or `--kit-file -` on stdin; never as an argument, so
   it stays out of the shell history), checks every signature against the file's setup key AND `keys/setup.pub`
   (they must be the same key), opens every store, and writes `jarvis2-stores-<date>.json` (mode 0600; `--out PATH`,
   a path ending in `/` = one `<store>.json` per store in a 0700 directory; never over an existing file without
   `--force`). Values reach the terminal only with `--stdout`. A failed check stops it before anything is written
   (`--skip-bad` leaves the bad objects out and lists them). It also takes the router's raw `/api/backups` answer and a
   single `stores/<name>.json` from the bucket (an older version, for example; both need `--setup-pub`), and a
   version-1 kit's master part.
3. **Keeping it**: the encrypted file can sit anywhere the backups could (Files, iCloud Drive, a USB stick); it is
   only as current as its fetch time. The decrypted `jarvis2-stores-*.json` is every secret in the clear: open it,
   use what's needed, and delete it; never put it in a synced folder (iCloud Drive, Dropbox).

### Carried secrets (DESIGN "Carried secrets")

Stores stay locked: a Start's Face ID unlocks them for that session only, the core locks them again once its machine has
pulled, and a paused session carries its secrets to its next machine (`snapshots/<machine>.carry` in the router's data
volume, sealed under a key only the running core holds). Nothing to operate. A session that says "Waiting for store X"
on a resume has no usable blob (lost, or paused under a core that predates carried secrets): Unlock… on its card, or
`infra/setup.py request unlock SESSION --why "…"` for the Inbox. After a core restart (and Reset or Recover) the
router destroys every earlier session by itself once it is paused (DESIGN "Carried secrets"): each is archived in
Previous, and Restore there starts it as a new line approved on the phone.

## Repos and their deploy keys

Each repo is added in the app (Settings → Repos → Add repo, or "Make key" on a listed repo whose store is missing):
the app makes an ed25519 key, the shell's secure page shows the core's signed request, and one Face ID lets the core
use `github-deploy-keys` for that call to add the key to the repo as a read/write deploy key titled `jarvis2 <store>`
and keep the app-wrapped private half in the store `github-<repo>` (the app keeps `github-jarvis2` sensitive). Nothing
for Claude to do. Remove deletes both. Repo stores have no backup: a Recover brings them back from the
core's line state when it is done on the same phone (DESIGN "Core continuity"); otherwise "Make key" again, which also
deletes the old key on GitHub. Sessions that include a repo's store clone, pull and push it over SSH
(`machine/deploykeys.go`).

Once the kernel serves, the same flow runs through the kernel's secrets and its **minter** (DECISIONS 232): secrets
opens the token store and hands the token, sealed, to the minter, the only kernel component that reaches GitHub; it
adds the key, or deletes it by the id GitHub gave at the add. A re-add leaves the earlier key on GitHub (the router
logs its id as an orphan), and so does a store recovered from before ids were kept: remove such a key by id
(`POST /api/repos/key/begin {action: remove, repo, keyId}`, one Face ID; the repo's store stays). A minter restart
makes the roster stale like any component's: `infra/setup.py kernel-roster`, then Sign roster in the app.

If the picker says "No match." for a repo that exists (a private one), the router's `GITHUB_READ_TOKEN` sees public
repos only: `infra/setup.py status` shows `githubRepos.private: 0`. Mint `jarvis2-repo-list` again with Metadata read
picked and write `--part github` (The router's secrets, below); then "refresh list" in the app.

If the core says the token can't manage a repo's deploy keys, the token in `github-deploy-keys` lacks Repository
"Administration: read and write" on it: mint `jarvis2-deploy-keys` again (`github-web pat-create-all
jarvis2-deploy-keys ~/.jarvis/gh-deploy-keys.token Administration=write`) and write the store (`setup.py write
github-deploy-keys GITHUB_DEPLOY_KEYS_TOKEN=file:~/.jarvis/gh-deploy-keys.token`, then shred the file).

Against real GitHub: `JARVIS2_LIVE_GITHUB_TOKEN_FILE=… JARVIS2_LIVE_REPO=<a throwaway repo> JARVIS2_LIVE_OTHER_REPO=<a
private repo> go test -run Live` in `core/` (the phone flow, then `git clone`/`push` over SSH with exactly that key,
the other repo refused, remove).

### Asking Deyao from a session or from the setup session (the Inbox)

Claude never adds a repo or allows anything itself: it files a request and Deyao approves it in the app's Inbox
(docs/API.md "Requests").

- Setup session: `infra/setup.py request add-repo DE0CH/claude-env --why "…"` (also `remove-repo`, `grant SESSION
  HOLDER [--minutes N | --days N]`, `unlock SESSION`); `infra/setup.py requests` lists what waits, `infra/setup.py
  repos` the router's repo list (check it before asking for a repo that may be there already).
- Inside a session: `jarvis-request add-repo OWNER/NAME --why "…"`, `jarvis-request grant HOLDER --minutes 5 --why
  "…"`, `jarvis-request unlock --why "…"`, `jarvis-request add-store STORE --why "…"`, `jarvis-request list`
  (`session-image/bin/jarvis-request`, through the machine's proxy). `add-store` also starts a background
  `jarvis-machine await-store STORE`, which has the supervisor pull the store (RAM only) once the approval lands in
  the cert (log `~/.jarvis-await-STORE.log`); a command then gets the keys it needs with `session-secret --keys K1,K2 --exec CMD`, and `pull-secrets` makes the supervisor pull again at once (it hands out no value); before the waiter, an approved store stayed unpulled (2026-10-12).

The reason is required, plain text, ≤ 600 characters. A request (and an approval in the Inbox) goes after 10 minutes (Deyao, 2026-10-12): ask again if it lapsed.

**Several at once = one batch** (Deyao, 2026-10-13): when Claude needs more than one thing, it files them as a batch,
so Deyao reviews one Inbox entry and allows everything with ONE Face ID (or denies it whole). `--summary` (required)
says what the batch is for; each item may carry its own `explanation`. Any kind can be in a batch (repo add/remove,
grant, unlock, add-store, new-session, jarvis1-import); at most 20 items; every item is checked before any is filed.

- Setup session: `infra/setup.py request batch --summary "…" --item repo/add,repo=DE0CH/x --item
  grant,session=sID,holder=terminal,minutes=5` (or `--file items.json`, a JSON list of `{"intent": …, …}`);
  several Jarvis 1 imports: `infra/setup.py jarvis1 import ID1 ID2 … --stores a,b --why "…" [--summary "…"]` (the
  summary defaults to the ids).
- Inside a session: `jarvis-request batch --summary "…" --item grant,holder=status,minutes=5 --item
  add-store,store=gmail` (or `--file`); `--item new-session,label=…,prompt=…,stores=a|b` (lists with `|`; a long
  prompt goes in a `--file` item). A batch counts as one of the session's 3 waiting proposals.
- `infra/setup.py requests` / `jarvis-request list` show the batches (`b…` ids) after the loose requests.

**The outcome comes back by itself** (Deyao, 2026-10-13): once Deyao decides an item a session filed, that session gets
a message from Jarvis, `[Inbox outcome] … APPROVED / DENIED / LAPSED / DROPPED / FAILED: …` (a batch in one message,
numbered like its items), with what was checked (the phone's grant, the new cert naming the store, the new session's
id). No polling needed; a paused session hears at its next start. `jarvis-request outcomes` lists them;
`jarvis-request wait ID` blocks on one (exit 0 approved). An outcome that wasn't delivered shows `not delivered: …` in
`outcomes` (e.g. an image from before outcomes); the router logs `[outcome]` lines.

### Emptying the core without its kit

A set-up core ends from the app only with the kit it was set up with (Reset or Recover asks for it). Without that
kit — a lost kit, or a core someone else claimed first (the app says "set up with a different recovery kit") —
change the `jarvis2/restart` annotation of the serving core's Deployment (`active.txt` names its colour) in
`k8s/control/apps/core/core.yaml` and push: Flux restarts that core, and the new one is empty.

## Stores

- `infra/setup.py stores` — the core's signed list.
- `infra/setup.py create NAME` — once per name, an empty store that is NOT sensitive. Without it, a store is
  sensitive.
- `infra/setup.py write NAME KEY[=SRC]… [--explain KEY=TEXT]…` — these keys, one at a time (values from this
  session's env or `file:PATH`, never printed); the store's other keys are never read or touched. Each is wrapped to
  the phone + core key and backed up first to S3 (bucket `jarvis2-backup-de0ch`, versioned, `keys/<store>/<key>.json`,
  encrypted to the master key the core was set up with, signed by the setup key). Sessions write the same way with
  `jarvis put-key` (`scripts/store-put.py` in claude-env).
- `infra/setup.py delete NAME KEY…` — removes keys (their backups keep the earlier versions).
- `infra/setup.py versions NAME` — the store's earlier versions the core keeps (the last 50 each).
- `infra/setup.py request restore NAME VERSION --why TEXT` — asks Deyao (Inbox) to put that version back (below).
- `infra/setup.py mark-sensitive NAME` — the one-way upgrade, in the core and in the backup.
- The Fly token: `infra/fly-token.sh ~/.jarvis/fly.tok` (narrowed to the app and to `jarvis2-init`), then
  `infra/setup.py backup-core ~/.jarvis/fly.tok` — sent to the core sealed to its key, and backed up as the
  `core` store (a Recover brings it back).

All of them need a set-up core: they learn the master public key and the phone's keys from the core's signed
state, after checking its keys against `keys/box.pub`.

### Restoring a store to an earlier version (DESIGN "Restoring a store")

Keys lost or overwritten by a write (a session's `put-key`, a delete, a mistaken `write`): no kit, no Recover.

1. `JARVIS2_URL=https://jarvis4.deyaochen.com infra/setup.py versions STORE` — find the version before the mistake (each
   line: number, time, what made it, the key names it held).
2. `infra/setup.py request restore STORE VERSION --why "…"` and Discord Deyao "waiting on you: restore STORE in the
   Inbox". He reviews exactly what the core will put back and remove, and allows it with one Face ID (or does it
   himself: Stores → the store → Versions → Restore…; the web page's Versions → Propose restore files the same request).
3. Check `infra/setup.py versions STORE`: the newest version says `restore of version N` and is current. Sessions holding
   the store get the restored values only after the refresh unlock the router files in his Inbox.

A core restart (a new core) keeps no versions: its first version of each store is what the Recover brought. The bucket
backups (Recover with the kit) stay the way back from anything older or from a lost core. A restore's own backups are in
the bucket like any key write's, so a later Recover brings the restored store back.

## The router's secrets

Non-sensitive only (nothing that can reach a code push), SOPS-encrypted to each box's age key (`keys/control-age.pub`,
`keys/services-age.pub`); each box's Flux decrypts its own with the age key the box got in user-data. Each part is one
Secret, rewritten whole by `infra/router-secrets.py --box control|services` (nobody can read the old values back), so
name every key of the one you write; the run bumps the part's annotation in the manifest, so the pod restarts with it.

The control box (`k8s/control/secrets/`, annotations in `k8s/control/apps/router/router.yaml`):

- `infra/router-secrets.py --box control KEY[=SRC]…` → `router.enc.yaml`:
  `LOBSTER_TOKEN STORAGEBOX_HOST STORAGEBOX_USER STORAGEBOX_PASSWORD FLY_READ_TOKEN=file:~/.jarvis/fly-read.tok
  JARVIS2_TUNNEL_KEY=file:…` (`JARVIS2_TUNNEL_KEY`: the tunnel proof key, the same value as the cf-tunnel Worker's
  secret `JARVIS2_TUNNEL_KEY_NEXT` — without it no OpenCode/OpenClaw web UI) (the read-only Fly token:
  `infra/fly-read-token.sh`). Nobody can read the old `JARVIS2_TUNNEL_KEY` back: a rewrite mints a new one and sets it on
  the Worker in the same step (`wrangler secret put` in claude-env `cf-tunnel/`); running OpenCode/OpenClaw sessions keep
  their old proof until they restart.
- `--part github GITHUB_READ_TOKEN=file:…` → `router-github.enc.yaml`: the repo picker's list token, the fine-grained
  PAT `jarvis2-repo-list-control` (`github-web pat-create-read <name> <out>`: all repositories, no expiry, **Metadata read
  picked explicitly**). A fine-grained token with NO permission picked sees public repos only, even on "All
  repositories" (0 private; Settings → Repos says "No match." for a private repo). Check after a rollout with
  `infra/setup.py status`: `githubRepos.private` > 0. It is the LAST `envFrom` in the router, so it wins over any
  `GITHUB_READ_TOKEN` in another part.
- `--part backup BACKUP_READ_ACCESS_KEY BACKUP_READ_SECRET_KEY` → `router-backup.enc.yaml`: the backup bucket's read
  credential, with which the router serves the locked backups to the app's Recover (`infra/backup-read-key.py install`
  writes it; below).
- `--part flyorgs FLY_ORG_READ_TOKENS=file:…` → `router-flyorgs.enc.yaml`: the Machines view's other orgs, JSON
  `{"jarvis2-370": "<token>", …}`, each `fly tokens create readonly -o <org>` (named "Jarvis 4 Machines tab
  (read-only)"; revoke with `fly tokens list -o <org>` + `fly tokens revoke`).
- `--part flypersonal FLY_PERSONAL_READ_TOKEN=file:…` → `router-flypersonal.enc.yaml`: org personal for the Machines
  view. `FLY_PERSONAL_ORG_TOKEN=<an org token of personal> infra/fly-personal-read-token.sh OUT` attenuates it offline to
  Organization read (it checks the result lists apps and can't create a machine). It reads every machine's config in
  personal, env included (DECISIONS 138); it dies only with the token it was made from.
- `--part flyvolumes FLY_VOLUME_TOKEN=file:…` → `router-flyvolumes.enc.yaml`: the leftover-volume sweep's token
  (`router/volsweep.go`). `JARVIS2_FLY_TOKEN=… infra/fly-volume-token.sh OUT` attenuates the org token to delete on app
  jarvis4-sessions plus a Volumes caveat (any volume, delete), which refuses every call that names no volume: it can
  only `DELETE /v1/apps/jarvis4-sessions/volumes/<id>` (proof: DECISIONS 195). It dies with the token it was made from.
- `--part browserbase BROWSERBASE_API_KEY` → `router-browserbase.enc.yaml`: the Browserbase spend DM
  (`router/bbbudget.go`; cap and warn line are `BROWSERBASE_BUDGET_USD` / `_WARN_USD` in the router's env).
- `--part devices CF_DEVICE_TOKENS_API=file:…` → `router-devices.enc.yaml`: the Cloudflare token with which the router
  mints and deletes the paired apps' tokens (Access: Service Tokens read + write on the account, nothing else).
  Written 2026-10-26 (Cloudflare token `jarvis2-device-tokens-control`). A Cloudflare API token can only be minted in the
  dashboard (`CLOUDFLARE_API` gets 9109 on both `/user/tokens` and `/accounts/<id>/tokens`); remint it with claude-env's
  `cloudflare-dash` skill (`cf_token.js jarvis2-device-tokens-control OUT a1c0fec57cf94af79479a6d827fa518c
  91f7ce32fa614d73b7e1fc8f0e78582b`), then this part. Without it every new pairing fails with "the router has no
  CF_DEVICE_TOKENS_API".
- `--part alloy GRAFANA_LOGS_URL GRAFANA_LOGS_USER GRAFANA_METRICS_URL GRAFANA_METRICS_USER GRAFANA_WRITE_TOKEN` →
  `alloy.enc.yaml` (both boxes have one): the host's Grafana Alloy ("Logs and metrics").

The services box (`k8s/services/secrets/`, Secrets in jarvis2-services):

- `infra/router-secrets.py --box cluster --part icloud-index OPENROUTER_API LOBSTER_TOKEN STORAGEBOX_HOST STORAGEBOX_USER STORAGEBOX_PASSWORD
  BACKUP_AGE_KEY=env:ICLOUD_BACKUP_AGE_KEY` (the last from the store `icloud-backup`) → `icloud-index.enc.yaml` (the
  iCloud index; LOBSTER_TOKEN for its DMs: login expired, budget used up).
- `--part icloud-session ICLOUD_RCLONE_CONF=file:<rclone.conf with the [icloud] section>` → `icloud-session.enc.yaml`:
  the saved iCloud login. After a re-login (claude-env `icloud-drive` skill), write it again and push; the pod reads the
  mounted file and switches by itself (no restart needed).

After a box rebuild, re-run all of that box's parts (its age key is new).

### The backup bucket's read credential

Jarvis 4's router (the cluster) holds its own credential `jarvis4-backup-read`: on `jarvis2-backup-de0ch` it may only
read (Sid `Jarvis4ReadKeyOnlyReads`, PutObject denied too: Jarvis 2's latest backups stay Jarvis 2's), and it writes
every key backup to Jarvis 4's own versioned bucket `jarvis4-backup-de0ch` (router env `BACKUP_WRITE_BUCKET`; Sid
`Jarvis4KeyOnlyAdds`: reads and new versions only, `infra/backup-read-key.py own-bucket`). `GET /api/backups` serves
both, Jarvis 4's object over Jarvis 2's of the same name, so a Recover brings back what was written in either.

The router's only way into the bucket; Deyao never sees it. It is the Hetzner S3 credential `jarvis2-backup-read`
in project "Cloud Code" (2827255), which also holds `de0ch-claude-6fdff6`. S3 credentials are project-wide, so
bucket policies narrow this one (principal `arn:aws:iam:::user/p2827255:<access key>`): on `jarvis2-backup-de0ch` a
Deny of every delete, delete-version, ACL, tagging, policy, versioning, lifecycle, CORS, website, logging,
notification, replication, object-lock and public-access-block change (26 actions, listed one by one: Hetzner
ignores `NotAction`, and refuses a policy naming `PutEncryptionConfiguration` or `PutBucketOwnershipControls` with
ServiceUnavailable); on `de0ch-claude-6fdff6` a Deny of `s3:*`. `PutObject` is allowed (`backup-read-key.py
allow-put`): the router adds each written key's backup (`keys/<store>/<key>.json`); the bucket is versioned, so a put
only adds a version (no prefix limit: Hetzner has no `NotResource` either; a version the router puts elsewhere is no
more than withholding, since every backup is checked against its writer's signature). Tested (throwaway names only):
list, get, list versions, get policy and put work; delete (plain, by version, multi), policy, versioning, lifecycle and
ACL changes are refused, and everything on the other bucket. A Ceph quirk seen with an earlier credential: a plain
delete (no version id) of an existing object may add a delete marker; that hides a backup but loses nothing (the
bucket is versioned), and the admin key removes the marker.

Making a new one (a control box rebuild needs one, since the value exists only in the box's Secret; so does a leak): `infra/backup-read-key.py`, one step at a time,
with a headed Chrome on CDP port 9333 (`Xvfb :99` + `google-chrome --remote-debugging-port=9333 --disable-quic`;
the Console logs in with password only) and `HETZNER_USER`/`HETZNER_PASSWORD` (`session-secret --keys
HETZNER_USER,HETZNER_PASSWORD --exec python3 infra/backup-read-key.py login` when they aren't in the env):

1. `login`, then `generate` — Console only (no API): Security → S3 credentials → a new `jarvis2-backup-read`
   (the Console accepts the same description twice), written straight to `~/.jarvis/backup-read.env`
   (mode 600, never printed).
2. `policies` — the new access key replaces the old one as the principal in both bucket policies (admin key).
   Wait a minute, then `test` (the checks above, throwaway names only, cleaned up): seconds after a policy write a
   multi-delete once went through, a gateway not yet holding the new policy.
3. `delete-old` — the old credential's row ⋯ → Delete → OK (real mouse clicks; the menu ignores synthetic ones). Don't
   leave a gap after `policies`: the policies are a Deny naming the key, so the old key, no longer named, can do
   anything in the project until it is deleted. The new key has to be in the router already (`install` first when the
   old router still serves with the old key).
4. `install` — `infra/router-secrets.py --box control --part backup` from the file, then the file is shredded; commit
   and push `k8s/control/secrets/router-backup.enc.yaml` and `k8s/control/apps/router/router.yaml` (the router restarts
   with it). Stop the Chrome
   and delete its profile.

## The Claude accounts

Each Claude account is the core store `claude-<name>` (`router/claudeaccounts.go`, `router/claudestores.go`,
`router/claudelogin.go`, API.md "Claude accounts", DECISIONS 115-121, 185 and 190): the router writes each account's pair
and record into it at every change (the core's writer `router`), keeps its working copy on its volume
(`claude-accounts/<store>.json`), and it is the ONLY refresher of each (Jarvis 4 never calls Jarvis 1; Jarvis 1, while it
still runs, follows one account through `/peer/claude-login`). `infra/setup.py claude-accounts` shows them (no secrets):
per account its email, expiry, last refresh, the participants of its refresh protocol (`m:<machine>` per session,
`jarvis1`), the sessions using it, and the default.

- **Pick an account:** New session (app, web page) lists the accounts with the default pre-picked; `jarvis-request
  new-session --account NAME`; a prompt task's account is picked when the task is made. A session keeps its account for
  its life (resumes included) and shows up in that account's Claude app (lessons/59). A running session can't switch.
- **Manage:** Settings → Claude accounts (web page or app). Add: a name, then the sign-in page opens; sign in, copy the
  code it shows (`code#state`), paste, Sign in. Re-login: the same for an existing account; a sign-in of another
  Claude account is kept as that account's own (its store, or a new `claude-<its name>`), the store asked for unchanged.
  Make default. Remove: refused while any session (running, paused, waiting, failed) uses it, since a session keeps its
  account for its life; removing the default makes the next account the default. A new box starts with no account: sessions start
  logged out until one is added.
- **A dead login** (the refresh was refused) DMs Deyao once, naming the account; nothing else happens by itself: only
  that account's sessions stop on "Please run /login" once their token runs out, and get "continue" after its Re-login.
- **Sessions:** a machine asks the router for its session's account's pair at boot (404 `noAccount`: no login, e.g.
  OpenCode) and keeps a long poll open (`jarvis-machine creds-sync`, its log in the machine's output), writing every
  newer pair. A pair for another account than the machine's (the session's account was switched, `POST
  /api/sessions/:id/account`, DECISIONS 202) is installed under the running claude: credentials and `oauthAccount`
  replaced under the CLI's refresh lock, the token's account checked with Anthropic (`~/.claude/.jarvis-account`, the
  status's `__ACCOUNT__`), Remote Control enabled again through `/remote-control` (its log says each step). No restart.
  The router never writes a login into a session (no login repair).
- **The account in the cert:** set the router's env `CLAUDE_STORE_IN_CERT=1` only once Deyao's iPhone runs an app build
  that accepts the router as a key's writer (the TestFlight after DECISIONS 190): new sessions' certs then name their
  account's store and the phone unlocks it at Start; an older build refuses that unlock.
- **The account in the signed settings:** set the router's env `SIGN_CLAUDE_ACCOUNT=1` (k8s/control/apps/router/router.yaml) only once
  Deyao's iPhone runs an app build that knows `claudeAccount` (the TestFlight after 2026-10-15's first accounts build):
  an older build refuses every New session whose settings carry it. New lines only; existing ones keep their config.
- **Before accounts (the clean cut, 2026-10-15):** the first router with accounts turned `claude-login.json` into the
  account `claude-<its email's name>` (the default and Jarvis 1's; the old file is kept as `claude-login.json.migrated`)
  and gave it to every session whose cert names the core's old store `claude`. New sessions don't get that store; it
  stays in the core (a store can't be deleted) for those older lines.

- **Two replicas, one login (a stopgap, 2026-10-28):** each router replica keeps every account's login in memory
  and only the leader refreshes. A refresh revokes the old access token at once, so the other replica used to keep
  serving the revoked pair to the sessions whose polls reached it ("Login expired · Please run /login" for some sessions
  after every refresh, until that replica restarted). Now every save sends `pg_notify('mq', 'l:<doc name>')` and each
  replica reloads the document when notified, every 30 s, and before a refresh (`loginHub.reload`,
  `claudeAccounts.follow`). Still per replica: a new account added on one replica isn't in the other's list until
  it restarts.
- **Sessions get no refresh token (a stopgap, 2026-10-28):** the router hands machines the pair without
  `refreshToken`/`refreshTokenExpiresAt` (`forMachine`: the long poll, `/m/api/credentials`, the account store's
  `CLAUDE_CREDENTIALS`), so a session's claude can't refresh by itself any more. Before this, a session that did
  revoked the router's pair: on 2026-10-28 `claude-chendeyao-uk`'s stored pair was dead (its refresh refused), every new
  session of the account started on it with channels and Remote Control off ("Channels are not currently available"),
  and only a Re-login fixed it. Claude Code runs on the access token alone (Remote Control and channels included) and
  picks up the file the supervisor swaps at each router refresh. Pushes are still accepted (a session image whose
  claude still holds an old token) and the prepare/ack protocol still runs, both harmless now. **The clean fix, to do:** the database row as the only truth (no in-memory copy: polls and status
  read the row, the refresh runs under `pg_advisory_xact_lock` per account and re-reads the row inside it, the
  notification only wakes waiters, the pending Re-login lives in the row); then sessions get the access token only
  (no refresh token on any machine), which deletes the push path and the prepare/ack/CLI-lock protocol.

## The iCloud index

Transcript search is not Jarvis's: DE0CH/services (README there), a tenant on the cluster in namespace `services`
(`k8s/cluster/tenants/services.yaml`), at https://search.deyaochen.com.

In jarvis4-services (`services/icloud-index`; `k8s/cluster/services/icloud-index/`), built by `.github/workflows/services.yml` (only the service that changed; its unit
tests run inside the image build) and pinned by digest like the router. The router reaches it at `ICLOUD_INDEX_URL`
(k8s/cluster/router/router.yaml). Only the router reaches it (`router/searchsvc.go`); API.md "iCloud index" for the
calls. Check it from a Jarvis 4 session holding `identity`: `curl -s "$JARVIS_URL/api/icloud/status"`.

- **The iCloud index has no downtime on a rollout or a crash** (`services/icloud-index/icloud_index/lease.py`, DECISIONS 174): two
  replicas on the one volume, every replica answers searches, only the writer-lease holder lists iCloud, reads files,
  spends the AI budget, embeds and backs up (every write and AI call checks the lease first, so a replica that lost
  it writes nothing). `GET /ready` (port 8091) turns 503 at SIGTERM; the replica serves `DRAIN_MS` more, stops its
  indexer (a file half read gets its try back), releases the lease, and the other takes it within `TICK_S`; a killed
  writer's lease lapses after 45 s. A reader's `POST /relist` / `/retry` waits for the writer's next tick.
  `GET /api/icloud/status` names `writer`, this `replica` and `previousReplica`. Only one replica seeds a missing
  database (a file lock beside it).
- **The iCloud index is identity-level**: sessions reach it only while they hold the `identity` store (router 403
  otherwise; Deyao's app always). Its Storage Box copy is age-encrypted; the private key is `BACKUP_AGE_KEY` in the
  `icloud-index` part and `ICLOUD_BACKUP_AGE_KEY` in the sensitive store `icloud-backup` (re-run the part from that
  store after a box rebuild, or the copy can't be opened).
- **Its database lives on the pods' volume, with a copy on the Storage Box** (`claude-records/.jarvis2-services/`:
  `icloud-index.db.gz.age` weekly). A missing database (a new box, a lost volume) is seeded from
  that copy at start. The iCloud index refuses to start without one (`SEED_REQUIRED=1`): its database holds the AI
  budget's lifetime ledger (`ai_spent`, USD 25 cap, Deyao 2026-10-01), and starting empty would spend it again. To
  really start from nothing, set `SEED_REQUIRED` to "0" for one rollout.
- **The AI budget**: `AI_BUDGET_USD` in `k8s/services/apps/icloud-index/icloud-index.yaml`. At the move (2026-10-13) it was used up
  (USD 25.00 spent), so images, scans, video and speech wait (`wait-ai`); names and text documents are still read.
  Raising it is Deyao's call.
- **The iCloud login expired**: the pod DMs Deyao once and pauses. A session re-logs in (claude-env `icloud-drive`
  skill), then the `icloud-session` part is written again (above).
- **A file that kills the pod** (out of memory, a native crash) is retried at most 3 times, then marked
  `error: not read: stopped the indexer N times`; images over 40 megapixels are decoded small (JPEG) or skipped.
- **Moving from Jarvis 1** (done 2026-10-13): Jarvis 1's session token can't exec into its pods, so a temporary
  read-only Job in claude-env (`selfhost/k8s/jarvis2-export`) copied both databases (SQLite online backup) and the
  iCloud pod's own rclone session to the Storage Box; the Jarvis 4 pods seeded from it. Jarvis 1's two pods keep running until its freeze: scale them to 0 then, so only one index reads
  iCloud and spends on embeddings.

## Importing a paused Jarvis 1 session

Jarvis 1's paused sessions stay where they are (`claude-records/.paused/<id>/`, read only). From the setup session
(`JARVIS2_URL=https://jarvis4.deyaochen.com`):

1. `infra/setup.py jarvis1` lists them with their import state; `infra/setup.py jarvis1 prepare ID… --wait` hashes
   each one's files (minutes for a few GB; the router streams them, nothing is staged).
2. Pick each one's Jarvis 4 stores: `default` for Jarvis 1's `default`, plus whatever split-off store the session's
   transcript shows it used (the store layout is private: claude-env `.claude/skills/jarvis2/`), plus the repo stores
   (`github-<repo>`) for its repos. Say the mapping in the reason.
3. Only when all are prepared (an approval lapses after 10 minutes): `infra/setup.py jarvis1 import ID --stores a,b
   --why "…"` for each, then ping Deyao on Discord ("waiting on you: …"). Each is one Inbox approval (Restore,
   "Restores machine <Jarvis 1 id>"), one Face ID each. A lapsed one: run the same import again.
4. After his approval: `infra/setup.py jarvis1` shows the new session ids (`imported` once one came up); check each
   machine's `~/artifacts/jarvis1-import/rearmed.txt` and the transcript tail (the move notice is the first prompt, so
   the reply shows the conversation resumed).

The machine has Fly's default 8 GB disk: an import that unpacks near 5 GB plus its pause snapshot is near the limit
(DECISIONS 130).

## Device leases and watches

Nothing to set up: both live in the router (`router/leases.go`, `router/watches.go`; API.md). Leases: `GET /api/leases`
shows every device's holder, queue and log; a stuck holder is cleared with `POST /api/leases/<name>/force-return`
(the app's Devices tab when it has one), and a lease that nobody renews lapses after its ttl (1 h) by itself.
Watches: each session's `watches` in `/api/state` show `runs`, `lastExit`, `lastError` and `lastOutput`; a watch whose
check always exits 2 with "not found" is usually missing a secret, which a check never gets (DECISIONS 114). The
watch runner is the Deployment `watch` in `jarvis2-edge` (`services/watch`, pinned by the `services` workflow); it
holds no state, so a restart only delays the due checks. When it is down every check counts as "not yet" (the
router logs `the watch runner is unreachable`) and nothing is delivered until it is back.

## Content stores

Jarvis 1's folders `claude-records/.content/<name>/` on the Storage Box, used in place (`router/content.go`, API "Content
stores"). Deyao manages them in the web page's Content tab; a session picks them in New session (web or the iPhone app)
and gets each in `~/content/<name>/` at every start (`content-sync pull` in the base image's entrypoint);
`content-sync status` / `content-sync push <name>` from inside the session. Nothing on the machine holds Storage Box
credentials. A task picks them with a field `optionsFrom: "content"` (`tasks/encrypt-to-content`, `paraphrase-to-content`,
`proton-send`; their key store is a field `optionsFrom: "stores"` whose store holds `AES_KEY`).

## Paired apps (OpenClaw, Paseo)

Deyao's OpenClaw and Paseo apps pair with `GET /api/devices/pair` (his Access login) and get their own Access service token;
Settings → Paired apps (web) lists and removes them. The Access app "Jarvis 4 devices" (`infra/cloudflare.py --devices`;
paths `/api/remotes`, `/api/sessions/*/start`; audience `ACCESS_DEVICES_AUD` in the router's env) lets any service
token through to those two paths and the router admits only paired ones. Check from outside: a service token that isn't
a paired app gets the router's 403 `{"error":"Access login required"}` on `/api/remotes` (not Cloudflare's login page).
The apps call `JarvisConfig.baseURL` (DE0CH/openclaw `apps/ios/Sources/Jarvis/JarvisModels.swift`) and `jarvis.url`
(DE0CH/paseo `packages/app/app.config.js`): both name jarvis4.deyaochen.com (TestFlight builds through claude-env skills
`openclaw-ios`, `paseo-ios`). Deyao pairs each app once: OpenClaw: Settings → Gateway → Jarvis → Sign In with Jarvis;
Paseo: Settings → Jarvis → Pair; each opens the Access sign-in sheet for this host. Paseo's CI simulator test runs its
Jarvis checks only with a paired device token (`JARVIS_E2E_CLIENT_ID/SECRET` in the fork's secrets); while the old
Jarvis 1 token is there, it only installs and launches the app.

## The boxes' network: IPv6-only, IPv4 out through WARP, the private Network

The two boxes talk over the Hetzner Network `jarvis2` (10.77.0.0/24; control 10.77.0.2, services 10.77.0.3, fixed by
`create.sh`). NodePorts listen on the private address only (`nodeport-addresses`), and each box's private guard
(`jarvis2-private-guard`, mangle PREROUTING, from `/etc/jarvis2/private-allow` written at creation) lets in only answers
and the allowed peers: on the services box the control box's router (10.77.0.2), on the control box nobody. The boxes
running now were made during the move and also allow 10.77.0.9 (the retired single box's address) until they are
rebuilt, so never attach a server to the Network at 10.77.0.9 (the NetworkPolicies admit only 10.77.0.2).

Every box has no public IPv4 (Deyao, 2026-10-13: the Hetzner account is at its limit of 10 primary IPs; DECISIONS 159).
`infra/warp-host.sh` (run by cloud-init, and by the unit `jarvis2-warp-host.service` on a converted box) installs
Cloudflare's WARP client in mode `tunnel_only` with IPv6 excluded (`tunnel ip add-range ::/0`): IPv4 (GitHub, GHCR,
Fly's WireGuard gateways, 1.1.1.1 for CoreDNS) goes through WARP, IPv6 stays native. k3s's node IP is `10.254.254.1`
on the dummy interface `k3s0` (`/etc/rancher/k3s/config.yaml`), so the cluster stays IPv4. Everything the pods reach goes through WARP (they have no IPv6), the cloudflared tunnel included. Signs that WARP
is down: jarvis4.deyaochen.com unreachable (tunnel down), Flux "failed to checkout" from github.com, ImagePullBackOff on ghcr.io, machines unable to reach the router over the
peer. There is no way in to look; WARP reconnects by itself (warp-svc, always on), and a box git can't fix is
rebuilt. The same WARP steps for every other Hetzner server Claude makes: claude-env `scripts/hetzner-warp.sh`.

## Bringing the kernel up (docs/PLAN-grants.md §5; DECISIONS 216)

Built and tested; not yet on the box. Each step in order:

1. **A control box with the kernel's bootstrap.** Flux makes no namespace, quota or box-key Secret, so the kernel
   (k8s/control/apps/kernel) runs only on a control box created after the bootstrap gained `jarvis2-kernel`
   (k8s/bootstrap-control, infra/cloud-init.sh's `kernel-box-key`, k8s/flux/control.yaml's `control-kernel`): a rebuild or
   a move ("Rebuilding a box"). Deyao's call when.
2. **Pin the kernel image** in k8s/control/apps/kernel/kernel.yaml (it names `:latest` until the pin job moves it) and set
   the router's `KERNEL_URL=http://%s.jarvis4-kernel.svc.cluster.local:8080` (router.yaml; `%s` = the Deployment
   `<role>-<copy>`).
3. **The spawner's Fly token** comes with Deyao's Recover of the kernel (step 4: the core store's backup, sealed to the
   spawner), or from the setup session: `infra/setup.py kernel-fly-token <file from infra/fly-token.sh>`. A spawner
   restart loses it; the router DMs when a spawn is refused for want of it.
4. **Deyao, in the app**: Settings → Kernel → Recover the kernel's secrets (the recovery kit), then Sign the root grant
   (the root key, its own warning). From then on new sessions start on the kernel; the old core's sessions go on there
   until destroyed, then the old core and `core/` go (DECISIONS 216).

### A kernel release (Deyao decides; DECISIONS 230, 233)

The kernel runs as two copies, blue and green (Deployments `<role>-<copy>`; docs/PLAN-cluster.md "Releases: the copy
flip"). `k8s/cluster/kernel/active-kernel.txt` names the one that serves; a release lands only on the other, which
takes over from it without stopping anything. Every component still makes fresh RAM-only keys at start, so the copy a
release lands on works only once Deyao signs its roster (one Face ID, whenever he likes: the serving copy goes on
meanwhile), and a release still needs his OK:

1. **Deyao's OK, in the commit.** The release commit (or an empty commit after the change) carries the trailer
   `Kernel-Release: <why> (Deyao, YYYY-MM-DD)`, written only when Deyao said so in that conversation. Never add it
   for a change he hasn't OK'd, nor to unblock CI.
2. **What CI moves** (the pin job, `infra/kernel-pin.py`): only the other copy, and only when a component's binary's
   inputs changed since the build the serving copy's Deployment of it pins (the module's packages `go list -deps
   ./cmd/<role>` reaches, their non-test .go and embedded files; kernel/go.mod, go.sum; kernel/Dockerfile's build
   lines) and a `Kernel-Release` commit lies after that pin with no input change after it. Then the other copy gets
   the release's build for those components, the serving copy's images for the rest, replicas 1 and the hold
   `jarvis2/kernel-release: pending` on each Deployment. Tests, `kerneltest`, `internal/kt`, `flowtest`, comments in
   the Dockerfile and anything outside kernel/ never count. Test and tool programs live outside kernel/
   (`ios/interop/vectors`, `ios/interop/rostervec`).
3. **Changed inputs with no release, or a release while one is in flight** (the other copy still holds the hold: it
   may serve already): the pin job pins the router and session as usual, pins no kernel Deployment and fails, naming
   why. Ask Deyao in one line for a missing OK (what changes, which components; he signs one roster). A release in
   flight: finish it (steps 4-6), then the next push pins. A hold on a copy that is known never to have taken over (the
   router's `GET /setup/kernel/roster` shows the other copy serving and no flip) may be deleted to let a newer release
   land.
4. **After the pin rolls out** (Flux, a minute): `infra/setup.py kernel-roster --copy <the other copy>` (its fresh
   identities through kernel-id; the serving secrets as its secrets and its own empty secrets as `secretsBoot`; every
   serving member as retired, with the retired keys a line still needs), and Discord Deyao "waiting on you: sign the
   kernel's <copy> roster in Settings → Kernel". He signs it at his leisure.
5. **The flip is the router's**, at once after the signature (router/kernelflip.go): every serving component hands
   over and freezes, the new copy's notarizer, spawner and secrets take their state (the Fly token and the open unlocks
   included), and every call goes to the new copy. Nothing restarts and no session notices (calls wait out the flip's
   seconds). `GET /setup/kernel/roster`'s `flip` shows it under way; a step that fails is retried every 30 s and DMs
   once (`waiting` says why: a component of either copy restarted since the roster was read → file and sign a new
   roster; one not answering → bring it back).
6. **Then commit the flip:** `infra/setup.py kernel-flipped` (refuses while a flip is under way) writes active-kernel.txt
   (the new serving copy), deletes its hold and scales the old copy to zero; commit and push (never a force push). The
   next release lands on the old copy.

A crash restart of a serving component (not a release: the node, an OOM) makes the roster stale as before: run
`infra/setup.py kernel-roster` (the serving copy; it names the restarted component's old keys as retired, so live
sessions' grants and documents keep checking) and Deyao signs it. A restarted spawner needs `infra/setup.py
kernel-fly-token <file from infra/fly-token.sh>` again (its token was in its memory only); a restarted secrets is a
Recover with the kit (Settings → Kernel).

If a component of the copy taking over restarts during the flip (its new keys aren't the signed roster's), the flip
waits: file and sign a new roster for that copy (`infra/setup.py kernel-roster --copy <it>`); the frozen components
hand the same state to it and the flip goes on (a component that already took a handoff serves and takes no other). A
secrets of that copy that restarted after its takeover, or before it, has lost what it held (memory only): Recover it
with the kit (Settings → Kernel), as after any secrets crash; the flip then counts its takeover done.

#### The first rollout of the two copies (once; DECISIONS 233)

The commit that brings the two copies replaces the single kernel (Deployments notary, notarizer, …, secrets-blue,
secrets-green): Flux prunes the old Deployments, Services and volumes (notary-data, notarizer-data, spawner-data) and
the kernel starts empty on blue. Right only while no session runs on the kernel (`infra/setup.py sessions` empty).
It costs Deyao one Recover with his kit (one Face ID):

1. The commit carries `Kernel-Release: … (Deyao, YYYY-MM-DD)`. Every kernel Deployment in it names `:latest`; the
   pin job pins every blue Deployment onto that build by digest in place (the bootstrap: a serving copy that pins no
   build), with no hold, and leaves green at `:latest`, replicas 0. Wait for that pin commit to roll out (Flux, a
   minute; blue's pods restart once more onto the digest).
2. `infra/setup.py kernel-roster` (blue; it retires nothing: nothing on the empty kernel is signed by the old keys).
   Until Deyao acts the router DMs once that the roster is stale (it re-posts the old one, which the new components
   refuse): expected.
3. Discord Deyao "waiting on you: Settings → Kernel → Recover the kernel's secrets with your kit". His Recover claims
   blue's secrets, signs the filed roster with the keys his kit derives (one Face ID) and gives the spawner its Fly
   token if the backups hold the core store.
4. `infra/setup.py kernel-fly-token <file from infra/fly-token.sh>` (always, so the spawner has the token either way),
   then `infra/setup.py sessions` / the app's Kernel page: healthy, blue serving.

The next release lands on green and flips as above.

Testing the selection: `python3 infra/kernel_pin_test.py` (a made-up history), or `python3 infra/kernel-pin.py plan
<kernel.yaml pinned at X^> blue X` for a real commit X.

The kernel's members (`infra/setup.py kernel-roster` reads each through kernel-id as `<role>-<copy>`): notary,
notarizer, mover, merger, spawner, identity, gullible, minter and secrets. Only the spawner (Fly) and the minter (GitHub
deploy keys) reach the internet; each copy's secrets reaches only its own minter (`KERNEL_MINTER_URL`, NetworkPolicies
`kernel-secrets-minter-<copy>`). Store versions on a box with no core are the router's (Postgres `store_versions`,
DECISIONS 232): a store's Versions page and its restore work as before, with no phone signature (each key put back
carries secrets' receipt; each key removed gets a delete marker carrying secrets' receipt of the delete, so a Recover
from the bucket leaves it out).

Testing it on real Fly from a session: `session-secret --keys JARVIS2_FLY_TOKEN --exec infra/e2e-kernel.sh` (a new
session on the kernel, its boot from its documents, pause into a source with its snapshot, resume, destroy).

## Rebuilding a box

**The services box** (`jarvis2-services`): delete the server, `BOX_KIND=services infra/create.sh` (a new age key,
`keys/services-age.pub`; attached to the Network at 10.77.0.3 before its first boot), write its four parts again
(`infra/router-secrets.py --box services --part search|icloud-index|icloud-session|alloy …`, values from `jarvis1`,
`default`, `icloud-backup`, `identity` and `jarvis2-ops`), commit and push. Search and the iCloud index seed from their
Storage Box copies. Nothing else waits on it; the router reports search unreachable meanwhile.

**The control box** (`jarvis2-control`), when it is gone (otherwise replace it with a move, above, with no gap):

1. Delete the server in the jarvis2 Hetzner project (API or console).
2. `infra/cloudflare.py ~/.jarvis/cloudflare.env` (with `ROTATE=1` if that file is gone: a new setup service
   token; put it in the `infra` store as JARVIS2_SETUP_ACCESS_ID/SECRET).
3. `BOX_KIND=control WG_PEER=jarvis2-box infra/create.sh` — a new box key (`keys/box-next.pub`: rename it to
   `keys/box.pub`) and age key (`keys/control-age.pub`), the WireGuard peer made again (the old router held the old
   one), attached to the Network at 10.77.0.2, no SSH, no open port, no IPv4 (above). Then every control part of
   `infra/router-secrets.py --box control` (above; the backup read credential needs a new one, since its old value
   exists nowhere but the old box's Secret). Commit and push; wait until `setup.py identity` answers.
4. Deyao sets the core up in the app: Recover (above). With continuity the sessions go on, provided the router's line
   state reached the new box: it is on the router's volume (`line-state.json`) and in the backup bucket
   (`keys/_jarvis2/line-state.json`, at most 5 minutes old, and fresh at the old router's drain); a new router reads
   the bucket's copy when its volume has none. The router's own state comes back from its Storage Box backup ("The
   router's state backup": `ROUTER_RESTORE=1` for its first start); without it a resumed session waits for an Unlock of
   its stores. Without a line state the sessions are lost as before.

## Testing

- Unit: `go test ./...` in core/, router/, machine/ (the core's guarantees are tested in core/).
- The app's crypto against the real core and router: the `ios` workflow's interop job (`ios/interop`, runs on
  Linux too with swift-crypto: `ios/ci/standins.sh W`, then `swift run Interop` with the `INTEROP_*` env).
- App code that needs no simulator (ResumeOnce: a continuation answered at most once): `swift run Units` in
  `ios/interop` (the interop job runs it first).
- The iOS app on a simulator: the `ios` workflow (compile both flavours, the walkthrough in light and dark against a
  real core and router on the runner, recorded, and the phone replica below); `transitions.yml` taps every navigation
  and fails on a blank screen.
- The web page: the `web` workflow (typecheck, `npm test`, export of `app/`).
- End to end on real Fly with a software phone and the public TEST master key: `infra/e2e.sh` (a local core
  and router, a throwaway WireGuard peer, the session image; set `E2E_SESSION_IMAGE` to a pinned tag). It sets its
  own core up and never touches the production core. It always runs with Jarvis 1 unreachable (DECISIONS 155; needs
  passwordless sudo, which sessions have): the router in its own mount namespace whose /etc/hosts sends
  jarvis.deyaochen.com to a listener that fails the test on any connection, each machine with it blackholed; search, the
  watch runner and the Storage Box are local stand-ins, so it also covers a search, a device lease, a watch, a content
  store pulled at boot and pushed back, and a newer Claude pair reaching a running machine. Its cleanup also deletes the
  run's own volumes whose machine is already gone (`infra/run-volumes.py`, from the run's router state and core log).
  `E2E_ONLY=drain` (with its own `E2E_PEER`/`E2E_PORT` when another run is going) checks a rollout's drain instead of
  the rest: SIGTERM to the router while the first session's pause waits for its snapshot → reads served, new actions
  503, the pause ends `paused`, the router exits.

### Rehearsing Recover on a real box

`infra/rehearse-recover.sh` proves Reset → backups → failure → Recover → a session, on a REAL throwaway control box
built the way production's is (`infra/cloudflare.py`, `BOX_KIND=control infra/create.sh` with `PRIVATE_IP=none`,
`infra/cloud-init.sh`, Flux applying `./k8s/control/apps` with the production images at a pinned commit; no services
box, so search and watches don't answer there), in the Hetzner project **runners** (`HCLOUD_TOKEN`). It never
touches the production box, core, router, tunnel, Access apps, WireGuard peer or bucket. About 45 minutes; one
cx23 for about an hour plus a second one for the rebuild (EUR 0.01056/h each; IPv6-only, no IPv4), a few minutes of small Fly
machines. Run it from a setup session (needs `JARVIS2_FLY_TOKEN`, `JARVIS2_SETUP_KEY`, `CF_JARVIS2_INFRA_TOKEN`,
`CLOUDFLARE_API`, `HETZNER_S3_*`) with a swift.org toolchain (`SWIFT_BIN`; the app's side is the `Rehearse` target
in `ios/interop`, the app's own CoreSetup/CoreCrypto):

1. its own tunnel + `jarvis2-rehearsal-<run>.deyaochen.com` + Access app + service token, its own versioned bucket
   `jarvis2-rehearsal-<run>` (the run id: the unix time at start), a core Fly token narrowed as production's that also expires after 6 h, then the box;
2. Reset with the TEST kit (`e2e/testdata`), stores written with `infra/setup.py` (dummy values: not sensitive,
   sensitive, created-then-marked, the harness's `claude` and `tunnel`, the core's Fly token), backups checked;
3. power failure (Hetzner hard reset) → Recover → every store and its sensitivity back (backups and the core's
   signed list) → a session on Fly with them, values checked on the machine → destroyed;
4. the app's restart (the kit wipes the core, Kubernetes starts an empty one) → Recover;
5. the server deleted and made again (new box key, new peer) → Recover → a session again (`SKIP_REBUILD=1` skips);
6. teardown, also on failure: servers, firewall, peer, the rehearsal cores' machines (`JARVIS2_CORE_KEY`),
   Cloudflare tunnel/DNS/app/token, every object version and the bucket: this run's only. After a crash:
   `infra/rehearse-recover.sh teardown <run>`.

Test-only differences (all in the box's user-data, none in git; `infra/rehearsal-box.sh`): the router runs `NO_ACCESS=1` behind an Access app whose only policy is the rehearsal service token (the
router's own check wants Deyao's email login); Flux patches set `MACHINE_URL` (the peer `jarvis2-rehearsal-<run>`) on
both cores and the router, and `BACKUP_BUCKET`, `RECORDS_OFF=1` and Discord off on the router, and there is no secrets
Kustomization (encrypted to production's age key); the router's backup read key is the admin S3 key (a narrowed one is Console-only); the kit is
the public test key, so the bucket holds only dummy values and the expiring Fly token. A hard reset waits 90 s after
the stores are written: a power cut seconds after the images were pulled leaves them truncated on disk ("exec
/router: exec format error" for ever after; only a rebuild cures it). Also checked: a session stuck at boot on a
locked store is destroyed within 90 s.

### The phone replica (the gate before a TestFlight build)

The `ios` workflow's job `replica` (main only, about 70 minutes, on GitHub's free `xcode-27` macOS runner; nothing
outside GitHub and Fly): the app's Release build (the TestFlight configuration of the native app in `ios/`; only
`JARVIS_BASE` = the runner's router and `JARVIS_KEYS_REF` = this run's keys branch differ) on an iPhone 17 simulator
(Deyao's iPhone18,3) on iOS 27.0, Face ID enrolled and driven by `ios/ci/replica-host.py`, against a real throwaway
Jarvis 4 on the same runner (`ios/ci/replica-stack.sh`):

- this commit's core and router, built from source (the real core, not the fakefly build), the core started again
  whenever it ends (a Reset or the app's restart-and-recover wipes it, as Kubernetes starts an empty one); the router
  with production's session image and signatures (`k8s/cluster/router`), `policy/stores.json`, the web page and a
  read-only Fly token, on 127.0.0.1:18080 with `NO_ACCESS=1` (the simulator talks to it directly: no Cloudflare);
- real Fly session machines in `jarvis4-sessions`, reaching the router over this run's WireGuard peer
  `jarvis4-replica-<run>-<attempt>`, which the router runs in userspace as production's does; the core's Fly token
  narrowed as production's and expiring after 6 hours (`infra/fly-token.sh`);
- a throwaway box key and setup key (their public halves on the branch `replica-keys-<run>-<attempt>`, which the
  Release build reads them from; the job's GITHUB_TOKEN can push it, never main: the ruleset's `update` rule), the
  backup bucket on rclone's S3 server on the runner;
- the setup session's part (`ios/ci/replica-setup.sh`, called by the host helper for each message from the test): the
  stores written with `infra/setup.py` after the Reset, `jarvis-request` run inside the session's machine with
  `flyctl machine exec`, `setup.py request add-repo/remove-repo`, and the test repo's deploy keys checked on GitHub.

`ios/UITests/ReplicaUITests.swift` taps every flow: Reset (the kit read off the page, backgrounded mid-flow), stores (a
Face ID failure, then unlock and lock), the encrypted backup opened offline with the kit, New session (one page, its
stores and the harness's unlocked, an image from Photos) running on Fly within 10 minutes and the image on its machine,
the Machines page, a kill and relaunch, the terminal (turned away → the grant review → Deny, then Allow with Face ID →
a command's output; backgrounded), the session's Log (supervisor lines and Fly steps), the Inbox from a session (a grant
request denied, another allowed with Face ID; a batch of two grants allowed with ONE Face ID), Grants (a standing rule,
forgotten), Settings → Repos (the test repo's deploy key added and removed by the core, checked on GitHub), the Inbox
from the setup session (remove-repo denied with the repo kept, add-repo allowed: the key made on GitHub), a session
stuck at boot destroyed within 90 s, Destroy, Recover with the kit (restart and recover) and every store back with its
sensitivity, and a relaunch. A step fails on a missing element within its time, a near-blank screenshot, or a session
not running in time. The video, screenshots and logs (core, router, the setup answers) are the run's artifact
`replica`; failed assertions are also the job's annotations.

- **Its secrets:** the GitHub environment `replica` (deployment branches: main only), used by that job alone:
  `REPLICA_FLY_TOKEN` (`infra/fly-replica-token.sh`: the org token narrowed to app `jarvis4-sessions`, the org's
  WireGuard peers and read on the rest: the peer, the machines and volumes, `flyctl machine exec`; the job narrows it
  further for the core and the router) and `REPLICA_REPO_TOKEN` (a fine-grained token, no expiry, for the private test
  repo `DE0CH/jarvis4-replica-test` only, Administration read and write: its deploy keys; Contents is refused). Both
  set 2026-10-22 with `gh secret set NAME --env replica -R DE0CH/jarvis4`. The job fails at its first step naming a
  missing one.
- **One run at a time** (the job's concurrency group `replica`): the test repo's deploy keys are shared, and each run
  starts by sweeping earlier runs' leftovers (machines whose router address names a `jarvis4-replica-*` peer, those
  peers, the repo's deploy keys); its teardown (always) removes its own machines and their volumes, its peer, the keys
  branch and the repo's deploy keys. It also deletes the run's volumes whose machine is already gone
  (`infra/run-volumes.py`: only ids the run's router state and core log name; "Leftover volumes" below).
- **The gate:** the `ios` workflow's TestFlight job (environment `release`, main only) needs the walkthrough, the
  interop test and the replica of the same run: every push to main touching the app ships once all three pass. Nothing
  is dispatched by hand.
- **The core it runs:** this commit's `core/`, also while a core Deployment carries `jarvis2/core-pin: hold` (the
  shipped app is tested against the core main builds).
- **The simulator:** the composite action `.github/actions/ios-simulator`, shared by the replica, the walkthrough and
  `transitions.yml`: Xcode 27.0 (build 27A266a), the iOS 27.0 runtime (Deyao's phone runs 27.0) and the device type
  whose profile says iPhone18,3 (iPhone 17), all pinned; a missing pin fails the run rather than falling back. It runs
  on GitHub's free `xcode-27` runner image, which ships that Xcode and runtime, so nothing is downloaded (only if the
  runtime were missing does it fetch it with `xcodebuild -downloadPlatform`). The jobs address the simulator by
  `$SIM_UDID` (the image has stock devices with the same name); `device.txt` and the run summary say what was used. A
  new iOS on his phone = bump the action's `ios`/`xcode`/`xcode-build` defaults (and `runs-on` when the Xcode moves to
  another image).
- **What only the replica differs in:** `JARVIS_BASE` and `JARVIS_KEYS_REF` in the Release build; Face ID on the
  simulator is LAContext in front of the software key (no Secure Enclave there); no Cloudflare Access in front of the
  router (its sign-in sheet is Cloudflare's own page; the router's Access checks are its unit tests').

## Looking at things

- What the core did: it keeps no log of its own (R2: as small and stateless as it can be); every change it makes is a
  signed answer the router keeps (certs, the input log in the router's `input-log.jsonl`).
- A session's supervisor log (boot, the keeper and the supervisor, DESIGN "The supervisor and the guard"): the app's Log beside
  the terminal (source Supervisor), or `GET /api/sessions/:id/events`; kept for the session's life, and in its archive
  (`jarvis2/supervisor-log.jsonl`) after Destroy. On the machine itself: `/run/jarvis/supervisor.log`.
- What a boot, pause, resume, Upgrade or destroy did, step by step (the router's steps, Fly's events and platform log,
  the supervisor's lines): the same Log, each operation from its start mark to its end mark; archived as
  `jarvis2/lifecycle.json`.
- A session machine's log: `FLY_API_TOKEN=$JARVIS2_FLY_TOKEN flyctl logs -a jarvis4-sessions --machine <id> --no-tail`
- The supervisor stopped answering (a pause waits on "the machine never reported"): the keeper (Fly's main child,
  `jarvis-machine boot`, root) restarts the worker within 30 s; the restarts are in the supervisor log ("supervisor
  worker exited …"). Both are out of the OOM killer's reach (`oom_score_adj` -1000) and out of the session's reach
  (root: user claude can't signal them), so an out-of-memory machine or a stray `kill` loses harness processes, not
  the supervisor (DESIGN "The supervisor and the guard", The keeper).
- Remote Control dropped under a live host (the app's session "disconnected", or no Remote Control in the pane): the
  supervisor's watch types `/remote-control` and re-enables it after 3 min down, between turns (`remote control: …`
  lines in the supervisor log; DECISIONS 239). A turn that never ends holds it off: interrupt the turn.
- The harness died (Remote Control gone, the app's session "disconnected"), the machine still up: the keeper starts it
  again with the same conversation; each end is a supervisor log line `keeper: HARNESS ENDED (<how>) after <uptime>
  (start n, pid p) … starting it again in <backoff>`, and the session's `registry.harness` (`/api/state`) has the count
  and the last end. On the machine: `/run/jarvis-keeper/harness.json`. Who killed it is not recorded; a signal name
  (`killed by SIGTERM`) with no OOM in Fly's log points at a process of the session.
- A machine that stopped by itself (Fly's stop, a host event): the keeper's teardown logged `teardown 1/2` (the
  transcripts it sent) and `snapshot streamed and committed` when the final snapshot made it; Pause then finds the
  snapshot already there and the session resumes from it. Fly's stop allows 5 s by default (the core sets no
  `stop_config`), so a large workspace's snapshot is usually cut off: the transcripts of step 1 are in the session's
  `.live` copies (archive and search), and the rest is lost (no volume snapshot is taken: DECISIONS 222).
- The boxes themselves: no way in by design; their logs and metrics are in Grafana Cloud (next section): Flux's
  reconciles (`container="manager"`), the kubelet and the kernel (`source="journal"`), every pod.

### Leftover volumes

A session volume (`jarvis4_state`, core/volumes.go) whose machine is gone shows on the Machines tab under
jarvis4-sessions' volumes as "not attached". The core deletes a machine's volume at its kill only while it remembers the
volume, so one can be left by a kill whose delete failed, a line from before a core restart or Reset, or a test core that
exited (DECISIONS 194).
- **The router sweeps them** (`router/volsweep.go`, DECISIONS 195): every 10 minutes (the first 2 minutes after a leader
  starts) it lists the app's volumes and machines with `FLY_READ_TOKEN` and deletes, with `FLY_VOLUME_TOKEN`, each volume
  named `jarvis4_state`, state `created`, attached to nothing, in no listed machine's `config.mounts`, at least 15 minutes
  old, and named by no session it knows (a session's current or booted machine's cert or start record). At most 20 a
  sweep; a failed delete is looked at again next sweep, 404 counts as done. Each sweep logs one line, `[volsweep] N volumes, M machines …: deleted [...], failed map[...], kept map[category:count]` (Grafana:
  `{box="control",container="router"} |= "volsweep"`), and `infra/setup.py status` shows the last one as `volumeSweep`
  (with `FLY_VOLUME_TOKEN` among `secrets`). Without either token the sweep is off and says so once at start.
- A volume the sweep keeps because a session still names it (`named`) and that is really left over (a failed session
  whose machine is gone, say) goes once that session is destroyed.
- Test runs still delete their own at teardown (`infra/run-volumes.py` in the replica's `down` and the e2e's cleanup);
  for a teardown that didn't run: `FLY_TOKEN=$JARVIS2_FLY_TOKEN python3 -I infra/run-volumes.py <the run's
  DATA_DIR>/state.json <its core.log>` deletes only what those files name. What it misses, the production sweep takes
  once it is 15 minutes old.

## Logs and metrics (DESIGN "Logs and metrics")

Grafana Cloud stack `jumboshortbread1389` (https://jumboshortbread1389.grafana.net, EU Germany, Free: 50 GB logs, 10k
metric series, 14 days). The account logs in **with GitHub as DE0CH** (no Grafana password). Credentials: the store
`jarvis2-ops`.

- **Query from a session** with `GRAFANA_READ_TOKEN`:
  `curl -u "1833850:$GRAFANA_READ_TOKEN" -G https://logs-prod-012.grafana.net/loki/api/v1/query_range --data-urlencode
  'query={box="control",container="router"}'` (labels `box` control | services | cluster | fly, `source` pod |
  journal, `namespace`, `container`, `unit`, `fly_app`; on the cluster's extra nodes also `node`, e.g.
  `{box="cluster",node="jarvis2-cluster-2"}`), and Prometheus at
  `https://prometheus-prod-65-prod-eu-west-2.grafana.net/api/prom/api/v1/query` with user 3676371 (e.g.
  `rate(node_pressure_memory_stalled_seconds_total{box="control"}[5m])`, `container_memory_working_set_bytes`).
- **The boxes:** Alloy on each host (cloud-init; `systemctl status alloy` would show it, but there is no way in: a box
  that sends nothing raises "gone quiet"). Its module is `infra/alloy/box.alloy` on main, pulled every 5 min; its
  credentials are the box's `alloy` secret part: `GRAFANA_LOGS_URL=https://logs-prod-012.grafana.net/loki/api/v1/push
  GRAFANA_LOGS_USER=1833850 GRAFANA_METRICS_URL=https://prometheus-prod-65-prod-eu-west-2.grafana.net/api/prom/push
  GRAFANA_METRICS_USER=3676371 infra/router-secrets.py --box <box> --part alloy GRAFANA_LOGS_URL GRAFANA_LOGS_USER
  GRAFANA_METRICS_URL GRAFANA_METRICS_USER GRAFANA_WRITE_TOKEN`.
- **The cluster's extra nodes:** the DaemonSet `jarvis2-obs/alloy` (k8s/cluster/obs/alloy.yaml) runs the same module
  on every node but the server, with the Secret `jarvis2-obs/alloy` (the server's host Alloy imports it from
  DE0CH/jarvis4 too: the DaemonSet `jarvis2-obs/host-alloy` keeps its stub so); a node that ships nothing: its pod's log is in
  Grafana only if it got that far, so look at `{box="cluster",namespace="kube-system"}` for its scheduling and at the
  node's `up` (`up{box="cluster",node="…"}`).
- **Session machines:** the Fly app `jarvis2-log-shipper` (`services/log-shipper`; deploy: `FLY_API_TOKEN=$JARVIS2_FLY_TOKEN
  flyctl deploy -c services/log-shipper/fly.toml --ha=false --remote-only`). Its secrets: `ORG=jarvis2-370`,
  `ACCESS_TOKEN` (`flyctl tokens create readonly jarvis2-370 --from-existing` with the org token), `LOKI_URL=https://logs-prod-012.grafana.net`,
  `LOKI_USERNAME=1833850`, `LOKI_PASSWORD` = `GRAFANA_WRITE_TOKEN`. One shared-cpu-1x 256 MB machine (USD 2.52/month at the budget's lhr rates, in
  the Fly budget; the Machines tab labels the app with what it is and this cost, `jarvisOwnApps` in `router/flyorgs.go`).
- **No alerts (Deyao, 2026-10-24):** Grafana sends nothing; the alert rules, contact points, the Synthetic
  Monitoring probe and Discord #jarvis2-alerts are gone (DECISIONS 237). Logs and metrics are for looking things up.
- **Re-minting** (each credential, when lost or leaked; then write it into `jarvis2-ops` with `infra/setup.py write`,
  and into the boxes' parts where named):
  - `GRAFANA_WRITE_TOKEN`, `GRAFANA_READ_TOKEN`: grafana.com → the org's Access Policies (log in with GitHub):
    `jarvis2-boxes-write` (logs:write, metrics:write) and `jarvis2-read` (logs:read, metrics:read, alerts:read) → Add
    token; or the same through `https://grafana.com/api/v1/tokens?region=prod-eu-west-2&orgId=1949146` from a logged-in
    browser page (header `X-Request-Id`). A new write token goes into both boxes' `alloy` parts and the shipper's
    `LOKI_PASSWORD`.
  - `GRAFANA_ADMIN_TOKEN`: the stack → Administration → Service accounts → `jarvis2-admin` → Add token.
  - `ROUTER_BACKUP_AGE_KEY`: can't be re-minted for the backups already made; a new pair means a new
    `ROUTER_BACKUP_AGE_PUB` in `k8s/control/apps/router/router.yaml` (backups from then on).
