# PLAN: the kernel (sources, the sink, succession certs, grants)

Status: stages 1-9 built and tested (2026-10-21); stage 10 (the box, Deyao's Recover) is next: docs/RUNBOOK.md "Bringing
the kernel up". The design is DESIGN "Target design" and DECISIONS 166; this file is how
it is built and what was decided on the way. It replaces the first draft (2026-10-14, git history), which was written
for a single held core release.

## 0. Decisions

From Deyao (2026-10-14):

- **D1.** A key written to any store reaches the next pull, whoever wrote it.
- **D2.** Secrets never locks by itself: unlocks end with a lock call.
- **D3.** The permission mode is fixed for the session's life (it is a start setting in the source).
- **D4.** The Claude login is the `claude` store; the router writes it, the guard pulls again.
- **D5.** No revocation.
- **D6.** Grants signed by a machine follow the same steps as the phone's.

From Deyao (2026-10-21):

- **D7. The kernel runs beside the old core.** Two cores with different keys can serve at once without a fork: every
  line belongs to exactly one of them. New sessions start on the kernel; sessions of the old core go on there until
  they are destroyed; then the old core and its code go. No archive-everything cutover.
- **D8. An image change is signed by the phone.** A resume on another image is a new source (sink, source-y, P) the
  phone signs after Face ID on a screen showing the image; the spawner only spawns a source's own image.
- **D9. A shell grant lasts at most 60 minutes** (`until` - the grant's notarized time ≤ 60 min, checked by the guard).

Taken as recommended in the first draft (Claude, 2026-10-21; each is easy to change before the kernel serves):

- Archived restore needs only the snapshot hash in the source the phone signs; the old "sensitive stays sensitive"
  check goes (the app warns when the restored session had a sensitive store).
- The watchdog nudge, "upgraded", lease taken/back and Inbox outcomes stay notices built in the image, each logged by
  the log notary; the stale-prompt Escape is a content-free command the guard obeys only after 1 h waiting.
- Rollback rides the resume: the router passes a marker, the guard drops the transcript lines from it, logged.
- The Claude refresh handshake stays as content-free commands (`claude-prepare <gen>`, ack), and the machine still
  pushes a pair its CLI refreshed by itself (output; the router writes the store).
- A command grant (`cmd:<sha256>`) lasts at most 1 h, like the shell.

## 1. Components

The kernel is a new Go module `kernel/` (stdlib and `filippo.io/nistec` only), one binary per component under
`kernel/cmd/<role>`, all in one image `ghcr.io/de0ch/jarvis4-kernel`, each run as its own Deployment in namespace
`jarvis2-kernel` on the control box. Shared code: `kernel/internal/sig` (P-256 signing, sealing, identities, signed
errors), `kernel/internal/perm` (permission pairs), `kernel/internal/h2c` (hash-to-curve keys of sources and the sink),
`kernel/internal/doc` (the documents below). Each binary's dependencies are listed in CI (`go list -deps`), so a
component can be read alone.

| role | state | holds | answers |
|---|---|---|---|
| notary | its log (own volume) | its key | `POST /challenge` |
| notarizer | the sources that have a successor (own volume) | its key | `POST /notarize` |
| mover | none | its key | `POST /move` |
| merger | none | its key | `POST /merge` |
| spawner | the machines it made and their volumes | the Fly token | `POST /spawn`, `/kill`, `/extend`, `/fly-token` |
| identity | none | its key | `POST /sign` (M, M, P) |
| gullible | none | its key | `POST /sign` any (X, Y, P) |
| secrets | stores, unlocks, phone and root keys (claimed) | the stores (it hands them out, never uses one) | today's core store API without versions or `store-key`, `POST /pull` with a grant |
| minter | the approvals it served | its key | `POST /mint`: one phone-approved deploy-key call, the token sealed to it (DECISIONS 230) |

Every component signs its identity `"jarvis2-kernel-<role>-identity <signing key> <agreement key>"` with the box key
at start; anyone checks it against `keys/box.pub`. All ingress only from the router pod (NetworkPolicy), and the
minter's from secrets too; egress only the spawner (api.machines.dev) and the minter (api.github.com, deploy keys);
secrets reaches only the minter.

What carries over from `core/`: secrets takes keys.go, deploykeys.go and the claim/Recover (the minter takes github.go;
store history is the router's, DECISIONS 230); the
spawner takes fly.go, realfly.go, fakefly.go, volumes.go and the start/init/kill checks. They are copied into the
kernel, not shared: `core/` is deleted whole once the last session of the old core is gone (D7).

## 2. Documents

Envelope as today: `{payload, sig}`, P-256 ECDSA over sha256(payload), base64 DER. ID(d) = hex sha256(payload).

**Objects** are strings: `sink`, `source-<32 hex>`, `fly-<Fly machine id>`. The keys of `sink` and every source are
hash-to-curve points (RFC 9380 P256_XMD:SHA-256_SSWU_RO_, DST `jarvis2-object-v1`) of `"jarvis2 <object> signing"`
and `"jarvis2 <object> encryption"`: nobody holds their private halves. A Fly machine's keys are the ones its image
generated, named in the spawner's cert.

**Permission pair** `{"allowed": {"only": [...]} | {"except": [...]}, "conditions": [...]}`, strings sorted and unique.
⊤ = `{"allowed": {"except": []}, "conditions": []}`. Meet and order as DESIGN says; `kernel/internal/perm` is the only
code that computes them, and the guard and the app use the same rules (shared golden vectors in
`kernel/testdata/`).

**Source** (the content a cert into a source carries): `{image, settings: {harness, permissionMode, title, model,
repos, prompt, attachments, restore?, task?, oneShot, apiProxy, accept}, snapshot?}`. A source is defined once, by the
first cert into it.

**Succession cert** (signed by its signer):
`{kind: "succession", pred, succ, pair, source?, machine?: {signingKey, encryptionKey, image}, signer, issuedAt}`.
`source` only when `succ` is a source; `machine` only when the spawner names a Fly machine.

**Notarization** (signed by the notarizer): `{kind: "notarized", cert: ID(cert), challenge: <notary challenge>}`; the
notary challenge's subject is ID(cert). The notarizer refuses a shape not in DESIGN's table, a signer whose identity
or key isn't the table's, and a second successor of a source.

**Grant** (signed by the mover or the merger, or the root key for ⊤ on the sink):
`{kind: "grant", machine: <object>, keys?: {signingKey, encryptionKey}, pair, from: [IDs], at}`. `at` is the newest
notarized time along its chain (what the guard measures `until` caps from).

**Notary challenge**: `{kind: "challenge", seq, prev, at, subject, about, nonce}`.

## 3. Lifecycles (the router's, each step certified)

- New session: the phone signs (sink, source-x, P) with source-x's content (one Face ID); notarized; the root's ⊤
  grant on the sink is moved along it (→ P on source-x); the spawner spawns from it (source-x, fly-M, ⊤), notarized;
  the grant is moved onto M. P names the stores (`store:x`) and `shell` when Deyao gave it; conditions carry
  `session:S`.
- Pause: the machine's signed snapshot as today; the spawner kills M and signs (fly-M, source-y, ⊤) with source-y =
  M's source content plus the snapshot hash; notarized; the grant moves onto source-y. Resume: a spawn from source-y.
- Resume on another image (D8): the phone signs (sink, source-z, P) with the new image and the same settings and
  snapshot; spawn from it. Size changes (Upgrade, More disk) are spawn parameters, no phone.
- Destroy: (source-y, sink) by the gullible signer; the router locks the session's unlocks.
- Adding to a running machine M (terminal, a store): the phone signs (sink, source-a, P_add) and (source-a, fly-M, ⊤);
  the identity signer narrows M's main grant to the same conditions, and the merger joins them.
- Narrowing (downgrade): the identity signer signs (fly-M, fly-M, P) and the main grant moves along it.

## 4. The guard (machine/)

As DESIGN says: one grant at a time, signed by the mover or the merger, naming this machine and its keys; start
settings from its source; `until`, `cmd:<hash>`, `once:<id>`, `session:` judged here; records in
`~/.jarvis2-grants.json`, which is in the snapshot. The supervisor keeps today's output paths (screen, status,
snapshot, changes, live sync).

## 5. Side by side (D7)

- The router keeps a line's kernel (`core` or `kernel`) on the session. Every lifecycle call goes to that line's
  kernel. New sessions use the kernel once it is claimed and serving; until then, the old core.
- The session image: new sessions get the newest image, which speaks the kernel's guard. A session of the old core
  resumes on its predecessor's image (as today) and never moves to a newer image; to get one, Deyao destroys it and
  restores the archive as a new session (on the kernel).
- Store writes go to both while both are claimed: the router writes each key to the old core and to secrets.
- The kernel's secrets is claimed once (a Recover from the same backups, with the root key added).
- The old core, its manifests and `core/` are deleted when no session of it remains.

## 6. Build order

Each stage builds and passes its tests; ✱ = a forbidden input that must be refused.

| # | Stage | Where it lands |
|---|---|---|
| 1 | `kernel/` module: sig, h2c, perm, doc; golden vectors | main, inert |
| 2 | notary, notarizer, mover, merger, identity, gullible (✱ every shape outside the table, ✱ a second successor of a source, ✱ wrong signer keys, ✱ a widening move) | main, inert |
| 3 | spawner (from core: Fly, volumes, start/init/kill) | main, inert |
| 4 | secrets (from core: stores, history, deploy keys, claim/Recover; pull with a grant; D1, D2) | main, inert |
| 5 | image build + manifests (`k8s/control/apps/kernel/`, not yet in the kustomization) | main |
| 6 | router: line kernel field, kernel client, the lifecycles of §3, store writes to both | main, off until claimed |
| 7 | guard v2 in the machine; session image | main (new sessions only once the kernel serves) |
| 8 | iOS: sign sources, the root key and its warning screen, claim the kernel's secrets; web | main, after the replica |
| 9 | e2e on real Fly, rehearsal, phone replica | CI |
| 10 | Deyao claims the kernel (one Recover); new sessions move to it | Deyao's go |
| 11 | the old core is deleted with its last session | later |
