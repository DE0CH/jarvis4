# Secrets controller — design

Design agreed between Deyao and Claude, 2026-10-03 → 10-09 (what is built is in PLAN.md). Goal: every
unencrypted secret is touched only by a very small core, and a key store only ever reaches the machine
Deyao chose — never, by bug or attack, a machine of a different privilege level.

## Trust boundary

| | Status |
|---|---|
| Providers we use (GitHub, Apple, Hetzner, Cloudflare, Fly, Anthropic, Discord, AWS if added) | **Trusted** to uphold their explicit contract (only the holder of the right credential/key controls an endpoint; the service does what it documents). If we don't trust a provider on those terms, we don't use it. |
| Provider infrastructure breach, rogue staff, legal compulsion | **Out of scope** |
| Languages, compilers, standard libraries, static-analysis tools | **Trusted** |
| Crypto libraries we use (CryptoKit, Go `crypto`, age, …) | **Trusted**, and preferred over our own code: if a library function exists, use it |
| iOS and iPhone hardware (kernel, process isolation, Keychain, Secure Enclave, Face ID) | **Trusted**; kernel/hardware bugs out of scope |
| Linux kernel and container isolation | **Trusted**; kernel bugs and container escapes out of scope |
| The Hetzner box as a whole (k3s, Flux, permissions, Jarvis, manifests) | **Not trusted** (much customisation = room for bugs) |
| Our own code (memory-safety and logic bugs) | **Not trusted** |
| Our use/configuration of providers and libraries (wrong endpoint, over-broad token, wrong parameters) | **Not trusted**; verified by tests that attempt the forbidden action and expect it to fail |
| All other open-source code (sops, Expo and the web page's npm tree, …) | **Not trusted**; the core and the iOS app never depend on it |

Consequences for our code: no single point (one bug must not expose a secret), memory-safe languages, as
little hand-written crypto as possible (tested against independent implementations), fail closed, small
surface. The core has no branching other than accept/reject, so it is easy to analyse statically; all
conditional logic lives outside it, where a bug can only make things fail, never do something dangerous.

Defence layers: (1) **visibility** — every behaviour change reaches the phone or the backend only from a
visible commit through CI; (2) **a small core** that can be read and analysed; (3) **prevention** against
changes nobody can see — no single compromised component is enough.

## Parts

- **Core (secrets controller):** the only holder of plaintext key stores. Runs in its own pod on the box with
  minimal network surface. Starts with fresh boot key pairs (signing, agreement), which only receive its claim; a
  claim from the app brings the seed the master key derives, and from then on the core's keys are the ones that seed
  derives, the same for every Recover with the same kit ("Core continuity"); their private halves never leave it. Holds the Fly API token in memory for its whole life (it must start machines
  unattended, e.g. a scheduled resume); the token comes from the special store `core`, never goes to a
  session and is never locked.
- **Router/manager (outside the core):** chains core primitives into useful actions and exposes them as an
  API; decides whether a challenge goes to the iPhone or to an automatic approval. Untrusted: a bug can only
  fail or crash.
- **iPhone:** the highest privilege: approves any challenge after Deyao's click on a hardened path; sets the core
  up (Reset or Recover).
- **Session machine (Fly):** its image generates at boot an **encryption key pair** and a **signing key pair**;
  private halves never leave the machine and live in its memory only (`/run/jarvis` is a tmpfs; never on a disk, its
  volume or a snapshot), so they end with the machine's run. It trusts the core that created it: the core puts its signing key in
  the machine's Fly config.
- **Box key:** made by the trusted setup session when it creates the box and delivered in Hetzner user-data
  (the only channel into the box we already trust); its public half is in git. On the box it is a secret only
  the core's namespace reads, and the core signs its fresh public keys with it, so its identity can travel as
  plain text through anything untrusted. (Hetzner keeps serving user-data from the metadata address; every pod
  is blocked from it.)
- **Master key pair:** made by the app at **Reset**. Its private half exists only inside the **recovery kit**,
  the one string Deyao saves in his password manager (the one Jarvis 1 already uses); the app holds it in memory
  only while it sets the core up (Reset, Recover, or ending a set-up core). Its public half goes to the empty core
  in a claim the master key signs, and the core keeps it until it ends. It is the key the backups are encrypted to,
  and what the app checks a core against: a core set up with another master key is refused. A new master key
  (Reset) means a new core, empty stores filled again, and a new kit. Nothing in git, the core's manifest or the
  session image names it.

## Records

- **Store** — kept in the core's memory: a name and its contents (the values under a data key, the name as
  associated data, the data key wrapped to the combined key `P + K`). Contents written under one name never
  decrypt under another, so moving them can't change what they are.
- **Non-sensitive set** — the only sensitivity state: the names of the stores that are not sensitive. Every
  other store is sensitive, including one the core never created. Nothing puts a name back into the set.
- **Approval** — a succession challenge (predecessor, store names, options, image) that one of the
  `approve_by_*` primitives approved. Certifies exactly one machine.
- **Started machine** — (Fly machine id, image, public encryption key, public signing key). The core creates it
  on anyone's request and reads its public keys from the output of the image's init command through Fly, so
  their trust chains to Fly. A started machine without a cert gets nothing.
- **Succession cert** — (predecessor → machine, store names, options): the machine's permission document.
  The core keeps each certified machine's **newest** cert nonce: a cert an add-store or a downgrade replaced is
  superseded and pulls, continues and succeeds to nothing (R1 audit, 2026-10-11: an older cert must not undo a
  downgrade).
- **Null machine / null image** — a new line is a succession **from** null (never consumed). A succession to
  the **null image** (a predecessor, no stores, no options) **burns** the predecessor: certify takes no
  machine, only marks it used (a **burn cert**), so it can never be continued.
- **A machine succeeding itself** — from one of its certs: one more store (approved by the phone), or a
  **downgrade**: a subset of its stores and a new key pair (approved by the old key). The phone's add-store means
  "add store X to this running machine", and the core answers every one the same way: onto the machine's newest cert
  (the router always sends it as `current`; the core takes it only if it signed it and it is that machine's newest,
  else refuses): the newest cert's stores and keys plus X (a cert that already holds X keeps the same stores, and the new cert reads the add-store's fresh unlock). Each challenge is
  answered once. A downgrade's challenge stays exact (its old key signs the exact keep-set); a stale one
  is refused and the machine starts the downgrade again.

## Core primitives

The core trusts itself: it does what it signs. It doesn't care who calls or why — the router decides that.
Its Fly token is narrowed (a Fly macaroon caveat) to app `jarvis4-sessions`: create, read, stop and destroy
machines and their volumes (and the volumes' snapshots), and run exactly one command inside a machine,
`/usr/local/bin/jarvis2-init` with no arguments.

| Primitive | Does |
|---|---|
| `identity()` | Its public keys, signed with the box key, and its own signed state: the master public key it was set up with (none while empty) and the phone's keys. |
| `claim(statement, masterSig, bundle)` | Once per core, on an empty core: Reset and Recover. The statement names a master public key, this core and the phone's keys, and that master key signs it; the core keeps both keys for its life. The bundle (sealed to the core, format `keys`) carries the stores — none for a Reset; for a Recover every store's name and every key from the backups, each key already wrapped by the app to `P + K` (the core's signed store key), so the core never sees their plaintext; the `core` store's Fly token, which the core keeps for its whole life (never a session's store); each deploy-key store's repo; and the names of the stores that are not sensitive. Who may claim is the router's business (Deyao's app only). |
| `wipe(statement, masterSig)` | The current master key's signature over a statement naming this core: the core answers and exits; Kubernetes starts a new, empty core. Nothing else empties a set-up core except a restart from git. |
| `set_fly_token(sealed)` | The Fly token, sealed to the core (the setup session, after a Reset). Open: the core calls Fly only for its own app, fixed in its code, so a wrong token can only fail. |
| `create_store(name)` | Once per name, on a set-up core: an empty, non-sensitive store. Open; the writer checks the core's word against its own list and marks a store sensitive before writing it (an empty store goes into no session). Never `github-deploy-keys`. |
| `mark_sensitive(name)` | The one-way upgrade: the name leaves the non-sensitive set. Open. |
| `write_key(store, key, sealed value, backupSha256, writer)` | One key written or deleted; the store's other keys are never read or touched (below, "Writing stores and their backups"). Open, on a set-up core. Writer `setup`: its signature over `WriterText` (store, key, `E`, data hash, backup hash), passed on in `unlock_begin` for the phone to check; its first key of a new name makes that store, sensitive. Writer `machine`: the machine's newest cert beside it, and the core checks the signature with the signing key in that cert (a live, certified machine only; never the deploy-key stores, and a store it makes is sensitive and never a `github-*` one). Writer `router`: the Claude account stores (`claude-<name>`) only, unsigned and named as the router on every unlock (DECISIONS 190). Answers a signed receipt (`key-written`). |
| `stores(nonce)` | The signed list: each store, sensitive or not, empty, unlocked. |
| `versions(store, nonce)` | The signed list of the store's last 50 versions, newest first: each one's number, time, what made it (a Recover, `create_store`, a key written or deleted and by whom, a deploy key, a restore) and its keys' names, `E`s, data hashes and writers; never a value (below, "Restoring a store"). |
| `restore_begin(store, version)` / `restore_finish(pending, phone sig, phone shares)` / `restore_commit(pending)` | Putting a kept version back (below, "Restoring a store"): the signed document of exactly what changes, then the phone's signature over it and its share of each key put back (the core opens them and seals their backups to the master public key), then, after the router wrote those backups, the change itself, only if the store is still the version the phone saw. Never a repo's deploy-key store or the `core` store. |
| `succession(predecessor or null, stores, options, image, salt)` | A signed challenge, before any machine exists (the phone shows each store's sensitivity from the signed store list). Exact values only (the router fills in defaults): a harness, permission mode `auto` or `bypass`, stores sorted and each once, and for a new line the caller's random salt (a repeated salt only gets its second approval refused). `options` = harness, permission mode, the session's settings (`config`) and one machine's one-time inputs (`once`): below, "Inputs to a machine". |
| `approve_by_phone(challenge, sig, current?)` | The phone is the highest privilege: any challenge it signs is approved, once. An add-store is always answered onto `current`, the machine's newest cert (above), and refused without it. |
| `approve_by_dead_machine(challenge)` | Automatic: the predecessor is killed (Fly-confirmed) and not used, and the stores, image and options are identical (the predecessor's `once` left out; this challenge has none) — or it is a burn. Never a new line, never a machine succeeding itself. |
| `approve_by_old_key(challenge, sig)` | Automatic: a downgrade (same machine, a subset of its stores, a new key pair) signed with the signing key in the cert it continues. |
| `start(image, region, size, diskGb?)` | Open (normally the router, which guards it; it can't lead to a secret): a new, empty Fly volume (`diskGb`, default 10, at most 500; `core/volumes.go`) and one Fly create with it mounted at `/data` → a created machine, its volume named in the `created` and `started` documents and so in its cert. The image is `ghcr.io/de0ch/jarvis4-session` pinned by digest; `size` is small, medium, large or a doubling past it, `16gb`, `32gb`, … (anything else is refused; `sizeGuest` makes the Fly guest); the machine's Fly config gets only what the core sets (its key, the router's address, the mount). A volume is never made from a snapshot: no machine starts on another's data. |
| `init(machine)` | One try, for a machine this core created: Fly must report it started, then one run of `jarvis2-init` (its output: the machine's keys) → the signed `started` document. 409 while it isn't up; the router retries and kills a machine that never comes up. |
| `certify(approval, started, carry?)` | The approval and a started machine (init's signed document) running the approved image (the digest Fly reports is the approval's) → the succession cert, naming the snapshot the predecessor signed at its kill. One machine per approval, one line per machine, one successor per predecessor (killed and not used). The null image: no machine, a burn cert. For a machine succeeding itself the approval is the new cert at once. Given the line's carry blob, certify (and an add-store's or downgrade's answer) answers it rebound to the new cert beside it, keeping only that cert's stores. |
| `kill(machine, snapshot?)` | One Fly destroy, Fly must report the machine destroyed → killed (409 before: the router asks again), then the machine's volume is deleted. No volume snapshot is taken, and volumes are made with Fly's automatic snapshots off (DECISIONS 222): the machine's signed snapshot is the only copy of its state. `snapshot` = the sha256 of the machine's last snapshot and its signature over it with its current key: kept as what its successor restores. A claim that doesn't check doesn't stop the kill: the record names no snapshot and says why (`snapshotRefused`), and the successor restores nothing; only `snapshot.required` (a pause, which would rather keep the machine) turns it into a 409 with the machine untouched (DECISIONS 190). |
| `extend(machine, sizeGb)` | More disk: the live machine's volume grows (never shrinks; at most 500 GB) → signed `extended {needsRestart}` (Fly's word whether the machine must restart to see it). |
| `attest(machine, input, origin, sha256)` | The input log: sign and append to a hash chain (no parsing); the answer is the entry. Certs are appended by the core itself, each cert's entry answered beside it. The core keeps only the head and the length; the router keeps the entries. |
| `unlock_begin(name, for)` / `unlock_finish(pending, phone shares)` | The split-key unlock of every key of the store (one share per key's `E`, all under one Face ID). `for` = the nonce of the one challenge or cert it is for (a Start, an add-store, a waiting session): only that cert reads it and its pull locks it again (below, "Carried secrets"); no `for` = a standing unlock, open until locked. |
| `lock(unlock id)` / `list_unlocked(nonce)` | Release; the signed list of open unlocks (each with what it is for). |
| `pull_secrets(cert, carry)` | The cert's stores sealed to that machine's encryption key — so no other proof is needed — each from an unlock open to that cert, else from the line's carried secrets; answers the next carry blob for that machine, and `stale`: the stores whose values are behind the store (a key written since they were unlocked). |
| `deploy_key_begin(action, repo, sensitive, store, title, publicKey, blob)` / `deploy_key_finish(pending, phone sig, phone share)` | A repo's deploy key, added or removed (below, "Deploy keys"): the signed request (naming the app's public key and its store blob's hash), then the phone's signature over it and its share of `github-deploy-keys`; the core uses that store's GitHub token for this one call to add exactly that public key, and stores exactly that blob or deletes the store. |
| `store_key(phone)` | Open: the signed store key P + K for that phone key, which the app wraps store data keys to (it can't add points). |

A succession from null is approved only by the phone: every new line starts with Deyao's click.

**State, in memory only:** its own key pairs, the carry key, the master and phone public keys (from the claim), the Fly token,
the stores, each store's last 50 versions and the pending restores, the non-sensitive set, the machines it created and not yet initialised (with the image asked for), each live machine's volume, each
initialised live machine's current signing key, the unlocked stores' plaintext (each unlock standing or for one cert), the pending unlocks and deploy-key requests, and append-only sets — **killed**
(Fly-confirmed), **used** (predecessors continued or burnt), **spent** approvals, and per certified machine the nonce of
its **newest** cert. What
it **trusts** about others (the phone's and the master's public keys, the box key's signature) needs no
secrecy; what it uses to **prove itself** (its private keys, the Fly token) never leaves it.

**Restart = an empty core,** set up again from the iPhone (Reset or Recover). Nothing is reloaded from the
box's disk. A Recover with the same kit brings back the same core (its keys from the master key's seed, its line state
from the router): its sessions go on as if nothing happened ("Core continuity").

## Writing stores and their backups

**A store is a set of keys, each sealed on its own** (Deyao, 2026-10-13: "writing one key by name is allowed, and it
doesn't just overwrite the whole key store"). Each key's value is under its own data key, with the store's and the
key's names as associated data (`store + "\n" + key`), and that data key is wrapped to `P + K`, the **store key**
(the core signs it for the claimed phone: `store_key`). Anyone can seal to it; only the phone and the core together
open a key. Writing a key (`write_key`) replaces that one key; the store's other keys are never read, sent or changed.

**Who writes.** Any running session (its machine key: `jarvis put-key STORE KEY < value`, `jarvis delete-key`), with
no approval (Deyao, 2026-10-13: "writing a key is perfectly safe (has backup, so can't overwrite, and also can't
read)"), and the setup session (`infra/setup.py write`). The writer takes the store key and the master public key from
the core's signed identity and store key (a machine checks them against its core key), seals the value to the store
key and, for the backup, to the master key (`info jarvis2/backup`, the same associated data), and signs
`WriterText = "jarvis2-store-key\n" store \n key \n E \n sha256(data) \n backupSha256` (a delete: empty `E`, data
and backup), where `backupSha256 = sha256(backup.e + "\n" + backup.data)`. The router (`router/storedocs.go`) writes
**the backup first**, `keys/<store>/<key>.json` in Deyao's Hetzner Object Storage bucket `jarvis2-backup-de0ch`
(**versioned**: a new version never removes an old one, and the router's credential may only add versions under
`keys/`), then the key into the core; no key reaches the core without its backup. The backup object holds the sealed
value, `E`, the data hash, the backup hash, the writer (`setup` + signature, or `machine` + signature + the machine's
core-signed cert), the core's identity (signed by the box key) and the key's explanation.

**What a session can't do by writing.** It can't read a key (sealed to `P + K`), can't remove an earlier value (the
bucket keeps every version), and can't change what any session holds without Deyao: a written key reaches a session
only through a new unlock on the phone (below). The core refuses a machine write to `github-deploy-keys` and to a
repo's deploy-key store (their keys come only from a phone-approved deploy-key call), and nobody writes the `core`
store. What a session CAN do is put a value Deyao didn't choose under a key name; the phone shows who wrote each key
(the session, from the core's word) on every unlock, so a value written by a session is never released unseen.

**A written key reaches sessions only with the phone.** The core can't open the new value without the phone's share,
so a session's copy (an unlock's values, the carried secrets) stays as it was until a new unlock. Every pull says
which stores are behind (`stale`, from each store's version: a hash of its keys' names, `E`s and data hashes); the
router asks the phone to refresh, as an Inbox unlock request for each running session holding the store (one batch
when several), right after a write and after any pull that comes back behind (a resume whose carried copy predates a
write). Once the phone's unlock for a running machine's cert goes through, the router tells that machine to pull
again (`refresh-secrets`) and its supervisor holds the store as it is now (RAM only).

**What each key is for** is the router's own record (`store-docs.json`, not a secret and in no trust decision): a new
key name needs its explanation when it is written, the setup session and Deyao (app, web) can edit them, and every
key's backup carries it. The app, the web page, `jarvis stores --keys` and the setup session list them with each
key's name and writer (`GET /api/stores`).

Sensitivity markers (`sensitive/<name>.json`, signed by the setup key) and older whole-store backups
(`stores/<name>.json`, signed by the setup key, from before stores were made of keys) are in the same bucket; a
Recover takes a store's whole-store backup and then every key backup of that store written after it.

## Restoring a store (Deyao, 2026-10-13)

"It needs to go through the core and be signed, because I don't want to randomly lose my master key": putting a store
back to an earlier version must never need the recovery kit for routine use, and is a core-verified, phone-signed action.
The master-key-sealed bucket backups stay the disaster path (Recover), untouched.

- **Versions.** Every change to a store makes a new version: the store's keys as they then were (`KeyEntry`s, each
  sealed to `P + K`, so a version reveals nothing the store didn't). The core keeps the last 50 of each store in memory
  (`core/history.go`), with what made each one; a Recover makes each store's first version. A new core starts with no
  history beyond what its Recover brought.
- **Restore = one Face ID, no kit.** `restore_begin(S, V)` answers, signed, the version it starts from and the one it
  puts back, every key put back (name, `E`, data and backup hashes, its writer, with a setup writer's signature, which
  the phone checks against `keys/setup.pub` as on an unlock), every key removed and the number kept, with a one-off
  `T`. The app's review page renders that document (rows: store, sensitive, version put back, version replaced, keys put
  back, written by a session, keys removed); under one Face ID the phone signs it and computes its share of every key
  put back, sealed to `T`. `restore_finish` checks the signature against the phone key from the claim and that the store
  is still the version it started from, opens each key put back (proving it intact), seals each value to the **master
  public key** as that key's backup (the writers' format: `info jarvis2/backup`, `store\nkey` as associated data), drops
  the plaintext, and answers the backups beside a signed receipt (`store-restore-approved`: each key's new backup hash,
  the keys removed, the begin document and the phone's signature over it). Nothing in the store has changed yet.
- **Backups first.** The router writes each backup to the bucket (`keys/<store>/<key>.json`, writer `restore` with the
  receipt; a removed key as a delete), then calls `restore_commit`, which puts the version back only if the store is
  still exactly the version the phone approved it from (a write in between: refused, nothing changes). The restore is
  itself a new version, so it is undone the same way. The entries put back are the very ones the core held (writer,
  time and backup hash unchanged), so a later unlock shows who wrote each key, as before.
- **After.** Sessions holding the store are behind until a new unlock, exactly as after a write: the router asks the
  phone to refresh them. A Recover takes a restore's key backups like any other (the core's receipt, under a core the box
  key vouched for, names the backup's hashes; the phone's signature over the begin is in it).
- **Who asks.** The app's Stores page (a store's page → Versions → Restore…), or an Inbox request (`…/requests/restore
  {store, seq}`) from the web page (Propose restore) or the setup session (`infra/setup.py request restore STORE V`);
  never a session, never in a batch. Only the phone approves.
- **Once the kernel serves** (DECISIONS 232): the kernel's secrets keeps no history. The router keeps each store's
  last 50 versions in Postgres (`router/storeversions.go`, `store_versions`): after every write secrets took, each entry
  it saw written (`P + K`-wrapped), secrets' signed `key-written` receipt for it and the backup object written with it
  (a key it never saw written, a Recover's, counts as unseen: kept as it is, never put back). The same routes answer:
  the list, and a plan (`replay: true`: keys put back with their receipts, removed, kept, and those it can't put back),
  which the app shows only after checking every receipt against the pinned secrets. Allow has the router write each
  key's backup object back, then each entry back to secrets as a `write_key` with writer `replay` carrying its
  receipt (secrets checks it is its own, for exactly that store, key, `E`, data and backup, and keeps the writer and
  time it names), then delete the keys the version didn't have (writer `replay`; a removed key keeps its last backup).
  No phone signature or share: nothing is opened, and writing is the router's to protect.

The plaintext a restore touches exists only inside the core, for the length of the finish call (like a deploy key's
token). A write never silently drops keys: every write is one key (`jarvis put-key`, `infra/setup.py write`), and the
store's other keys are never read or touched.

## Setting a core up: Reset and Recover (on the iPhone)

Two paths, nothing else, and neither needs Claude or waits on anything Claude does (Deyao, 2026-10-10). Both
live on one page of the iOS app ("Reset or recover"), which first checks the core itself: the box key
(`keys/box.pub`, fetched from GitHub, never from the router) signed its keys, and the core signed its state. The
page says only what Deyao acts on; errors are one plain sentence with the details folded away.

- **Reset (make new):** the app makes a master key pair in memory and shows the **recovery kit**
  `jarvis2-kit:2:<master private key>` with Copy and "I've saved it". On that, it signs a claim naming the
  master public key, the core's keys and its own, with an empty bundle, and the empty core takes it. The stores
  start empty; the setup session fills them later by normal writes (`infra/setup.py write`, which learns the
  master public key from the core's signed state) and sends the core its Fly token (`backup-core`).
- **Recover:** Deyao pastes his kit. The app fetches the backups through the router (which holds the bucket's
  credential and passes the objects on as they are), checks each writer (a whole-store backup or a setup-written
  key: `keys/setup.pub` from GitHub; a session-written key: the machine's signature with the key in its cert, the cert
  signed by a core whose identity the box key signed; a restore's key: that core's signed receipt naming its hashes), decrypts them with the master key, takes each store's
  whole-store backup and then its key backups written after it (a deleted key leaves), wraps each key to `P + K` (the
  store key the core signs for this phone: CryptoKit can't add points), and claims the empty core with the same
  statement and a bundle of those keys (format `keys`: every store's name, every key, the `core` store's Fly token on
  its own, the names that aren't sensitive, each deploy-key store's repo), sealed to the core. The plaintext lives only on the phone, well inside a 10-minute cap; the core never sees it.

With a core that takes it (`continuity` in its identity) both paths also send the seed the master key derives, and
Recover the line state the router kept ("Core continuity"); Recover keeps the phone's keys. Either way the app pins
the core's keys (with a seed: the derived ones, checked after the claim) and its own master public key, then forgets
the master private key. From
then on it refuses a core set up with another master key, or for another phone. Stores are locked; Deyao unlocks
them as usual.

**A core that is already set up** takes neither path: Reset or Recover first asks for the kit it was set up with
and sends `wipe` signed by that master key; the core exits and a new, empty one takes its place. Without that kit
(a lost kit, or a core someone else claimed first) the core is emptied only by a restart from git (the
`jarvis2/restart` annotation of the serving core's Deployment in `k8s/control/apps/core/core.yaml`).

**The router's part** is to admit a claim or a wipe only from the app's device login and to serve the backups.
It can withhold a backup or serve an older signed version (the bucket is versioned), never read, change or forge
one: each is sealed to the master key and signed by its writer. The bucket's credential is the router's own (a
Hetzner S3 credential narrowed by bucket policies to reads of the backup bucket and new versions under `keys/`), set
once with the box.

## Core continuity (Deyao, 2026-10-15)

"A core restart + Recover must be invisible to sessions": on 2026-10-15 a hard reset of the box and then a core
resources change each forced a Recover, and each Recover made a core with new random keys, so every running session's
machine (which trusts the key Fly's config fixed at its creation) rejected the new core's signatures, its certs meant
nothing to the new core, paused sessions couldn't resume, archives couldn't be restored and the deploy-key stores were
gone. Deyao: "even the current design allows my iPhone to sign arbitrary certs": the master key, his kit, is the root
of trust and may vouch for the core.

**The same kit, the same core.** The app derives a seed from the kit's master private key (HKDF, info
`jarvis2/core-seed`) and sends it in the claim bundle, sealed to the empty core's boot keys; the master key signs the
bundle's hash and names the keys the seed derives in the statement (`identity`), so a core and an app that derive
differently refuse each other. From the seed the core derives its signing key, its share K of every store key, the
carry key, the nonce key and the line-state key (`core/continuity.go`). Every Recover with that kit therefore makes the
same core: `JARVIS2_CORE_KEY` in every machine's Fly config stays right (sessions on any image, the machine code is
unchanged), every cert, carry blob, input-log entry and store key P + K stays valid, the app's and the setup session's
pins stay. The box key still vouches for the core's identity (it signs the derived keys at the claim); a new box (new
host, new box key in `keys/box.pub`) changes nothing here, since the keys come from the kit, not from the box.

**The line state.** Keeping the key is safe only if the core also keeps what makes its certs single-use: each
machine's newest cert (an older one continues nothing, R1), the machines it created and initialised with their current
signing keys, the killed and used sets (a line can't fork, a burnt line stays burnt), the spent approvals, the input
log's head and length, and the stores as it holds them (each key wrapped to P + K, so no plaintext). After every call
that changes it the core seals it under the line-state key and signs a head `{seq, sha256}`; every answer names the
newest `seq` (`X-Line-Seq`) and the router fetches and keeps the newest before it passes the answer on
(`router/linestate.go`: its volume at once, the backup bucket at most every 5 minutes and at its drain, so a router or
box that comes back without its volume still has it). At a Recover the app reads it through the router, checks the head
against the derived key, its hash, and that its `seq` is at least the highest the app itself has seen in the core's
signed state, and puts it into the bundle; the core restores it. A Recover takes the deploy-key stores from it (they
have no backup; only when wrapped for the same phone key, so the app keeps its Secure Enclave keys across a Recover);
every other store comes from the backups, as before.

**What the router can still do.** It can't read or forge a line state (sealed and signed by the core), so it can't
add a line, a cert or a store. It can withhold it: the lines then end, exactly as before continuity (the sessions are
marked `oldCore` for want of their line state, a paused one is destroyed and restorable from Previous). It can hand an
older one: the app refuses one older than the newest number it has seen, so the most it can roll back is what happened
since the app last read the core's state; rolled back, a line's newest cert, kill, burn or downgrade is forgotten, which
can let a line continue from an earlier point it really had (an earlier downgrade undone, a burnt line resumed, a
paused line resumed twice): always a machine on a CI-signed image with the stores Deyao approved for that line at some
point, never a store to a line that never had it, and never a plaintext outside the core.

**At most one core with these keys serves (blue/green, Deyao 2026-10-15).** Two live cores with one identity would let
an untrusted router fork a line or answer one approval twice. So the cores hand over themselves: on the router's call
the serving core seals a FINAL line state (`POST /handoff`) and from then on serves nothing; a core Recovered with
`standby` in its master-signed statement serves nothing until `POST /takeover` gives it a final state sealed by the same
keys whose `seq` is at least the one it was Recovered with, and takes the lines and every store from it (they are newer
than any backup the Recover read). A Recover whose line state is already final serves at once. A Recover that is
neither (after a crash, when the old core is gone and sealed nothing final) serves at once from the newest state the
router kept: there the guarantee is that the old core is gone, which the app can't check; the app's standby option for
a planned move comes with the blue/green flow.

**Archives from any earlier core.** A restore checks the archived cert against the machine's core key, or, for an
earlier core's cert, through the master key: the running core's signed state names its master, the master signed the
claim naming the earlier core (the archive's `core-cert.json`; a seeded claim names its derived key as `identity`), and
that core's key signed the cert (`machine/restore.go`, `router/restore.go`).

**A kill the core can't check** (a machine an earlier core initialised) names no snapshot instead of refusing, so
destroying an earlier core's session never fails on it.

**Sessions of an earlier core (random keys) are taken over, not ended** (Deyao, 2026-10-15: the release must not end
the sessions he is working in). The master key claimed that core (the router keeps every claim it passes on, and the
running core's own claim: `core-certs.json`), so its certs count: at a machine's kill the router sends its cert and that
claim (`legacy`), and the core, after checking the claim is its master's, that it names the core that signed the cert,
and that the machine's current key (the cert's) signed the final snapshot, records the kill and signs the same cert
as its own (`adopted`), which becomes the session's cert (`core/legacy.go`, `router/legacy.go`). A paused session is
taken over at once (its machine is long gone: Fly answers 404, which counts as destroyed), a running one at its own
next pause; nothing is forced. Each resumes like any other: the dead-machine responder, its snapshot, its image (the
successor's machine checks the re-signed predecessor cert with the new key, so an old image works). What it loses:
until it pauses, a running session can't pull new secrets or add stores (its machine trusts only the earlier key), and
the earlier core's carry blob doesn't open here, so the first resume waits once for an unlock of its stores, which the
router files in the Inbox itself; from then on its secrets are carried as usual. What this trusts the router for: which
earlier cert of a line is the newest (an older one can only have fewer stores: a downgrade's new key signs the
snapshot) and that a line the earlier core already continued isn't taken over from an older machine (that core's used
set is gone): once per machine, only for cores the master key claimed, only with a signed snapshot.

**The flip (`router/nextcore.go`).** The router has one serving core (`CORE_URL`) and, with `NEXT_CORE_URL`, a next one.
The app's Reset-or-Recover calls (`/api/core/identity`, `/api/core/claim`, `/api/core/wipe`) reach the next core with
`?core=next` (or `X-Jarvis2-Core: next`), so Deyao Recovers it as a standby while the serving core goes on. The flip —
`POST /setup/core/flip` (setup-signed), or by itself with `FLIP_AUTO=1` once the next core is a standby — drains,
calls `POST /handoff` on the serving core and `POST /takeover` with that final state on the next, then points every
later core call at it and records it in the state (`activeCore`), so a restarted router talks to the same core; the
drain ends. A takeover refused after the handoff leaves no core serving: the router DMs Deyao, keeps the final state
and a retry of the flip reuses it (a handed-off core stays handed off; there is no undo). The serving core is handed
off only to the standby checked before the drain: the drain looks at it again every 30 s and once more after it ends,
and a standby that went (restarted empty, another signing key) aborts the flip with nothing handed off, undrains and DMs
Deyao. A takeover that happened through the next core's own Recover (the current core handed off, the next one serving
with its signing key and a line state at least as new as the final one) is finished the same way: the router switches
to it and records `activeCore`. `/setup/status` shows each core's URL, `serving` value and identity, and `activeCore`
(`core`).

## The boxes (Deyao, 2026-10-15)

"An unimportant job must never be able to bring down the control plane, because that takes away the tool he uses to
fix things." On 2026-10-15 the one 4 GB box ran the control plane next to transcript search and the iCloud index; they
starved it of memory, a Flux backlog landed at once, and the app, the web page and every session lost the router until
a hard reset. So Jarvis 4 runs on TWO Hetzner boxes (fsn1, IPv6-only with WARP for IPv4, DECISIONS 156), each its
own single-node k3s with its own Flux, joined only by a Hetzner Network (`jarvis2`, 10.77.0.0/24):

- **The control box** (`jarvis2-control`, cx23, 10.77.0.2; `k8s/control`, `k8s/bootstrap-control`,
  `k8s/flux/control.yaml`): the cores (blue and green, "Core continuity"), the router (one, whose rollout surge pod is the
  standby; measured 48–171 MB, 512 Mi requested) and cloudflared. Nothing
  else: its bootstrap gives each namespace a ResourceQuota that Flux's `admin` role can read but not change, the control
  plane a PriorityClass, and the kubelet reserved memory with eviction thresholds, so even a push can't put a heavy job
  there. On the private interface only answers come in (`jarvis2-private-guard`, mangle PREROUTING, before any
  NodePort).
- **The services box** (`jarvis2-services`, cx33, 10.77.0.3; `k8s/services`, `k8s/bootstrap-services`,
  `k8s/flux/services.yaml`): transcript search, the watch runner, the iCloud index (each two replicas, rolled with no
  gap) and `jarvis2-poc` for experiments (quota 1.5 GiB, one core). The router reaches them on NodePorts that listen on
  the private address only (`nodeport-addresses`); the box's private guard and their NetworkPolicies admit only the
  control box's address (10.77.0.2). No
  service calls the router, so a services box that is broken into or thrashing has no way into the control box.
- **Each box's Flux** applies only its own tree, one Kustomization per app, so a manifest Flux refuses holds back only
  that app (2026-10-15: one refused RoleBinding held every rollout for 40 min), and a services commit never touches the
  control box. CI dry-runs every tree as flux-applier (`infra/flux-dryrun.sh`, k8s.yml).
- **Each box's host runs Grafana Alloy** (outside k3s, so it keeps shipping when the cluster doesn't; "Logs and
  metrics" below).
- **A control-box reboot** empties its cores (in memory by design): the router comes back from its volume and Deyao
  Recovers, as before; with core continuity his sessions are not cut off. A services-box reboot needs nothing.

Both boxes take changes only from git: no SSH, no reachable k8s API, no inbound port; everything arrives through Flux from
the public repo. A box git can't fix is replaced (`BOX_KIND=control|services infra/create.sh`). Session machines reach
the router over Fly's private network (the control box's router is a WireGuard peer of the org), not through
Cloudflare, so no credential on a machine opens anything on the edge.

**A core release never empties the serving core.** CI pins a new core only into the core that doesn't serve
(`k8s/control/apps/core/active.txt` names the serving one; never one whose Deployment carries `jarvis2/core-pin:
hold`, and the pin itself puts that hold on the core it lands on, so no later release restarts it while it may be a
standby); Deyao Recovers it alongside as a standby and the router flips to it ("Core continuity", "The flip"); a commit
then names the new serving colour in `active.txt` (swaps the router's `CORE_URL`/`NEXT_CORE_URL` and deletes the
hold), so the next release goes into the other core. RUNBOOK "A core release: blue/green and the flip".

### Logs and metrics

Grafana Cloud (Free, stack `jumboshortbread1389`, EU Germany). Grafana Labs joins the trusted providers (Trust
boundary): logs leave the boxes, so secret shapes are replaced first (Bearer tokens, `sk-ant-`, GitHub tokens, age and
PEM private keys, the kit's prefix), as a second layer under "the core logs nothing, the router logs no value".

- **Each box's host:** Alloy (`infra/alloy/box.alloy`, imported from DE0CH/jarvis4 by a stub cloud-init writes, which
  the DaemonSet `jarvis2-obs/host-alloy` keeps so on the cluster's server; credentials from
  the k8s Secret `jarvis2-obs/alloy`, which a host timer copies out) ships every pod's log, the journal (persistent:
  after a hard reset the last minutes of the previous boot still go out) and metrics: PSI memory/IO pressure, OOM kills,
  disk, network, per-container memory and CPU. Labels: `box` (control | services | cluster), `source` (pod | journal),
  `namespace`, `container`, `unit`.
- **The cluster's other nodes** (infra/cluster-node.sh): no host Alloy; the DaemonSet `jarvis2-obs/alloy`
  (k8s/cluster/obs) runs the same module in a privileged pod on every node but the server (the host's / under /host),
  label `node` = the node's name, so a new node ships from the moment it joins.
- **The session machines:** the Fly app `jarvis2-log-shipper` in org jarvis2-370 (`services/log-shipper`: Fly's log
  shipper with only the Loki sink, the same redaction, and no listening port: Vector's API would let any machine on the
  org's network tap every session's log), label `box="fly"`.
- **No alerts** (Deyao, 2026-10-24; DECISIONS 237): nothing pages; logs and metrics are looked up when needed.

- **The metadata address** (169.254.169.254, which keeps serving the user-data with the box key): NetworkPolicies keep
  the core, the router and cloudflared from it, and a box built from 2026-10-11 on drops every pod's packets to it in
  the raw table at each boot (`jarvis2-no-metadata.service`), whatever a namespace's policy says.
- **GitHub (layer 1, R1 audit 2026-10-11):** a ruleset on `main` lets only repo admins (Deyao's token) and deploy keys
  update it (no deletion, no force push); a workflow's GITHUB_TOKEN can't. The environment `release` (refs/heads/main
  only) holds the App Store Connect key, the CI image key and the images pin job's deploy key, so a branch with a
  rewritten workflow gets none of them. k8s pins the router, the session image and (from its next release) the core by
  digest, so a tag pushed again from anywhere changes nothing that runs.

**The setup session trusts only Deyao's core** (R1 audit, 2026-10-11: claim is first-come, so a router or box that
claims an emptied core first would otherwise receive every store `fill-stores` writes, and every backup sealed to its
master). `infra/setup.py` writes, backs up and sends nothing until the core's master key is the one pinned in the bucket
(`pins.json`, signed by the setup key), or the core's claim names the pinned **device key** — the app's long-lived
Secure Enclave key, kept across Reset and Recover — inside the master-signed statement and the router kept that
device's signature over the statement (`deviceKey`/`deviceSig` on POST /api/core/claim). A claim under the pinned master
pins the device key it names; a claim countersigned by the pinned device key moves the master pin (a Reset).

**The router is two stateless replicas (docs/STATE.md step 10).** Every record is in Postgres (`router/statedb.go`):
a `State.Do` takes the `state_version` row FOR UPDATE, so changes are serialised across the replicas, and a replica whose
copy is older reloads it first; a write the database refuses is retried on a fresh copy and never dropped quietly (an
HTTP caller gets a 503, a job is left for another replica). Any replica serves anything: the app, the web page, setup
and the machines' API (through m-gateway); the periodic loops run on the replica holding the scheduler's lease
(`router/leaderlease.go`), and a job another replica began is carried on from the records (`router/jobs.go`). A rollout
replaces one pod at a time (`maxUnavailable: 0`): a stopping replica answers `GET /readyz` with 503 so it leaves the
Service, hands the lease on, lets its jobs end, then closes its listeners. The pods keep nothing (scratch is an
emptyDir); the database has its own backups.

## The path between iPhone and core

The network path is ordinary for everything (the router, the tunnel) — no hardened channel. Integrity
comes from signatures at both ends. **Rule: everything that leaves the core is signed by the core** — every
challenge, cert and answer (including lists and errors), with the caller's nonce where freshness matters.

- **Core → iPhone:** every challenge (and the store list, burn certs, `list_unlocked` answers) is signed by the
  core. The phone verifies the core's signature against the core key it pinned when it set the core up.
- **iPhone → core:** every response is signed by the phone's Secure Enclave key under Face ID. The core
  verifies it against the phone's public key from the claim.

So the router can delay, drop or replay messages, but can't forge or alter one without the signature check
failing.

## Sensitive stores

Sensitivity lives in the core and only grows: `create_store` makes the only non-sensitive stores (besides
a Recover), `mark_sensitive` takes one out of the set for good, a store the core never created is sensitive.
The core marks sensitive stores in every challenge it signs, so the phone learns them from the core, never
from the router: a sensitive store is never pre-selected, may be picked on the secure page or proposed by the web
page (DECISIONS 164; the web only files a request), and any approval that includes one marks it and shows an
obvious warning before Face ID.
Which stores a harness brings is the router's business (`policy/stores.json`); the app hides them.

## Unlocking a store (split key agreement)

Each key's data key is encrypted to the **combined public key** `P + K`: `P = p·G` is the iPhone's Secure Enclave
key, `K = k·G` the core's. Writing a key picks a fresh one-off `e` and stores `E = e·G`; the shared secret is
`e·(P + K)`. It's Diffie–Hellman with the recipient split in two: `p·E + k·E = (p + k)·E = e·(P + K)`.

1. `unlock_begin(store)` → core returns (store, one-off `T`, the store's version, and per key: its name, `E`, data and
   backup hashes, when it was written and its **writer**: the setup key's signature over `WriterText`, a machine
   (the session's machine and line, whose signature the core checked), or "core" for a key the core vouches for: a
   Recover's or a deploy key's, which the master key or the phone signed for), signed.
2. iPhone checks the signature and every writer (`keys/setup.pub` from GitHub), shows "Unlock <store>?" (a key a
   session wrote is named with that session), and on Face ID the Enclave computes its share `p·E` for every key.
   The phone encrypts each share to `T`, so the router relaying them never sees them.
3. `unlock_finish` → core decrypts the shares, deletes the one-off key, adds `k·E` to each, decrypts every key the
   begin named (a key written in between isn't in this unlock: the store counts as behind).

Neither side ever learns the other's private key: the core gets `p·E`, never `p` (recovering `p` from it is the
discrete-log problem). A share opens only the store written with that `E`, and every write picks a fresh `e`.
The Enclave returns only the x-coordinate of `p·E`, so the core tries both points with that x and keeps the
one that decrypts.

## Deploy keys (a repo's push access)

Each GitHub repo Deyao adds in the app's Settings gets its own store, `github-<repo>`, holding an SSH key that GitHub
accepts for that one repo, read and push, with no expiry: a **deploy key** (Deyao, 2026-10-10). The key is made
by the core, approved by the phone; the box alone can never make one, and no AI is in the path.

- **The token** that may manage deploy keys lives only in its own sensitive store, `github-deploy-keys`: a
  fine-grained GitHub token on all of Deyao's repositories with Repository "Administration: read and write" and
  nothing else (it can't read or write code). No other store is opened by this flow.
- **Add:** the app makes an ed25519 key pair and wraps the store holding the repo's name and the OpenSSH private
  key to the core's store key (`P + K`, signed by the core), so the core never sees the private key; it asks for the
  repo with that public key and blob. `deploy_key_begin` answers, signed, exactly what will happen: the repo, the
  store's name, whether it is sensitive (asked for, and a store that is sensitive stays so; the app always asks for
  `DE0CH/jarvis2`, whose push reaches the core, and refuses an answer that isn't), whether it replaces an existing
  store, the key's title on GitHub (`jarvis2 <store>`), the public key and the blob it will store, and the token
  store's `E` with a one-off `T`, as an unlock. The app's review page shows it; under one
  Face ID the phone signs that document and computes its share of the token store, sealed to `T`.
  `deploy_key_finish` checks the signature against the phone key from the claim, opens the token store with the
  share for this call only (it never joins the unlocked set; the plaintext goes when the call returns), deletes
  that repo's keys titled `jarvis2 <store>`, adds the app's public key to the repo through GitHub's API
  (api.github.com, fixed in the core), and keeps the app's blob as the store. Its signed answer carries the public
  key.
- **Remove:** the same request and approval; the core deletes the titled keys on GitHub and the store.
- **Once the kernel serves** (DECISIONS 232: secrets hands out, the minter uses): the same calls and phone approval, but
  secrets never uses the token. After checking the phone's signature and opening the token store with its share,
  secrets seals the token to the **minter**'s agreement key (from the root key's roster) and sends it the begin
  document, the phone's signature and secrets' signed keys statement. The minter (`kernel/minter`, the kernel's only
  GitHub egress) checks that request itself (secrets signed the begin, the phone signed exactly it), makes exactly one
  GitHub call — add the begin's public key, or delete the key **by the id GitHub gave it at the add** (secrets records
  it, and it travels in the line state) — drops the token and answers signed; secrets checks the answer against the
  roster's minter and then writes or deletes the store. Nothing is listed or deleted by title: a re-add answers the
  earlier key's id as `replacedKeyId`, and a key no store knows (a re-add's, a lost race's, a Recover's from before
  ids) is an orphan the router can find with a read token and remove by id (`keyId` on a remove: only that key goes).
- **Sessions:** a session that includes `github-<repo>` gets the key with its other secrets; the machine writes it
  with an SSH host alias that uses only that key and pins GitHub's host keys, and git rewrites that repo's URLs to
  the alias, so clone, pull and push work with no setup, and no other repo is reachable with it.
- **The router** keeps the repo list, adding or removing an entry only from the core's answer; it holds no token
  that can push or manage keys. The repos' stores have no backup (the core can't write one); they travel in the
  core's line state, wrapped to P + K as the core holds them, so a Recover with the same kit on the same phone brings
  them back ("Core continuity"). After a Recover on another phone (new phone keys, so P + K changed) each repo is made
  again with one Face ID, which also deletes the old key on GitHub.

## Flows (router, outside the core)

- **New session:** the router adds the harness's stores (policy) → `succession(null, …)` ← iPhone approval →
  `start(image)` → `certify(approval, machine)` → succession cert. (The router may start the machine while
  Deyao is still deciding, and destroy it on a reject.)
- **Pause:** the machine stops every process of the session (SIGSTOP), signs its snapshot (artefacts, workspace, transcript, the harnesses' state)
  with its signing key and uploads it; it signs only this one in its life and answers any later snapshot command with
  the same one, so the router holds no earlier signed state to roll a successor back to →
  `kill(machine, snapshot hash + its signature)`: the successor's cert names that snapshot and no other. Its carried secrets (sealed by the core at its last pull) are already next to the snapshot.
  The snapshot streams into the router as it is made, so it needs no free disk on the machine; the machine signs the
  router's hash of what arrived (`router/snapstream.go`). A machine paused while still booting signs its predecessor's
  snapshot (the one its cert names: it has no state of its own yet) and stops booting, so the line keeps it.
  **A pause never loses state (2026-10-15, `router/snapsafe.go`):** a machine whose snapshot fails (an error, the snapshot
  making no progress for 10 min, or a machine gone silent) is kept, never destroyed, with or without a volume (session
  `failed`, `snapshotFailed`, a "needs you" DM; DECISIONS 215); only Destroy anyway goes on without it. A line
  whose last kill named no snapshot doesn't resume (it would start empty): the session says why (`noSnapshot`) and
  Deyao gets a DM naming the backup; recovery from a backup is by hand. No secret moves.
- **Resume, nothing changed (also unattended, e.g. scheduled):** `succession(old, …)` ← approve_by_dead_machine
  → `start` → `certify` (with the line's carry) → succession cert + the carry rebound → the machine pulls its secrets from the carried blob,
  no store unlocked, no Face ID.
- **Resume with a change (e.g. newer image), approved:** `succession(old, …)` ← iPhone (shows the difference,
  Deyao clicks) → `start` → `certify`. Rejecting leaves the session paused as it was.
- **Add a store to a running session:** the session finds the store holding the key it needs (`jarvis stores`:
  every store's key names, never values — the router's record, kept by the setup session's writes; repo stores'
  names follow from the repo), then asks through the router (signed with its machine key) for
  one more store → `succession(machine → same machine, set + store)` → `approve_by_phone` (the same Face ID unlocks
  the added store for that challenge only, if it is locked) → new cert + its carry rebound → the machine pulls its
  secrets again (its stores from the carried blob, the added one from its unlock, locked again by that pull).
- **Downgrade in place:** the machine makes a new key pair → `succession(machine → same machine, a subset, new
  keys)` → the machine signs the challenge with its old key → `approve_by_old_key` → new cert + its carry rebound (the
  dropped stores leave the carried blob) → only then the machine shreds its old keys and the dropped stores'
  secrets, and re-pulls with the new keys.
- **End a session:** `kill`, then burn: `succession(old, no stores, no options, null image)` ← respond by
  dead machine → `certify(approval, none)` → burn cert. The router deletes the carried blob with the snapshots;
  burnt, it could open for nothing anyway (no successor can be certified, the killed machine's certs read none).

- **A router rollout never cuts a flow off (Deyao, 2026-10-13).** Every flow above runs in a goroutine of the replica
  that began it; each is tracked (the session lifecycle lock and the approval answer begin one), and the long ones are
  jobs in the records (`router/jobs.go`). On SIGTERM the replica leaves the Service, lets its running jobs end (the
  pod's grace period, 30 min, covers the longest one) and exits; a job still running then, or one cut off by a crash,
  is carried on by the other replica from the records ("The router is two stateless replicas").

## Carried secrets (Deyao, 2026-10-11)

"After a session is started, there's no reason to keep the store unlocked in the core. So just lock it then." For
unattended resumes (a wakeup, a cron, a task run with nobody there) he chose: **the session carries its secrets**.

- **Unlocks are for one session.** The phone's unlock names what it is for: `unlock_begin(store, for)` with the nonce
  of the Start's challenge (New session, an approval of a new line), of an add-store's challenge, or of a waiting
  session's cert (Unlock…, an Inbox unlock request). The core signs `for` into the begin document, only the cert with
  that nonce reads the plaintext, and that cert's first pull that goes through locks it again; one its cert never
  pulls with lapses after 30 minutes. Start stays one Face ID that unlocks what the session needs (Deyao,
  2026-10-10). A **standing** unlock (no `for`: the Stores page's Unlock) stays what it was, open to every session
  until locked; it is the only kind the store list calls unlocked.
- **The carry blob.** Every pull that goes through also answers the values it sealed, per store, under the core's
  **carry key** (AES-256-GCM), bound to that machine. The router keeps it next to the machine's snapshot
  (`snapshots/<machine>.carry` on its volume) and sends it with the machine's next pull. The blob names the cert it was
  sealed for; the core reads a store from it only when no unlock is open to the cert, only for the machine's newest
  cert whose blob was sealed for that cert or the one it directly continues (the same machine's previous cert, or the
  predecessor's newest), so a blob from before a downgrade opens for nothing after it,
  only while that machine isn't killed, and only the stores that cert names. The call that makes a new cert rebinds it
  and answers it beside the cert: a successor's certify (so one that dies before pulling doesn't break the line), an
  add-store's or a downgrade's answer (the dropped stores leave it at once).
- **The carry key** is 32 random bytes the core makes when it starts, in memory only: sealed to the running core
  and nothing else — no backup, no setup step, no new trust path. Nothing else (the router, the Storage Box, a
  machine, another session, another core) can open or forge a blob.
- **A Recovered core keeps the sessions; only another core destroys them** (Deyao, 2026-10-11: "They are just
  automatically destroyed"; superseded 2026-10-15 by "Core continuity": a restart + Recover must be invisible to
  sessions). The carry key is derived from the master key's seed, so a Recover with the same kit opens every earlier
  blob, and the line state brings back the killed/used sets. Only a core with OTHER keys (a Reset, a claim from an app
  without continuity, a core from before it) can open none of the earlier blobs or continue their lines. The router
  watches the core's identity (`router/corechange.go`, every 30 s, once the core is set up: an empty core shows only its
  boot keys); when it changes, every session whose cert the new key didn't sign is marked `oldCore` and destroyed the
  normal way once it is paused — archived as a record in Previous, its snapshots and blob deleted, its machine and
  Discord channel cleaned up (a running one goes when it next pauses). Restoring one from Previous is an ordinary new
  line approved on the phone, and works from any earlier core the master key claimed (below).
- **What still needs the phone:** a new line (Start, a restore, a task's first line), a store added, a changed image
  or permission mode on resume — as before. A paused session whose blob is gone (lost by the router, a session
  paused under a core that predates carried secrets) waits on its locked store as before ("Waiting for store X",
  Unlock… or an Inbox unlock request), now unlocked for that session's cert only.
- **Values are the session's own.** A resume gets the values its line last pulled. A store rewritten since reaches
  the line at its next pull with an unlock open to it (Unlock… for that session, or a standing unlock).
- Grants are unchanged: they open a shell on a machine, not a store; a standing rule still serves the unattended
  features, which now also find their stores without anything left unlocked.

## Requests: the Inbox (Deyao, 2026-10-11)

Anything that needs the phone's Face ID and is asked for somewhere other than the phone itself — by a session, the
web page or the setup session (Claude) — waits in the app's **Inbox** tab (a badge counts it; no push, no Discord).
A caller calls an **intent endpoint** on the router (`…/requests/repo/add`, `repo/remove`, `grant`, `unlock`; a
session also `add-store`) with the intent's arguments and its own explanation. The router keeps the request
(persisted, deduplicated by kind + arguments, gone after 10 minutes, at most 20 per caller) with **who called**, worked out
from the credential the call carried — the machine key (a session), the setup key (Claude), Deyao's Access login
(the web page, or the app when its device token is sent) — never from what the caller says about itself, and the
exact call it made. The router's own approvals (new session, resume on the latest image, add a store) are listed in
the same Inbox with their caller and call recorded when they were made, and also go after 10 minutes (rejected like a Deny).

Opening one shows the app's review page for it (the same review stop the app's own buttons use) with three
read-only fields on top, in **decreasing trust and increasing level of explanation**:

1. **What you sign (exact)** — fully trusted. Rendered by the app from the very content the phone signs (the core's
   signed begin document, the core-signed challenge, the session's core-signed cert and the checked grant), never
   from router prose (`Shell/SignedAction.swift`): the lowest level, what happens mechanically. Drawn strongest; the
   one that matters.
2. **Requested via (router)** — as trustworthy as the router: the caller and the endpoint with its arguments. The
   intent.
3. **Reason given by <caller> (unverified)** — the caller's own words: plain text (control and format characters
   dropped, at most 600 characters and 8 lines), shown as theirs and never as instructions or markup. The why.

**Allow** is the page's own action, unchanged (one Face ID over what field 1 shows); **Deny** drops the request (an
approval is rejected). Nothing a non-phone caller does can approve anything: a request is only a pointer to a secure
page, and the phone's signature over the exact content stays the only approval. Requests made in the app itself keep
their direct flow (no Inbox detour). What a caller may ask for: a session only for itself (a grant, an unlock, a
store) and for a repo to be added (a new key in its own store, which no session holds until Deyao picks it); not
removing a repo or anything about another session. The web page, the app and the setup session may ask for any kind.

**Batches** (Deyao, 2026-10-13): a caller may file several items as one batch, through the API, with a **summary** of
its own. The Inbox shows the batch as one entry; its review page shows the summary as the caller's unverified words,
then every item with its own three fields as above (each item's "What you sign (exact)" rendered from that item's
signed content), and **Allow all** asks for ONE Face ID: the app evaluates Face ID once on an LAContext and signs every
item with the Secure Enclave key on that context (the simulator: one stand-in check), each exactly as it would be signed
alone and sent on its own, so the core and the grant store verify each item unchanged. Nothing about what a signature
covers changes; a batch is only the router's grouping. Any kind may be in a batch; Deny drops it whole (an item can be
denied or allowed alone); it goes after 10 minutes like any request; an item that fails is shown failed while the
others stand, and Retry reads it again and asks for another Face ID.

**Outcomes** (Deyao, 2026-10-13): when an item a session filed is decided (approved, denied, lapsed after 10 minutes,
dropped without a decision, or failed after approval), the requesting session is told by a delivery the machine checks,
like a lease wake: the text is built in the image from the session's own signed filing (what was asked) and image
texts for the outcome; the router names only the outcome word, an id, a status number and a proof per item. An
approval that leaves a signed trace must carry it and the machine checks it (the phone's grant, the machine's new
core-signed cert, the core's phone approval of the proposal, the core's deploy-key answer); an unlock, an API call and
every non-approval are the router's word and the text says so (docs/DECISIONS.md 162). Deyao's own words never travel.
A batch is told once, all items together; a paused session hears at its next start (nothing boots it for this).

## Machine side (in the image)

`jarvis-machine boot`, the image's entry point, runs as root and is Fly's main child for the machine's whole life:
the keeper ("The supervisor and the guard", The keeper). It starts the boot steps as user `claude`; they make the machine's keys and wait. `jarvis2-init` (run by the core through Fly, no arguments) prints the
public keys and lets boot go on: it takes the core's key from its own Fly config (the core sets it when it creates
the machine; only the core's token, and the setup session's org token, can create or change machines in the app,
the router's are read-only, plus one that can only delete volumes: DECISIONS 195), fetches its core-signed succession cert through the router, checks it against the
core key and that it names its own keys; if the predecessor is a real machine it fetches the snapshot and checks
it against the hash the cert names and the predecessor's signing key from the cert. Then it pulls its secrets and
hands the harness's env (no secret value) to the keeper, which starts the harness from the cert's options. Any failed
check → start nothing. Everything else it takes: below. Once init asked, the keeper starts the supervisor ("The
supervisor and the guard").

**The volume (`machine/volume.go`).** A machine with a volume (mounted at `/data` by Fly, as the core asked) keeps the
session's state on it: before restoring anything, boot bind-mounts each of the snapshot's directories (`~/workspace`,
`~/artifacts`, `~/.claude/projects`, the harnesses' state) from `/data/home/<path>`, so every path stays the same, and
the supervisor copies the snapshot's single files (`~/.claude.json`, the Jarvis records) there every minute and before the
final snapshot. The volume is always new and empty at boot; the successor's state still comes only from the
predecessor's signed snapshot. The supervisor reports the root disk and the volume every 30 s (`POST /m/disk`).

**Harnesses.** The cert's options name the harness; `harness-claude.sh` (the entrypoint's launcher) execs the others'
launchers. Each keeps what Jarvis reads in a Claude session's shape (a registry entry in `~/.claude/sessions/`,
transcripts in `~/.claude/projects/`, the tmux session `claude` for the terminal), so auto-pause, attention, the stall
watchdog, one-shot, snapshots and archives have one path; all but `claude` take Jarvis's messages through
`harness-send` and publish their front end on the session's tunnel origin (store `tunnel`).

| harness | agent | front end | LLM login |
|---|---|---|---|
| `claude` | `claude --remote-control` in tmux | the Claude app (Remote Control) | the session's Claude account, read by claude from `~/.claude/.credentials.json` |
| `opencode` | OpenCode, driven by a Paseo daemon | the Paseo app (relay) + the daemon's web UI | OpenRouter key from the store `openrouter` |
| `openclaw` | claw-code, run per turn by an OpenClaw gateway | the OpenClaw app + Control UI | the session's Claude account, sent by `api-proxy.js` |
| `paseo-claude` (Deyao, 2026-10-20) | the image's unmodified Claude Code, driven by a Paseo daemon through the Claude Agent SDK | the Paseo app (relay) + the daemon's web UI | the session's Claude account, sent by `api-proxy.js` per request |
| `cloudcli` (Deyao, 2026-10-25) | the image's unmodified Claude Code, driven by Deyao's CloudCLI fork (DE0CH/claudecodeui) through the Claude Agent SDK | the Jarvis 4 Chat app (DE0CH/pwa-shell-ios) + the fork's chat web UI | the session's Claude account, sent by `api-proxy.js` per request |

Claude Code · Paseo (`harness-paseo-claude.sh`, DECISIONS 204): Claude Code loads the working dir's CLAUDE.md, skills,
settings, hooks (the worker count) and MCP servers itself; its transcripts are its own; a pause keeps `~/.paseo` and the
transcripts, so the resumed daemon's agent resumes the same Claude conversation. Claude Code runs with a placeholder
OAuth token (`CLAUDE_CODE_OAUTH_TOKEN`) and `ANTHROPIC_BASE_URL` = the local `api-proxy.js` (`API_PROXY_CLAUDE_AUTH=1`),
which sends `~/.claude/.credentials.json`'s access token on every request. So Claude Code holds no refresh token and
never refreshes (the router stays the only refresher, DECISIONS 185), and an account switch (DECISIONS 202) is the new
pair on disk: the next request goes out on the new account, a turn in flight included, nothing restarted. A Jarvis
message waits until the main agent is idle (Paseo's send interrupts a running turn). Claude Code's own calls outside
the API base URL (its profile, claude.ai connectors, bootstrap, telemetry) go to Anthropic with the placeholder and are
refused, so claude.ai MCP connectors are not available in these sessions.

Claude Code · CloudCLI (`harness-cloudcli.sh`, DECISIONS 240) logs in the same way. Its front end is the same server and
chat protocol as YYC AI (the fork in local Jarvis mode, `JARVIS_LOCAL_WORKSPACE`: Claude Code on the machine, in the
session's working dir), so YYC AI's iPhone app, built a second time as "Jarvis 4 Chat", is its app: it pairs with Jarvis 4
(`app=jarvis4chat`), lists the `cloudcli` sessions (`/api/remotes?harness=cloudcli`) and talks to each session's origin
with its device token. A session is one conversation (the server's main one, `GET /api/jarvis/main`, made by the first
prompt); Jarvis's messages are `POST /api/jarvis/deliver` (409 while a turn runs → harness-send 75, the inbox retries).
The fork, its Node and a portable PostgreSQL are a runtime bundle fetched on first use (`cloudcli-runtime`, pinned by
sha256 in `session-image/cloudcli-runtime.json` by `fork-pin.yml`). The fork's Postgres (conversation rows, names) is
not in the snapshot (a live data folder isn't safe to copy): after a resume the server rebuilds its rows from the
transcripts, which are, as are the chat's pictures (`~/.claude/cloudcli-assets`).

### The supervisor and the guard (Deyao, 2026-10-16)

**The supervisor** is two long-running processes that talk to the control plane (`machine/supervisor.go`), both
children of the keeper (below), split so it doesn't bloat (Deyao, 2026-10-24): **supervisor-core** (`jarvis-machine
supervisor --core`) keeps the control plane alive (answering stop, snapshot, Upgrade and pause, the guarded execs and
deliveries, the secrets, the log, the teardown's uploads); **supervisor-normal** (`supervisor --normal`) does the
less important work (the reports, the read-only terminal's pane, the stall watchdog, the worker count, the API proxy,
the live transcript sync, the Claude login sync). Only supervisor-core has the memory and OOM protection; supervisor-normal
runs at the default OOM score in the session's memory cgroup, so a session that fills the machine may take it down,
and the keeper starts it again. The keeper starts both as soon as init asked, before the boot steps need them, so
the router is answered from the machine's first seconds to the kill; the harness's launcher (for Claude
`harness-claude.sh`, which only keeps the `claude --remote-control` host alive in tmux) is another child of the
keeper. Their components:

| component | process | file | guarded | what it does |
|---|---|---|---|---|
| the guard | core | `guard.go` | — | checks what comes in and lets through only what is vouched for (below) |
| commands and deliveries | core | `supervisor.go` | execs and deliveries: yes; commands: no | reads `/m/commands` for the machine's life: execs (a router feature's shell command with its grant) and deliveries (prompts into the harness) through the guard; one-word commands as they are |
| snapshot and freeze | core | `snapstream.go`, `main.go`, `memory.go`, `snapprogress.go` | no | `snapshot`: the final snapshot (pause, destroy): the session stopped, the state taken and signed once; while booting "nothing to snapshot" or the predecessor's; `free` before an Upgrade's snapshot; its progress (measured, then counted as the compressed tar is made; it goes straight to the bucket in parts, `snapdirect.go`) is reported every 3 s as numbers the router words into the session's status line ("pausing: uploading snapshot 1.2/3.4 GB (35%), 40 MB/s, 55 s left") and logged every 10 s |
| Claude pause and resume | core | `supervisor.go` | no | `pause-harness` / `resume-harness`: SIGSTOP / SIGCONT the Claude process (the launcher, the tmux panes and everything under them); the freeze for the snapshot starts with it. The router's `POST /api/sessions/:id/harness`; no app button |
| worker count | normal | `workers.go` | no | subagents and background jobs: the harness's hook only notifies the supervisor over a local socket (ids, types, the event name; never a command), the supervisor holds the count and the status report carries it; the hook never fails a turn |
| screen | normal | `screen.go` | no | the harness's pane for the read-only terminal (output only) |
| stall watchdog | normal | `stall.go` | no | a nudge into its own harness after 15 idle minutes with background jobs; nothing while the harness is paused or frozen |
| Remote Control watch | normal | `rcwatch.go` | no | the `claude` host's Remote Control, checked every minute (its registry entry, the entry's `connection_status` on claude.ai); down for 3 min → between turns it types `/remote-control`, Disconnect (an entry the host still holds) then Enable; again after 10 min if it didn't take; nothing while paused |
| status, memory, disk | normal | `status.go`, `memory.go`, `disk.go` | no | the reports the router's card and watches read (output only) |
| API proxy | normal | `apiproxy.go` | — | `$JARVIS_URL` for the session's scripts, each call signed as this machine |
| live transcript sync | normal | `livesync.go` | no | the transcripts to the Storage Box (through the router) for search (output only); what it sent is in `/run/jarvis/live-sent.json`, so the teardown sends only what changed since |
| Claude login sync | normal | `claudelogin.go` | no | the session's Claude pair kept in step with the router's (long poll); on an account switch the new pair and account record are installed under the running claude (no restart), the token's account checked with Anthropic, Remote Control started again (Claude Code · Paseo: nothing to start, its API proxy sends the new pair) |
| log | core | `supervisorlog.go` | no | the supervisor log (below) |
| secrets | core | `secrets.go`, `deploykeys.go` | no | the session's secrets, in RAM only (below) |

**The guard** is supervisor-core's component that checks the commands coming in and protects only the ones that need
it: anything that can run code in the session or steer its agent. Execs (shell commands) need the holder's
signature and a phone grant, a standing rule or the session's allow list ("Grants" below); deliveries (wakeups,
crons, watches, Inbox outcomes, leases, the image's own texts) need their voucher and the core's attestation, each
once ("Inputs to a machine"). The one-word commands (snapshot, free, refresh-secrets, pause-harness,
resume-harness), the hook's count notifications and everything the supervisor only sends out (screen, status, log)
can't carry an instruction and are not guarded. Nothing guarded runs once the session is frozen for its final
snapshot, and resume-harness is refused then too.

**The keeper (Deyao, 2026-10-21):** "The supervisor should be the main child. Nothing should be able to kill the supervisor other than a sigterm or
sigkill from something with higher privilege." Fly ends a machine when its main child (the image's entry point) ends,
so that process is the supervisor's and nothing in the session can end it (`machine/keeper.go`, DECISIONS 218):

- **The keeper** is `jarvis-machine boot`, run as root for the machine's whole life. Its children, each in its own
  session (setsid): the boot steps (`jarvis-machine prepare`, user `claude`, which end by handing the harness's env
  over a pipe, never on disk), supervisor-core and supervisor-normal (`supervisor --core`, `supervisor --normal`, each
  started again whenever it exits, backoff 1 s doubling to 30 s and 1 min) and the harness (Jarvis 1's entrypoint, then `harness-*.sh`, user `claude`).
- **The uid split.** The session runs as `claude` (with its sudo: root through sudo is the higher privilege, accepted).
  The keeper and both supervisors run as root, so `kill`, `pkill -f jarvis-machine`, `kill -TERM -1` and process-group
  kills from the session fail with EPERM on them; their `/proc` files (environ, mem, oom_score_adj) are root's and
  both are marked not dumpable. The supervisors keep root's uid but takes `claude`'s file identity (setfsuid/setfsgid and
  `claude`'s groups), so what it reads and writes under `~`, `/data` and `/run/jarvis` (its sockets included) is
  checked and owned exactly as before, and its sockets serve `claude` and root. Every command they run for the session
  (git, tmux, an exec, the text into the harness, a watch's check, the freeze's `kill -1`) goes through
  `jarvis-machine unprotected`, which takes `claude`'s uid, gid and groups for good and the default OOM score; the
  freeze and the Upgrade's free signal only `claude`'s processes. What only the keeper writes is in
  `/run/jarvis-keeper` (root's): `harness.pid` (the boot steps', then each harness's launcher) and `harness.json`.
- **The harness is started again.** A harness that ends (killed by anything, or exiting) never ends the machine: the
  keeper logs how it ended (exit status or signal) and its uptime in the supervisor log, ends what is left of its
  process group (SIGTERM, SIGKILL after 5 s) and starts it again after a backoff (1 s doubling to 1 min, back to 1 s
  after 10 min up) with the secrets the supervisor holds now (`boot-env`, answered to the keeper: a downgrade sticks)
  and `JARVIS_HARNESS_START=n`. The entrypoint then skips its one-time steps (the Claude login and account, which the
  supervisor keeps current; the content stores, which may hold unpushed changes; the on-start hooks, still running),
  and `harness-claude.sh` keeps a Claude host still running in tmux, else resumes the newest conversation as a
  reboot's resume would. Not once the session is stopped for its final snapshot. The status report carries the
  keeper's record (`__HARNESS__`: starts, running, last end; `registry.harness` in the router).
- **Kept alive.** The keeper sets its own `oom_score_adj` to -1000 as root; supervisor-core inherits it and supervisor-normal sets its own back to 0. The harness and the
  session's other processes are not protected: `unprotected` sets the default score as root before it drops, which
  also sets the floor, so a session process can't take -1000 back. A restarted supervisor carries on from files in
  `/run/jarvis` (the signed final snapshot, the worker count, how far the log and the live sync got) and the secrets in the
  keeper's memfd.
- **Memory for the control plane** (`oomguard.go`, DECISIONS 221). Every session process runs under the cgroup v1
  memory cgroup `jarvis2-session`, which the keeper makes at boot with a limit of the machine's RAM minus 640 MB;
  `unprotected` joins it as root before it drops. The rescue path (a grant's exec, such as the terminal holder's, and
  the status and screen readers) goes through `unprotected --rescue` into `jarvis2-rescue` (384 MB) instead, so a
  terminal command can still restart Claude or kill a hog on a machine the session has filled. The session hits its
  own limit (the kernel OOM-kills inside it) before it can take the memory the supervisor, Fly's init and the kernel
  need. The keeper and supervisor-core lock their pages in RAM (`mlockall`, MCL_ONFAULT), so a thrashing machine never drops
  their code.
- **The teardown.** SIGTERM, SIGINT (Fly's stop signal, 5 s by default before SIGKILL), SIGHUP and SIGQUIT to the
  keeper start a clean teardown that uploads the most important first (Deyao, 2026-10-21: "Transcript tail is the
  most important, artifacts is less"), each step counting on its own: the keeper kills supervisor-normal, and supervisor-core (SIGUSR1) sends the transcripts that
  changed since their last copy (newest first, then the subagents': the live sync's `/m/live-transcript`, so the
  router's archive and search have them), then streams the final snapshot in priority order (the conversations and
  `~/.claude.json`, the small records, the other harnesses' state, the workspace, the artifacts last) and commits it
  with its one signature; with it the session resumes as after a pause. A snapshot cut off by the kill is not used
  (the router keeps the transcripts of the first step; the rest is lost). A machine whose final
  snapshot the router already has (a pause) uploads nothing. Then the harness's process group and every other
  process of `claude` get SIGTERM, then SIGKILL, and the keeper exits.

**Secrets, in RAM only (Deyao, 2026-10-16).** The supervisor alone pulls the session's secrets from the core (sealed
to this machine, through the router): at boot when boot asks, on the router's `refresh-secrets`, and when a process of
the session asks it to pull (`pull-secrets`, add-store's waiter, a downgrade, which empties the copy if the pull
fails). It holds exactly what the core sealed for the cert's stores, in its memory and in a memfd its keeper keeps (so
a restarted worker has them without a new pull); nothing is written to disk: no `~/.secrets`, nothing in
`/run/jarvis`, the await logs, the delivery dir or the snapshot. It answers on a unix socket only the session's
user (and root) can reach, `/run/jarvis/secrets.sock`, and keeps two kinds of request strictly apart (Deyao,
2026-10-20):
- **Pulling** (`pull-secrets`): the supervisor pulls the session's stores from the core into its RAM now. Agents and
  scripts may call it, but it hands the caller no secret: no value, nothing in its env, no file; it prints only the
  cert's stores and the key names now held.
- **Asking** (`session-secret --keys K1,K2 --exec CMD | --write FILE`, `--names`): a process gets exactly the keys it
  names, from what the supervisor holds; it never triggers a pull. There is no request for all keys: the supervisor
  refuses a request with no keys (and has no "all" op), and a key the session doesn't hold is an error naming it.

No mode of either prints a value, and a malformed invocation prints usage without asking. Each request is logged in
the supervisor log with its op, the key names asked for (or a count) and the caller's pid and command, never a value.
It needs no guard check: it carries no instruction, and it serves only what the core sealed. The harness's env carries
the values (the keeper builds it from them at each start of the harness, RAM only, through the one hand-over of every
value, `boot-env`, which the supervisor answers only to the keeper (root, its parent) and, before the machine has
booted, to the boot steps named in the keeper's `harness.pid`), so `$VAR` works in the agent's commands;
a process started before a change gets a key through `session-secret --keys KEY --exec`. The repos' deploy keys stay in RAM too: the
supervisor's own ssh-agent (`/run/jarvis/ssh-agent.sock`, read-only to callers, every signature logged with the
repo and the caller) holds them, and `~/.ssh` has only their public halves, which each repo's SSH alias names
(`IdentityFile …pub`, `IdentitiesOnly`, `IdentityAgent`). What stays on disk by Deyao's choice: the Claude login
(`~/.claude/.credentials.json`) and a file a session writes itself with `session-secret --keys … --write`.

**The supervisor log.** The boot steps, the keeper and both supervisors write each log line as JSON (`{at, text}`, the text
prefixed `boot:`, `keeper:`, `supervisor:` or `supervisor-normal:`) to `/run/jarvis/supervisor.log` (`claude`'s file) (tmpfs, rotated once pushed); supervisor-core pushes new lines
to the router every 2 s (`POST /m/supervisor-log`), which keeps the session's log for its whole life and puts it in
the session's archive on Destroy. Lines name commands, ids, counts and errors, never a command's text, a prompt or a
secret value; as a second line of defence every secret value the supervisor holds (8 characters or more) is replaced by `[secret]`
before a line leaves the machine. The app (iPhone and web) shows it in the session's Log, next to the read-only
terminal: one stream with the lifecycle log below (`GET /api/sessions/:id/events`).

**The lifecycle log** (router, `router/lifecycle.go`). Each boot, pause, resume, Upgrade and destroy is an operation
with its own log: the router's own steps, what Fly is doing (the machine's Fly events and Fly's platform log lines:
create, image pull, start, stop, destroy, with times), read by the router with its read-only Fly token while the
operation runs, and the supervisor log lines of the operation's machines in that window, merged in time order. The
app shows the operations in the session's Log, one stream with every supervisor line (each entry with its time and a
source tag), live while it runs; kept for the session's life and archived on Destroy.
The core takes no part.

## Peer messages (Deyao, 2026-10-20)

A session with fewer secrets must not get one with more to act for it behind Deyao's back (a confused deputy). So
there is one path between sessions, through Jarvis: sender → router (`POST /m/api/requests/peer`, the sender named
from its machine key) → the receiving machine's supervisor → its claude.

- **Claude Code's own channels are off.** The image's managed settings set `crossSessionInbound: "refuse"`: every
  cross-session peer message (SendMessage over Remote Control, a local peer socket) is refused, whatever the modes.
  The session's own subagents are not cross-session and are unaffected.
- **Jarvis's messages use the Jarvis channel.** A local MCP channel server (`session-image/bin/jarvis-channel`, loaded
  by harness-claude.sh with `--dangerously-load-development-channels server:jarvis`, whose warning the harness
  confirms) pushes what the supervisor drops into its spool (`jarvis-channel-send`) as `<channel source="jarvis">`.
  A channel isn't a peer message, so `crossSessionInbound` doesn't touch it, and nothing depends on the session's
  permission mode.
- **Deyao's resume prompt is typed, not sent.** His words from the app (in only under the phone's signature of exactly
  them) are his prompt, so in a Claude host they go into the input box: the supervisor queues them with
  `harness-send --queue` and harness-claude.sh types them as keystrokes (as the first prompt) and presses Enter. It
  types only while the host shows no dialog (registry status not `waiting`, no "Esc to cancel" in the pane), so the
  keystrokes never answer a permission ask or a question.
- **The direction rule.** Equal or downward (the receiver's stores ⊆ the sender's, and the receiver no more
  permissive) is delivered at once; upward waits for Deyao's one tap in the Inbox (no Face ID, nothing signed). Stores
  are what the certs name (a repo is its store); grants don't count (they admit router features, not more for the
  session's Claude). The receiving machine checks the direction against its own cert before delivering. A message
  can be an item of a batch (intent `peer`): an upward one then waits in the same Inbox entry as the session's other
  asks; an equal or downward one is delivered as the batch is filed.
- **Provenance.** The delivery carries the verified sender (id, title), both sides' stores and modes and the
  direction (and Deyao's approval for upward); the core attests it; the machine wraps the text with all of it from
  texts in the image, so the receiver sees who really asked and that it isn't Deyao.

## Inputs to a machine (Deyao, 2026-10-11)

Deyao's question: once a session is certified (new or an unattended resume), can the machine that receives its
secrets run another image, another entry point, or anything carrying state other than the certified transcript?
The rule: **every input our infrastructure delivers into a machine that holds secrets — at start, resume, restore,
and later (wakeups, nudges, attachments, an added store) — is vouched for by one of**

- **(a) the cert**: what the phone approved, or what an unattended resume carried over unchanged;
- **(b) the predecessor's signature**: its snapshot, whose hash the cert names (the core took it from the signed kill);
- **(c) the line's own signature**: what a machine of this line asked for itself (a wakeup, a cron), kept by the router
  exactly as signed and checked against the line's signing keys, which travel in the signed snapshot;
- **(d) a trusted provider over an authenticated channel**: GitHub over SSH with the repo's deploy key (or HTTPS for a
  public repo the cert names), the GitHub release a runtime bundle is pinned to by sha256.

Router-only data never reaches a program or the session's agent (the model), **except values whose strict format can't carry an
instruction** (listed below). "Data" is no exemption: a prompt, a title, a transcript all steer the agent. This
guards the **entry points** only: it establishes a chain of trust from Deyao's approval to the running agent that
the router or box can't break. What the session itself chooses to read afterwards (the web, email, files it fetches,
Deyao telling it to) is outside it, and so are shell grants (below, "Grants"): a phone grant or standing rule is
Deyao handing a feature a shell, and the session's own allow list is the session's choice.

| Input | Who vouches |
|---|---|
| The image | (a) the approval names `ghcr.io/de0ch/jarvis4-session` pinned by its linux/amd64 digest; certify refuses a machine whose Fly-reported digest differs. A resume runs the predecessor's digest. |
| The entry point | the image (Fly config has no init/cmd, no files, mounts or services; only the core's token can create or change machines) |
| The env | none needed: the core sets only `JARVIS2_CORE_KEY` and `JARVIS2_URL` (from its own deployment); the machine also throws away anything else at boot (keeps the image's own ENV, recorded at build, and Fly's `FLY_*`) |
| Title, first prompt, model, repos, one-shot, API proxy, attachments (by sha256), a restore (machine + snapshot sha256), task parameters | (a) `Options.Config`, fixed for the line; the first prompt and attachments only for its first machine; each attachment also carries the core's attestation (input log) and is taken only when its bytes match |
| A resume's prompt, a rollback | (a) `Options.Once`: only the phone approves one; never carried over. A prompt left for a session already running goes in as a `resume-prompt` delivery, only under the phone's signature of exactly it ("Message approvals") |
| The predecessor's state (transcripts, workspace, artifacts, `~/artifacts/on-start`, `.claude` settings and hooks, the allow list, the line keys) | (b) the one snapshot the cert names, signed by the predecessor |
| An archived snapshot (restore) | (a) its sha256 in the config, plus the old cert (core-signed) and its machine's signature |
| Repo contents (CLAUDE.md, hooks, skills) | (d) GitHub, for exactly the repos the cert names (a cert whose config names none: the repos of the deploy-key stores in the cert) |
| Secrets | the cert's stores, sealed to the machine by the core; held by the supervisor in RAM only (env-name keys only), served on its socket and put in the harness's env |
| The Claude login | (d) Anthropic: the router hands the pair of the session's Claude account (DECISIONS 185: one Claude key store per account, `claude-<name>`, the router's own; picked when the session is made and kept until Deyao switches it, `POST /api/sessions/:id/account` (DECISIONS 202), the router's word) over `/m/claude-login` (machine-signed); taken at boot, kept in step by a long poll with the router's refresh protocol (`machine/claudelogin.go`, `router/claudelogin.go`, `router/claudeaccounts.go`); no router write, no grant, no machine-side account check (Deyao, 2026-10-15) |
| Wakeups, crons | (c) the session's own signed request + the core's attestation; the line records what it delivered (in the snapshot): a wakeup once, a cron once per run and at most every half period |
| "continue" after a re-login, "upgraded" after an Upgrade (the 15-minute watchdog is the supervisor's own: machine/stall.go) | the image: texts built into it; the router picks when, never what (numbers, or a size: small, medium, large or a doubling past it) |
| An Inbox request's outcome | (c) the session's own signed filing (an Inbox request, or the wakeup/cron/watch whose message Deyao denied or let lapse) + image texts; per item the router names an outcome word, an id, a status number, and a proof the machine checks for approvals (phone grant, core-signed cert or approval, core key answer); the core attests it; each item once |
| An upward peer message into a session holding a sensitive store | also the phone's signature over that very message ("Message approvals") |
| An added store | (a) the new cert, phone-approved |
| The OpenClaw runtime | (d) the GitHub release, pinned by sha256 in the image |
| Jarvis 1's restore-snapshot (would fetch unsigned state from the Storage Box when a store holds its credentials) | removed from the image |

**Format exceptions** (the router's word alone, `GET /m/config`, each refused unless it matches): the session id
(`[a-z0-9-]`), the Discord channel id (digits), the live-sync interval (5–86400 s), a task run's id and its trigger
(a word), the tunnel proof (a token, `[A-Za-z0-9._~+/=-]`).

**The input log** (the record, beside the voucher): every input delivered after a machine started carries the core's
attestation over (machine, input hash, kind, origin) and the machine refuses one without it. The core appends each,
and every cert it issues, to a hash chain of core-signed entries; the router persists them to its volume
(`input-log.jsonl`, `GET /api/input-log`) from the answers that carry them; a new core's chain starts again at seq 0
(the router's file shows where one core's ends). The core keeps only the head and the length; it only
hashes, signs and appends.

## Message approvals (Deyao, 2026-10-20)

Deyao: a message from a session holding less into a session holding a sensitive store is approved or denied **per
message**, never by letting a router feature in for a while; Jarvis's own messages never need him (Deyao, 2026-10-21;
DECISIONS 210). So an **upward peer message** into such a session (from a session holding fewer stores, or less
permissive), and every resume prompt that goes into an already running session (any session: nothing else vouches for
Deyao's words from the app), waits in the Inbox as a **pending message** (`router/messages.go`, `machine/messages.go`).
Jarvis's own messages (an Inbox outcome, the watchdog's check-in, a login "continue", a lease or upgrade note), the
session's own wakeups, cron runs and watches, and equal or downward peer messages go straight in, vouched for by the
core's attestation as "Inputs to a machine" says (the machine checks a peer message's direction against its own cert):

- **What Deyao sees**: who sends what to whom, plainly ("Message from session “X” to session “Y”"; From: Session “X”
  (id), To: session “Y”; "Deyao (the prompt given with Resume in the app)"), and the exact text. A running machine renders the text itself (a preview delivery: nothing
  attested, sent or recorded); for a paused session the router renders the kinds it has twins for and holds the
  message without starting anything; a peer message first starts the receiver. Messages for one session are listed
  together in one Inbox entry.
- **Deliver** = the phone signs `{kind "messages", session <line>, items [{id, delivery, sha256, from, text}], issued,
  expires}` (one Face ID for the whole batch, each message listed; good for an hour). `sha256` is of exactly the bytes
  the core attests, `text` exactly what the machine renders. The machine takes the delivery only when an item names its
  kind, those bytes and that text, the phone key from its core-signed cert signed it for its line, the hour hasn't run
  out and the item id is unused (recorded in the snapshot's `.jarvis2-delivered.json`). A machine that renders another
  text refuses with its own, and the router holds that one for Deyao instead.
- **A kernel line** has no core-signed cert: the line it signs for is the session's id, and the phone key is the one
  in secrets' signed key statement (the machine reads the same statement at boot; the router checks the signature with
  it too). Its resume carries no one-time inputs, so Resume with a prompt files the prompt at once as a pending
  message, no DM; the app that sent it opens that message's page and signs it under one Face ID, and the router
  delivers it as soon as the session is up (DECISIONS 238).
- **Deny** signs nothing: the message is dropped, and whoever asked is told as an Inbox outcome: a peer message's
  sender, or the session for its own wakeup, cron or watch (the outcome of the request that armed it). The same for a
  lapse (24 h without an answer) and for a failure after approval. A newer message of the same thing (the next
  check-in, the cron's next run) replaces one still waiting.
- **A rule** for one kind into one session (made when every kind waited; now no kind that waits can be ruled): the phone
  signs `{kind "message-rule", session <line>, delivery <kind>, issued, until}` (a year); the router attaches it to every
  delivery of that kind until Deyao removes it from the session's card (the router stops at once; the signature stays
  valid on the machine until it ends, as with a grant). No rule covers a peer message or a resume prompt. There are no
  time windows for message delivery: no router feature holds a grant for it (the `scheduler` holder is gone).
- A session without a sensitive store takes its messages unapproved, as "Inputs to a machine" vouches for them.

## iPhone approval screen

Show only what Deyao understands; what he clicks is exactly the challenge string. The phone translates each
challenge field and refuses anything it can't: store names; "Claude" / "opencode"; the image as "latest CI
build" / "CI build from <date>" (verified with CI's signature over the image, `keys/ci.pub` from GitHub: the key
exists only in the GitHub environment `release`, which admits refs/heads/main only; the router passes it on as the
approval's `imageSig` and can only withhold it; every image CI ever pinned keeps its signature in
`k8s/control/apps/router/session-image-sigs.txt`, so a resume on a session's own older image is still a CI build);
machine ids and public keys are signed but not shown.

## iOS app structure: one native app (Deyao, 2026-10-11)

The iPhone and iPad app is one native SwiftUI app (`ios/`), built from Apple's frameworks and our own Swift only: no
React Native, no third-party packages, no extension process. The whole app is therefore trusted code, and a page where
Deyao signs is an ordinary sheet of it; no process boundary is needed to keep its text and taps honest. What makes a
signature safe stays the same:

- **What is signed is rendered from the signed content.** Every review page (New session, an approval, a grant, an
  unlock, a repo key, and the Inbox's "What you sign (exact)") draws its text from the core's signed documents, checked
  against the core key pinned at Reset/Recover, or, for a grant, from the session's core-signed cert. The session a page
  acts on is named from signed content too: an approval from its predecessor's cert, a grant or unlock from the
  session's cert (title and first prompt from a core that vouches, its line, machine and sensitivity); the router's
  label shows only as unverified. The app remembers each session id's line and refuses a cert naming another.
- **Face ID for every signature**: the phone's two Secure Enclave keys are bound to the faces enrolled now
  (`.biometryCurrentSet`) and made fresh at every Reset (a Recover keeps them while they work, so the certs' phone key, the
store key P + K and the deploy-key stores stay valid: "Core continuity"); a long-lived device key (Face ID or passcode) countersigns
  claims and wipes, so the setup session can tell this iPhone's claims from the router's.
- **Nothing the router says decides what is signed**: the stores a harness brings are pinned in the app from git
  (`policy/stores.json`); Start refuses a store that wasn't picked and isn't the harness's, and a sensitive one it didn't
  pick. The image must carry CI's signature (`keys/ci.pub`).
- **New session is one page** (Deyao, 2026-10-10): prompt, title, stores, harness, repos, model and the other options;
  the permission mode is always bypass, shown but not picked (DECISIONS 219), and still signed; its **Start** signs the session and, under the same Face ID, unlocks every store the session gets that is
  locked, for that session only. An approval made elsewhere (the web page, a restore, a task) and an add-store do the same
  under their one Face ID. A request from elsewhere (a session, the web page, Claude's setup session) waits in the Inbox
  and opens the same review page, with **Allow** (Face ID) and **Deny**.
- **No prose assembled by code** (Deyao, 2026-10-12): the app and the web page show facts as UI, not sentences pieced
  together from fields. A review page is labelled rows and lists (Action, Repo, Store, Session, Until; a store list, a
  Sensitive badge), a status is a short label or badge, an action is a button; no "What is being signed: you allow X to
  Y until Z" paragraphs and no template strings with a field dropped in. Fixed strings stay short (a section title, a
  one-line hint, a button). Prose appears only when an LLM wrote it (a caller's reason, a session's title or summary),
  shown as that author's text. Follow Apple's HIG / standard platform controls (Form, LabeledContent, List, badges).
- **The terminal is a web page**: the router serves it (`/term/{id}`) and the app shows it in a `WKWebView` with its
  Access login; WebKit runs it in its own process. The machine still runs its commands only under a grant, which the
  page asks the app for.
- **Web:** the web page (`app/`) only files requests; approval happens in the app.
- **A session waiting on a locked store says so:** the router notes the core's 423 on the machine's secrets pull
  (`lockedStore`); the session's page and the terminal show "Waiting for store X to be unlocked" with Unlock…, a review
  that unlocks exactly the locked stores of the session's core-signed cert, for that cert only. The machine retries every
  2 s for 10 minutes, then starts the session without any secrets (the core seals all of a cert's stores or none; running
  without them is the lower-privilege state); the unlock then brings them (refresh-secrets: the supervisor pulls again).

## Guarantees

- A key store reaches a machine only through a succession: from null (Deyao's click), or from a killed,
  never-used predecessor (exact match automatically, or with Deyao's click when something changed).
- Plaintext stores exist only in the core's memory: an unlock for one session until that session's machine has
  pulled (at most 30 minutes), a standing unlock until locked, during a Recover for at most 10 minutes, and
  `github-deploy-keys` for the length of one phone-approved deploy-key call, and the keys a phone-approved restore puts
  back for the length of its finish call (to seal their backups to the master public key). Elsewhere a store's values exist only
  sealed: to a machine's key (its pull), or under the core's carry key, bound to that machine (its carried secrets). The Fly token is the one
  secret the core keeps in memory for its whole life.
- A deploy key is made or deleted only on a phone-approved request; the core uses the GitHub token for nothing else.
- A session's line can't fork: each predecessor is used at most once (succession and burn both consume it), also
  across a restart + Recover (the line state), except for what an older line state the router hands back at a Recover
  forgets ("Core continuity": bounded by the newest number the app has seen).
- At most one core with one identity serves at a time in a planned move (handoff / standby / takeover).
- A bug or compromise outside the core (router, Jarvis, the box) can block or fail actions, never move a store
  to a machine not approved for it.
- A machine that holds secrets runs only the approved image's own entry point, and takes at its entry points only
  inputs the cert, its predecessor's signature, its own line's signature or a trusted provider vouches for, each
  later input recorded in the core's input log ("Inputs to a machine").

## Grants (shell access for router features, checked by the machine)

Features outside the core (terminal, status, archive, remote) need a shell in a session, as
Jarvis 1 got through Fly exec. The core's Fly token can exec only `jarvis2-init`, so the machine itself decides
(Deyao, 2026-10-09); the core only adds three fields to every succession cert: the phone's signing key, whether
any of the line's stores is sensitive, and the **line id** (the line's first machine; a successor inherits it).

- Each feature is a **holder** with its own key pair on the router's volume (`router/grants.go`).
- A holder's request (`{id, session: line, holder, cmd, timeout, at}`) is signed by its key and reaches the
  machine through `/m/commands`; the result goes back signed by the machine (`/m/exec-result`).
- The machine runs it (`bash -lc` as the session user) when one of these allows it:
  - a **phone grant**: the phone signs `{kind "grant", holder, session, scope "shell", issued, expires}`,
    at most 10 minutes long;
  - a **standing rule**: the phone signs `{kind "rule", …, until}` once, for things that happen while Deyao is
    away (auto-pause, the changes check);
  - the session's **own allow list** (`jarvis-machine allow <holder> <duration>`, kept in the snapshot): the
    machine approving for itself.
- A session holding a **sensitive** store accepts only a fresh phone grant.
- Messages into a session are no holder's: they are deliveries, approved per message ("Message approvals").
- **Viewing the terminal needs no grant** (Deyao, 2026-10-12): the machine pushes its own capture of the harness's
  pane to the router (`/m/screen`, every 2 s when it changed, 30 s heartbeat), as it pushes its status, and the
  terminal shows the last one, however old (Deyao, 2026-10-24: "The supervisor should just upload it"). Nothing goes
  into the machine for it, not even as a fallback; the page sends no resize until typing went through. Typing, resizing and the Escape on a stale prompt stay behind the `terminal` / `status`
  grants; the "switch model?" dialog check reads the pushed pane.
- Grants name the line, which the machine reads from its core-signed cert, so the router can't make one line's
  grant open another line's machine. Request ids are single-use and at most 2 minutes old.
- Re-pairing the phone: running machines trust the old phone key until their line's next cert.
- **Asking for one** (Deyao, 2026-10-10): the app's Grants page (feature; 1–10 minutes or a standing rule until a
  date) or a one-tap button where a feature was turned away builds the whole request; the app's grant review only
  reviews it (Allow with Face ID, or Deny).

## Target design: succession certs, grants and the kernel (Deyao, 2026-10-14)

Built beside the old core (DECISIONS 216; kernel/, router/kernelline.go, machine/kernelboot.go, the app's Security/KernelSetup.swift),
not yet on the box: docs/RUNBOOK.md "Bringing the kernel up". DECISIONS 166 has the why, docs/PLAN-grants.md the build. It replaces the core's succession-cert options,
the holders' shell grants ("Grants" above), the core's automatic locks and the Claude login's own channel.

**Layers**

| layer | parts | trust |
|---|---|---|
| Kernel | log notary, succession notarizer, grant mover, grant merger, spawner, identity signer, gullible signer, secrets, minter | trusted; each small and isolated, a separate component; checks only exact-string set operations and a policy table |
| Interpreters | the guard (in each machine's supervisor), the iPhone app | give the strings meaning; can only refuse, or act within the grant they hold |
| Router | everything else on the box | untrusted. Authenticates its callers (Cloudflare Access, API keys, machine signatures); the kernel trusts it only for transport over the k8s network. It stores, carries and schedules; it can deny service but grants nothing. **Writing secrets is protected only by the router.** |

**Objects**

- `source-<random id>`: a conceptually infinite set. Each holds an image hash, the session's start settings (harness,
  permission mode, title, model, repos, first prompt) and, for one made by a kill, the hash of the snapshot.
- Fly machines.
- `sink`: one, global; no image, no settings. Holds ⊤ (below), signed by the root key.
- Every object has keys. A source's and the sink's are hash-to-curve points derived from their names (`jarvis2 sink
  signing`, `jarvis2 source-<id> encryption`, …), whose private halves nobody knows; anyone can recompute and check them.
  So secrets seals to whatever machine a grant names, and a grant on a source or the sink yields a blob nobody opens.

**Permission pair** `(allowed, conditions)`

- `allowed`: a finite or cofinite set of exact strings (e.g. `store:claude`, `shell`). Covariant.
- `conditions`: a finite set of exact strings (e.g. `session:s4f…`, `until:2026-10-14T12:10Z`, `cmd:<sha256>`).
  Contravariant.
- Order: P' ≤ P iff allowed' ⊆ allowed and conditions' ⊇ conditions. Meet: P ⊓ Q = (allowed ∩, conditions ∪).
- ⊤ = (everything, ∅). Conditions are a conjunction and are only ever added, so the kernel never compares their values
  (`{until:12:10, until:12:00}` means 12:00 to the guard).

**A succession cert** is (predecessor, successor, P), a signer's signature, and a succession notarization.

**A grant** is (machine, allowed, conditions). Grants are made only by the grant mover and the grant merger (and ⊤ on the
sink, by the root key).

**The kernel**

- **Log notary:** issues challenges with its own timestamp and logs each one.
- **Succession notarizer:** checks a succession cert against the table, then answers the log notary's challenge for it.
  A shape not in the table is refused.

  | shape | signer | condition |
  |---|---|---|
  | (sink, source-x) | iPhone | none |
  | (source-x, Fly machine) | spawner | first successor of source-x |
  | (source-x, Fly machine) | iPhone | first successor of source-x |
  | (Fly machine M, M) | identity signer | none |
  | (Fly machine, source-y) | spawner | none |
  | (source-x, sink) | gullible signer | none |
  | (anything, anything) | root | none |

  "First successor of source-x": source-x has no earlier notarized successor, through any row.
- **Grant mover:** grant G on a cert's predecessor, along a notarized cert with pair P → (successor, G ⊓ P). It never
  refuses; a move can only narrow.
- **Grant merger:** two grants on one machine with identical conditions → (M, allowed₁ ∪ allowed₂, conditions);
  otherwise refuses.
- **Spawner:** alone holds the Fly token, which never leaves it. Spawn from source-x (given source-x's notarized cert):
  make an empty volume (the machine's size as Fly's placement hint) and a Fly machine on it with only the source's own
  `jarvis4-session` image by digest, its env naming the source, the kernel's roster and root key. Init: once Fly says the
  machine is started with that digest, read its keys through Fly and sign (source-x, M, ⊤); the first cert signed is
  kept. Kill M: destroy it and sign only after Fly says destroyed, take its snapshot hash only if M's key signed it, sign
  (M, source-y, ⊤), source-y holding M's image, settings and that hash; one kill cert per machine, kept on its volume.
  Destroy: a machine it made that never came up, no cert. It attests Fly facts only, so its P is always ⊤. Its calls
  are single Fly calls with no waiting or retrying; the router retries: it spawns again when the volume's host was full
  (the spawner deleted that volume), finds the machine of a spawn whose answer was lost with its read-only token and
  adopts or destroys it (a second machine can't take the line: the notarizer refuses a second successor), doesn't ask
  for a kill that would lose state it needs, and kills again while a volume is left.
- **Identity signer:** signs (M, M, P) for any P; the router picks P. Narrowing a running machine's grant = moving it along
  M's identity edge.
- **Gullible signer:** signs any pair given to it; it counts only where the table accepts any signer (ending).
- **Secrets:** holds the stores, the unlocks and a signed list of open unlocks. Given a grant (signed by the mover or the
  merger), returns the stores its `allowed` names (`store:x`), encrypted to the grant's machine and signed. An unlock is
  per store; it never locks by itself (no release after a pull, no timer): unlocks end with a lock call, and the phone sees
  open ones. Any written key is served on the next pull, whoever wrote it (secrets are not code and the model never reads
  them). The Claude login is the `claude` store: the router writes it, the guard pulls again. It hands secrets out and
  never uses one, and keeps nothing it doesn't need (DECISIONS 232): no store history (the router keeps it; a restore
  is a write carrying secrets' earlier receipt), no store key (every writer computes `P + K`), and no internet: a
  deploy-key call's token goes sealed to the minter.
- **Minter:** the only component with GitHub egress and the only one that uses a secret. Given a phone-approved
  deploy-key request (secrets' begin, the phone's signature over it, secrets' keys statement) and the token sealed to
  it, it checks the request itself, makes exactly one GitHub call (add a key, or delete one by id), drops the token and
  answers signed. Holds nothing but the approvals it has served (each reaches GitHub once).

**Signers of succession certs**

| signer | signs | its own condition |
|---|---|---|
| iPhone key | (sink, source-x, P) | Deyao's Face ID on the screen showing source-x's image, settings and P |
| iPhone key | (source-x, Fly machine M, P) | Face ID on the screen showing M and P |
| root key (a separate iPhone key) | anything | Face ID on a separate root-key warning screen |
| spawner | (source-x, M, ⊤), (M, source-y, ⊤) | as above |
| identity signer | (M, M, P), any P | none |
| gullible signer | any (X, Y, P) | none |

**Paths and lifecycles.** The kernel knows only spawn, kill, identity, burn and the phone's steps; pause, resume, destroy
and end are lifecycles the router manages, each certified by succession certs:
`sink → source → M1 → source → M2 → … → source → sink`.

- New session: the phone signs (sink, source-x, P); the spawner spawns from it.
- Pause: a kill into a fresh source. Resume: a spawn from it.
- A machine stopped outside Jarvis (`fly machine stop`, an exit, Fly's own doing; `router/lostmachine.go`): it is
  never started again in place (its key pair was in its memory only, so it couldn't prove it is the machine its cert
  names). Resume is a kill into a fresh source naming the newest signed snapshot, then a spawn from it; what the session
  did after that snapshot is lost. With no signed snapshot at all, Resume refuses (`noSnapshot`).
- End: a burn, (source, sink). Only a source can be burned: a machine has no used-once rule and stays alive whatever is
  signed about it, so (machine, sink) would stop nothing.
- Widening happens only out of the sink.
- **Adding to a running machine M** (e.g. a terminal): the phone signs (sink, source-x, P_add) and (source-x, M, ⊤), e.g.
  P_add = (`{shell}`, `{session:S, until:T}`); the router moves M's main grant along (M, M, (everything, `{until:T}`)) so
  the conditions match, and merges. The main grant stays untouched for after T; extending signs only a new small grant.

**The guard** (the supervisor's component that checks inputs; the supervisor, started at the image's entry point, pulls everything)

- Accepts exactly one grant at a time: signed by the grant mover or merger, naming this machine.
- Reads the start settings from its source (fixed for the session's life: the permission mode never changes).
- Gives conditions their meaning: `until` against the clock, `cmd:<hash>` against the command, `once:<id>` against its
  records (kept in the snapshot), `session:` against its session. Anything that needs the clock, a hash or memory is the
  guard's.
- `shell`: runs any command while the grant holds, getting a log-notary challenge over each command's hash first.
- Wakeups, crons and watches: their texts live in the snapshot (carried by the kill's snapshot hash); the router sends
  only "X is due" / "X fired".
- Screen, status, repo changes and the snapshot are output only.

**The iPhone app** shows what Deyao signs: known strings readably, unknown JSON pretty-printed, anything else raw; a
separate warning screen for the root key.

**Two kernel copies, and a release without an interruption** (Deyao, 2026-10-24; DECISIONS 233, docs/PLAN-cluster.md
"Releases: the copy flip"). Every component makes fresh RAM-only keys at start, which the root key's roster vouches
for. So the kernel runs as two copies, blue and green, each with all nine components, its own volumes and its own
roster; one serves, and a release lands only on the other. That copy's roster names its fresh keys, the serving secrets
(the keys the kit derives, the same in both copies), its own empty secrets as `secretsBoot`, and every serving member
as **retired**: retired keys sign nothing new, but what they signed while they served still counts — a grant by a
retired mover or merger opens (gv.Open), a cert, a notarization or a handoff by a retired member is that member's. Once
Deyao signs that roster (the release's one Face ID), every serving component hands over and **freezes** in the same
step: the notarizer's defined and succeeded sources, the spawner's machine records, kill certs and Fly token, and
secrets' seed, claim keys and final line state (the open unlocks included) are sealed to the agreement key the new
roster names for their role and signed by the component; the new copy's component takes a handoff only for exactly
the roster it holds, sealed to its own key and signed by the member of its role that roster retires. Then every call
goes to the new copy; live sessions keep their grants and documents (the machine checks them against the new copy's
roster, which the router serves root-signed). A frozen component serves nothing until a later flip hands state back
to it, and a component that took a handoff (kept on its volume) takes no other, so no state goes on in two places. A
crash restart (not a release) needs a re-signed roster, which names the restarted component's old keys as retired, so
live grants keep opening there too.

**Out of scope:** messages between sessions (the kernel guards only the entry point).

## Open

- Where the core's log lives. Plan: AWS CloudWatch Logs (append-only: no API deletes a single event; only a whole stream/group; the core's credential gets append rights only; free tier 5 GB/month covers it), added AFTER the core is running. Until then the log is local to the core.
- The secure pages' exact design (New session one page, review stops: 2026-10-10).
- Free text into high-privilege machines: the first prompt, a resume prompt and the session's own wakeups are vouched
  for ("Inputs to a machine"); wakeups made from the app or web (not by the session) are not delivered to a machine whose cert vouches, until the
  phone can sign them. Peer messages from other sessions: "Peer messages".
- Shell grants: a standing rule hands a feature (the router) a shell for its length; every exec under one bypasses
  the input log. Narrowing each holder to fixed commands is not done.
- Layer 1 hardening (CI-only builds and deploys) — see `SECURITY.md` PENDING 5–6.
