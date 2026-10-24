# PLAN: one cluster, the kernel on it, state apart from compute (Deyao, 2026-10-22)

Claude runs this plan autonomously (Deyao, 2026-10-22: "you can do all of these autonomously"), service disruption
accepted during the migration. Deyao is asked only for what needs his phone (Face ID with the root key, a Recover with
the kit). Order (Deyao): the kernel, the iOS app, the new cluster, then the state separated from compute.

## Decided
- One Kubernetes cluster that can span several nodes, on a NEW clean Hetzner VM; the old VMs (jarvis2-control,
  jarvis2-services) never join it: they are drained and deleted at the end. The control plane's share is held by
  Kubernetes memory reservations, not by separate clusters (replaces DECISIONS 186's two clusters).
- The kernel has no box key. Each component generates its own key inside its container. The root key (Deyao's phone)
  vouches for them: a setup session reads each component's public key straight from the new cluster's API, signs the
  list with the setup key (keys/setup.pub), and the app checks it and signs it with the root key under one Face ID.
  The old core keeps the box key until it is gone.
- Blue/green = two fully independent kernel copies. Each knows only its own components (its own roster) and rejects
  everything else; one serves, a release lands on the other, which takes over in the copy flip (below; Deyao,
  2026-10-24: "a kernel release never interrupts anything and costs one Face ID at his leisure").
- Everything about the kernel's identity lives in RAM only (Deyao, 2026-10-22): a component makes a new key at every
  start, so after a restart or release it works again only once the one-time setup has run for it (Face ID).
- Git manages the whole cluster (Deyao, 2026-10-22): Flux applies k8s/cluster as cluster admin, its own sync included;
  only the k3s install and the age key come from cloud-init.
- Setup sessions reach only the kernel's read-only identity endpoints, at kernel-id.deyaochen.com behind Cloudflare
  Access (service token jarvis2-kernel-id, infra store KERNEL_ID_ACCESS_ID/SECRET); no Kubernetes login.
- State apart from compute (Deyao, 2026-10-22): the router's records go into Postgres (CloudNativePG on the new
  cluster, run by Flux, WAL archived to object storage); the router becomes stateless replicas behind a rolling update;
  long actions (start, pause, destroy, archive, upgrade, restart) become durable jobs whose steps are safe to repeat,
  claimed by any replica; only the scheduler's tick has a leader (a lease in the database). Paused sessions' snapshots
  go to Hetzner Object Storage (Claude's pick; Deyao had no preference). The drain, the flock leader and the
  single-writer state.json go.
- Trust model, stated (Deyao, 2026-10-22): whoever can push to DE0CH/jarvis2 main controls the router and everything
  Flux runs, so git, CI and the router are all untrusted. What protects the stores is only the phone's keys (Face ID)
  checked by the kernel. The kernel's own anchor in git (keys/root.pub, below) is the one exception, at the same trust
  as keys/box.pub had for the old core.

## The roster (step 2: the kernel without a box key)
- A component starts with fresh keys and answers `GET /identity` with them (self-signed; nobody vouches yet). Until it
  holds a roster it answers 503 to everything that needs another component's identity.
- The roster is one document per kernel copy: `{"kind":"kernel-roster","copy":"blue","members":[{role, signingKey,
  agreementKey}, …],"retired":[…],"secretsBoot":{…}}` (members sorted by role; `retired` and `secretsBoot` below, each
  left out when empty), signed by the root key. `infra/setup.py kernel-roster` reads every component's identity
  through kernel-id.deyaochen.com (`/<role>-<copy>/identity`), signs the payload with the setup key and files it with
  the router; the app checks the setup signature against keys/setup.pub from GitHub, shows the members and signs the
  same payload with the root key (its own Face ID); the router posts it to every component of that copy (`POST
  /roster`).
- Every component checks the roster against the root key's public half in `KERNEL_ROOT` (keys/root.pub, a ConfigMap),
  keeps it only if it lists its own keys under its own role, and checks every other component's identity against it
  (sig.CheckIdentity takes the roster instead of the box key). A machine gets the roster and the root key from the
  spawner (JARVIS2_KERNEL_ROSTER, JARVIS2_KERNEL_ROOT) in place of JARVIS2_KERNEL_BOX.
- secrets' claimed keys (derived from the kit's seed) replace its boot keys: the app, which derives them itself, signs
  a roster naming the derived keys in the same Recover, so the roster always names the keys secrets serves with.
- keys/root.pub: the app registers its root key's public half with the router (no Face ID); the setup session commits
  it once. Changing it later is a commit, as box.pub was.
- The members: notary, notarizer, mover, merger, spawner, identity, gullible, minter and secrets, all of one copy. The
  minter (DECISIONS 232) is the only component with GitHub egress; secrets reaches nothing outside the cluster but its
  copy's minter, which it finds by role in the roster (its agreement key seals the deploy-key token, its signing key
  signs the answer). A minter restart makes the roster stale like any other component's.
- Retired keys: a roster also names keys that served before and sign nothing new: a restarted component's old keys (its
  copy's next roster), and the other copy's members (the roster of the copy that takes over). What a retired key signed
  while it served still counts (gv.Open takes a grant by a retired mover or merger; a cert, a notarization, a handoff
  by a retired member is that member's), so a live session's grant keeps opening across a release or a crash restart.
  The next roster names a retired key again only while something a line holds is signed by it (the router's
  `retiredInUse`). Never secrets: both copies' secrets serve with the keys the kit derives.

## Releases: the copy flip (DECISIONS 233)
- Deployments `<role>-<copy>`; `k8s/cluster/kernel/active-kernel.txt` names the serving copy. CI's pin job (infra/
  kernel-pin.py, still gated on the `Kernel-Release` trailer and each component's inputs, compared with the serving
  copy's pins) pins only into the other copy: the release's build for the components whose inputs changed, the serving
  copy's images for the rest, replicas 1, and the hold `jarvis2/kernel-release: pending`, which refuses a second release
  until the flip is committed.
- The setup session files that copy's roster (`infra/setup.py kernel-roster --copy <it>`): its components' fresh keys,
  the serving secrets as its secrets, its own empty secrets as `secretsBoot`, the serving copy's members as retired.
  Deyao signs it in the app: the release's one Face ID, at his leisure (nothing waits on it: the serving copy goes on).
- Then the router flips by itself (router/kernelflip.go), each step kept so a restart carries on: with every kernel
  call held, each serving component hands over (`POST /handoff` with the new roster) and freezes in the same step; the
  notarizer (defined and succeeded sources), the spawner (machines, kill certs, the Fly token) and secrets (its seed,
  the claim's keys, a final line state with the open unlocks) seal their state to the new copy's agreement key from the
  signed roster and sign it; the new copy's notarizer, spawner and secrets take it only from the member of their role
  that their roster retires (secrets: from the secrets it names), only for exactly that roster, sealed to their own
  keys; then every call goes to the new copy. A frozen component never serves again until it takes a handoff back, so
  no state goes on in two places; it hands the same frozen state to a newer roster of the other copy (one of whose
  components restarted before taking over), and a component that took a handoff serves and takes no other, so a frozen
  state can't come back over a newer one. Secrets, which keeps nothing on disk, hands over to one roster only; one of
  the new copy that lost its memory is Recovered with the kit, as after any secrets crash.
- Live machines learn the new copy from the router's root-signed roster (`/m/kernel/boot`), checked against the root
  key in their Fly config; their documents from before (signed by the old copy) check as the retired members'.
- Afterwards the setup session runs `infra/setup.py kernel-flipped` and commits: active-kernel.txt names the new
  serving copy, its hold goes, the old copy's Deployments scale to zero until the next release lands on them (the
  router can't push; git is how the cluster changes; never a force push).
- A crash restart of a serving component (not a release) still needs a re-signed roster (its fresh keys), which retires
  the old keys, so live grants keep opening; a crashed secrets is Recovered with the kit as before.

## Steps
0. This plan.
1. The new cluster on a new Hetzner VM.
2. The kernel on it, components generating their own keys; the one-time setup with the root key (the roster).
3. Two independent kernel copies.
4. An ad hoc router that works with all three clusters (old control, old services, new).
5. Move everything over to the new cluster (router, services, edge); new sessions on the kernel.
6. The router in its proper form: state in Postgres, stateless replicas, durable jobs, snapshots in object storage.
7. Drain the old clusters; delete their VMs.

## Done
- Step 1 (2026-10-22): jarvis2-cluster-1 (cx23, fsn1, 10.77.0.4), k3s --cluster-init, Flux on k8s/cluster; logs in
  Grafana as box="cluster".
- Step 2a (2026-10-22): the tunnel jarvis2-cluster, its cloudflared in jarvis2-edge; kernel-id.deyaochen.com answers 200
  with the service token and 403 without (a test page until the kernel's identity endpoints replace it).
