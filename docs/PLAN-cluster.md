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
- Blue/green = two fully independent kernel copies. Each knows only its own components and rejects everything else;
  the router tracks which copy each line is on and writes store changes to both; the phone has keys per copy.
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
  agreementKey}, …]}` (sorted by role), signed by the root key. `infra/setup.py kernel-roster` reads every
  component's identity through kernel-id.deyaochen.com, signs the payload with the setup key and files it with the
  router; the app checks the setup signature against keys/setup.pub from GitHub, shows the members and signs the same
  payload with the root key (its own Face ID); the router posts it to every component (`POST /roster`).
- Every component checks the roster against the root key's public half in `KERNEL_ROOT` (keys/root.pub, a ConfigMap),
  keeps it only if it lists its own keys under its own role, and checks every other component's identity against it
  (sig.CheckIdentity takes the roster instead of the box key). A machine gets the roster and the root key from the
  spawner (JARVIS2_KERNEL_ROSTER, JARVIS2_KERNEL_ROOT) in place of JARVIS2_KERNEL_BOX.
- secrets' claimed keys (derived from the kit's seed) replace its boot keys: the app, which derives them itself, signs
  a roster naming the derived keys in the same Recover, so the roster always names the keys secrets serves with.
- keys/root.pub: the app registers its root key's public half with the router (no Face ID); the setup session commits
  it once. Changing it later is a commit, as box.pub was.
- The members: notary, notarizer, mover, merger, spawner, identity, gullible, minter and secrets (the serving colour).
  The minter (DECISIONS 230) is the only component with GitHub egress; secrets reaches nothing outside the cluster but
  the minter, which it finds by role in the roster (its agreement key seals the deploy-key token, its signing key
  signs the answer). A minter restart makes the roster stale like any other component's.

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
