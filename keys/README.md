Public keys Jarvis 4 trusts (docs/DESIGN.md):
- `box.pub` — the control box's key (private half only on that box, from user-data at creation). Signs each core's
  identity; the app and `infra/setup.py` check it before they trust a core. A new control box = a new key:
  infra/create.sh writes `box-next.pub`, which becomes `box.pub` (a commit) before Deyao sets the new box's core up.
- `control-age.pub`, `services-age.pub` — each box's age key: the SOPS recipient of its secrets (k8s/<box>/secrets/,
  infra/router-secrets.py).
- `ci.pub` — CI's image key: the phone shows a session image as a CI build only with its signature.
- `setup.pub` — the setup session's key (private half JARVIS2_SETUP_KEY in Jarvis 1's default store). The
  router checks it on every /setup call; the app checks it on the backups the setup session writes.

No master key is here: Deyao's app makes it (Reset), its private half exists only in his recovery kit, and the
core learns the public half from his claim.
