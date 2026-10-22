# Jarvis 4 — the web page

An Expo (React Native for web) app: the **web page** the router serves at `/`. It talks to the router exactly as
`docs/API.md` says. The iPhone and iPad app is a separate native SwiftUI app in [`../ios`](../ios) (TestFlight
"Jarvis 4", `dev.de0ch.jarvis4`). Design choices of both: [DECISIONS.md](DECISIONS.md).

```
src/       the UI (expo-router): sessions, Inbox, search, stores, previous sessions, tasks, machines, settings, and the
           pages: new session, terminal, transcript, grants, schedules
scripts/   make-icon.py: the app icon (also written into ios/Jarvis4/Assets.xcassets) and the favicon
```

## Web page → the router

```bash
cd app && npm ci && npx expo export --platform web --output-dir ../web    # = npm run build:web
```

The output is **`web/` at the repo root**; the images workflow runs exactly this command and the router
image serves that directory (`WEB_DIR`). The web page views everything and can request a new session,
reject an approval and pause/resume/destroy; approvals happen only in the app (it has no keys).

## CI

`.github/workflows/web.yml`: typecheck, the tests (`npm test`, node's test runner over `test/*.test.mjs`) + the web export. The iOS app's CI (compile, interop, the simulator
walkthrough, the phone replica, TestFlight) is `ios.yml`, the transitions run `transitions.yml`; see
docs/RUNBOOK.md "Testing" and the `jarvis2-ios` skill (`.claude/skills/jarvis2-ios`).
