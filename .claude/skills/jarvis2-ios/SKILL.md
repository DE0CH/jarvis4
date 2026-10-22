---
name: jarvis2-ios
description: Work on the Jarvis 4 iPhone/iPad app, the native SwiftUI app in ios/ (bundle dev.de0ch.jarvis4, TestFlight "Jarvis 4"). How it is laid out, the security rules every review page must keep, how to build and test it with no Mac (GitHub macOS runners), the walkthrough, transitions and phone-replica tests, and shipping to TestFlight. Use when a task touches ios/, the app's Face ID review pages, its CI (ios.yml, transitions.yml) or a TestFlight build. Follow the swiftui-pro and swift-concurrency-pro skills for code style.
---

# jarvis2-ios

One native SwiftUI app for iPhone and iPad (Deyao, 2026-10-11). It uses Apple frameworks and our Swift only: no
packages, no pods, no React Native. The web page is a separate Expo app in `app/`. Decisions: `app/DECISIONS.md`.
Design: `docs/DESIGN.md` "iOS app structure".

## Layout (`ios/`)

```
project.yml          xcodegen spec (Jarvis4.xcodeproj is generated, not in git); iOS 26.0, iPhone + iPad
Jarvis2/App          @main, RootView (setup cover, review sheet, alerts, notice), MainTabs (sidebarAdaptable)
Jarvis2/Model        AppModel (state, polling, pending labels, exclusive, ask/confirm, present review),
                     AppModel+Actions (pause/resume/destroy/…), JSON (lenient), Shapes (router shapes), SecureRequest
Jarvis2/Network      RouterClient: sign-in + every router/core call; core answers verified against the pinned key
Jarvis2/Security     CoreCrypto / CoreSetup / SignedAction (pure, ALSO compiled into interop/), PhoneKeys, KeySource,
                     LinePins + PinnedPolicy, StoreUnlock, Attestation
Jarvis2/Review       the Face ID sheets: NewSession (+ AttachmentsSection, PickedImage/ImagePrep, CameraPicker), Approval
                     (+ SignedAttachmentRow: a signed image checked against the router's copy), GrantReview, UnlockReview,
                     RepoKey, RequestReviewSection
Jarvis2/<feature>    Sessions (split view, detail, terminal WebView, grants, schedules, remote, transcript), Inbox,
                     Previous, Search, Stores, Tasks, Settings (usage, Fly, repos, machines), Setup (Reset or recover)
UITests/             UITestKit (helpers, blank checks), Jarvis4UITests (walkthrough), TransitionsUITests, ReplicaUITests
interop/             swift run Interop / Rehearse: the Security files (symlinks) against the real core
ci/                  standins.sh (keys, S3 stand-in, core + router), standin.py, replica-stack.sh (the replica's Jarvis 4),
                     replica-setup.sh (the setup session's answers), replica-host.py (Face ID, those answers)
```

## Rules for any page that signs (keep them)

- **Render what is signed from the signed content.** Decode the core's signed doc (`CoreCrypto.decode` with
  `CoreTrust.key()`), set the page's "What you sign" from `SignedAction.*`, and check the answer that comes back
  (`Checks.answerFor`, `deployKeyAnswer`, the stored grant).
- **Name the session from signed content, never the router's label**: an approval reads `Checks.continues` (the
  predecessor's cert); a grant or unlock reads the session's cert (`LineIdentity`). Run `LinePins.check(session:line:)`
  and `Checks.sameSession`. The router's label may show only as "(unverified)".
- **Never let the router widen a signature**: New session runs `Checks.matchesPicked` + `Checks.onlyHarnessExtras`
  against `PinnedPolicy` (policy/stores.json bundled in the app) and `ImageAttestation.check` (keys/ci.pub).
- **One Face ID per action**: a Secure Enclave use goes through `offMain { PhoneKeys.shared… }`; combine
  signature + shares in one call (`signAndShares`). Keys are `.biometryCurrentSet`; Reset/Recover `renew()` them;
  the device key (`devicePublic`/`deviceSign`) countersigns claims and wipes.
- Store unlocks verify the blob's writer (`Checks.writer`, required when the signed store list says `writers: true`).
- New settings for a session = `Checks.configKeys` + `SignedSettingsSection` + `SessionConfig` in router/ and machine/.

## UI copy (Deyao, 2026-10-12)

- **No prose pieced together by code.** Show facts as UI: `LabeledContent` rows, lists, badges, buttons, short
  section titles. Never a sentence built from fields ("The machine turned away status (…)", "You allow X to Y until
  Z"). "What you sign (exact)" is a section of labelled rows rendered from the signed content, not a paragraph.
- **Prose only from an LLM** (a caller's reason, a session's title or summary), shown as that author's text.
- Standard platform controls and the HIG over custom layouts. The same rule holds for the web page (`app/`).

## Build and test without a Mac

- There is no Swift-for-iOS compiler on Linux: push and let **`ios.yml` → compile** (macos-26, Release and JARVIS_CI
  flavours, about 5 min) tell you; its `compile` artifact has `errors.txt`. `gh run view <id> --json jobs` for status;
  job logs: `gh api --allow-escape-sequences repos/DE0CH/jarvis2/actions/jobs/<job>/logs`.
- Pitfalls hit so far: `Section("Title") { … } footer: { … }` doesn't exist (use `Section { } header: { Text(…) }
  footer: { }`); a long `Form` body times out the type checker (split it into `@ViewBuilder` properties); an
  `.accessibilityIdentifier` on a container overrides its children's unless `.accessibilityElement(children: .contain)`.
- **Walkthrough** (`ios.yml` simulator job, xcode-27 runner, `.github/actions/ios-simulator` = iPhone 17 / iOS 27.0):
  a real core (fakefly) and router on the runner, Recover with the public TEST kit, every flow, light and dark,
  recorded (`results` artifact: screenshots per step, `walkthrough-*.mov`).
- **Transitions** (`transitions.yml`): every tab, push, pop, edge swipe, sheet, background and relaunch; fails on a
  blank screen over 1.5 s or a near-uniform screenshot.
- **Interop** (`ios.yml` interop): `ios/ci/standins.sh W` then `swift run Interop` in `ios/interop` (also on Linux
  with a swift.org toolchain and swift-crypto).
- **Phone replica** (`ios.yml` job `replica`, main only, about 70 min on the `xcode-27` runner): the Release build
  against a real throwaway Jarvis 4 on the runner (`ios/ci/replica-stack.sh`: this commit's core and router, real Fly
  session machines over the run's own WireGuard peer), Face ID driven by `ios/ci/replica-host.py`, the setup session's
  answers by `ios/ci/replica-setup.sh`. Secrets: GitHub environment `replica` (REPLICA_FLY_TOKEN, REPLICA_REPO_TOKEN for
  `DE0CH/jarvis4-replica-test`). docs/RUNBOOK.md "The phone replica".

## Ship

Push to main → `ios.yml`: TestFlight ships when the walkthrough, the interop test and the replica of that run pass.
The job runs in environment `release` (main only; ASC secrets there), archives unsigned and cloud-signs at export
(lessons/75), build number = run number + 1000. Check with the apple-dev skill's
`testflight-status.py dev.de0ch.jarvis4`. Never use Deyao's iPhone to test.
