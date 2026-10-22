import XCTest

/// The phone replica (ios.yml job `replica`): the RELEASE build of the native app on the simulator matching Deyao's
/// iPhone, against a real throwaway Jarvis 4 on the runner (ios/ci/replica-stack.sh: this commit's core and router,
/// backups) and real Fly sessions, every flow tapped as a person would. Face ID is enrolled on the simulator and each
/// match or failure is sent by the runner (ios/ci/replica-host.py on 127.0.0.1:18300), which also passes messages to the
/// setup session's part on the same runner (ios/ci/replica-setup.sh: "reset done" → the stores are written;
/// "session-file" → the image attached on New session is on the session's machine). A step fails on a blank screen, a
/// stuck state (a session not running within its time) or a broken transition.
final class ReplicaUITests: JarvisUITestCase {
  var kit = ""

  func must(_ ok: Bool) throws { if !ok { throw XCTSkip("stopping: an earlier step failed") } }

  // ---- the runner: Face ID and the relay to the setup session ----
  @discardableResult func host(_ path: String, timeout: TimeInterval = 30) -> String {
    let sem = DispatchSemaphore(value: 0)
    nonisolated(unsafe) var out = ""
    var r = URLRequest(url: URL(string: "http://127.0.0.1:18300/" + path)!)
    r.timeoutInterval = timeout
    URLSession.shared.dataTask(with: r) { d, _, _ in out = String(decoding: d ?? Data(), as: UTF8.self); sem.signal() }.resume()
    _ = sem.wait(timeout: .now() + timeout + 5)
    return out
  }
  func faceIDMatches(_ seconds: Int = 90) { host("faceid/match?for=\(seconds)") }
  func faceIDFails() { host("faceid/nomatch") }
  func relay(_ msg: String) -> String { host("relay?msg=\(msg)", timeout: 600) }

  func background(_ seconds: UInt32 = 5) { XCUIDevice.shared.press(.home); sleep(seconds); app.activate(); sleep(2) }
  func relaunch() { app.terminate(); sleep(2); app.launch() }

  // ---- waiting on the first of several elements (a Cancel that may sit in the app, SpringBoard or the Face ID sheet) ----
  func waitAny(_ es: [XCUIElement], _ s: TimeInterval) -> XCUIElement? {
    let until = Date().addingTimeInterval(s)
    while Date() < until { if let e = es.first(where: { $0.exists }) { return e }; usleep(500_000) }
    return nil
  }
  func openNewSession() -> Bool {
    sessionsList()
    guard wait(el("newBtn"), 30, "sessions") else { return false }
    el("newBtn").tap()
    let ok = arrives(el("secure-create"), 60, "the New session page")
    if ok {
      sleep(1); shot("new-session")
      scrolledTo(prefixed("ns-repo-"), max: 4)
      let picked = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'ns-repo-' AND selected == true")).count
      if !el("ns-repo-claude-env").exists { XCTAssertEqual(picked, 0, "no repo pre-selected without claude-env on the list") }
      else { XCTAssertTrue(el("ns-repo-claude-env").isSelected, "claude-env pre-selected") }
      scrolledUpTo(el("ns-prompt"))
    }
    return ok
  }
  func openStores() { tabRoot("Settings"); if wait(el("open-stores"), 30, "Settings → Stores") { el("open-stores").tap() } }

  // ---- the Inbox: a request filed elsewhere shows on the tab's badge; Review opens its page with the three fields ----
  func inboxReview(_ what: String) -> Bool {
    let inboxTab = app.tabBars.buttons["Inbox"]
    _ = wait(inboxTab, 30, "the Inbox tab")
    let until = Date().addingTimeInterval(90)
    while Date() < until && ((inboxTab.value as? String) ?? "").isEmpty { sleep(2) }
    XCTAssertFalse(((inboxTab.value as? String) ?? "").isEmpty, "[\(what)] the badge counts the request")
    inboxTab.tap()
    guard wait(prefixed("request-review-"), 60, "the request in the Inbox (\(what))") else { return false }
    sleep(1); shot("inbox-" + what)
    prefixed("request-review-").tap()
    let ok = arrives(el("request-call"), 30, "the review page (\(what))")
    let signed = el("signed-kind")
    _ = signed.waitForExistence(timeout: 30)
    sleep(1); shot("inbox-review-" + what)
    for id in ["signed-kind", "signed-action", "signed-repo", "signed-store", "signed-feature", "signed-session", "request-caller", "request-call", "request-explanation"] where el(id).exists { note("\(what)-\(id)", said(el(id))) }
    XCTAssertFalse(el("request-mismatch").exists, "[\(what)] the request matches the page")
    XCTAssertTrue(said(signed).contains("Core request") || said(signed).contains("Phone grant"), "[\(what)] what is signed, rendered from the signed content: \(said(signed))")
    return ok
  }
  func inboxDeny(_ what: String) {
    guard scrolledTo(el("request-deny"), max: 6) else { XCTFail("[\(what)] no Deny on the review page"); note("tree-deny-\(what)", app.debugDescription); return }
    el("request-deny").tap()
    XCTAssertTrue(gone(el("request-call"), 30), "[\(what)] Deny leaves the page")
    XCTAssertTrue(gone(prefixed("request-review-"), 60), "[\(what)] denied: off the Inbox")
    shot("inbox-denied-" + what)
  }
  func inboxAllowed(_ what: String, button: String) {
    faceIDMatches()
    el(button).tap()
    XCTAssertTrue(gone(el("request-call"), 90), "[\(what)] the page closes after Face ID")
    XCTAssertTrue(gone(prefixed("request-review-"), 60), "[\(what)] allowed: off the Inbox")
    shot("inbox-allowed-" + what)
  }

  func testReplica() throws {
    continueAfterFailure = true
    tag = "replica"
    app.launch()

    // ---- Reset: a new kit, copied and confirmed; the core is set up with no stores ----
    try must(wait(el("setup-state-empty"), 180, "Reset or recover: the core is empty"))
    shot("setup-empty")
    el("setup-choose-reset").tap()
    try must(wait(el("setup-kit"), 30, "the new recovery kit"))
    kit = el("setup-kit").label
    XCTAssertTrue(kit.hasPrefix("jarvis2-kit:2:"), "the kit is one string (\(kit.prefix(16))…)")
    shot("setup-kit", checkBlank: false)
    background()
    XCTAssertTrue(el("setup-kit").exists, "the kit page survives backgrounding")
    el("setup-kit-copy").tap()
    faceIDMatches(240)   // the device key countersigns the claim (the iOS 27 simulator can take 3 tries to show the sheet)
    el("setup-kit-saved").tap()
    try must(wait(el("setup-done"), 240, "reset done"))
    shot("setup-reset-done")
    el("secure-back").tap()
    XCTAssertEqual(relay("reset-done"), "filled", "the setup session wrote the stores")

    // ---- stores: Face ID refused, then unlock and lock ----
    try must(arrives(el("newBtn"), 120, "the app's list"))
    openStores()
    try must(wait(el("unlock-rh-plain"), 60, "stores page with rh-plain"))
    XCTAssertFalse(el("sensitive-rh-plain").exists, "rh-plain is not sensitive")
    XCTAssertTrue(el("sensitive-rh-secret").exists, "rh-secret is sensitive")
    shot("stores")
    faceIDFails()
    el("unlock-rh-plain").tap()
    sleep(3)
    shot("faceid-failed", checkBlank: false)
    let laui = XCUIApplication(bundleIdentifier: "com.apple.LocalAuthenticationUIService")
    if let c = waitAny([app.buttons["Cancel"].firstMatch, springboard.buttons["Cancel"].firstMatch, laui.buttons["Cancel"].firstMatch], 20) { c.tap() }
    XCTAssertTrue(wait(app.alerts.firstMatch, 20, "a failed Face ID leaves the store locked, with a message"))
    if app.alerts.firstMatch.exists { note("faceid-failure", app.alerts.firstMatch.label); app.alerts.firstMatch.buttons["OK"].tap() }
    XCTAssertFalse(el("lock-rh-plain").exists, "no unlock without Face ID")
    faceIDMatches()
    el("unlock-rh-plain").tap()
    wait(el("lock-rh-plain"), 60, "rh-plain unlocked")
    shot("stores-unlocked")
    el("lock-rh-plain").tap()
    XCTAssertTrue(gone(el("lock-rh-plain"), 30), "rh-plain locked again")
    back()

    // ---- the offline copy: Settings → Encrypted backup (checked, never opened), then the runner opens the saved file
    // with this run's kit (tools/decrypt-backup.py, offline, keys/setup.pub) and finds the stores the setup session wrote
    if downloadBackup() {
      let opened = host("backup-open?kit=" + (kit.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? ""), timeout: 60)
      note("backup-open", opened)
      XCTAssertTrue(opened.hasPrefix("ok ") && opened.contains("rh-plain,") && opened.contains("rh-secret*"), "the saved file opens offline with the kit: \(opened)")
    }

    // ---- new session: one page, its stores (and the harness's) unlocked with Face ID, running on Fly ----
    try must(openNewSession())
    scrolledTo(el("secure-store-rh-plain"), max: 4)
    if wait(el("secure-store-rh-plain"), 30, "rh-plain offered") { el("secure-store-rh-plain").tap() }
    XCTAssertFalse(el("secure-store-claude").exists, "the harness's own store isn't offered as a pick")
    // an image from Photos (the replica job added one): Start uploads it and signs its sha256 + size with the session
    for _ in 0..<3 { app.swipeDown() }
    let image = attachImage()
    shot("new-session-picked")
    faceIDMatches(90)
    el("secure-create").tap()
    let row = prefixed("srow-")
    try must(arrives(row, 120, "the session's row"))
    let sid = String(row.identifier.dropFirst("srow-".count))
    note("session", sid)
    // the New session page slides away first; a tap during that is lost (replica run 38182890226), so tap again as a
    // person would until the session's page is up
    XCTAssertTrue(gone(el("secure-create"), 60), "the New session page closes")
    for _ in 1...3 where !el("more-\(sid)").exists { if row.isHittable { row.tap() }; _ = el("more-\(sid)").waitForExistence(timeout: 10) }
    try must(wait(el("term-\(sid)"), 600, "the session is running on Fly (Terminal offered) within 10 minutes"))
    sleep(2); shot("session-running")
    // the machine took the image only if its bytes hash to what the phone signed (and the core attested it): the setup
    // session looks for it on the machine
    if let image {
      let seen = relay("session-file:\(sid):\(image)")
      note("session-file", seen)
      XCTAssertTrue(seen.hasPrefix("ok"), "the session's machine has the image it was started with: \(seen)")
    }

    // ---- machines: the session's machine listed as its session's ----
    tabRoot("Settings")
    if wait(el("open-machines"), 30, "Machines") {
      el("open-machines").tap()
      wait(prefixed("machine-session-"), 60, "the Machines page lists the session's machine")
      shot("machines")
      back()
    }

    // ---- a kill and relaunch mid-flow: no setup page, the session still there ----
    relaunch()
    XCTAssertFalse(el("setup-state-empty").waitForExistence(timeout: 10), "no Reset or recover after a relaunch")
    sessionsList()
    try must(wait(el("srow-\(sid)"), 90, "the running session after a relaunch"))
    shot("after-relaunch")
    el("srow-\(sid)").tap()

    // ---- terminal: the screen shows view only with no grant; typing is turned away → the grant review → Deny, then
    // Allow with Face ID → a command runs ----
    try must(wait(el("term-\(sid)"), 30, "Terminal"))
    el("term-\(sid)").tap()
    let input = app.webViews.textFields["Terminal input"].firstMatch
    let viewOnly = app.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH 'view only'")).firstMatch
    if wait(viewOnly, 90, "the session's screen, view only, before any grant") { shot("terminal-view-only") }
    let allow = app.webViews.buttons["Allow terminal for 10 minutes"]
    if wait(input, 30, "the terminal input") {
      input.tap(); input.typeText("x")
      app.webViews.buttons["Send"].tap()
    }
    if wait(allow, 60, "typing asks for a grant") {
      shot("terminal-needs-grant")
      allow.tap()
      if arrives(el("secure-grant-allow"), 30, "the grant review") {
        XCTAssertTrue(said(el("signed-feature")).contains("Terminal"), "the review names the feature")
        shot("grant-review")
        el("secure-back").tap()
        // denied: the screen stays view only; the next keystroke is turned away again
        if input.waitForExistence(timeout: 20) { input.tap(); input.typeText("x"); app.webViews.buttons["Send"].tap() }
        if wait(allow, 60, "denied: typing still turned away") {
          allow.tap()
          _ = arrives(el("secure-grant-allow"), 30, "the grant review again")
          faceIDMatches()
          el("secure-grant-allow").tap()
          XCTAssertTrue(gone(el("secure-grant-allow"), 90), "the review closes after Face ID")
          XCTAssertTrue(gone(allow, 60), "allowed: the terminal opens")
        }
      }
    }
    if wait(input, 30, "the terminal input") {
      let marker = "replica\(Int.random(in: 1000...9999))"
      input.tap()
      for c in marker { input.typeText(String(c)) }
      app.webViews.buttons["Send"].tap()
      let out = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", marker)).firstMatch
      XCTAssertTrue(out.waitForExistence(timeout: 60), "what was typed shows on the session's screen")
      shot("terminal-output")
      background(3)
      XCTAssertTrue(input.waitForExistence(timeout: 20), "the terminal survives backgrounding")
    }
    back()

    // ---- the session's Log: the real machine's supervisor lines, the boot's start (Router) and its Fly steps, one stream
    checkLogs(sid, supervisorLine: true, flyStep: true, "running")

    // ---- the Inbox, from a session: deny one grant request, allow another with Face ID ----
    XCTAssertEqual(relay("inbox-session:\(sid):status"), "ok", "the session filed a grant request")
    if inboxReview("session-deny") {
      if scrolledTo(el("request-caller"), max: 4) { XCTAssertTrue(said(el("request-caller")).contains("session"), "the caller is the session: \(said(el("request-caller")))") }
      if scrolledTo(el("request-explanation"), max: 4) {  // the caller's reason sits below the signed rows
        XCTAssertTrue(said(el("request-explanation")).contains("replica-the-session"), "the session's reason is shown")
      } else { XCTFail("the session's reason is shown"); note("tree-reason", app.debugDescription) }
      inboxDeny("session")
    }
    XCTAssertEqual(relay("inbox-session:\(sid):archive"), "ok", "the session filed another")
    if inboxReview("session-allow") { inboxAllowed("session", button: "secure-grant-allow") }

    // ---- a batch from the session: two grants under one summary, one Inbox entry, both allowed with ONE Face ID ----
    XCTAssertEqual(relay("inbox-batch:\(sid)"), "ok", "the session filed a batch")
    tabRoot("Inbox")
    if wait(prefixed("batch-review-"), 90, "the session's batch in the Inbox") {
      shot("inbox-batch")
      prefixed("batch-review-").tap()
      if arrives(el("batch-allow"), 30, "the batch page") {
        XCTAssertTrue(said(el("batch-summary")).contains("replica-the-session-asks-for-two-grants"), "the session's summary: \(said(el("batch-summary")))")
        XCTAssertTrue(said(el("batch-caller")).contains("session"), "the caller is the session: \(said(el("batch-caller")))")
        let until = Date().addingTimeInterval(60)
        while !el("batch-allow").isEnabled && Date() < until { sleep(1) }
        if el("batch-item-signed-1").exists { el("batch-item-signed-1").tap(); sleep(1) }
        shot("batch-review")
        faceIDMatches()
        el("batch-allow").tap()
        XCTAssertTrue(gone(el("batch-allow"), 120), "both grants signed under one Face ID: the page closes")
        XCTAssertTrue(gone(prefixed("batch-review-"), 60), "the batch is off the Inbox")
        shot("batch-allowed")
      }
    }

    // ---- Jarvis's own messages go straight in (DECISIONS 210): the Inbox outcomes of what the session filed above (the
    // denied grant, the allowed one, the batch) never wait for Deyao, though the session holds a sensitive store ----
    sessionsList()
    if wait(el("srow-\(sid)"), 30, "the session") { el("srow-\(sid)").tap() }
    sleep(10)  // the outcomes are delivered within seconds of the decisions; a held one would show by now
    XCTAssertFalse(el("msg-count-\(sid)").exists, "no Inbox outcome waits on the session's page: \(said(el("msg-count-\(sid)")))")
    tabRoot("Inbox")
    XCTAssertFalse(el("msg-group-\(sid)").exists, "no message for the session waits in the Inbox")
    shot("outcomes-not-held")
    sessionsList()
    if wait(el("srow-\(sid)"), 30, "the session") { el("srow-\(sid)").tap() }

    // ---- grants: a 5-minute status grant, then forget it (the page is long: scroll to its Grants) ----
    if scrolledTo(el("grants-\(sid)"), max: 6) || wait(el("grants-\(sid)"), 30, "Grants") {
      el("grants-\(sid)").tap()
      if wait(el("grant-review"), 30, "grants page") {
        shot("grants")
        XCTAssertTrue(el("grant-forget-terminal").exists, "the terminal's grant is listed in force")
        pick("grant-holder", "Status")
        pick("grant-len", "5 min")
        el("grant-review").tap()
        if arrives(el("secure-grant-allow"), 30, "the grant review (status)") {
          faceIDMatches()
          el("secure-grant-allow").tap()
          XCTAssertTrue(gone(el("secure-grant-allow"), 90), "the review closes after Face ID")
          if wait(el("grant-forget-status"), 60, "the status grant listed") {
            shot("grants-two")
            el("grant-forget-status").tap()
            answer("Forget")
            XCTAssertTrue(gone(el("grant-forget-status"), 30), "forgotten")
          }
        }
        back()
      }
    }

    // ---- repos: add the throwaway repo (its deploy key made by the core on a Face ID), the setup session asks to remove
    // it (deny), remove it here, then the setup session asks to add it again (allow) ----
    let repo = env["REPLICA_REPO"] ?? ""
    let repoName = String(repo.split(separator: "/").last ?? "")
    if !repo.isEmpty {
      tabRoot("Settings")
      if wait(el("open-repos"), 30, "Repos") {
        el("open-repos").tap()
        if wait(el("repo-add"), 30, "Add repo") {
          el("repo-add").tap()
          let f = el("repo-url")
          if wait(f, 30, "the repo field") {
            f.tap(); slowType(f, repo + "\n")
            if arrives(el("secure-repo-go"), 30, "the add-repo review") {
              shot("repo-add")
              faceIDMatches()
              el("secure-repo-go").tap()
              if wait(el("repo-key-" + repoName), 90, "the repo listed with its deploy key") {
                shot("repo-added")
                XCTAssertEqual(relay("repo-added"), "ok", "GitHub shows the repo's deploy key")
                XCTAssertEqual(relay("inbox-setup-remove"), "ok", "the setup session filed a remove request")
                if inboxReview("setup-deny") {
                  XCTAssertTrue(said(el("request-caller")).contains("Claude"), "the caller is the setup session: \(said(el("request-caller")))")
                  inboxDeny("setup")
                }
                tab("Settings")
                XCTAssertTrue(wait(el("repo-key-" + repoName), 30, "denied: the repo is still listed"), "deny kept the repo")
                el("repo-remove-" + repoName).tap()
                if arrives(el("secure-repo-go"), 30, "the remove-repo review") {
                  faceIDMatches()
                  el("secure-repo-go").tap()
                  XCTAssertTrue(gone(el("repo-key-" + repoName), 90), "the repo is removed")
                  shot("repo-removed")
                }
              }
            }
          }
        }
      }
      XCTAssertEqual(relay("repo-check"), "ok", "GitHub shows the deploy key added and removed")
      XCTAssertEqual(relay("inbox-setup-add"), "ok", "the setup session filed an add request")
      if inboxReview("setup-allow") {
        XCTAssertTrue(said(el("signed-repo")).contains(repo) && el("signed-store").exists, "what is signed names the repo and its store: \(said(el("signed-repo")))")
        inboxAllowed("setup", button: "secure-repo-go")
        XCTAssertEqual(relay("repo-added"), "ok", "GitHub shows the deploy key made from the Inbox")
      }
    }

    // ---- a session stuck at boot (its store locked again right after Start) is destroyed at once ----
    if openNewSession() {
      scrolledTo(el("secure-store-rh-secret"), max: 4)  // below the Images section
      if wait(el("secure-store-rh-secret"), 30, "rh-secret offered") { el("secure-store-rh-secret").tap() }
      faceIDMatches(90)
      el("secure-create").tap()
      XCTAssertTrue(gone(el("secure-create"), 120), "the New session page closes")  // the list shows behind it already
      _ = arrives(el("newBtn"), 30, "back on the list")
      openStores()
      // the unlock is for this one session and ends once its machine has pulled the store (carried secrets): when the
      // machine was faster than this page, rh-secret is Locked already and the session runs — nothing to strand
      if !el("lock-rh-secret").waitForExistence(timeout: 20) {
        XCTAssertTrue(el("unlock-rh-secret").exists, "rh-secret locked again once the new session's machine pulled it")
        shot("stores-relocked-after-pull")
        back()
        sessionsList()
        let second = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'srow-' AND identifier != %@", "srow-" + sid)).firstMatch
        if wait(second, 30, "the second session") {
          let sid2 = String(second.identifier.dropFirst("srow-".count))
          second.tap()
          if (scrolledTo(el("destroy-\(sid2)")) || true), wait(el("destroy-\(sid2)"), 20, "Destroy (second)") {
            el("destroy-\(sid2)").tap()
            answer("Destroy session", timeout: 60)
            XCTAssertTrue(gone(el("srow-\(sid2)"), 900), "the second session is destroyed")
          }
        }
      } else {
      el("lock-rh-secret").tap(); _ = gone(el("lock-rh-secret"), 30)
      back()
      sessionsList()
      sleep(150)
      shot("stuck-session")
      let others = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'srow-' AND identifier != %@", "srow-" + sid))
      if others.count > 0 {
        let stuck = others.firstMatch
        let stuckSid = String(stuck.identifier.dropFirst("srow-".count))
        stuck.tap()
        if (scrolledTo(el("destroy-\(stuckSid)")) || true), wait(el("destroy-\(stuckSid)"), 20, "Destroy (stuck)") {
          el("destroy-\(stuckSid)").tap()
          answer("Destroy session", timeout: 30)
          let t0 = Date()
          let wait10 = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS 'last snapshot'")).firstMatch
          if wait10.waitForExistence(timeout: 5) { XCTFail("a never-booted session's destroy waits for a snapshot: \(wait10.label)") }
          XCTAssertTrue(gone(el("srow-\(stuckSid)"), 90), "a session stuck at boot is destroyed within 90 s")
          note("stuck-destroy-seconds", "\(Int(Date().timeIntervalSince(t0)))")
          shot("stuck-destroyed")
        }
      } else { XCTFail("no second session to destroy") }
      }
    }

    // ---- destroy the running session ----
    sessionsList()
    if wait(el("srow-\(sid)"), 30, "the running session") {
      el("srow-\(sid)").tap()
      if (scrolledTo(el("destroy-\(sid)")) || true), wait(el("destroy-\(sid)"), 20, "Destroy") {
        el("destroy-\(sid)").tap()
        answer("Destroy session", timeout: 60)
        XCTAssertTrue(gone(el("srow-\(sid)"), 900), "the session is destroyed")
      }
    }

    // ---- Recover with the kit: Settings → Reset or recover → Recover (restart) → every store back ----
    tabRoot("Settings")
    if (scrolledTo(el("open-setup")) || true), wait(el("open-setup"), 30, "Reset or recover in Settings") {
      el("open-setup").tap()
      try must(wait(el("setup-choose-recover"), 60, "the setup page (set up: mine)"))
      shot("setup-mine")
      el("setup-choose-recover").tap()
      try must(wait(el("setup-kit-field"), 15, "kit field"))
      el("setup-kit-field").tap(); el("setup-kit-field").typeText(kit)
      el("setup-recover-go").tap()
      if wait(el("setup-restart-confirm"), 30, "restart and recover") {
        shot("setup-restart")
        faceIDMatches(120)
        el("setup-restart-confirm").tap()
      }
      try must(wait(el("setup-done"), 600, "recovered"))
      shot("setup-recovered")
      el("secure-back").tap()
      openStores()
      if wait(el("unlock-rh-plain"), 60, "rh-plain back") {
        XCTAssertFalse(el("sensitive-rh-plain").exists, "rh-plain came back not sensitive")
        XCTAssertTrue(el("sensitive-rh-secret").exists, "rh-secret came back sensitive")
        shot("stores-recovered")
      }
    }
    relaunch()
    XCTAssertTrue(app.tabBars.buttons["Sessions"].waitForExistence(timeout: 90), "the app opens after the Recover and a relaunch")
    shot("end")
    XCTAssertEqual(relay("done"), "ok")
  }
}
