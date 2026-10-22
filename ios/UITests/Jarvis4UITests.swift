import CryptoKit
import XCTest

/// Walks the native Jarvis 4 app on a simulator against the REAL core (fakefly build) and router running on the CI runner,
/// with the backups on a local S3 stand-in, keeping a screenshot of every step. ios.yml runs it once per appearance
/// (light, then dark), each against a fresh, empty core and router and a reset simulator keychain:
/// Reset or recover (an old kit refused; Recover with the public TEST kit) → stores (create, unlock) → the encrypted
/// backup (download, checked, share sheet) → New session (the
/// one page; Start also opens the locked harness store) → grants (a 10-minute grant and a standing rule on the Face ID
/// review, one denied, one forgotten) → schedules (listed, nothing to arm: the session arms its own) → terminal (the
/// router's page in a WebView) → the session's Log (the boot's start) → pause → transcript → the Log again →
/// resume with a prompt (signed, shown on the approval) → permission mode → resume with the latest image → destroy →
/// Previous → search → repos (add with its deploy key, Jarvis 4's own repo comes up sensitive, remove; claude-env
/// pre-selected on New session only when listed) → tasks → Reset (the kit ends the core; a new kit; the stores empty).
final class Jarvis4UITests: JarvisUITestCase {

  /// New session pre-selects DE0CH/claude-env (and its store) only when it is on the repo list (Deyao, 2026-10-11)
  func checkNewSessionRepoDefault(expect: Bool) {
    tab("Sessions")
    guard wait(el("newBtn"), 20, "the list (repo default)") else { return }
    el("newBtn").tap()
    guard arrives(el("secure-create"), 20, "New session (repo default)") else { return }
    sleep(2)
    let repo = el("ns-repo-claude-env"), store = el("secure-store-github-claude-env")
    if expect {
      XCTAssertTrue(store.waitForExistence(timeout: 10) && store.isSelected, "[\(tag)] github-claude-env pre-selected with it")
      XCTAssertTrue(scrolledTo(repo) && repo.isSelected, "[\(tag)] claude-env pre-selected on New session")
      shot("new-session-claude-env-default")
      repo.tap(); sleep(1)
      XCTAssertFalse(repo.isSelected, "[\(tag)] claude-env can be de-selected")
    } else {
      scrolledTo(prefixed("ns-repo-"))
      let anyRepo = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'ns-repo-' AND selected == true")).count
      XCTAssertEqual(anyRepo, 0, "[\(tag)] no repo pre-selected without claude-env")
    }
    el("secure-back").tap()
    arrives(el("newBtn"), 20, "the list after the repo-default check")
  }

  func openRepos() {
    tabRoot("Settings")
    if wait(el("open-repos"), 15, "Settings → Repos") { el("open-repos").tap() }
  }
  func addRepo(_ repo: String) -> Bool {
    openRepos()
    guard wait(el("repo-add"), 15, "Add repo") else { return false }
    el("repo-add").tap()
    let f = el("repo-url")
    guard wait(f, 15, "the repo field") else { return false }
    f.tap(); slowType(f, repo + "\n")
    return arrives(el("secure-repo-go"), 30, "the add-repo review for \(repo)")
  }

  /// a new session filed as the web page files it, with an image: its approval (Inbox) shows the image from the signed
  /// config, the router's copy read back and checked against the signed hash; then Reject
  static let testPNG = Data(base64Encoded: "iVBORw0KGgoAAAANSUhEUgAAADAAAAAgCAIAAADbtmxLAAAAQ0lEQVR42u3WsQkAMAgEQEdypIzsSFnAlJLCgy8fvEqNPNWmMttM9wMICGgd6NfgVx8ICGgfyKYGAgLyDzkdQEDLQRcnYbBqPxrSZwAAAABJRU5ErkJggg==")!
  func webSessionWithImage() {
    let (up, _) = routerRaw("POST", "api/uploads", body: Self.testPNG, headers: ["x-upload-id": "ci-web-\(tag)", "x-upload-name": "web.png"])
    XCTAssertEqual(up, 200, "[\(tag)] the web page's upload")
    let req: [String: Any] = ["requestId": "ci-web-\(tag)", "label": "web image", "prompt": "what is in this image?", "stores": ["default"], "harness": "claude",
                              "permissionMode": "bypass", "attachments": ["uploadId": "ci-web-\(tag)", "files": [["name": "web.png"]]]]
    let (made, out) = routerRaw("POST", "api/sessions", body: try? JSONSerialization.data(withJSONObject: req), headers: ["Content-Type": "application/json"])
    XCTAssertEqual(made, 200, "[\(tag)] the web page's session request: \(String(decoding: out, as: UTF8.self))")
    tabRoot("Inbox")
    guard wait(prefixed("request-review-"), 60, "the web session's approval in the Inbox") else { return }
    // the Inbox open with a pending request, the app sent away and back (as locking and unlocking the phone does: the
    // crash of builds 1039/1064 came on unlock, from the foreground refresh)
    XCUIDevice.shared.press(.home)
    sleep(5)
    app.activate()
    XCTAssertTrue(app.wait(for: .runningForeground, timeout: 20), "[\(tag)] the app is back in the foreground")
    sleep(3)
    XCTAssertEqual(app.state, .runningForeground, "[\(tag)] still running after coming back (no crash on the foreground refresh)")
    guard wait(prefixed("request-review-"), 30, "the approval still in the Inbox after coming back") else { return }
    shot("inbox-after-foreground")
    prefixed("request-review-").tap()
    guard arrives(el("secure-approve"), 30, "the approval page") else { return }
    let row = el("signed-attachment-web.png")
    XCTAssertTrue(scrolledTo(row), "[\(tag)] the signed image is listed")
    let until = Date().addingTimeInterval(20)
    while row.exists && !said(row).contains("Hash matches") && Date() < until { usleep(500_000) }
    note("signed-attachment", said(row))
    XCTAssertTrue(said(row).contains("Hash matches"), "[\(tag)] the router's copy is the signed file: \(said(row))")
    XCTAssertTrue(row.label.contains("web.png"), "[\(tag)] named from the signed config")
    shot("approval-image")
    if scrolledTo(el("secure-reject")) { el("secure-reject").tap() }
    XCTAssertTrue(gone(el("secure-approve"), 30), "[\(tag)] Reject closes the approval")
    tab("Sessions")
    XCTAssertTrue(gone(prefixed("srow-"), 30), "[\(tag)] the rejected session is gone from the list")
  }

  /// a resume asked for on the web page with a prompt (Deyao, 2026-10-13: "YYC AI research megathread"): its approval
  /// waits in the Inbox; opened from there, the page loads with Approve enabled and Reject at hand; Reject sends the
  /// session back to paused. Ends on the session's page again.
  func webResumeFromInbox(_ sid: String) {
    let body = try? JSONSerialization.data(withJSONObject: ["upgrade": false, "prompt": "from the web page"])
    let (code, out) = routerRaw("POST", "api/sessions/\(sid)/resume", body: body, headers: ["Content-Type": "application/json"])
    XCTAssertEqual(code, 200, "[\(tag)] the web page's resume: \(String(decoding: out, as: UTF8.self))")
    tabRoot("Inbox")
    if wait(prefixed("request-review-"), 90, "the web resume's approval in the Inbox") {
      prefixed("request-review-").tap()
      if arrives(el("secure-approve"), 30, "the resume approval from the Inbox") {
        let until = Date().addingTimeInterval(30)
        while !el("secure-approve").isEnabled && Date() < until { usleep(500_000) }
        XCTAssertTrue(el("secure-approve").isEnabled, "[\(tag)] Approve is ready on a resume approval opened from the Inbox")
        XCTAssertFalse(el("secure-error").exists, "[\(tag)] the resume approval loads without an error")
        XCTAssertTrue(scrolledTo(el("signed-once-prompt")), "[\(tag)] the signed resume prompt is shown")
        shot("inbox-resume-approval")
        if scrolledTo(el("secure-reject")) { el("secure-reject").tap() }
        XCTAssertTrue(gone(el("secure-approve"), 30), "[\(tag)] Reject closes the page")
        XCTAssertTrue(gone(prefixed("request-review-"), 30), "[\(tag)] the rejected resume leaves the Inbox")
      }
    }
    tab("Sessions")
    if !el("resume-\(sid)").waitForExistence(timeout: 10), wait(el("srow-\(sid)"), 20, "the session row after the Inbox") {
      el("srow-\(sid)").tap()
    }
    XCTAssertTrue(wait(el("resume-\(sid)"), 60, "paused after the rejected resume"), "[\(tag)] a rejected resume leaves it paused")
  }

  /// a single request in the Inbox (a grant asked for the session, as a session's jarvis2-request files it), denied each
  /// way the app offers: the review page's Deny (top left), the page's "Deny request", and a swipe on the row. Each time
  /// the item leaves the Inbox and the router has dropped it (Deyao, 2026-10-13: the page's Deny only closed the page)
  func inboxDenySingle(_ sid: String) {
    func file(_ holder: String) -> String? {
      let req: [String: Any] = ["session": sid, "holder": holder, "minutes": 2, "explanation": "deny test (\(holder))"]
      let (code, out) = routerRaw("POST", "api/requests/grant", body: try? JSONSerialization.data(withJSONObject: req), headers: ["Content-Type": "application/json"])
      XCTAssertEqual(code, 200, "[\(tag)] grant request for \(holder): \(String(decoding: out, as: UTF8.self))")
      return (try? JSONSerialization.jsonObject(with: out) as? [String: Any])?["id"] as? String
    }
    func droppedOnRouter(_ id: String, _ how: String) {
      let until = Date().addingTimeInterval(20)
      var code = 0
      repeat { (code, _) = routerRaw("GET", "api/requests/\(id)"); if code == 404 { break }; usleep(500_000) } while Date() < until
      XCTAssertEqual(code, 404, "[\(tag)] \(how): the router dropped the request")
    }
    for way in ["toolbar", "button", "swipe"] {
      guard let id = file(["toolbar": "status", "button": "archive", "swipe": "remote"][way]!) else { continue }
      tabRoot("Inbox")
      let row = el("request-review-\(id)")
      guard wait(row, 60, "the grant request in the Inbox (\(way))") else { continue }
      switch way {
      case "swipe":
        row.swipeLeft()
        let b = app.buttons["Deny"].firstMatch
        if wait(b, 10, "the row's swipe Deny") { b.tap() }
      default:
        row.tap()
        guard arrives(el("signed-feature"), 30, "the grant review from the Inbox (\(way))") else { continue }
        if way == "toolbar" {
          XCTAssertTrue(el("secure-back").label.contains("Deny"), "[\(tag)] the page's Deny")
          shot("inbox-grant-review")
          el("secure-back").tap()
        } else {
          if scrolledTo(el("request-deny")) { el("request-deny").tap() }
        }
        XCTAssertTrue(gone(el("signed-feature"), 30), "[\(tag)] Deny (\(way)) closes the page")
      }
      XCTAssertTrue(gone(row, 30), "[\(tag)] Deny (\(way)): the request leaves the Inbox")
      XCTAssertFalse(app.alerts.firstMatch.exists, "[\(tag)] Deny (\(way)) raised no error")
      droppedOnRouter(id, "Deny (\(way))")
    }
    shot("inbox-denied")
  }

  /// a batch of two deploy keys filed by the web page: the Inbox lists it once; its page shows the summary (unverified)
  /// and each item's "What you sign"; Deny all drops both, Allow all adds both under one Face ID
  func inboxBatch(deny: Bool) {
    let names = deny ? ["batch-denied-a", "batch-denied-b"] : ["batch-one", "batch-two"]
    let req: [String: Any] = ["summary": deny ? "Two repos for a test (deny this)" : "Two repos for the batch test",
                              "items": names.map { ["intent": "repo/add", "repo": "DE0CH/\($0)", "explanation": "item \($0)"] }]
    let (code, out) = routerRaw("POST", "api/requests/batch", body: try? JSONSerialization.data(withJSONObject: req), headers: ["Content-Type": "application/json"])
    XCTAssertEqual(code, 200, "[\(tag)] the web page's batch: \(String(decoding: out, as: UTF8.self))")
    tabRoot("Inbox")
    guard wait(prefixed("batch-review-"), 60, "the batch in the Inbox") else { return }
    XCTAssertFalse(prefixed("request-review-").exists, "[\(tag)] the batch's items aren't listed on their own")
    shot(deny ? "inbox-batch" : "inbox-batch-2")
    prefixed("batch-review-").tap()
    guard arrives(el("batch-allow"), 30, "the batch page") else { return }
    XCTAssertTrue(said(el("batch-summary")).contains("Two repos"), "[\(tag)] the caller's summary: \(said(el("batch-summary")))")
    XCTAssertTrue(el("batch-item-1").exists && el("batch-item-2").exists, "[\(tag)] both items listed")
    let until = Date().addingTimeInterval(30)
    while !el("batch-allow").isEnabled && Date() < until { usleep(500_000) }
    XCTAssertTrue(el("batch-allow").isEnabled, "[\(tag)] every item read and checked")
    if el("batch-item-signed-1").exists { el("batch-item-signed-1").tap(); sleep(1) }
    shot(deny ? "batch-review" : "batch-review-2")
    if deny {
      if scrolledTo(el("batch-deny")) { el("batch-deny").tap() }
      XCTAssertTrue(gone(el("batch-allow"), 30), "[\(tag)] Deny all closes the page")
      XCTAssertTrue(gone(prefixed("batch-review-"), 30), "[\(tag)] the batch is off the Inbox")
      return
    }
    el("batch-allow").tap()
    XCTAssertTrue(gone(el("batch-allow"), 90), "[\(tag)] Allow all signs both and closes the page")
    XCTAssertTrue(gone(prefixed("batch-review-"), 30), "[\(tag)] the batch is off the Inbox")
    openRepos()
    XCTAssertTrue(wait(el("repo-key-batch-one"), 60, "the first batch repo listed") && wait(el("repo-key-batch-two"), 30, "the second batch repo listed"),
                  "[\(tag)] both deploy keys made from one Face ID")
    shot("batch-repos")
  }

  func testWalkthrough() {
    continueAfterFailure = true
    tag = env["JARVIS4_APPEARANCE"] ?? "run"
    let kit = env["JARVIS4_KIT"] ?? ""
    app.launch()

    // ---- Reset or recover: the core is empty (checked against the box key by the app itself)
    guard wait(el("setup-state-empty"), 60, "setup page: the core is empty") else { return }
    shot("setup-empty")
    el("setup-choose-recover").tap()
    guard wait(el("setup-kit-field"), 15, "recovery kit field") else { return }
    el("setup-kit-field").tap(); el("setup-kit-field").typeText("jarvis2-kit:1:AAAA:ak:sk")
    el("setup-recover-go").tap()
    if wait(el("secure-error"), 15, "an old kit is refused") {
      XCTAssertTrue(el("secure-error").label.contains("older Jarvis 4"), "[\(tag)] plain message: \(el("secure-error").label)")
      shot("setup-old-kit")
    }
    el("secure-back").tap()
    guard wait(el("setup-choose-recover"), 15, "the choice again") else { return }
    el("setup-choose-recover").tap()
    guard wait(el("setup-kit-field"), 15, "recovery kit field") else { return }
    XCTAssertEqual((el("setup-kit-field").value as? String)?.hasPrefix("jarvis2-kit:1"), false, "[\(tag)] the old kit was forgotten on Back")
    el("setup-kit-field").tap(); el("setup-kit-field").typeText(kit)
    shot("setup-recover-kit")
    el("setup-recover-go").tap()
    guard wait(el("setup-done"), 120, "recovered") else { return }
    shot("setup-recovered")
    el("secure-back").tap()
    guard arrives(el("newBtn"), 60, "the session list after Done") else { return }
    sleep(2)
    shot("sessions-empty")

    // ---- stores: the core's signed list; create one, unlock default (Face ID: a software key here)
    tabRoot("Settings")
    guard wait(el("open-stores"), 15, "Settings → Stores") else { return }
    el("open-stores").tap()
    wait(el("unlock-default"), 30, "the stores page")
    sleep(1)
    shot("stores")
    XCTAssertFalse(el("store-core").exists, "[\(tag)] the core's own store is not listed")
    XCTAssertTrue(el("sensitive-marked").exists, "[\(tag)] a store with a sensitive marker in the backups came back sensitive")
    XCTAssertFalse(el("sensitive-default").exists, "[\(tag)] default came back not sensitive")
    el("store-new").tap()
    answer("Create", text: "ci-notes")
    wait(el("store-ci-notes"), 20, "created store listed")
    el("unlock-default").tap()
    wait(el("lock-default"), 30, "default unlocked (the core's signed unlocked list)")
    shot("stores-unlocked")
    // Lock works the moment the open unlock shows: the unlock's trailing reload once kept it a disabled "Unlocking…"
    // that dropped the tap (replica runs 38399852797, 38407156816: "rh-plain locked again")
    XCTAssertTrue(el("lock-default").isEnabled && el("lock-default").label == "Lock", "[\(tag)] the new unlock's Lock is ready at once: \(el("lock-default").label)")
    el("lock-default").tap()
    XCTAssertTrue(gone(el("lock-default"), 30), "[\(tag)] default locked again")
    el("unlock-default").tap()
    wait(el("lock-default"), 30, "default unlocked again")
    // a store's own page: its keys (the core's names and writers; never values) and its about text, edited in place
    el("store-open-default").tap()
    if arrives(el("key-default-OTHER"), 20, "default's keys") {
      XCTAssertTrue(el("key-default-GITHUB_TOKEN").exists, "[\(tag)] every key of default is listed")
      XCTAssertFalse(el("key-writer-default-OTHER").exists, "[\(tag)] a recovered key isn't shown as a session's")
      el("store-about-default-edit").tap()
      let field = el("store-about-default-field")
      if wait(field, 10, "the about text box") {
        focusAndType(field, "everyday keys")
        el("store-about-default-save").tap()
        XCTAssertTrue(wait(el("store-about-default-saved"), 15, "Saved") && said(el("store-about-default")).contains("everyday keys"), "[\(tag)] the about text is saved: \(said(el("store-about-default")))")
      }
      shot("store-detail")
      restoreStore()
      back()
    }
    back()

    // ---- the offline copy: Settings → Encrypted backup (the stand-in bucket's six stores, every signature checked;
    // nothing opened, no kit asked for), then the share sheet
    downloadBackup(stores: 6)

    // ---- an image on a session made outside the app: the approval checks the router's copy against the signed hash
    webSessionWithImage()

    // ---- New session: one page; Start signs and opens the locked harness store under one Face ID (and an image from
    // Photos: Start uploads it and checks the signed config names its sha256 + size)
    XCTAssertEqual(coreStores().first { ($0["name"] as? String) == "claude-login" }?["unlocked"] as? Bool, false, "[\(tag)] the harness store starts locked")
    tab("Sessions")
    guard wait(el("newBtn"), 10, "list again") else { return }
    el("newBtn").tap()
    guard arrives(el("secure-create"), 15, "New session") else { return }
    sleep(2)
    shot("new-session")
    XCTAssertTrue(el("ns-prompt").exists && el("ns-title").exists && el("ns-mode").exists, "[\(tag)] prompt, title and one-shot are on the one page")

    XCTAssertTrue(el("secure-store-default").exists, "[\(tag)] default offered")
    XCTAssertFalse(el("secure-store-core").exists, "[\(tag)] the core store is not offered")
    XCTAssertFalse(el("secure-store-claude-login").exists, "[\(tag)] the harness's own store is not offered as a pick")
    XCTAssertTrue(scrolledTo(el("ns-harness-store-claude-login")), "[\(tag)] …but listed as what the harness brings")
    XCTAssertTrue(scrolledTo(el("ns-permission-mode")) && said(el("ns-permission-mode")).contains("bypass"), "[\(tag)] the page shows bypass, the only start mode (no picker)")
    XCTAssertFalse(el("secure-mode-auto").exists, "[\(tag)] no permission-mode picker")
    let unlocks = el("ns-unlocks")
    XCTAssertTrue(scrolledTo(unlocks) && said(unlocks).contains("claude-login"), "[\(tag)] Start says it unlocks the locked harness store")
    scrolledUpTo(el("ns-title"))
    focusAndType(el("ns-title"), "ci session")
    let image = attachImage()
    if el("secure-store-gmail").waitForExistence(timeout: 3) {
      el("secure-store-gmail").tap(); sleep(1)
      XCTAssertTrue(scrolledTo(el("secure-sensitive-warning"), max: 3), "[\(tag)] sensitive warning")
      shot("new-session-sensitive")
      el("secure-store-gmail").tap()
    }
    el("secure-create").tap()
    let row = prefixed("srow-")
    guard arrives(row, 120, "the new session's row after Start") else {
      if el("secure-error").exists { note("create-error", el("secure-error").label) }
      return
    }
    XCTAssertTrue(coreUnlocked().contains { ($0["store"] as? String) == "claude-login" }
                  || coreStores().first { ($0["name"] as? String) == "claude-login" }?["unlocked"] as? Bool == true,
                  "[\(tag)] one Start opened the locked harness store")
    let sid = String(row.identifier.dropFirst("srow-".count))
    note("session", sid)
    if let image {
      let (st, bytes) = routerRaw("GET", "api/sessions/\(sid)/attachments/\(image)")
      XCTAssertTrue(st == 200 && bytes.count > 0, "[\(tag)] the image went up with the session (HTTP \(st), \(bytes.count) bytes)")
    }
    sleep(2)
    shot("session-created")
    row.tap()
    guard arrives(el("grants-\(sid)"), 20, "the session's page") else { return }
    shot("session-detail")

    // ---- grants: chosen here, reviewed on the Face ID page: a 10-minute grant, a denied one, a standing rule, forget one
    el("grants-\(sid)").tap()
    if wait(el("grant-review"), 20, "grants page") {
      sleep(1)
      shot("grants-empty")
      pick("grant-holder", "Terminal")
      pick("grant-len", "10 min")
      el("grant-review").tap()
      if arrives(el("signed-feature"), 15, "the grant review") {
        sleep(1)
        for id in ["signed-kind", "signed-feature", "signed-session", "signed-duration", "signed-until"] { note(id, said(el(id))) }
        XCTAssertTrue(said(el("signed-kind")).contains("Phone grant"), "[\(tag)] a phone grant: \(said(el("signed-kind")))")
        XCTAssertTrue(said(el("signed-feature")).contains("Terminal") && said(el("signed-duration")).contains("10 minutes"), "[\(tag)] the review says what is asked: \(said(el("signed-feature"))) / \(said(el("signed-duration")))")
        XCTAssertTrue(said(el("signed-session")).contains("ci session"), "[\(tag)] the session is named from its signed cert: \(said(el("signed-session")))")
        XCTAssertTrue(el("secure-back").label.contains("Deny"), "[\(tag)] Allow or Deny")
        shot("grant-review")
        el("secure-grant-allow").tap()
        wait(el("grant-forget-terminal"), 60, "terminal grant listed")
        shot("grants-one")
      }
      pick("grant-holder", "Status")
      pick("grant-len", "2 min")
      el("grant-review").tap()
      if arrives(el("signed-feature"), 15, "the grant review (deny)") {
        el("secure-back").tap()
        arrives(el("grant-review"), 10, "the grants page after Deny")
        XCTAssertFalse(el("grant-forget-status").exists, "[\(tag)] Deny signed nothing")
      }
      pick("grant-holder", "Status")
      pick("grant-len", "Standing rule")
      pick("grant-days", "30 days")
      el("grant-review").tap()
      if arrives(el("signed-feature"), 15, "the grant review (rule)") {
        sleep(1)
        XCTAssertTrue(said(el("signed-feature")).contains("Status") && el("signed-until").exists && !el("signed-duration").exists, "[\(tag)] the rule's review: \(said(el("signed-feature"))) / \(said(el("signed-until")))")
        shot("grant-review-rule")
        el("secure-grant-allow").tap()
        wait(el("grant-forget-status"), 60, "standing rule listed")
        shot("grants-two")
      }
      if el("grant-forget-terminal").exists {
        el("grant-forget-terminal").tap()
        answer("Forget")
        XCTAssertTrue(gone(el("grant-forget-terminal"), 30), "[\(tag)] forgotten grant gone")
        shot("grants-forgot")
      }
      back()
    }

    // ---- a single Inbox request for this session, denied from the page and from the row; then back to its page
    inboxDenySingle(sid)
    tab("Sessions")
    if !el("schedules-\(sid)").waitForExistence(timeout: 5), wait(el("srow-\(sid)"), 20, "the session row after the Inbox") {
      el("srow-\(sid)").tap()
    }

    // ---- schedules: only the session arms its wakeups and crons (the router refuses the app), so the page lists them
    // (none here) and has no arming form
    if wait(el("schedules-\(sid)"), 20, "Schedules") {
      el("schedules-\(sid)").tap()
      if arrives(el("sch-none"), 20, "the schedules page (nothing armed)") {
        XCTAssertFalse(el("sch-prompt").exists || el("sch-save").exists, "[\(tag)] no arming form")
        shot("schedules")
      }
      back()
    }

    // ---- the terminal: the router's page in a WebView (a fake machine answers nothing: the page, its status, its keys)
    if wait(el("term-\(sid)"), 20, "Terminal") {
      el("term-\(sid)").tap()
      let input = app.webViews.textFields["Terminal input"].firstMatch
      if arrives(input, 30, "the terminal page") {
        sleep(3)
        shot("terminal")
        XCTAssertTrue(app.webViews.buttons["Send"].exists, "[\(tag)] the page's Send")
      }
      back()
    }

    // ---- the session's Log (the fake machine writes no supervisor lines; the router records the boot's start)
    checkLogs(sid, supervisorLine: false, flyStep: false, "running")

    // ---- pause → transcript → resume with a prompt (a one-time input the phone signs: the approval shows it)
    guard wait(el("pause-\(sid)"), 60, "Pause") else { return }
    el("pause-\(sid)").tap()
    shot("pausing")
    guard wait(el("resume-\(sid)"), 120, "paused") else { return }
    shot("paused")
    if wait(el("tail-\(sid)"), 10, "Transcript") {
      el("tail-\(sid)").tap()
      arrives(el("transcript"), 15, "the transcript")
      sleep(2)
      shot("transcript")
      back()
    }
    checkLogs(sid, supervisorLine: false, flyStep: false, "paused")
    el("resume-\(sid)").tap()
    answer("Resume", text: "carry on")
    if arrives(el("secure-approve"), 90, "the resume-prompt approval") {
      sleep(1)
      shot("approval-resume-prompt")
      XCTAssertTrue(el("signed-once-prompt").exists && said(el("signed-once-prompt")).contains("carry on"), "[\(tag)] the approval shows the signed resume prompt")
      XCTAssertTrue(el("secure-session").exists && el("secure-session").label.contains("ci session"), "[\(tag)] the session is named from the signed predecessor: \(el("secure-session").label)")
      el("secure-approve").tap()
    }
    guard wait(el("pause-\(sid)"), 150, "resumed") else { return }
    shot("resumed")

    // ---- permission mode (signed) and resume with the latest image (the approval opens by itself)
    el("pause-\(sid)").tap()
    guard wait(el("resume-\(sid)"), 120, "paused again") else { return }
    webResumeFromInbox(sid)
    el("more-\(sid)").tap()
    let toAuto = app.buttons["Switch to auto mode"]
    XCTAssertTrue(toAuto.waitForExistence(timeout: 10), "[\(tag)] made in bypass: switch to auto offered")
    if toAuto.exists { toAuto.tap(); answer("Switch"); sleep(2); shot("mode-switched") } else { app.tap() }
    el("more-\(sid)").tap()
    if wait(app.buttons["Resume with latest image"], 10, "menu: resume latest") {
      app.buttons["Resume with latest image"].tap()
      answer("Resume with latest image")
      if arrives(el("secure-approve"), 120, "the resume-upgrade approval") {
        sleep(2)
        shot("approval-upgrade")
        XCTAssertTrue(el("secure-mode").exists, "[\(tag)] the approval shows the signed permission mode")
        el("secure-approve").tap()
        sleep(3)
        shot("upgraded")
      }
    }

    // ---- destroy → Previous
    if (scrolledTo(el("destroy-\(sid)")) || true), wait(el("destroy-\(sid)"), 60, "Destroy") {
      el("destroy-\(sid)").tap()
      answer("Destroy session", timeout: 30)
      XCTAssertTrue(gone(el("srow-\(sid)"), 120), "[\(tag)] session gone from the list")
      shot("destroyed")
    }
    tab("Sessions")
    if wait(el("previousBtn"), 10, "Previous") {
      el("previousBtn").tap()
      sleep(3)
      shot("previous")
      let rec = prefixed("record-")
      if rec.waitForExistence(timeout: 5) {
        rec.press(forDuration: 1.2)
        if app.buttons["Remove from the list"].waitForExistence(timeout: 5) {
          app.buttons["Remove from the list"].tap()
          answer("Remove")
          XCTAssertTrue(gone(rec, 30), "[\(tag)] removed from the list")
        }
      }
      back()
    }

    // ---- search: the router forwards to the services box's transcript search, which CI doesn't run (ios.yml points
    // SEARCH_URL at a closed port), so the answer is an error in words
    tab("Search")
    let field = app.searchFields.firstMatch
    if wait(field, 15, "the search field") {
      field.tap(); field.typeText("hello\n")
      wait(el("search-error"), 30, "search answer (no search service in CI)")
      shot("search")
      if app.buttons["iCloud files"].waitForExistence(timeout: 5) { app.buttons["iCloud files"].tap(); sleep(2); shot("search-icloud") }
    }

    // ---- repos: add DE0CH/china-train (the CI core's fake GitHub takes the key), Jarvis 4's own comes up sensitive, remove
    if addRepo("DE0CH/china-train") {
      wait(el("signed-store"), 15, "…naming the repo's store")
      XCTAssertTrue(said(el("signed-store")).contains("github-china-train") && said(el("signed-repo")).contains("DE0CH/china-train"), "[\(tag)] what you sign names the repo and its store: \(said(el("signed-store")))")
      XCTAssertTrue(said(el("signed-sensitive")).contains("No"), "[\(tag)] signed as not sensitive: \(said(el("signed-sensitive")))")
      XCTAssertFalse(isOn(el("secure-repo-sensitive")), "[\(tag)] a repo's store isn't sensitive by default")
      shot("repo-add")
      el("secure-repo-go").tap()
      if wait(el("repo-key-china-train"), 60, "the repo listed with its deploy key") {
        XCTAssertTrue(el("repo-key-china-train").label.contains("github-china-train"), "[\(tag)] the key lives in github-china-train")
        shot("repo-added")
      }
    }
    checkNewSessionRepoDefault(expect: false)
    if addRepo("DE0CH/claude-env") {
      sleep(1); el("secure-repo-go").tap()
      wait(el("repo-key-claude-env"), 60, "claude-env listed")
    }
    checkNewSessionRepoDefault(expect: true)
    if addRepo("DE0CH/jarvis2") {
      wait(el("signed-store"), 15, "…naming github-jarvis2")
      sleep(1)
      XCTAssertTrue(said(el("signed-store")).contains("github-jarvis2") && said(el("signed-sensitive")).contains("Yes"), "[\(tag)] signed as sensitive: \(said(el("signed-store"))) / \(said(el("signed-sensitive")))")
      XCTAssertTrue(isOn(el("secure-repo-sensitive")), "[\(tag)] Jarvis 4's own repo comes up sensitive (the core's word)")
      shot("repo-sensitive")
      el("secure-back").tap()
    }
    openRepos()
    if wait(el("repo-remove-china-train"), 30, "Remove on the repo") {
      el("repo-remove-china-train").tap()
      if arrives(el("secure-repo-go"), 30, "the remove-repo review") {
        shot("repo-remove")
        el("secure-repo-go").tap()
        XCTAssertTrue(gone(el("repo-key-china-train"), 60), "[\(tag)] the repo is off the list after remove")
      }
    }

    // ---- a batch (router/batches.go): filed as the web page files it, one Inbox entry with the caller's summary and
    // each item's signed details; the first is denied whole, the second allowed whole under one Face ID
    inboxBatch(deny: true)
    inboxBatch(deny: false)

    // ---- tasks: make one from the hello template (its line's approval opens by itself), run it, stop the run, schedule it
    tab("Tasks")
    if (scrolledTo(el("new-hello")) || true), wait(el("new-hello"), 30, "the hello template") {
      shot("tasks")
      el("new-hello").tap()
      if wait(el("tf-message"), 15, "new task form") {
        el("tf-message").tap(); el("tf-message").typeText("hello from CI")
        shot("task-new")
        el("te-save").tap()
        if arrives(el("secure-approve"), 90, "the task's approval") {
          sleep(1); shot("task-approval")
          el("secure-approve").tap()
        }
        if wait(el("td-schedule"), 60, "task page") {
          sleep(2)
          shot("task-page")
          if el("td-run").waitForExistence(timeout: 60) {
            el("td-run").tap()
            // the runs are listed below the task's rows: scroll down to them while the run is queued
            let firstRun = prefixed("td-run-"), until = Date().addingTimeInterval(45)
            while !firstRun.exists && Date() < until { scrolledTo(firstRun, max: 2); if !firstRun.exists { sleep(2) } }
            if wait(firstRun, 5, "a run listed") {
              prefixed("td-run-").tap()
              if wait(el("tr-stop"), 20, "run page") {
                shot("task-run")
                el("tr-stop").tap()
                answer("Stop")
                XCTAssertTrue(gone(el("tr-stop"), 30), "[\(tag)] run stopped")
              }
              back()
            }
          }
          if wait(el("td-schedule"), 10, "task page again") {
            el("td-schedule").tap()
            if wait(el("se-save"), 15, "schedule form") { shot("task-schedule"); el("se-save").tap() }
            sleep(2)
            back()
          }
        }
      }
    }
    tab("Tasks")
    sleep(2)
    shot("task-schedules")

    // ---- Reset on a set-up core: only with its kit; a new, empty core, a new kit, the stores empty
    tabRoot("Settings")
    if (scrolledTo(el("open-setup")) || true), wait(el("open-setup"), 15, "Reset or recover") {
      el("open-setup").tap()
      if wait(el("setup-state-mine"), 30, "setup page: set up on this iPhone") {
        shot("setup-mine")
        el("setup-choose-reset").tap()
        if wait(el("setup-kit-field"), 15, "the current kit's field") {
          el("setup-kit-field").tap(); el("setup-kit-field").typeText(kit)
          el("setup-reset-go").tap()
          if wait(el("setup-kit"), 180, "the new kit after the core restarted empty") {
            let newKit = el("setup-kit").label
            XCTAssertTrue(newKit.hasPrefix("jarvis2-kit:2:MIG") && newKit != kit, "[\(tag)] a new kit \(newKit.prefix(18))…")
            shot("reset-new-kit", checkBlank: false)
            el("setup-kit-copy").tap()
            el("setup-kit-saved").tap()
            if wait(el("setup-done"), 60, "reset done") {
              shot("reset-done")
              el("secure-back").tap()
              tabRoot("Settings")
              if wait(el("open-stores"), 15, "stores") {
                el("open-stores").tap()
                sleep(3)
                XCTAssertFalse(el("unlock-default").exists, "[\(tag)] no stores after a Reset")
                shot("reset-stores-empty")
              }
            }
          }
        }
      }
    }
    app.terminate()
  }
}

extension Jarvis4UITests {
  /// the router's JSON (the test reads payloads; the app checks signatures)
  func routerJSON(_ method: String, _ path: String, _ body: String? = nil) -> (Int, [String: Any]) {
    let (s, d) = routerRaw(method, path, body: body.map { Data($0.utf8) }, headers: ["Content-Type": "application/json"])
    return (s, (try? JSONSerialization.jsonObject(with: d) as? [String: Any]) ?? [:])
  }
  func sig(_ k: P256.Signing.PrivateKey, _ text: String) -> String {
    (try? k.signature(for: Data(text.utf8)).derRepresentation.base64EncodedString()) ?? ""
  }
  /// a /setup call as infra/setup.py signs it: "<METHOD> <path> <unix time> <sha256hex body>"
  func setupCall(_ k: P256.Signing.PrivateKey, _ method: String, _ path: String, _ body: [String: Any]) -> (Int, Data) {
    let raw = (try? JSONSerialization.data(withJSONObject: body)) ?? Data()
    let t = String(Int(Date().timeIntervalSince1970))
    let sum = SHA256.hash(data: raw).map { String(format: "%02x", $0) }.joined()
    return routerRaw(method, String(path.dropFirst()), body: raw,
                     headers: ["Content-Type": "application/json", "X-Setup-Time": t, "X-Setup-Sig": sig(k, "\(method) \(path) \(t) \(sum)")])
  }
  func storeKeyNames(_ store: String) -> [String] {
    let (_, j) = routerJSON("GET", "api/stores")
    return ((j["stores"] as? [[String: Any]]) ?? []).first { $0["name"] as? String == store }?["keys"] as? [String] ?? []
  }

  /// On default's page: a key deleted behind the app's back (as the setup session), then Versions → the version before
  /// the delete → Restore… → the review names the key put back → Restore (Face ID: a software key here) → it is back.
  /// core/history.go: no kit, the phone's signature over the core's begin document and its share of the key.
  func restoreStore() {
    let key = "OTHER"
    // the walkthrough's router checks the setup key (SETUP_KEY): the stand-in's private half comes in TEST_RUNNER_JARVIS4_SETUP_KEY
    guard let pem = env["JARVIS4_SETUP_KEY"], let sk = try? P256.Signing.PrivateKey(pemRepresentation: pem) else {
      XCTFail("[\(tag)] no setup key for the restore step (TEST_RUNNER_JARVIS4_SETUP_KEY)"); return
    }
    let (ds, db) = setupCall(sk, "POST", "/setup/stores/default/keys/\(key)",
                             ["delete": true, "sig": sig(sk, "jarvis2-store-key\ndefault\n\(key)\n\n\n")])
    XCTAssertEqual(ds, 200, "[\(tag)] \(key) deleted as the setup session: \(String(decoding: db.prefix(200), as: UTF8.self))")
    XCTAssertFalse(storeKeyNames("default").contains(key), "[\(tag)] \(key) is gone from default")
    let (_, v) = routerJSON("POST", "api/core/stores/versions", #"{"store":"default","nonce":"0123456789abcdef"}"#)
    let versions = ((v["payload"] as? String).flatMap { try? JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any] })?["versions"] as? [[String: Any]] ?? []
    guard versions.count >= 2, let seq = versions[1]["seq"] as? Int else { XCTFail("[\(tag)] the core lists the version before the delete: \(versions.count)"); return }
    let link = el("store-versions-default")
    guard scrolledTo(link) else { XCTFail("[\(tag)] Versions on the store's page"); return }
    link.tap()
    let restore = el("version-restore-\(seq)")
    guard arrives(restore, 20, "the version before the delete") else { return }
    shot("store-versions")
    restore.tap()
    let allow = el("secure-restore-allow")
    guard arrives(allow, 20, "the restore review") else { return }
    XCTAssertTrue(wait(el("restore-put-\(key)"), 10, "the key put back"), "[\(tag)] the review names \(key) as put back (from the core's signed begin)")
    shot("restore-review")
    allow.tap()
    var restored = false
    for _ in 0..<30 where !restored { restored = storeKeyNames("default").contains(key); if !restored { sleep(1) } }
    XCTAssertTrue(restored, "[\(tag)] \(key) is back in default after the restore")
    XCTAssertFalse(allow.waitForExistence(timeout: 5) && allow.isHittable, "[\(tag)] the review closed")
    shot("store-restored")
    back()
  }
}
