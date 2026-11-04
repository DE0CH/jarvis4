import XCTest

/// What every UI test of the native app shares: elements by accessibility id, waits that leave evidence, the blank-screen
/// checks (a screen with no navigation bar, tab bar or sheet for over 1.5 s, or a near-uniform screenshot), tabs and
/// the app's alerts.
class JarvisUITestCase: XCTestCase {
  let app = XCUIApplication()
  let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
  let env = ProcessInfo.processInfo.environment
  var tag = "run"
  var step = 0

  // ---- evidence ----
  func shot(_ name: String, checkBlank: Bool = true) {
    step += 1
    let s = XCUIScreen.main.screenshot()
    let a = XCTAttachment(screenshot: s)
    a.name = String(format: "%@-%02d-%@", tag, step, name); a.lifetime = .keepAlways; add(a)
    if checkBlank { XCTAssertFalse(Self.blank(s.image), "[\(tag)] blank screen at \(name)") }
  }
  func note(_ name: String, _ text: String) { let a = XCTAttachment(string: text); a.name = "\(tag)-\(name)"; a.lifetime = .keepAlways; add(a) }
  /// a blank screen: below the status bar, fewer than 0.2% of the sampled pixels differ from the background colour
  static func blank(_ img: UIImage) -> Bool {
    guard let cg = img.cgImage, let data = cg.dataProvider?.data, let p = CFDataGetBytePtr(data) else { return false }
    let bpr = cg.bytesPerRow, bpp = cg.bitsPerPixel / 8
    let y0 = cg.height * 12 / 100
    let bg = (Int(p[y0 * bpr + 4 * bpp]), Int(p[y0 * bpr + 4 * bpp + 1]), Int(p[y0 * bpr + 4 * bpp + 2]))
    var n = 0, differ = 0
    for y in stride(from: y0, to: cg.height, by: 4) {
      for x in stride(from: 0, to: cg.width, by: 4) {
        let o = y * bpr + x * bpp
        n += 1
        if abs(Int(p[o]) - bg.0) > 24 || abs(Int(p[o + 1]) - bg.1) > 24 || abs(Int(p[o + 2]) - bg.2) > 24 { differ += 1 }
      }
    }
    return n > 0 && differ * 500 < n
  }

  // ---- elements ----
  func el(_ id: String) -> XCUIElement { app.descendants(matching: .any).matching(identifier: id).firstMatch }
  func prefixed(_ p: String) -> XCUIElement { app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH %@", p)).firstMatch }
  /// what a row says: its label and its value (a LabeledContent row may expose its value separately)
  func said(_ e: XCUIElement) -> String { e.label + " " + ((e.value as? String) ?? "") }
  func labelled(_ text: String) -> XCUIElement { app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", text)).firstMatch }
  @discardableResult func wait(_ e: XCUIElement, _ s: TimeInterval, _ what: String) -> Bool {
    let ok = e.waitForExistence(timeout: s)
    XCTAssertTrue(ok, "[\(tag)] \(what)")
    if !ok {
      note("tree-\(what)", app.debugDescription); shot("missing-" + what.replacingOccurrences(of: " ", with: "-"), checkBlank: false)
      errorDetail(what)
    }
    return ok
  }
  /// a page that shows an error with Details: open them and keep the text, so a failed run says why
  func errorDetail(_ what: String) {
    let d = el("secure-error-details")
    guard d.exists else { return }
    if !el("secure-error-detail").exists { d.tap() }
    if el("secure-error-detail").waitForExistence(timeout: 3) { note("error-detail-\(what)", el("secure-error-detail").label) }
  }
  func gone(_ e: XCUIElement, _ s: TimeInterval) -> Bool {
    let until = Date().addingTimeInterval(s)
    while e.exists && Date() < until { usleep(300_000) }
    return !e.exists
  }
  /// something the app draws is on screen: a navigation bar, the tab bar, or an alert
  var somethingDrawn: Bool { app.navigationBars.firstMatch.exists || app.tabBars.firstMatch.exists || app.alerts.firstMatch.exists }
  /// after a transition: `target` must come up within `s` seconds, and the screen may never be blank (nothing drawn)
  /// for longer than `blank` seconds on the way
  @discardableResult func arrives(_ target: XCUIElement, _ s: TimeInterval, _ what: String, blank: TimeInterval = 1.5) -> Bool {
    let until = Date().addingTimeInterval(s)
    var blankSince: Date?
    while Date() < until {
      if target.exists { return true }
      if somethingDrawn { blankSince = nil } else if blankSince == nil { blankSince = Date() }
      if let b = blankSince, Date().timeIntervalSince(b) > blank {
        shot("blank-" + what.replacingOccurrences(of: " ", with: "-"), checkBlank: false)
        XCTFail("[\(tag)] blank screen for over \(blank) s on the way to \(what)")
        return target.waitForExistence(timeout: max(0, until.timeIntervalSinceNow))
      }
      usleep(150_000)
    }
    XCTFail("[\(tag)] \(what) didn't come up within \(Int(s)) s")
    note("tree-\(what)", app.debugDescription)
    shot("missing-" + what.replacingOccurrences(of: " ", with: "-"), checkBlank: false)
    return false
  }

  // ---- the app's furniture ----
  func tab(_ name: String) {
    let b = app.tabBars.buttons[name]
    if b.waitForExistence(timeout: 10) { b.tap() } else { XCTFail("[\(tag)] no tab \(name)"); note("tree-tab-\(name)", app.debugDescription) }
  }
  /// a tab at its first screen: select it, then tap it again (iOS pops a selected tab's stack to its root)
  func tabRoot(_ name: String) {
    tab(name)
    let b = app.tabBars.buttons[name]
    if b.exists { b.tap(); usleep(600_000) }
    // a second tap on the tab pops to its root on iOS, but not always while the switch is still animating
    // (replica run 38188675401): back out of whatever is still open
    for _ in 0..<4 {
      let back = app.navigationBars.buttons["BackButton"].firstMatch
      guard back.waitForExistence(timeout: 1) else { break }
      back.tap(); usleep(600_000)
    }
  }
  /// the Sessions tab at its list: switching tabs keeps each tab's place (as on iOS), so a session page left open there is
  /// backed out of
  func sessionsList() {
    tab("Sessions")
    for _ in 0..<4 where !el("newBtn").waitForExistence(timeout: 2) {
      let b = app.navigationBars.buttons["BackButton"].firstMatch
      if b.exists { b.tap() } else { back() }
    }
  }
  /// back one screen in the current navigation stack
  func back() {
    let b = app.navigationBars.buttons.element(boundBy: 0)
    if b.waitForExistence(timeout: 5) { b.tap() }
  }
  /// answer the app's alert: type `text` into its field when given, then tap `button`
  @discardableResult func answer(_ button: String, text: String? = nil, timeout: TimeInterval = 20) -> Bool {
    let alert = app.alerts.firstMatch
    guard wait(alert, timeout, "an alert for \(button)") else { return false }
    if let text {
      let f = alert.textFields.firstMatch
      if f.waitForExistence(timeout: 5) { f.tap(); f.typeText(text) }
    }
    let b = alert.buttons.matching(NSPredicate(format: "label == %@", button)).firstMatch
    guard wait(b, 5, "alert button \(button)") else { return false }
    b.tap()
    return true
  }
  /// a Form picker: open it, choose an option
  func pick(_ pickerId: String, _ option: String) {
    let p = el(pickerId)
    guard wait(p, 10, "picker \(pickerId)") else { return }
    p.tap()
    let o = app.buttons.matching(NSPredicate(format: "label == %@", option)).firstMatch
    if o.waitForExistence(timeout: 5) { o.tap() } else {
      let c = app.collectionViews.buttons[option].firstMatch
      if c.waitForExistence(timeout: 3) { c.tap() } else { XCTFail("[\(tag)] no option \(option) in \(pickerId)"); note("tree-pick-\(pickerId)", app.debugDescription) }
    }
  }
  /// one character at a time (a burst into a URL keyboard can reorder characters)
  /// tap a field until it has the keyboard (a tap right after a scroll can land while the form still moves: "Neither
  /// element nor any descendant has keyboard focus", walkthrough run 38347022232), then type
  func focusAndType(_ e: XCUIElement, _ text: String) {
    for _ in 1...4 {
      // left under the navigation bar by the scroll up (ns-title at y 27 in run 38358382751): drag the form down a
      // little, never a full swipe (one at the top pulls the sheet away)
      if e.exists && e.frame.minY < 140 {
        let a = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.45)), b = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.6))
        a.press(forDuration: 0.1, thenDragTo: b)
        sleep(1)
      }
      if e.isHittable { e.tap() }
      if (e.value(forKey: "hasKeyboardFocus") as? Bool) == true { break }
      sleep(1)
      if (e.value(forKey: "hasKeyboardFocus") as? Bool) == true { break }
    }
    e.typeText(text)
  }
  /// turn a CheckRow (a picked/unpicked row) on or off and confirm it took. New session's stores sit under the
  /// keyboard right after the title is typed, and a tap there never picked the row (gmail in walkthrough runs
  /// 41759948902 light, 41810155475 dark and 41837091525 both: no sensitive warning, the row then scrolled away). So:
  /// Return first (the keyboard goes), bring the row into the middle of the screen with a slow drag (a full swipe at
  /// the top of a sheet pulls the sheet away), let it settle, tap, and tap again only if it did not take.
  @discardableResult func setChecked(_ e: XCUIElement, _ on: Bool) -> Bool {
    if app.keyboards.firstMatch.exists {
      app.typeText("\n")
      if !gone(app.keyboards.firstMatch, 5) { note("keyboard-stays", app.debugDescription) }
    }
    if !e.exists { scrolledUpTo(e, max: 3) }
    var log: [String] = []
    for _ in 1...6 {
      guard e.exists else { break }
      if e.isSelected == on { return true }
      let h = app.frame.height, f = e.frame
      log.append("frame \(f) hittable \(e.isHittable) keyboard \(app.keyboards.firstMatch.exists)")
      if f.midY > h * 0.7 || f.midY < h * 0.2 {
        let from = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5))
        from.press(forDuration: 0.1, thenDragTo: from.withOffset(CGVector(dx: 0, dy: max(-300, min(300, h * 0.45 - f.midY)))))
        sleep(1)
        continue
      }
      // at its centre, settled: no scroll-to-visible of XCUITest's own, which moved the form again
      e.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).tap()
      let until = Date().addingTimeInterval(3)
      while e.exists && e.isSelected != on && Date() < until { usleep(300_000) }
    }
    let ok = e.exists && e.isSelected == on
    if !ok { note("set-checked", log.joined(separator: "\n") + "\n\n" + app.debugDescription) }
    return ok
  }
  func slowType(_ e: XCUIElement, _ text: String) { for ch in text { e.typeText(String(ch)); usleep(120_000) } }
  /// scroll the current list until `e` is there (a Form draws rows lazily), then back to the top
  @discardableResult func scrolledTo(_ e: XCUIElement, max: Int = 6) -> Bool {
    var n = 0
    while !e.exists && n < max { app.swipeUp(); n += 1 }
    return e.exists
  }
  /// scroll back up until `e` shows; stops as soon as it does, since one more swipe down at the top of a sheet
  /// pulls the sheet away
  @discardableResult func scrolledUpTo(_ e: XCUIElement, max: Int = 6) -> Bool {
    var n = 0
    while !e.exists && n < max { app.swipeDown(velocity: .slow); n += 1 }
    return e.exists
  }
  /// Settings → Encrypted backup: download (the signatures checked, nothing opened), then Save file… opens the system
  /// share sheet, which is closed again. Returns whether every signature was valid; `stores` = how many stores the
  /// page should count.
  @discardableResult func downloadBackup(stores: Int? = nil) -> Bool {
    tabRoot("Settings")
    scrolledTo(el("open-backup"))
    guard wait(el("open-backup"), 15, "Settings → Encrypted backup") else { return false }
    el("open-backup").tap()
    guard arrives(el("backup-download"), 15, "the encrypted backup page") else { return false }
    shot("backup")
    el("backup-download").tap()
    let valid = el("backup-valid"), invalid = el("backup-invalid")
    let until = Date().addingTimeInterval(60)
    while !valid.exists && !invalid.exists && !el("backup-error").exists && Date() < until { usleep(300_000) }
    if el("backup-error").exists { XCTFail("[\(tag)] the backup download failed: \(el("backup-error").label)") }
    XCTAssertTrue(valid.exists, "[\(tag)] every backup signature is valid (\(invalid.exists ? said(invalid) : "no answer"))")
    if let stores { XCTAssertTrue(said(el("backup-stores")).contains("\(stores)"), "[\(tag)] the page counts \(stores) stores: \(said(el("backup-stores")))") }
    let ok = valid.exists
    shot("backup-checked")
    if scrolledTo(el("backup-share")) {
      // the system share sheet (UIActivityViewController): its list, its close button or the Save to Files action
      let sheet = [app.otherElements["ActivityListView"], app.buttons["Close"], app.buttons["close"],
                   app.cells.matching(NSPredicate(format: "label CONTAINS 'Save to Files'")).firstMatch,
                   app.buttons.matching(NSPredicate(format: "label CONTAINS 'Save to Files'")).firstMatch]
      var up = false
      for _ in 0..<2 where !up {
        el("backup-share").tap()
        let until = Date().addingTimeInterval(15)
        while !up && Date() < until { up = sheet.contains { $0.exists }; if !up { usleep(500_000) } }
      }
      shot("backup-share-sheet", checkBlank: false)
      if !up { note("share-sheet-tree", app.debugDescription) }
      XCTAssertTrue(up, "[\(tag)] Save file… opens the share sheet")
      let close = app.buttons.matching(NSPredicate(format: "label == 'Close' OR identifier == 'Close' OR label == 'close'")).firstMatch
      if close.exists { close.tap() } else if up { app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.08)).tap() }
      XCTAssertTrue(el("backup-share").waitForExistence(timeout: 20) && el("backup-share").isHittable, "[\(tag)] the share sheet closes")
    } else { XCTFail("[\(tag)] no Save file… after the download") }
    back()
    return ok
  }
  func isOn(_ e: XCUIElement) -> Bool { (e.value as? String) == "1" || e.isSelected }

  // ---- the router on the runner (the test reads payloads; the app checks signatures) ----
  func corePayload(_ path: String, _ field: String) -> [[String: Any]] {
    var r = URLRequest(url: URL(string: "http://127.0.0.1:18080/" + path)!)
    r.httpMethod = "POST"; r.setValue("application/json", forHTTPHeaderField: "Content-Type")
    r.httpBody = Data(#"{"nonce":"0123456789abcdef0123456789abcdef"}"#.utf8)
    nonisolated(unsafe) var out: [[String: Any]] = []
    let done = DispatchSemaphore(value: 0)
    URLSession.shared.dataTask(with: r) { data, _, _ in
      if let data, let doc = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let p = doc["payload"] as? String,
         let pj = try? JSONSerialization.jsonObject(with: Data(p.utf8)) as? [String: Any], let st = pj[field] as? [[String: Any]] { out = st }
      done.signal()
    }.resume()
    _ = done.wait(timeout: .now() + 20)
    return out
  }
  func coreStores() -> [[String: Any]] { corePayload("api/core/stores", "stores") }
  func coreUnlocked() -> [[String: Any]] { corePayload("api/core/unlocked", "unlocked") }

  /// any call to the router on the runner: status and body
  func routerRaw(_ method: String, _ path: String, body: Data? = nil, headers: [String: String] = [:]) -> (Int, Data) {
    var r = URLRequest(url: URL(string: "http://127.0.0.1:18080/" + path)!)
    r.httpMethod = method; r.httpBody = body
    for (k, v) in headers { r.setValue(v, forHTTPHeaderField: k) }
    nonisolated(unsafe) var out: (Int, Data) = (0, Data())
    let done = DispatchSemaphore(value: 0)
    URLSession.shared.dataTask(with: r) { d, resp, _ in out = ((resp as? HTTPURLResponse)?.statusCode ?? 0, d ?? Data()); done.signal() }.resume()
    _ = done.wait(timeout: .now() + 30)
    return out
  }

  /// New session: one image added from Photos (ios.yml's walkthrough and replica put a test image in the library with
  /// `simctl addmedia`), the picker driven as a person would; the clipboard's PasteButton when the picker shows no photo.
  /// The attachment's name on the page, nil when none arrived.
  @discardableResult func attachImage() -> String? {
    let row = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'ns-attachment-' AND NOT (identifier BEGINSWITH 'ns-attachment-remove-')")).firstMatch
    let add = el("ns-attach-photos")
    if wait(add, 10, "Add from Photos") {
      add.tap()
      sleep(3)
      shot("photos-picker", checkBlank: false)
      // the picker runs out of process; its grid is reachable through the app's tree: photos are Images
      // "PXGGridLayout-Info" labelled "Photo, <date>", newest first (the one simctl addmedia added)
      let photo = app.images.matching(identifier: "PXGGridLayout-Info").firstMatch
      if photo.waitForExistence(timeout: 60) {
        photo.tap()
        // with more than one allowed, the picker's confirm button (identifier "Add", label "Done") ends the pick
        let done = app.buttons.matching(identifier: "Add").firstMatch
        if done.waitForExistence(timeout: 10) { done.tap() } else { note("tree-photos-no-add", app.debugDescription) }
      } else {
        note("tree-photos-picker", app.debugDescription)
        // a picker stuck on "Loading…" (replica run 38393761270) has no tree to find its close button in: tap its X
        // (top left of the sheet) by position, then swipe the sheet down, so the Paste fallback below can reach the
        // page. Both only while the page is covered: the page's own Cancel sits where the X is
        if !add.isHittable { app.coordinate(withNormalizedOffset: .zero).withOffset(CGVector(dx: 37, dy: 109)).tap(); sleep(2) }
        if !add.isHittable {
          app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.1)).press(forDuration: 0.1, thenDragTo: app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.95)))
          sleep(2)
        }
        shot("photos-picker-closed", checkBlank: false)
      }
    }
    if !row.waitForExistence(timeout: 30) {
      // the clipboard: a test image, then the page's Paste button (no paste prompt for PasteButton)
      UIPasteboard.general.image = UIGraphicsImageRenderer(size: CGSize(width: 64, height: 48)).image { c in
        UIColor.systemRed.setFill(); c.fill(CGRect(x: 0, y: 0, width: 64, height: 48))
        UIColor.systemBlue.setFill(); c.fill(CGRect(x: 16, y: 12, width: 32, height: 24))
      }
      let paste = el("ns-attach-paste")
      if wait(paste, 10, "the Paste button") { paste.tap() }
    }
    guard wait(row, 30, "an image attached on New session") else { return nil }
    sleep(1)
    shot("new-session-image")
    return String(row.identifier.dropFirst("ns-attachment-".count))
  }

  /// Reset or recover at first launch: Recover with the kit (the core is empty)
  func recoverAtLaunch(_ kit: String) -> Bool {
    guard wait(el("setup-state-empty"), 90, "setup page: the core is empty") else { return false }
    el("setup-choose-recover").tap()
    guard wait(el("setup-kit-field"), 15, "recovery kit field") else { return false }
    el("setup-kit-field").tap(); el("setup-kit-field").typeText(kit)
    el("setup-recover-go").tap()
    guard wait(el("setup-done"), 120, "recovered") else { return false }
    el("secure-back").tap()
    return arrives(el("newBtn"), 60, "the session list after setup")
  }
}

extension JarvisUITestCase {
  /// the session page's read-only Log (Sessions/LogViews.swift): ONE stream of supervisor lines and lifecycle
  /// operations. It opens and is never blank: the router's entries are always there (every session had a boot; the list
  /// follows the end, so the check takes any router entry, not the first one), plus a supervisor line when
  /// `supervisorLine` and a Fly step when `flyStep` (the replica's real machines); then back on the session page
  func checkLogs(_ sid: String, supervisorLine: Bool, flyStep: Bool, _ what: String) {
    guard scrolledTo(el("log-\(sid)")) else { XCTFail("[\(tag)] Log on the session page (\(what))"); return }
    el("log-\(sid)").tap()
    if arrives(el("session-log"), 20, "the session's log (\(what))") {
      func entry(_ labels: String...) -> XCUIElement {
        let p = NSPredicate(format: "identifier BEGINSWITH 'ev-'")
        let all = labels.map { NSPredicate(format: "label CONTAINS %@", $0) }
        return app.descendants(matching: .any).matching(NSCompoundPredicate(andPredicateWithSubpredicates: [p] + all)).firstMatch
      }
      let end = el("log-end"), latest = el("log-latest")
      // it opens at the tail (app DECISIONS 78): once entries are in, the end marker is on screen without any scrolling
      let any = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'ev-'")).firstMatch
      if wait(any, 30, "an entry in the log (\(what))") {
        sleep(1)
        XCTAssertTrue(end.exists && end.isHittable, "[\(tag)] the log opens at its tail (\(what))")
        shot("session-log-tail-\(what)")
      }
      // the list is lazy, so an older entry (the boot's Router and Fly steps) has no element once later lines fill the
      // screen: not there within 10 s → scroll back up to it. Scrolled up, new lines must not pull the list back down.
      // An entry seen once counts (a new line can push it off between two queries; replica 39369735322)
      func seen(_ e: XCUIElement, _ t: TimeInterval, _ name: String) {
        if e.waitForExistence(timeout: 10) { return }
        if scrolledUpTo(e, max: 40) { return }
        wait(e, t, "\(name) in the log (\(what))")
      }
      seen(entry("Router"), 60, "a router entry")
      XCTAssertFalse(el("log-empty").exists, "[\(tag)] the log isn't empty (\(what))")
      if supervisorLine { seen(entry("Supervisor"), 90, "a supervisor line") }
      if flyStep { seen(entry("Fly"), 60, "a Fly step") }
      // scrolled up (a log longer than the screen): it stays put through a few polls and offers Latest, which goes back
      // to the tail
      if end.exists && end.isHittable { app.swipeDown(velocity: .fast); app.swipeDown(velocity: .fast) }
      if !(end.exists && end.isHittable) {
        sleep(5)
        XCTAssertFalse(end.exists && end.isHittable, "[\(tag)] scrolled up, new lines leave the reader where they are (\(what))")
        if wait(latest, 10, "Latest while scrolled up (\(what))") {
          latest.tap()
          sleep(2)
          XCTAssertTrue(end.exists && end.isHittable, "[\(tag)] Latest goes back to the tail (\(what))")
          XCTAssertTrue(gone(latest, 10), "[\(tag)] at the tail, no Latest (\(what))")
        }
      }
      shot("session-log-\(what)")
    }
    back()
  }
}
