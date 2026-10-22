import XCTest

/// Every navigation of the native app, recorded on video by transitions.yml (light and dark): each tab, each push and
/// pop (Back and the edge swipe), each sheet in and out, background and back, a relaunch. Each step must land on its
/// target with no blank screen over 1.5 s on the way (`arrives`), and every screenshot is checked for a near-uniform
/// (blank) picture.
final class TransitionsUITests: JarvisUITestCase {
  func edgeSwipeBack() {
    let w = app.windows.firstMatch
    w.coordinate(withNormalizedOffset: CGVector(dx: 0.01, dy: 0.5)).press(forDuration: 0.05, thenDragTo: w.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)))
  }

  func testTransitions() {
    continueAfterFailure = true
    tag = "transitions-" + (env["JARVIS4_APPEARANCE"] ?? "run")
    app.launch()
    // launch → Reset or recover (a full-screen cover) → Recover → Done → the list
    guard recoverAtLaunch(env["JARVIS4_KIT"] ?? "") else { return }
    shot("list")

    // tabs, each twice
    for _ in 0..<2 {
      for (t, target) in [("Inbox", "Inbox"), ("Tasks", "Tasks"), ("Settings", "Settings"), ("Sessions", "Sessions")] {
        tab(t)
        arrives(app.navigationBars[target].firstMatch, 10, "the \(t) tab")
      }
    }
    tab("Search"); arrives(app.searchFields.firstMatch, 10, "the Search tab"); shot("search")
    tab("Sessions")

    // sheets: New session in and out (Cancel, then a swipe down)
    for how in ["cancel", "swipe"] {
      el("newBtn").tap()
      guard arrives(el("secure-create"), 15, "New session (\(how))") else { break }
      shot("new-session-\(how)")
      if how == "cancel" { el("secure-back").tap() } else {
        // a person's drag down from the sheet's top edge
        let w = app.windows.firstMatch
        w.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.09)).press(forDuration: 0.05, thenDragTo: w.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.98)), withVelocity: .fast, thenHoldForDuration: 0)
      }
      arrives(el("newBtn"), 10, "the list after New session (\(how))")
      XCTAssertTrue(gone(el("secure-create"), 5), "[\(tag)] the sheet left (\(how))")
    }

    // pushes: Previous (Back, then the edge swipe); Settings → Stores, Repos → Add repo, Machines
    for how in ["back", "swipe"] {
      el("previousBtn").tap()
      arrives(app.navigationBars["Previous"].firstMatch, 10, "Previous (\(how))")
      if how == "back" { back() } else { edgeSwipeBack() }
      arrives(el("newBtn"), 10, "the list after Previous (\(how))")
    }
    tab("Settings")
    for (link, title) in [("open-stores", "Stores"), ("open-repos", "Repos"), ("open-machines", "Machines")] {
      guard wait(el(link), 10, link) else { continue }
      el(link).tap()
      arrives(app.navigationBars[title].firstMatch, 15, title)
      shot(title.lowercased())
      if title == "Repos", el("repo-add").waitForExistence(timeout: 5) {
        el("repo-add").tap()
        arrives(el("repo-url"), 10, "Add repo")
        back()
        arrives(app.navigationBars["Repos"].firstMatch, 10, "Repos again")
      }
      back()
      arrives(el(link), 10, "Settings after \(title)")
    }

    // the Face ID review sheet: Add repo → the review → Cancel, and Reset or recover from Settings → Close
    tab("Settings")
    el("open-repos").tap()
    if wait(el("repo-add"), 10, "Add repo") {
      el("repo-add").tap()
      let f = el("repo-url")
      if wait(f, 10, "repo field") {
        f.tap(); slowType(f, "DE0CH/china-train\n")
        if arrives(el("secure-repo-go"), 30, "the add-repo review") {
          shot("review")
          el("secure-back").tap()
          arrives(el("repo-url"), 10, "Add repo after Cancel")
        }
      }
      back(); back()
    }
    tab("Settings")
    if (scrolledTo(el("open-setup")) || true), wait(el("open-setup"), 10, "Reset or recover") {
      el("open-setup").tap()
      arrives(el("setup-state-mine"), 30, "Reset or recover from Settings")
      shot("setup")
      el("secure-back").tap()
      arrives(el("open-setup"), 10, "Settings after Close")
    }

    // a session: New session → Start → the row → its page → back; the background; a relaunch
    tab("Sessions")
    el("newBtn").tap()
    if arrives(el("secure-create"), 15, "New session (start)") {
      el("ns-title").tap(); el("ns-title").typeText("transitions")
      el("secure-create").tap()
      let row = prefixed("srow-")
      if arrives(row, 120, "the new session's row") {
        let sid = String(row.identifier.dropFirst("srow-".count))
        row.tap()
        arrives(el("grants-\(sid)"), 15, "the session's page")
        el("grants-\(sid)").tap()
        arrives(el("grant-review"), 15, "Grants")
        edgeSwipeBack()
        arrives(el("grants-\(sid)"), 10, "the session's page after the swipe")
        if el("term-\(sid)").waitForExistence(timeout: 20) {
          el("term-\(sid)").tap()
          arrives(app.webViews.firstMatch, 20, "the terminal page")
          // the native progress view covers the web view until the page has loaded; then the page itself shows
          XCTAssertTrue(gone(el("terminal-loading"), 30), "[\(tag)] the terminal page loads")
          arrives(app.webViews.textFields["Terminal input"].firstMatch, 20, "the terminal page's input row")
          shot("terminal")
          back()
        }
        back()
      }
    }
    XCUIDevice.shared.press(.home)
    sleep(3)
    app.activate()
    arrives(el("newBtn"), 10, "the list after the background")
    shot("after-background")
    app.terminate()
    app.launch()
    arrives(el("newBtn"), 30, "the list after a relaunch")
    XCTAssertFalse(el("setup-state-empty").exists, "[\(tag)] no Reset or recover after a relaunch")
    shot("after-relaunch")
    app.terminate()
  }
}
