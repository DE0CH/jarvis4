import XCTest

/// The first launch on a Jarvis 4 box: a router with the kernel and no core (NO_CORE=1, as k8s/cluster/router runs it),
/// a fresh Keychain. The app must open the kernel's setup, never the old core's Reset or recover page (which answers
/// "isn't answering": the router has no core), and the root key's registration must reach the router.
/// ios.yml's simulator job runs it against the real router with KERNEL_URL pointing at nothing (no components yet,
/// the state of a new box before a setup session has read them).
final class KernelUITests: JarvisUITestCase {
  func testKernelFirstLaunch() {
    continueAfterFailure = false
    tag = "kernel-first-launch"
    app.launch()
    XCTAssertTrue(arrives(el("kernel-root-key-router"), 30, "the kernel's setup on first launch"), "the first launch didn't open Settings → Kernel")
    XCTAssertFalse(el("setup-retry").exists, "the old core's Reset or recover page came up")
    shot("first-launch")
    XCTAssertTrue(said(el("kernel-root-key-git")).contains("Not yet"), "keys/root.pub isn't this iPhone's root key yet")
    XCTAssertTrue(said(el("kernel-root-key-router")).contains("Not yet"))
    let reg = el("kernel-root-register")
    XCTAssertTrue(wait(reg, 10, "Register the root key"))
    reg.tap()
    let registered = NSPredicate(format: "label CONTAINS 'Registered'")
    expectation(for: registered, evaluatedWith: el("kernel-root-key-router"))
    waitForExpectations(timeout: 30)
    shot("root-key-registered")
    // the router keeps it for the setup session (GET /setup/kernel/root-key), and says so to the app
    let (st, body) = routerRaw("GET", "api/kernel")
    XCTAssertEqual(st, 200)
    let k = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any]
    XCTAssertEqual(k?["core"] as? Bool, false, "the router doesn't say it runs no core")
    XCTAssertEqual((k?["roster"] as? [String: Any])?["rootKey"] as? Bool, true, "the router has no root key")
    // closable: the tabs are there behind it
    el("kernel-close").tap()
    XCTAssertTrue(arrives(app.tabBars.firstMatch, 10, "the tabs after Close"))
  }
}
