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
    // the kernel isn't set up (no signed roster, no component answers): Sessions says so, never "Core not answering"
    tabRoot("Sessions")
    let banner = el("banner-kernel")
    XCTAssertTrue(arrives(banner, 30, "the kernel's warning on Sessions"), "an unhealthy kernel shows no warning")
    XCTAssertTrue(said(banner).contains("No signed kernel roster"), "the warning doesn't name what is wrong: \(said(banner))")
    XCTAssertFalse(el("banner-core").exists, "a box with no core warns about the core")
    shot("kernel-unhealthy")
  }

  /// A healthy kernel shows no warning on Sessions, and one component that stops answering does, by name.
  /// ios.yml's simulator job runs it against the real router (NO_CORE=1) with ios/ci/fakekernel as the eight components,
  /// which signed and posted a roster every component holds (the router says healthy before the test starts).
  func testKernelHealthBanner() {
    continueAfterFailure = false
    tag = "kernel-health"
    app.launch()
    if el("kernel-close").waitForExistence(timeout: 20) { el("kernel-close").tap() }
    XCTAssertTrue(arrives(app.tabBars.firstMatch, 10, "the tabs"))
    tabRoot("Sessions")
    _ = el("newBtn").waitForExistence(timeout: 20)
    sleep(3) // api/state answered (the banners show only once it has)
    // healthy: no warning, for a few of the app's refreshes
    for _ in 0..<6 {
      XCTAssertFalse(el("banner-kernel").exists, "a healthy kernel shows a warning: \(said(el("banner-kernel")))")
      XCTAssertFalse(el("banner-core").exists, "a box with no core says \"Core not answering\"")
      sleep(1)
    }
    shot("kernel-healthy")
    // notary stops answering: the router's next check (every 15 s) names it
    XCTAssertEqual(fakeKernel("_down/notary"), 200)
    let banner = el("banner-kernel")
    XCTAssertTrue(arrives(banner, 60, "the kernel's warning after notary went down"), "an unhealthy kernel shows no warning")
    XCTAssertTrue(said(banner).contains("notary not answering"), "the warning doesn't name notary: \(said(banner))")
    shot("kernel-notary-down")
    // and back: the warning goes
    XCTAssertEqual(fakeKernel("_up/notary"), 200)
    XCTAssertTrue(gone(banner, 60), "the warning stays after notary answers again")
    shot("kernel-healthy-again")
  }

  /// ios/ci/fakekernel's switches (POST /_down/<role>, /_up/<role>) on the runner
  private func fakeKernel(_ path: String) -> Int {
    var r = URLRequest(url: URL(string: "http://127.0.0.1:18310/" + path)!)
    r.httpMethod = "POST"
    nonisolated(unsafe) var code = 0
    let done = DispatchSemaphore(value: 0)
    URLSession.shared.dataTask(with: r) { _, resp, _ in code = (resp as? HTTPURLResponse)?.statusCode ?? 0; done.signal() }.resume()
    _ = done.wait(timeout: .now() + 20)
    return code
  }
}
