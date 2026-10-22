// The terminal: the router's own terminal page (GET /term/{id}, router/web/terminal.html) in a WKWebView. WebKit runs
// the page in its own process, so the app carries no terminal code. The page goes through Cloudflare Access like every
// request: it is loaded with the app's Access login (the `cf-access-token` header, the CF_Authorization cookie for the
// router's host, and every fetch of the page given the header), in a non-persistent website data store, so nothing
// of it outlives the view. The machine still runs the terminal's commands only under a grant: the page asks the app
// (message handler `jarvis2`, action "grant") and the app opens its Face ID review; "signin" re-runs the sign-in sheet.
import SwiftUI
import WebKit

struct TerminalView: View {
  @Environment(AppModel.self) private var model
  let sessionId: String
  let title: String
  /// until the page has loaded, a native progress view stands over the dark web view (never a blank screen)
  @State private var page: TerminalPage = .loading
  @State private var attempt = 0

  var body: some View {
    TerminalWeb(sessionId: sessionId, model: model, attempt: attempt, page: $page)
      .background(Color(red: 0.043, green: 0.051, blue: 0.071))
      .overlay {
        switch page {
        case .loading:
          ProgressView("Opening the terminal…").tint(.white).foregroundStyle(.white).accessibilityIdentifier("terminal-loading")
        case .failed(let why):
          ContentUnavailableView {
            Label("The terminal didn't open", systemImage: "exclamationmark.triangle")
          } description: {
            Text(why)
          } actions: {
            Button("Try again") { page = .loading; attempt += 1 }.buttonStyle(.borderedProminent)
          }
          .foregroundStyle(.white)
          .accessibilityIdentifier("terminal-failed")
        case .ready:
          EmptyView()
        }
      }
      .toolbarVisibility(.hidden, for: .tabBar)
      .navigationTitle(title)
      .navigationBarTitleDisplayMode(.inline)
      .toolbarColorScheme(.dark, for: .navigationBar)
      .safeAreaInset(edge: .top) {
        if let m = model.session(sessionId), let lock = m.lockedStore {
          HStack {
            Label { Text(lock).monospaced() } icon: { Image(systemName: "lock") }.font(.footnote).accessibilityLabel("Locked store")
            Spacer()
            Button("Unlock…") { model.present(.unlock(session: m.id, label: m.title)) }.buttonStyle(.borderedProminent).controlSize(.small)
          }
          .padding(10)
          .background(.orange.opacity(0.18))
        }
      }
  }
}

enum TerminalPage: Equatable { case loading, ready, failed(String) }

private struct TerminalWeb: UIViewRepresentable {
  let sessionId: String
  let model: AppModel
  let attempt: Int
  @Binding var page: TerminalPage

  func makeCoordinator() -> Coordinator { Coordinator(sessionId: sessionId, model: model, page: $page) }

  func makeUIView(context: Context) -> WKWebView {
    let cfg = WKWebViewConfiguration()
    cfg.websiteDataStore = .nonPersistent()
    let ucc = WKUserContentController()
    ucc.add(WeakHandler(context.coordinator), name: "jarvis2")
    ucc.addUserScript(WKUserScript(source: Coordinator.tokenScript(RouterClient.shared.token), injectionTime: .atDocumentStart, forMainFrameOnly: true))
    cfg.userContentController = ucc
    let web = WKWebView(frame: .zero, configuration: cfg)
    web.isOpaque = false
    web.backgroundColor = UIColor(red: 0.043, green: 0.051, blue: 0.071, alpha: 1)
    web.scrollView.backgroundColor = web.backgroundColor
    web.scrollView.contentInsetAdjustmentBehavior = .never
    web.accessibilityIdentifier = "terminal"
    web.navigationDelegate = context.coordinator
    context.coordinator.web = web
    context.coordinator.attempt = attempt
    context.coordinator.load()
    return web
  }
  func updateUIView(_ web: WKWebView, context: Context) {
    if context.coordinator.attempt != attempt { context.coordinator.attempt = attempt; context.coordinator.load() }
  }
  static func dismantleUIView(_ web: WKWebView, coordinator: Coordinator) {
    web.configuration.userContentController.removeScriptMessageHandler(forName: "jarvis2")
    web.stopLoading()
  }

  @MainActor
  final class Coordinator: NSObject, WKScriptMessageHandler, WKNavigationDelegate {
    let sessionId: String
    let model: AppModel
    weak var web: WKWebView?
    var attempt = 0
    let page: Binding<TerminalPage>
    init(sessionId: String, model: AppModel, page: Binding<TerminalPage>) { self.sessionId = sessionId; self.model = model; self.page = page }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) { page.wrappedValue = .ready }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) { failed(error) }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) { failed(error) }
    private func failed(_ error: Error) {
      if (error as NSError).code == NSURLErrorCancelled { return }
      page.wrappedValue = .failed(error.localizedDescription)
    }

    /// the page's fetches carry the Access login as a header (the page only talks to its own origin)
    static func tokenScript(_ token: String) -> String {
      let lit = (try? String(decoding: JSONSerialization.data(withJSONObject: [token]), as: UTF8.self)).map { String($0.dropFirst().dropLast()) } ?? "\"\""
      return """
      (function () {
        window.__jarvis2Token = \(lit);
        var f = window.fetch;
        window.fetch = function (input, init) {
          init = init || {};
          var h = new Headers(init.headers || {});
          if (window.__jarvis2Token) h.set("cf-access-token", window.__jarvis2Token);
          init.headers = h;
          return f.call(window, input, init);
        };
      })();
      """
    }

    func load() {
      guard let web else { return }
      let base = RouterClient.shared.base
      let token = RouterClient.shared.token
      var req = URLRequest(url: base.appending(path: "term/\(sessionId)"))
      if !token.isEmpty { req.setValue(token, forHTTPHeaderField: "cf-access-token") }
      let go = { web.load(req) }
      if !token.isEmpty, let host = base.host(), let cookie = HTTPCookie(properties: [
        .name: "CF_Authorization", .value: token, .domain: host, .path: "/", .secure: base.scheme == "https" ? "TRUE" : "FALSE",
      ]) {
        web.configuration.websiteDataStore.httpCookieStore.setCookie(cookie) { go() }
      } else {
        go()
      }
    }

    func userContentController(_ ucc: WKUserContentController, didReceive message: WKScriptMessage) {
      guard let body = message.body as? [String: Any], let action = body["action"] as? String else { return }
      switch action {
      case "grant":
        let holder = (body["holder"] as? String) ?? "terminal"
        let label = model.session(sessionId)?.title ?? sessionId
        model.requestGrant(sessionId, label, holder: holder) { [weak self] _ in self?.refreshPage() }
      case "signin":
        Task {
          let t = await RouterClient.shared.signIn()
          guard !t.isEmpty else { return }
          await self.renewLogin(t)
        }
      default:
        break
      }
    }

    private func renewLogin(_ token: String) async {
      guard let web else { return }
      let base = RouterClient.shared.base
      if let host = base.host(), let cookie = HTTPCookie(properties: [.name: "CF_Authorization", .value: token, .domain: host, .path: "/", .secure: base.scheme == "https" ? "TRUE" : "FALSE"]) {
        await web.configuration.websiteDataStore.httpCookieStore.setCookie(cookie)
      }
      let lit = String(decoding: (try? JSONSerialization.data(withJSONObject: [token])) ?? Data("[\"\"]".utf8), as: UTF8.self).dropFirst().dropLast()
      _ = try? await web.evaluateJavaScript("window.__jarvis2Token = \(lit); window.jarvis2Refresh && window.jarvis2Refresh();")
    }

    func refreshPage() {
      web?.evaluateJavaScript("window.jarvis2Refresh && window.jarvis2Refresh();", completionHandler: nil)
    }
  }
}

/// the user content controller keeps its handler strongly: this breaks the cycle web view → controller → coordinator
@MainActor
private final class WeakHandler: NSObject, WKScriptMessageHandler {
  weak var target: (any WKScriptMessageHandler)?
  init(_ target: any WKScriptMessageHandler) { self.target = target }
  func userContentController(_ ucc: WKUserContentController, didReceive message: WKScriptMessage) {
    target?.userContentController(ucc, didReceive: message)
  }
}
