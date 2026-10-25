// The app's client of the router (docs/API.md) — an ordinary network path: integrity comes from the core's signatures
// (checked here against the core keys pinned when this iPhone set the core up) and the phone's (made here). Sign-in:
// ASWebAuthenticationSession on /api/auth/start → jarvis2://auth#token=<Access JWT>, kept in the Keychain and sent as
// `cf-access-token` on every request (never cookies, except into the terminal page's WebView: TerminalView).
import AuthenticationServices
import Foundation
import UIKit

/// a failed request, in words; `status` and `body` for the callers that act on them (a 403 {needsGrant}, a 404)
struct RouterError: LocalizedError {
  let message: String
  var status = 0
  var body: JSON = .null
  var errorDescription: String? { message }
}
/// Cloudflare Access refused the login and the sign-in sheet didn't complete
struct SignedOut: LocalizedError { var errorDescription: String? { "Signed out of Cloudflare Access." } }

@MainActor
final class RouterClient: NSObject, ASWebAuthenticationPresentationContextProviding {
  static let shared = RouterClient()
  let base: URL = {
    let s = (Bundle.main.object(forInfoDictionaryKey: "JarvisBase") as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "https://jarvis4.deyaochen.com/"
    return URL(string: s.hasSuffix("/") ? s : s + "/") ?? URL(string: "https://jarvis4.deyaochen.com/")!
  }()
  /// the Access login, kept in memory once read: its Keychain item opens only while the phone is unlocked, and a poll
  /// that runs as the phone locks or wakes went out without it, so Access turned it away and the sign-in sheet popped
  /// up (and closed itself) the next time the app opened
  private var tokenCache: String?
  var token: String {
    if let tokenCache { return tokenCache }
    tokenCache = Keychain.string("access-token")
    return tokenCache ?? ""
  }
  /// told when sign-in failed or came back (AppModel shows the signed-out screen)
  var onSignedOut: ((Bool) -> Void)?

  // ---- sign-in ----
  private var signing: Task<String, Never>?
  private var webSession: ASWebAuthenticationSession?
  /// runs the sign-in sheet once (callers meanwhile share it); "" when cancelled or failed
  func signIn() async -> String {
    if let signing { return await signing.value }
    let t = Task { @MainActor () -> String in
      defer { signing = nil }
      var c = URLComponents(url: base.appending(path: "api/auth/start"), resolvingAgainstBaseURL: false)
      c?.queryItems = [URLQueryItem(name: "redirect", value: "jarvis2://auth")]
      guard let start = c?.url else { return "" }
      // not while the phone is locked or the app is on its way back (a refresh on unlock finds the login expired):
      // the sheet can't present then, so wait until the app is active with a window to present on
      while UIApplication.shared.applicationState != .active || Self.keyWindow == nil {
        try? await Task.sleep(for: .milliseconds(300))
      }
      // ResumeOnce: a sheet that can't present both calls back (with an error) and returns false from start()
      let url: URL? = await ResumeOnce.run(failed: nil) { done in
        let s = ASWebAuthenticationSession(url: start, callback: .customScheme("jarvis2")) { u, _ in done(u) }
        s.presentationContextProvider = self
        webSession = s
        return s.start()
      }
      webSession = nil
      guard let frag = url?.fragment, let tok = URLComponents(string: "x:?" + frag)?.queryItems?.first(where: { $0.name == "token" })?.value, !tok.isEmpty else {
        onSignedOut?(true)
        return ""
      }
      Keychain.setString("access-token", tok)
      tokenCache = tok
      onSignedOut?(false)
      return tok
    }
    signing = t
    return await t.value
  }
  private static var keyWindow: UIWindow? {
    UIApplication.shared.connectedScenes.compactMap { ($0 as? UIWindowScene)?.keyWindow }.first
  }
  nonisolated func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
    MainActor.assumeIsolated { Self.keyWindow ?? ASPresentationAnchor() }
  }

  // ---- requests ----
  /// Access turned the request away: it ended on the Access login, or a 401/403 that isn't JSON, or the router's own
  /// "Access login required"
  private func refused(_ resp: HTTPURLResponse, _ data: Data) -> Bool {
    if (resp.url?.host ?? "").hasSuffix("cloudflareaccess.com") { return true }
    guard resp.statusCode == 401 || resp.statusCode == 403 else { return false }
    let ct = resp.value(forHTTPHeaderField: "Content-Type") ?? ""
    return !ct.contains("json") || String(decoding: data, as: UTF8.self).contains("Access login required")
  }
  func url(_ path: String) -> URL {
    // a path with a query ("api/icloud/search?q=…") is resolved as a relative reference, so the query stays a query
    URL(string: path, relativeTo: base)?.absoluteURL ?? base.appending(path: path)
  }
  /// `upload`: raw bytes as the body instead of JSON, with `headers`
  func raw(_ method: String, _ path: String, _ body: [String: Any]? = nil, upload: Data? = nil, headers: [String: String] = [:],
           timeout: TimeInterval = 60) async throws -> (Int, Data) {
    // a launch in the background or a locked phone can't read the login yet: wait for the unlock, never go out without it
    while token.isEmpty && !UIApplication.shared.isProtectedDataAvailable { try await Task.sleep(for: .seconds(1)) }
    for attempt in 0..<2 {
      var r = URLRequest(url: url(path))
      r.httpMethod = method
      r.timeoutInterval = timeout
      if let body { r.httpBody = try JSONSerialization.data(withJSONObject: body); r.setValue("application/json", forHTTPHeaderField: "Content-Type") }
      if let upload { r.httpBody = upload; r.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type") }
      for (k, v) in headers { r.setValue(v, forHTTPHeaderField: k) }
      if !token.isEmpty { r.setValue(token, forHTTPHeaderField: "cf-access-token") }
      r.httpShouldHandleCookies = false
      let (data, resp) = try await URLSession.shared.data(for: r)
      guard let h = resp as? HTTPURLResponse else { throw RouterError(message: "no HTTP answer") }
      if refused(h, data) {
        if attempt == 0, !(await signIn()).isEmpty { continue }
        throw SignedOut()
      }
      return (h.statusCode, data)
    }
    throw SignedOut()
  }
  /// JSON answer; errors (the router's {error} or the core's signed error doc) as their message
  func json<T: Decodable>(_ method: String, _ path: String, _ body: [String: Any]? = nil, as: T.Type = T.self, headers: [String: String] = [:]) async throws -> T {
    let (status, data) = try await raw(method, path, body, headers: headers)
    guard (200..<300).contains(status) else { throw Self.failure(method, path, status, data) }
    return try JSONDecoder().decode(T.self, from: data)
  }
  /// any router call, its answer as JSON
  @discardableResult
  func call(_ method: String, _ path: String, _ body: [String: Any]? = nil, timeout: TimeInterval = 60) async throws -> JSON {
    let (status, data) = try await raw(method, path, body, timeout: timeout)
    guard (200..<300).contains(status) else { throw Self.failure(method, path, status, data) }
    return JSON.parse(data)
  }
  func get(_ path: String) async throws -> JSON { try await call("GET", path) }
  /// switch a session's Claude account (router/accountswap.go): 202 {started} for a running session (its `wake` job,
  /// kind "account"), 200 {nextStart} for a paused or failed one, 200 {unchanged} when it already uses it
  func switchAccount(id: String, account: String, continue cont: Bool) async throws -> JSON {
    try await call("POST", "api/sessions/\(id)/account", ["account": account, "continue": cont])
  }

  // ---- first-prompt attachments (router/uploads.go) ----
  /// the router's record of one uploaded file: the name it made safe, the size it stored
  struct Uploaded: Decodable { let name: String; let size: Int; let isImage: Bool }
  /// RFC 3986 unreserved characters (ASCII only: a header value and a URL path segment)
  static func escaped(_ s: String) -> String {
    s.addingPercentEncoding(withAllowedCharacters: CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")) ?? s
  }
  /// one file of New session's attachments, staged on the router under `id` (the form's upload id)
  func upload(id: String, name: String, data: Data) async throws -> Uploaded {
    let (status, out) = try await raw("POST", "api/uploads", upload: data, headers: ["x-upload-id": id, "x-upload-name": Self.escaped(name)], timeout: 300)
    guard (200..<300).contains(status) else { throw Self.failure("POST", "api/uploads", status, out) }
    return try JSONDecoder().decode(Uploaded.self, from: out)
  }
  /// a staged file of a session not started yet (the approval page hashes it against the signed config)
  func attachment(session: String, name: String) async throws -> Data {
    let path = "api/sessions/\(Self.escaped(session))/attachments/\(Self.escaped(name))"
    let (status, out) = try await raw("GET", path, timeout: 120)
    guard (200..<300).contains(status) else { throw Self.failure("GET", path, status, out) }
    return out
  }

  static func failure(_ method: String, _ path: String, _ status: Int, _ data: Data) -> RouterError {
    let hint: [Int: String] = [400: "bad request", 401: "not authorised", 403: "forbidden", 404: "not found", 409: "conflict", 413: "request too large",
                               423: "locked", 429: "rate-limited, try again shortly", 500: "router error", 502: "bad gateway", 503: "unavailable", 504: "timed out"]
    let why = reason(data) ?? hint[status] ?? "request failed"
    return RouterError(message: why, status: status, body: JSON.parse(data))
  }
  static func reason(_ data: Data) -> String? {
    guard let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
    if let p = j["payload"] as? String, let pj = try? JSONSerialization.jsonObject(with: Data(p.utf8)) as? [String: Any], let e = pj["error"] as? String { return "core: " + e }
    return (j["error"] as? String) ?? (j["message"] as? String)
  }

  // ---- the core, relayed: every answer checked against the pinned core key ----
  func stores() async throws -> [StoreView] { try await storesDoc().stores }

  /// the content stores (router/content.go): name, file count, bytes
  struct ContentStoreDTO: Decodable, Identifiable, Hashable { let name: String; let files: Int; let bytes: Int; var id: String { name } }
  private struct ContentList: Decodable { let stores: [ContentStoreDTO] }
  func contentStores() async throws -> [ContentStoreDTO] { try await json("GET", "api/content", as: ContentList.self).stores }
  /// who signs the store documents: the kernel's secrets on a box with no core (router storeCore: the store calls go
  /// there), else the core
  private func storesKey() async throws -> String {
    if let k = try? await kernelStatus(), k.configured, !k.core { return try KernelTrust.key() }
    return try CoreTrust.key()
  }
  /// the signed list itself
  func storesDoc() async throws -> StoresDoc {
    let n = CoreCrypto.nonce()
    let d = try CoreCrypto.decode(try await json("POST", "api/core/stores", ["nonce": n], as: SignedDoc.self), by: try await storesKey(), as: StoresDoc.self, what: "the store list")
    guard d.kind == "stores", d.nonce == n else { throw TrustError.stale("store list") }
    return d
  }
  /// the setup key from git, only when a writer needs checking
  private func setupKeyIfNeeded(_ ws: [StoreWriter?]) async throws -> String? {
    ws.contains { $0?.by == "setup" } ? try await KeySource.key("setup.pub") : nil
  }
  private func setupKeyIfNeeded(_ w: StoreWriter?) async throws -> String? { try await setupKeyIfNeeded([w]) }
  /// the router relays a core call to the NEXT core (blue/green, router/nextcore.go) when it carries this header
  static func coreHeaders(_ next: Bool) -> [String: String] { next ? ["X-Jarvis2-Core": "next"] : [:] }
  func unlocked() async throws -> [UnlockRow] {
    let n = CoreCrypto.nonce()
    let d = try CoreCrypto.decode(try await json("POST", "api/core/unlocked", ["nonce": n], as: SignedDoc.self), by: try await storesKey(), as: UnlockedDoc.self, what: "the unlocked list")
    guard d.kind == "unlocked-list", d.nonce == n else { throw TrustError.stale("unlocked list") }
    return d.unlocked
  }
  /// forNonce: the challenge or cert nonce the unlock is for (the core locks it again once that cert has pulled);
  /// nil = a standing unlock
  func unlockBegin(_ store: String, for forNonce: String? = nil) async throws -> UnlockBegin {
    var body: [String: Any] = ["store": store]
    if let forNonce { body["for"] = forNonce }
    let b = try CoreCrypto.decode(try await json("POST", "api/core/unlock/begin", body, as: SignedDoc.self), by: try await storesKey(), as: UnlockBegin.self, what: "the unlock")
    guard b.kind == "unlock-begin", b.store == store else { throw TrustError.stale("unlock of \(b.store)") }
    if let got = b.forNonce, !got.isEmpty, got != (forNonce ?? "") { throw TrustError.stale("unlock of \(b.store) for another session") }
    if forNonce == nil, let got = b.forNonce, !got.isEmpty { throw TrustError.stale("unlock of \(b.store) for one session") }
    // each key's writer: the setup key's signature, a session's machine (the page names it), the router or the core
    try Checks.unlockKeys(b, setupKey: try await setupKeyIfNeeded(b.keys.map(\.writer)))
    return b
  }
  /// this phone's shares x(p·E), one per `b.es` in order, each sealed to the core's one-off key T
  func unlockFinish(_ b: UnlockBegin, shares: [Data]) async throws {
    guard shares.count == b.es.count else { throw TrustError.stale("unlock of \(b.store)") }
    var m: [String: Any] = [:]
    for (k, x) in zip(b.keys, shares) { m[k.key] = try CoreCrypto.sealShare(x, to: b.t) }
    let body: [String: Any] = ["pending": b.pending, "shares": m]
    let d = try CoreCrypto.decode(try await json("POST", "api/core/unlock/finish", body, as: SignedDoc.self), by: try await storesKey(), as: KindDoc.self, what: "the unlocked answer")
    guard d.kind == "unlocked", d.store == b.store else { throw TrustError.stale("unlocked \(d.store ?? "?")") }
  }
  func lock(_ id: String) async throws {
    let d = try CoreCrypto.decode(try await json("POST", "api/core/lock", ["id": id], as: SignedDoc.self), by: try await storesKey(), as: KindDoc.self, what: "the locked answer")
    guard d.kind == "locked", d.id == id else { throw TrustError.stale("lock") }
  }
  func markSensitive(_ name: String) async throws {
    let d = try CoreCrypto.decode(try await json("POST", "api/core/stores/mark-sensitive", ["name": name], as: SignedDoc.self), by: try await storesKey(), as: KindDoc.self, what: "the mark")
    guard d.kind == "marked-sensitive", d.name == name else { throw TrustError.stale("mark") }
  }
  func createStore(_ name: String) async throws {
    let d = try CoreCrypto.decode(try await json("POST", "api/core/stores/create", ["name": name], as: SignedDoc.self), by: try await storesKey(), as: KindDoc.self, what: "the new store")
    guard d.kind == "store-created", d.name == name else { throw TrustError.stale("create") }
  }

  // ---- deploy keys: a repo added or removed (core/deploykeys.go) ----
  /// the core's signed begin document, checked: this action, this repo, its store, the one token store it opens
  /// An add: the app makes the ed25519 pair, wraps the repo's store (the private half among its keys) to the core's
  /// store key, and sends both; the core's signed begin must echo them.
  /// Once the kernel serves, its secrets keeps the stores and answers these calls (router/repos.go deployKeyCall):
  /// its store key and its signatures, checked against the keys this iPhone pinned (KernelTrust).
  func deployKeyBegin(action: String, repo: String, sensitive: Bool) async throws -> (doc: SignedDoc, begin: DeployKeyBegin) {
    let store = Checks.repoStore(repo), title = Checks.deployKeyTitle(store)
    var body: [String: Any] = ["action": action, "repo": repo, "sensitive": sensitive, "store": store, "title": title]
    var sent: DeployKeySent?
    let signer = try await deployKeySigner()
    if action == "add" {
      let sk = try await deployKeyStoreKey(signer)
      let kp = try OpenSSH.ed25519(comment: title)
      let values = OpenSSH.storeValues(repo: repo, privateKeyFile: kp.privateKeyFile)
      // each value under its own data key, "<store>\n<key>" as associated data
      let keys = try CoreCrypto.wrapKeys(store: store, values: values, storeKey: sk)
      body["publicKey"] = kp.publicKey
      body["keys"] = keys.map(\.json)
      sent = DeployKeySent(publicKey: kp.publicKey, keys: keys)
    }
    let d = try await json("POST", "api/repos/key/begin", body, as: SignedDoc.self)
    let b = try Checks.deployKeyBegin(d, coreKey: signer.key, action: action, repo: repo, sensitive: sensitive, sent: sent)
    try await checkTokenWriter(b)
    return (d, b)
  }
  /// who signs the deploy-key documents: the kernel's secrets once the kernel serves, else the core
  private func deployKeySigner() async throws -> (key: String, kernel: Bool) {
    if (try? await kernelStatus())?.serves == true { return (try KernelTrust.key(), true) }
    return (try CoreTrust.key(), false)
  }
  /// the store key the repo's store is wrapped to: secrets' C = P + K for the K this iPhone pinned, or the core's
  private func deployKeyStoreKey(_ signer: (key: String, kernel: Bool)) async throws -> String {
    guard signer.kernel else { return try await storeKey(coreKey: signer.key) }
    guard let k = KernelTrust.pinned else { throw TrustError.notSetUp }
    return try kernelStoreKey(secrets: k.agreementKey)
  }
  /// who wrote the GitHub token the phone's share opens: the setup key (its signature over the token key's writer text)
  /// or the core; never a session (the core refuses a machine write to that store)
  private func checkTokenWriter(_ b: DeployKeyBegin) async throws {
    guard let w = b.tokenWriter, w.by != "machine" else { throw TrustError.mismatch("the GitHub token's writer") }
    try Checks.keyWriter(w, store: b.tokenStore, key: b.tokenKey, e: b.e, dataSha256: b.tokenDataSha256, backupSha256: b.tokenBackupSha256,
                         setupKey: try await setupKeyIfNeeded(w))
  }
  /// the phone's signature over the begin document and its share of the token store; the answer, checked
  /// inbox: the Inbox request this answers; the router then names the add-store approval it filed for the session that
  /// asked (followups, beside the core's document; DECISIONS 182)
  func deployKeyFinish(_ b: DeployKeyBegin, signature: Data, share: Data, inbox: String? = nil) async throws -> (answer: DeployKeyAnswer, followups: [String]) {
    let body: [String: Any] = ["pending": b.pending, "signature": signature.base64EncodedString(), "share": try CoreCrypto.sealShare(share, to: b.t)]
    var path = "api/repos/key/finish"
    if let inbox, let q = inbox.addingPercentEncoding(withAllowedCharacters: .alphanumerics) { path += "?inbox=" + q }
    let (status, data) = try await raw("POST", path, body)
    guard (200..<300).contains(status) else { throw Self.failure("POST", path, status, data) }
    let a = try Checks.deployKeyAnswer(try JSONDecoder().decode(SignedDoc.self, from: data), coreKey: try await deployKeySigner().key, begin: b)
    let f = JSON.parse(data)["followups"].strings
    return (a, f)
  }

  /// the core's store key C = P + K for this phone's agreement key, checked against `coreKey`
  /// core: the core point K to add (a Recover's derived K, CoreContinuity), nil = the answering core's own
  func storeKey(coreKey: String, core: String? = nil, next: Bool = false) async throws -> String {
    let phone = try PhoneKeys.shared.publicKeys().agreementKey
    var body: [String: Any] = ["phone": phone]
    if let core { body["core"] = core }
    let (status, data) = try await raw("POST", "api/core/store-key", body, headers: Self.coreHeaders(next))
    guard status == 200 else { throw Self.failure("POST", "api/core/store-key", status, data) }
    return try CoreCrypto.storeKey(try JSONDecoder().decode(SignedDoc.self, from: data), coreKey: coreKey, phone: phone, core: core)
  }
  /// the record of the sessions the router kept from the core (core/continuity.go); nil when it has none (the caller
  /// checks it: CoreSetup.checkLineState)
  func lineState() async throws -> CoreSetup.LineStateDoc? {
    let (status, data) = try await raw("GET", "api/core/line-state", nil)
    if status == 404 { return nil }
    guard status == 200 else { throw Self.failure("GET", "api/core/line-state", status, data) }
    // anything else than a record is the router withholding one (which it may: the sessions then end, as before)
    return try? JSONDecoder().decode(CoreSetup.LineStateDoc.self, from: data)
  }

  // ---- what each store and key is for (router/storedocs.go): names, writers, explanations; never values ----
  // ---- a store's earlier versions and putting one back (core/history.go, router/storerestore.go) ----
  /// the core's signed list of a store's kept versions (checked: the core's key, this call's nonce, this store); once
  /// the kernel serves, the router's list (router/storeversions.go: each key's receipt is secrets', checked on restore)
  func storeVersions(_ store: String) async throws -> StoreVersionsDoc {
    let n = CoreCrypto.nonce()
    let body: [String: Any] = ["store": store, "nonce": n]
    let d: StoreVersionsDoc
    if try await kernelKeepsStores() {
      d = try await json("POST", "api/core/stores/versions", body, as: StoreVersionsDoc.self)
    } else {
      d = try CoreCrypto.decode(try await json("POST", "api/core/stores/versions", body, as: SignedDoc.self), by: try CoreTrust.key(),
                                as: StoreVersionsDoc.self, what: "the store's versions")
    }
    guard d.kind == "store-versions", d.nonce == n, d.store == store else { throw TrustError.stale("versions of \(store)") }
    return d
  }
  /// the core's signed begin document of putting version `seq` back, checked (each key put back has a writer the phone
  /// accepts); the payload is what the phone signs. Once the kernel serves: the router's plan (doc nil), each key put
  /// back with secrets' receipt of exactly that entry, checked against the pinned secrets
  func restoreBegin(_ store: String, seq: Int) async throws -> (doc: SignedDoc?, begin: RestoreBegin) {
    let body: [String: Any] = ["store": store, "seq": seq]
    if try await kernelKeepsStores() {
      let b = try await json("POST", "api/core/stores/restore/begin", body, as: RestoreBegin.self)
      guard b.replay == true else { throw TrustError.stale("restore of \(store)") }
      try Checks.replayReceipts(b, secretsKey: try KernelTrust.key())
      try Checks.restoreBegin(b, store: store, seq: seq, setupKey: try await setupKeyIfNeeded(b.put.map { Optional($0.writer) }))
      return (nil, b)
    }
    let doc = try await json("POST", "api/core/stores/restore/begin", body, as: SignedDoc.self)
    let b = try CoreCrypto.decode(doc, by: try CoreTrust.key(), as: RestoreBegin.self, what: "the restore")
    try Checks.restoreBegin(b, store: store, seq: seq, setupKey: try await setupKeyIfNeeded(b.put.map { Optional($0.writer) }))
    return (doc, b)
  }
  /// the kernel's restore: the router writes each entry back to secrets with its receipt (secrets checks it), then
  /// deletes the keys the version didn't have; the answer is checked against the plan
  func restoreReplay(_ b: RestoreBegin) async throws -> RestoreDone {
    struct Out: Decodable { let restored: RestoreDone }
    let out = try await json("POST", "api/stores/restore/finish", ["pending": b.pending], as: Out.self)
    let d = out.restored
    // (no version check: keys the router never saw written stay as they are, so the store may differ from version seq)
    guard d.kind == "store-restored", d.pending == b.pending, d.store == b.store, d.from == b.to.seq else { throw TrustError.stale("the restore of \(b.store)") }
    return d
  }
  /// the kernel's secrets keeps the stores (a box with no core): the router keeps their versions
  private func kernelKeepsStores() async throws -> Bool { (try? await kernelStatus())?.serves == true }
  /// the phone's signature over the begin document and its share of every key put back (in `b.es` order): the router
  /// writes the core's backups, then the core commits; the committed answer is checked
  func restoreFinish(_ b: RestoreBegin, signature: Data, shares: [Data]) async throws -> RestoreDone {
    guard shares.count == b.put.count else { throw TrustError.stale("restore of \(b.store)") }
    var m: [String: Any] = [:]
    for (p, x) in zip(b.put, shares) { m[p.key] = try CoreCrypto.sealShare(x, to: b.t) }
    struct Out: Decodable { let restored: SignedDoc }
    let out = try await json("POST", "api/stores/restore/finish", ["pending": b.pending, "signature": signature.base64EncodedString(), "shares": m], as: Out.self)
    let d = try CoreCrypto.decode(out.restored, by: try CoreTrust.key(), as: RestoreDone.self, what: "the restored answer")
    try Checks.restoreDone(d, begin: b)
    return d
  }

  func storeRows() async throws -> [StoreRowDTO] {
    struct L: Decodable { let stores: [StoreRowDTO] }
    return try await json("GET", "api/stores", as: L.self).stores
  }
  /// a store's about text (nil = unchanged) and its keys' explanations ("" removes one)
  func setStoreDocs(_ store: String, about: String?, keys: [String: String]) async throws {
    var body: [String: Any] = ["keys": keys]
    if let about { body["about"] = about }
    try await call("PUT", "api/stores/\(Self.escaped(store))/docs", body)
  }

  // ---- setting the core up: Reset and Recover ----
  /// the core's keys, the box key's signature over them and its signed state (the caller checks both: CoreSetup.check).
  /// Throws CoreNotRunning when there is no core to ask (its pod restarting, e.g. after a wipe: 503 {coreDown}; 502/504
  /// from the edge mean the same)
  /// next: the next core's (blue/green), through the same route with the header
  func identity(next: Bool = false) async throws -> CoreSetup.Identity {
    let (status, data) = try await raw("GET", "api/core/identity", nil, headers: Self.coreHeaders(next))
    if status == 503 || status == 502 || status == 504 { throw CoreNotRunning() }
    guard status == 200 else { throw Self.failure("GET", "api/core/identity", status, data) }
    return try JSONDecoder().decode(CoreSetup.Identity.self, from: data)
  }
  struct CoreNotRunning: Error {}
  /// POST api/core/claim; the answer must be that core's signed "claimed" — signed with the derived key when the claim
  /// brought a seed (`answeredBy`: the core the claim made, core/continuity.go)
  func claim(_ body: [String: Any], core: PublicKeys, answeredBy: String? = nil, next: Bool = false) async throws -> Int {
    let d = try CoreCrypto.decode(try await json("POST", "api/core/claim", body, as: SignedDoc.self, headers: Self.coreHeaders(next)), by: answeredBy ?? core.signingKey,
                                  as: KindDoc.self, what: "the core's answer")
    guard d.kind == "claimed" else { throw TrustError.stale("claim") }
    return d.stores ?? 0
  }
  /// POST api/core/wipe; the answer must be that core's signed "wiping" (it then ends; a new, empty core follows)
  func wipe(_ body: [String: Any], core: PublicKeys, next: Bool = false) async throws {
    let d = try CoreCrypto.decode(try await json("POST", "api/core/wipe", body, as: SignedDoc.self, headers: Self.coreHeaders(next)), by: core.signingKey,
                                  as: KindDoc.self, what: "the core's answer")
    guard d.kind == "wiping", d.core == core.signingKey else { throw TrustError.stale("wipe") }
  }
  /// the locked store backups, as the router reads them from the bucket (the caller checks and opens them)
  func backups() async throws -> [CoreSetup.BackupObject] {
    struct B: Decodable { let objects: [CoreSetup.BackupObject] }
    return try await json("GET", "api/backups", as: B.self).objects
  }
  /// the same with the bucket's name, for the offline copy (Settings → Encrypted backup)
  func backupDump() async throws -> (bucket: String, objects: [CoreSetup.BackupObject]) {
    struct B: Decodable { let bucket: String?; let objects: [CoreSetup.BackupObject] }
    let b = try await json("GET", "api/backups", as: B.self)
    return (b.bucket ?? "", b.objects)
  }

  // ---- approvals ----
  /// an approval with its signed challenge (checked by Checks.review against the pinned core key)
  /// imageSig: CI's signature over the image the challenge names (keys/ci.pub; Attestation)
  struct ApprovalDTO: Decodable {
    let id: String; let kind: String; let session: String?; let label: String?; let challenge: SignedDoc; let options: [String: String]?; let imageSig: String?
    /// an add-store on a kernel line: its second cert (router/kernelline.go)
    var earlier: [SignedDoc]? = nil
  }
  struct SessionDTO: Decodable { let id: String; let state: String; let createRequestId: String? }
  struct StateDTO: Decodable { let sessions: [SessionDTO]; let approvals: [ApprovalDTO] }
  struct RespondDTO: Decodable { let answer: SignedDoc; let session: String }
  func approvalsState() async throws -> StateDTO { try await json("GET", "api/state") }
  func approval(_ id: String) async throws -> ApprovalDTO? { try await approvalsState().approvals.first { $0.id == id } }
  func respond(_ id: String, signature: Data) async throws -> RespondDTO { try await json("POST", "api/approvals/\(id)/respond", ["signature": signature.base64EncodedString()]) }
  func reject(_ id: String) async throws { try await call("POST", "api/approvals/\(id)/reject") }

  // ---- grants (the session's cert is checked against the pinned core key) ----
  func sessionCert(_ session: String) async throws -> SessionCert {
    try Checks.cert(try await json("GET", "api/sessions/\(session)/cert", as: SignedDoc.self), coreKey: try CoreTrust.key())
  }
  /// the router's features and their public keys (the router owns every one of them)
  func holders() async throws -> [String: String] {
    struct H: Decodable { let holders: [String: String] }
    return try await json("GET", "api/holders", as: H.self).holders
  }
  func draftGrant(_ session: String, _ body: [String: Any]) async throws -> String {
    struct T: Decodable { let text: String }
    return try await json("POST", "api/sessions/\(session)/grants/draft", body, as: T.self).text
  }
  struct StoredGrantDTO: Decodable { let id: String; let holder: String; let kind: String; let ends: String }
  func addGrant(_ session: String, payload: String, sig: Data) async throws -> StoredGrantDTO {
    try await json("POST", "api/sessions/\(session)/grants", ["payload": payload, "sig": sig.base64EncodedString()])
  }

  // ---- messages into sessions, each delivered or denied by Deyao (router: per-message delivery approval) ----
  /// every pending (and recently approved or failed) message, and the per-kind rules in force
  func messages() async throws -> (messages: [PendingMessage], rules: [MessageRule]) {
    let j = try await get("api/messages")
    return (j["messages"].array.map(PendingMessage.init), j["rules"].array.map(MessageRule.init))
  }
  /// the exact text the phone signs to deliver these messages (all of one session, all pending); the caller checks it
  /// (Checks.reviewMessages) before signing
  func draftMessages(_ ids: [String]) async throws -> (text: String, session: String) {
    struct T: Decodable { let text: String; let session: String? }
    let t = try await json("POST", "api/messages/draft", ["ids": ids], as: T.self)
    return (t.text, t.session ?? "")
  }
  /// the signed batch: the router delivers each message (the machine checks the phone's signature); → the ids delivering
  @discardableResult
  func approveMessages(payload: String, sig: Data) async throws -> [String] {
    try await call("POST", "api/messages/approve", ["payload": payload, "sig": sig.base64EncodedString()])["delivering"].strings
  }
  /// no signature: the messages are dropped
  func denyMessages(_ ids: [String]) async throws { try await call("POST", "api/messages/deny", ["ids": ids]) }
  /// the text the phone signs for a per-kind rule (Checks.reviewMessageRule)
  func draftMessageRule(_ session: String, kind: String) async throws -> String {
    struct T: Decodable { let text: String }
    return try await json("POST", "api/sessions/\(session)/message-rules/draft", ["kind": kind], as: T.self).text
  }
  /// the signed rule; adding it also delivers the session's pending messages of that kind
  func addMessageRule(_ session: String, payload: String, sig: Data) async throws -> MessageRule {
    let j = try await call("POST", "api/sessions/\(session)/message-rules", ["payload": payload, "sig": sig.base64EncodedString()])
    return MessageRule(j: j)
  }
  func messageRules(_ session: String) async throws -> [MessageRule] {
    try await get("api/sessions/\(session)/message-rules")["rules"].array.map(MessageRule.init)
  }
  /// revoke: the router stops using it at once
  func removeMessageRule(_ id: String) async throws { try await call("DELETE", "api/message-rules/\(id)") }

  // ---- the Inbox (docs/API.md "Requests") ----
  /// one Inbox entry (GET api/requests/:id); nil when it is gone
  func inboxItem(_ id: String) async throws -> InboxItem? {
    let (status, data) = try await raw("GET", "api/requests/\(id)")
    if status == 404 { return nil }
    guard status == 200 else { throw Self.failure("GET", "api/requests/\(id)", status, data) }
    return InboxItem(j: JSON.parse(data))
  }
  func inboxDeny(_ id: String) async throws { try await call("DELETE", "api/requests/\(id)") }
  /// one batch with its items (GET api/requests/batches/:id); nil when it is gone
  func inboxBatch(_ id: String) async throws -> (batch: InboxBatch, items: [InboxItem])? {
    let (status, data) = try await raw("GET", "api/requests/batches/\(id)")
    if status == 404 { return nil }
    guard status == 200 else { throw Self.failure("GET", "api/requests/batches/\(id)", status, data) }
    let j = JSON.parse(data)
    return (InboxBatch(j: j["batch"]), j["items"].array.map(InboxItem.init))
  }
  /// Deny the whole batch: its requests leave, its approvals are rejected
  func inboxDenyBatch(_ id: String) async throws { try await call("DELETE", "api/requests/batches/\(id)") }
  func inboxDone(_ id: String) async { _ = try? await raw("POST", "api/requests/\(id)/done") }
  /// an api-call request (router/apicalls.go): the router runs the call now as Deyao → its outcome
  func inboxApproveCall(_ id: String) async throws -> JSON { try await call("POST", "api/requests/\(id)/approve") }
  /// an approved call's follow-ups (GET api/requests/calls/:id): the core requests it brought about and whether one
  /// may still come; nil when the router no longer keeps it
  func callFollowups(_ id: String) async throws -> JSON? {
    let (status, data) = try await raw("GET", "api/requests/calls/\(id)")
    if status == 404 { return nil }
    guard status == 200 else { throw Self.failure("GET", "api/requests/calls/\(id)", status, data) }
    return JSON.parse(data)
  }
}
