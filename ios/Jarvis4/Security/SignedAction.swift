// "What you sign (exact)": the first of the three fields a request's review page shows (docs/DESIGN.md
// "Requests"). It is rendered here, in the app, from the very content the phone signs — the core's signed begin
// document, the core-signed challenge, the session's core-signed cert and the checked grant — never from the
// router's words, so a lying router can't make it say something other than what gets signed. It is a list of
// labelled facts (no sentences assembled from fields: docs/DESIGN.md "No prose assembled by code"); the page shows
// each as a row with the accessibility id `signed-<id>`. Foundation only: the interop test (ios/interop) renders it
// from the real core's documents too.
import Foundation

/// a repo a session asked for: its store comes into that session in the same approval (router repos.go, DECISIONS 182)
struct RepoInto: Equatable, Hashable {
  let session: String
  let label: String
  let store: String
}

/// one signed fact: a labelled value, shown as a row
struct SignedFact: Equatable, Identifiable {
  enum Style: Equatable {
    case plain
    /// an id, a digest, a key title: monospaced
    case code
    /// worth a second look (a sensitive store, bypass mode, a replaced key): drawn as a warning
    case warning
  }
  let id: String
  let label: String
  /// one value per line (a list of stores, repos, images)
  let value: String
  var style: Style = .plain
}

enum SignedAction {
  static func list(_ xs: [String]) -> String { xs.isEmpty ? "None" : xs.joined(separator: "\n") }
  static func yes(_ b: Bool) -> String { b ? "Yes" : "No" }
  /// the value of a fact by id (interop and tests)
  static func value(_ facts: [SignedFact], _ id: String) -> String? { facts.first { $0.id == id }?.value }

  /// a deploy key, from the core's signed deploy-key-begin document
  static func deployKey(_ b: DeployKeyBegin) -> [SignedFact] {
    var f: [SignedFact] = [
      .init(id: "kind", label: "Kind", value: "Core request"),
      .init(id: "action", label: "Action", value: b.action == "remove" ? "Remove deploy key" : "Add deploy key"),
      .init(id: "repo", label: "Repo", value: b.repo, style: .code),
      .init(id: "key-title", label: "Key on GitHub", value: b.title, style: .code),
    ]
    if b.action != "remove" { f.append(.init(id: "access", label: "Access", value: "Read and push")) }
    f.append(.init(id: "store", label: b.action == "remove" ? "Deletes store" : "Store", value: b.store, style: .code))
    f.append(.init(id: "sensitive", label: "Sensitive", value: yes(b.sensitive), style: b.sensitive ? .warning : .plain))
    if b.action != "remove" && b.replaces {
      f.append(.init(id: "replaces", label: "Replaces earlier key", value: "Yes", style: .warning))
    }
    f.append(.init(id: "token-store", label: "GitHub token from", value: b.tokenStore, style: .code))
    f.append(.init(id: "token-use", label: "Token use", value: "This request only"))
    return f
  }

  /// a repo a session asked for: the add-store this page signs under the same Face ID once the key is made (its
  /// challenge doesn't exist before the store does; it is checked to be exactly this before it is signed)
  static func repoInto(_ into: RepoInto, store: String) -> [SignedFact] {
    [.init(id: "then", label: "Then", value: "Add store \(store) to the session that asked", style: .warning),
     .init(id: "into-session", label: "Session", value: into.label == into.session ? into.session : "\(into.label) (\(into.session))"),
     .init(id: "into-checked", label: "Checked before signing", value: "An add-store of exactly \(store), continuing this session's line")]
  }

  /// the signed settings and one-time inputs, one row per key (what the machine takes: docs/DESIGN.md "Inputs");
  /// Checks.checkKnown refuses a challenge with a key this list has no row for
  static func inputs(_ r: Checks.Reviewed) -> [SignedFact] {
    var f: [SignedFact] = []
    if let c = r.config {
      let s = { (k: String) -> String in (c[k] as? String) ?? "" }
      if !s("label").isEmpty { f.append(.init(id: "title", label: "Title", value: s("label"))) }
      if !s("prompt").isEmpty { f.append(.init(id: "prompt", label: "First prompt", value: s("prompt"))) }
      if let repos = c["repos"] as? [String], !repos.isEmpty { f.append(.init(id: "repos", label: "Repos", value: list(repos), style: .code)) }
      if let cs = Checks.content(c), !cs.isEmpty { f.append(.init(id: "content", label: "Content stores", value: list(cs), style: .code)) }
      if !s("model").isEmpty { f.append(.init(id: "model", label: "Model", value: s("model"))) }
      if !s("claudeAccount").isEmpty { f.append(.init(id: "claude-account", label: "Claude account", value: s("claudeAccount"))) }
      if (c["oneShot"] as? Bool) == true { f.append(.init(id: "one-shot", label: "One-shot", value: "Yes")) }
      if (c["apiProxy"] as? Bool) == true { f.append(.init(id: "api-proxy", label: "API proxy log", value: "Yes")) }
      if let atts = Checks.attachments(c), !atts.isEmpty {
        f.append(.init(id: "images", label: "Images", value: list(atts.map { "\($0.name) · \($0.size) B · sha256 \($0.sha256.prefix(12))…" }), style: .code))
      }
      if let rs = c["restore"] as? [String: Any] {
        f.append(.init(id: "restore", label: "Restores machine", value: (rs["machine"] as? String) ?? "?", style: .code))
        f.append(.init(id: "restore-sha", label: "Snapshot sha256", value: String(((rs["sha256"] as? String) ?? "").prefix(12)) + "…", style: .code))
      }
      if let t = c["task"] as? [String: Any] {
        f.append(.init(id: "task", label: "Task", value: (t["name"] as? String) ?? ""))
        f.append(.init(id: "task-params", label: "Task parameters", value: Checks.compact(t["params"]), style: .code))
      }
    } else if r.kind == .newSession || r.kind == .resumeUpgrade {
      f.append(.init(id: "settings", label: "Settings in the cert", value: "None"))
    }
    if let o = r.once {
      if let p = o["prompt"] as? String, !p.isEmpty { f.append(.init(id: "once-prompt", label: "Resume prompt", value: p)) }
      if let m = o["rollback"] as? String, !m.isEmpty { f.append(.init(id: "once-rollback", label: "Roll back from", value: m, style: .warning)) }
    }
    return f
  }

  /// the session a fact list names, from a core-signed cert
  static func session(_ id: LineIdentity?, line: String? = nil) -> [SignedFact] {
    var f: [SignedFact] = [.init(id: "session", label: "Session", value: id?.label ?? "Untitled")]
    if let l = id?.line ?? line { f.append(.init(id: "line", label: "Line", value: l, style: .code)) }
    if id?.sensitive == true { f.append(.init(id: "session-sensitive", label: "Holds a sensitive store", value: "Yes", style: .warning)) }
    return f
  }

  /// a succession, from the core-signed challenge (Checks.review)
  /// `of`: the session the challenge continues, from its predecessor's core-signed cert (Checks.continues)
  static func approval(_ r: Checks.Reviewed, of id: LineIdentity? = nil) -> [SignedFact] {
    var f: [SignedFact] = [.init(id: "kind", label: "Kind", value: "Core request")]
    let action: String = switch r.kind {
    case .newSession: "New session"
    case .resumeUpgrade: "Continue on a new machine"
    case .addStore: "Add a store"
    case .other: "Sign a challenge"
    }
    f.append(.init(id: "action", label: "Action", value: action))
    if r.kind == .resumeUpgrade || r.kind == .addStore { f += session(id) }
    let sens = r.sensitive
    switch r.kind {
    case .addStore:
      let added = r.addedStore ?? ""
      f.append(.init(id: "store", label: "Store", value: added, style: .code))
      if sens.contains(added) { f.append(.init(id: "sensitive", label: "Sensitive", value: "Yes", style: .warning)) }
      f.append(.init(id: "machine", label: "Running machine", value: r.challenge.request.machine?.id ?? "", style: .code))
      f.append(.init(id: "keeps-keys", label: "Keeps its keys", value: "Yes"))
      f.append(.init(id: "stores", label: "Stores when asked", value: list(r.stores), style: .code))
    case .other:
      f.append(.init(id: "challenge", label: "Challenge kind", value: r.challenge.request.kind, style: .code))
      f.append(.init(id: "stores", label: "Stores", value: list(r.stores), style: .code))
      if !sens.isEmpty { f.append(.init(id: "sensitive", label: "Sensitive", value: list(sens), style: .warning)) }
    case .newSession, .resumeUpgrade:
      f.append(.init(id: "image", label: "Image", value: r.image, style: .code))
      f.append(.init(id: "stores", label: "Stores", value: list(r.stores), style: .code))
      if !sens.isEmpty { f.append(.init(id: "sensitive", label: "Sensitive", value: list(sens), style: .warning)) }
      f.append(.init(id: "harness", label: "Harness", value: r.harness))
      f.append(.init(id: "mode", label: "Permission mode", value: r.permissionMode, style: r.permissionMode == "bypass" ? .warning : .plain))
      f += inputs(r)
    }
    return f
  }

  /// unlocks: the stores the session's core-signed cert names that the core's signed list shows locked. scoped =
  /// the unlock is for this session's cert (then only it reads them and its pull locks them again); a standing unlock
  /// (no cert nonce to name) stays open to every session until locked.
  static func unlock(stores: [String], session id: LineIdentity?, scoped: Bool) -> [SignedFact] {
    var f: [SignedFact] = [
      .init(id: "kind", label: "Kind", value: "Core request"),
      .init(id: "action", label: "Action", value: stores.isEmpty ? "Nothing to unlock" : "Unlock stores"),
    ]
    f += session(id)
    if !stores.isEmpty { f += scope(stores, scoped: scoped, id: "stores", label: "Stores") }
    return f
  }

  /// the stores an approval also unlocks under its Face ID (for that one session; scoped as above)
  static func alsoUnlocks(_ stores: [String], scoped: Bool) -> [SignedFact] {
    stores.isEmpty ? [] : scope(stores, scoped: scoped, id: "unlocks", label: "Also unlocks")
  }

  private static func scope(_ stores: [String], scoped: Bool, id: String, label: String) -> [SignedFact] {
    [.init(id: id, label: label, value: list(stores), style: .code),
     .init(id: "unlock-scope", label: "Open to", value: scoped ? "This session only" : "Every session", style: scoped ? .plain : .warning),
     .init(id: "relock", label: "Locked again", value: scoped ? "When the machine has its secrets" : "When you lock it")]
  }

  /// a grant: signed by this iPhone (not the core) for the line in the session's core-signed cert; the router's draft
  /// is checked field for field against it before signing (Checks.reviewGrant). `minutes` nil = a standing rule.
  static func grant(feature: String, allows: String, minutes: Int?, until: Date, line: String, of id: LineIdentity?) -> [SignedFact] {
    var f: [SignedFact] = [
      .init(id: "kind", label: "Kind", value: "Phone grant"),
      .init(id: "feature", label: "Feature", value: feature),
      .init(id: "allows", label: "Allows", value: allows),
      .init(id: "runs-as", label: "Runs as", value: "The session's user"),
    ]
    f += session(id, line: line)
    if let minutes { f.append(.init(id: "duration", label: "Duration", value: minutes == 1 ? "1 minute" : "\(minutes) minutes")) }
    f.append(.init(id: "until", label: "Until", value: until.formatted(date: minutes == nil ? .abbreviated : .omitted, time: .shortened)))
    f.append(.init(id: "checked-by", label: "Checked by", value: "The session's machine"))
    return f
  }

  /// the request's call as one line: `POST /api/requests/repo/add {"repo":"DE0CH/claude-env"}`
  static func call(method: String, path: String, args: [String: Any]?) -> String {
    var s = "\(method) \(path)"
    if let args, !args.isEmpty, let d = try? JSONSerialization.data(withJSONObject: args, options: [.sortedKeys, .withoutEscapingSlashes]) {
      s += " " + String(decoding: d, as: UTF8.self)
    }
    return s
  }

  /// the keys of the page's own options that must equal the request's (so the request shown is the one this page
  /// acts on); "" = they match
  static func mismatch(page: [String: Any], request: [String: Any]) -> String {
    for k in ["approvalId", "action", "repo", "sessionId", "holder", "grantKind", "minutes", "store", "seq", "into"] {
      let a = page[k].map { "\($0)" } ?? "", b = request[k].map { "\($0)" } ?? ""
      if k == "repo" ? a.lowercased() != b.lowercased() : a != b { return k }
    }
    return ""
  }
}
