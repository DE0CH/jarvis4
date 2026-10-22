// What a review sheet is asked to do. Each kind has its own page (Review/): the page reads what it shows from the
// core's signed documents (or, for a grant, the session's core-signed cert) and signs only that, under one Face ID.
// Opened by the app's own buttons, or from an Inbox entry (`inbox` set: the page then shows the three fields of
// Review/RequestReview.swift above its own content).
import Foundation

struct GrantAsk: Equatable, Hashable {
  let session: String
  let label: String
  let holder: String
  /// "grant" (minutes, at most 10) or "rule" (a standing rule until a date)
  let kind: String
  var minutes = 10
  var until: Date?
  static let ruleDays = 30
}

enum SecureRequest: Identifiable, Equatable, Hashable {
  case newSession
  case approval(id: String, inbox: String? = nil)
  case grant(GrantAsk, inbox: String? = nil)
  case unlock(session: String, label: String, inbox: String? = nil)
  case repoKey(action: String, repo: String, sensitive: Bool, inbox: String? = nil, into: RepoInto? = nil)
  /// a batch from the Inbox (router/batches.go): its items on one page, allowed under one Face ID
  case batch(id: String)
  /// a store put back to an earlier version (core/history.go)
  case restore(store: String, seq: Int, inbox: String? = nil)
  /// an API call a session's actions asked for (router/apicalls.go): its own sheet, which then follows the core
  /// requests the call brings about (APICallReviewView)
  case apiCall(id: String)
  /// a session's pending messages (router: per-message delivery approval): every one listed, delivered under one
  /// Face ID (or one by one), or denied (MessageReviewView)
  case messages(session: String)

  var id: String {
    switch self {
    case .newSession: "new-session"
    case .approval(let a, _): "approval-\(a)"
    case .grant(let g, _): "grant-\(g.session)-\(g.holder)-\(g.kind)"
    case .unlock(let s, _, _): "unlock-\(s)"
    case .repoKey(let a, let r, _, _, _): "repo-\(a)-\(r)"
    case .batch(let b): "batch-\(b)"
    case .restore(let st, let q, _): "restore-\(st)-\(q)"
    case .apiCall(let c): "api-call-\(c)"
    case .messages(let s): "messages-\(s)"
    }
  }
  var inboxId: String? {
    switch self {
    case .newSession, .batch, .messages: nil
    case .approval(_, let i), .grant(_, let i), .unlock(_, _, let i), .repoKey(_, _, _, let i, _), .restore(_, _, let i): i
    case .apiCall(let c): c
    }
  }
  /// what this page acts on, in the Inbox's option names: compared with the request's own (SignedAction.mismatch)
  var options: [String: Any] {
    switch self {
    case .newSession, .batch, .apiCall, .messages: return [:]
    case .approval(let a, _): return ["approvalId": a]
    case .grant(let g, _):
      var o: [String: Any] = ["sessionId": g.session, "holder": g.holder, "grantKind": g.kind]
      if g.kind == "grant" { o["minutes"] = g.minutes }
      return o
    case .unlock(let s, _, _): return ["sessionId": s]
    case .repoKey(let a, let r, _, _, let into):
      var o: [String: Any] = ["action": a, "repo": r]
      if let into { o["into"] = into.session }
      return o
    case .restore(let st, let q, _): return ["store": st, "seq": q]
    }
  }

  /// the page an Inbox entry opens (router/inbox.go requestItem / approvalItem: open {kind, options})
  static func fromInbox(_ it: InboxItem) -> SecureRequest? {
    let o = it.openOptions
    switch it.openKind {
    case "approval":
      return o["approvalId"].text.map { .approval(id: $0, inbox: it.id) }
    case "grant":
      guard let s = o["sessionId"].text, let h = o["holder"].text else { return nil }
      let rule = o["grantKind"].string == "rule"
      let g = GrantAsk(session: s, label: o["label"].text ?? s, holder: h, kind: rule ? "rule" : "grant",
                       minutes: o["minutes"].int ?? 10, until: rule ? o["until"].string?.isoDate : nil)
      return .grant(g, inbox: it.id)
    case "unlock":
      guard let s = o["sessionId"].text else { return nil }
      return .unlock(session: s, label: o["label"].text ?? s, inbox: it.id)
    case "repo-key":
      guard let r = o["repo"].text else { return nil }
      var into: RepoInto?
      if let s = o["into"].text, let st = o["store"].text { into = RepoInto(session: s, label: o["intoLabel"].text ?? s, store: st) }
      return .repoKey(action: o["action"].string == "remove" ? "remove" : "add", repo: r, sensitive: o["sensitive"].bool == true, inbox: it.id, into: into)
    case "restore":
      guard let st = o["store"].text, let q = o["seq"].int, q > 0 else { return nil }
      return .restore(store: st, seq: q, inbox: it.id)
    case "api-call":
      return .apiCall(id: it.id)
    case "message":
      guard let s = o["sessionId"].text ?? it.session else { return nil }
      return .messages(session: s)
    default:
      return nil
    }
  }
}
