// Words and numbers as the app shows them: times relative to now, schedules, money, names of things.
import Foundation

enum Fmt {
  static let region: [String: String] = ["arn": "Stockholm", "fra": "Frankfurt", "ams": "Amsterdam", "lhr": "London", "cdg": "Paris", "waw": "Warsaw",
    "mad": "Madrid", "iad": "Virginia", "ord": "Chicago", "sjc": "San Jose", "lax": "Los Angeles", "sin": "Singapore", "nrt": "Tokyo",
    "hkg": "Hong Kong", "syd": "Sydney"]
  static let busyLabel: [String: String] = ["starting": "Starting…", "restarting": "Restarting…", "pausing": "Pausing…", "destroying": "Destroying…", "mode": "Switching mode…",
                                              "upgrading": "Upgrading…", "upgrade": "Upgrading…", "growing-disk": "Adding disk…", "disk": "Adding disk…", "account": "Switching account…"]
  /// the More disk job's steps (router/disk.go), as the busy label
  static let diskPhase: [String: String] = ["extending": "Adding disk…", "snapshotting": "Snapshotting…", "resuming": "Resuming…"]
  /// a Claude account switch's steps (router/accountswap.go), as the busy label
  static let accountPhase: [String: String] = ["starting": "Switching account…", "switching": "Switching account…", "taking the login": "Taking the login…",
                                               "checking the account": "Checking the account…", "Remote Control": "Bringing Remote Control back…",
                                               "restarting Claude": "Restarting Claude…", "delivering continue": "Typing “continue”…"]
  /// "Upgrade to Large (8 GB)"; past the named sizes, which are named by their memory ("16gb"), "Upgrade to 16 GB"
  /// (router/sizes.go: every next size doubles the memory)
  static func upgradeTitle(_ a: MemAlert) -> String {
    guard let size = a.nextSize else { return "Upgrade" }
    let gb = a.nextGB.map { "\($0) GB" } ?? size
    return size.hasSuffix("gb") ? "Upgrade to \(gb)" : "Upgrade to \(size.capitalized) (\(gb))"
  }

  /// "just now" / "5 min ago" / "3 h ago" / "2 d ago"
  static func ago(_ d: Date) -> String {
    let s = max(0, Date.now.timeIntervalSince(d))
    if s < 60 { return "just now" }
    if s < 3600 { return "\(Int(s / 60)) min ago" }
    if s < 86400 { return "\(Int(s / 3600)) h ago" }
    return "\(Int(s / 86400)) d ago"
  }
  /// "in 5 min" for the future, "5 min ago" for the past
  static func fromNow(_ d: Date) -> String {
    let s = d.timeIntervalSinceNow
    if s < 0 { return ago(d) }
    if s < 60 { return "in a moment" }
    if s < 3600 { return "in \(Int(s / 60)) min" }
    if s < 86400 { return "in \(Int(s / 3600)) h" }
    return "in \(Int(s / 86400)) d"
  }
  /// "at 07:52 (in 40 min)" / "Oct 12 07:52 (in 2 d)"
  static func when(_ d: Date) -> String {
    let today = Calendar.current.isDateInToday(d)
    let clock = d.formatted(date: .omitted, time: .shortened)
    let day = today ? "at \(clock)" : "\(d.formatted(.dateTime.month(.abbreviated).day())) \(clock)"
    let mins = Int((d.timeIntervalSinceNow / 60).rounded())
    let rel = mins < 1 ? "now" : mins < 120 ? "in \(mins) min" : mins < 48 * 60 ? "in \(mins / 60) h" : "in \(mins / 1440) d"
    return "\(day) (\(rel))"
  }
  /// "daily" / "every 6 h" / "every 3 d"
  static func every(_ sec: Int) -> String {
    if sec == 86400 { return "daily" }
    if sec == 604800 { return "weekly" }
    if sec % 86400 == 0 { return "every \(sec / 86400) d" }
    if sec % 3600 == 0 { return "every \(sec / 3600) h" }
    return "every \(sec / 60) min"
  }
  static func usd(_ n: Double) -> String { "USD " + n.formatted(.number.precision(.fractionLength(2))) }
  static func bytes(_ n: Int) -> String { n.formatted(.byteCount(style: .file)) }
  static func plural(_ n: Int, _ word: String) -> String { "\(n) \(word)\(n == 1 ? "" : "s")" }
  static func clip(_ t: String, _ n: Int = 90) -> String { t.count > n ? String(t.prefix(n)) + "…" : t }

  /// "2 subagents · 1 background shell" (the web's workersText says the same), "None" when nothing runs
  static func workers(subagents: Int, jobs: [String: Int]) -> String {
    let words: [String: (String, String)] = ["shell": ("background shell", "background shells"), "monitor": ("monitor", "monitors"),
                                             "workflow": ("workflow", "workflows"), "teammate": ("teammate", "teammates")]
    var parts = subagents > 0 ? ["\(subagents) \(subagents == 1 ? "subagent" : "subagents")"] : []
    for (t, n) in jobs.sorted(by: { $0.key < $1.key }) where n > 0 {
      let w = words[t] ?? ("\(t) job", "\(t) jobs")
      parts.append("\(n) \(n == 1 ? w.0 : w.1)")
    }
    return parts.isEmpty ? "None" : parts.joined(separator: " · ")
  }

  static func harness(_ h: String) -> String {
    if h.hasPrefix("task:") { return "Task “\(h.dropFirst(5))”" }
    return Harness.all.first { $0.id == h }?.title ?? h
  }
}

/// the harnesses a session can run (session image), as the New session page offers them
struct Harness: Identifiable, Equatable {
  let id: String, title: String, sub: String
  static let all = [
    Harness(id: "claude", title: "Claude Code", sub: "Claude subscription · Claude app"),
    Harness(id: "opencode", title: "OpenCode · OpenRouter", sub: "Paseo app + web UI"),
    Harness(id: "openclaw", title: "claw-code · OpenClaw", sub: "Claude subscription · OpenClaw app + Control UI"),
    Harness(id: "paseo-claude", title: "Claude Code · Paseo", sub: "Claude subscription · Paseo app + web UI"),
  ]
  /// what an approval page says for a signed harness (a task line names its template)
  static func name(_ h: String) -> String {
    if h.hasPrefix("task:") { return "Task script · \(h.dropFirst(5))" }
    return all.first { $0.id == h }?.title ?? h
  }
}

/// the router's features that may hold a grant (router/grants.go holderNames), in words
struct Holder: Identifiable, Equatable {
  let id: String, title: String, sub: String, symbol: String
  static let all = [
    Holder(id: "terminal", title: "Terminal", sub: "Read the session's screen and type into it", symbol: "terminal"),
    Holder(id: "status", title: "Status", sub: "Read the screen, press Escape on a prompt left waiting, answer the model-switch dialog", symbol: "waveform.path.ecg"),
    Holder(id: "login", title: "Login repair", sub: "Write fresh Claude credentials into the session and send “continue”", symbol: "key"),
    Holder(id: "archive", title: "Archive check", sub: "List uncommitted and unpushed work before a destroy", symbol: "archivebox"),
    Holder(id: "remote", title: "Remote page", sub: "Read the web UI's link and the pairing offer or gateway token (OpenCode, OpenClaw)", symbol: "link"),
  ]
  static func title(_ h: String) -> String { all.first { $0.id == h }?.title ?? h }
  static func sub(_ h: String) -> String { all.first { $0.id == h }?.sub ?? "a router feature" }
}
