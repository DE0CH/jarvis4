// The router's shapes (docs/API.md), read through JSON (Model/JSON.swift). Each is a thin view over the object the
// router sent: identity comes from the object's own id, so lists keep their rows across polls.
import Foundation

/// a session line (GET api/state `sessions`)
struct Session: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  var state: String { j["state"].string ?? "" }
  /// Resume brings it back: paused, or failed with no machine (a failed or cut-off start; router Resume)
  /// a failed session with a machine finishes its pause first (router Resume, DECISIONS 181); not one whose last
  /// machine left no snapshot (the router refuses: it would start empty — router/snapsafe.go)
  var resumable: Bool { (state == "paused" || state == "failed") && noSnapshot == nil }
  var status: String? { j["status"].text }
  var harness: String { j["harness"].text ?? "claude" }
  /// the Claude account it runs on (router/claudeaccounts.go), fixed when it was made
  var claudeAccount: String? { j["claudeAccount"].text }
  var model: String? { j["model"].text }
  var region: String? { j["region"].text }
  var guest: String? { j["guest"].text }
  var size: String? { j["size"].text }
  var image: String? { j["image"].text }
  var created: Date? { j["created"].string?.isoDate }
  var pausedAt: Date? { j["pausedAt"].string?.isoDate }
  var error: String? { j["error"].text }
  var permissionMode: String { j["permissionMode"].string == "bypass" ? "bypass" : "auto" }
  var oneShot: Bool { j["oneShot"].bool == true }
  var oneShotDone: Bool { j["oneShotDone"].bool == true }
  var authFailed: Bool { j["authFailed"].bool == true }
  var autoPause: Bool { j["autoPause"].string != "off" }
  var notifyIdle: Bool { j["notifyIdle"].string != "off" }
  var bgTasks: Int { j["bgTasks"].int ?? 0 }
  var pauseInMs: Double? { j["pauseInMs"].double }
  var needsGrant: String? { j["needsGrant"].text }
  /// messages for it waiting in the Inbox to be delivered or denied (router: per-message delivery approval)
  var pendingMessages: Int { j["pendingMessages"].int ?? 0 }
  var lockedStore: String? { j["lockedStore"].text }
  var waiting: String? { j["waiting"].text }
  var resumePrompt: String? { j["resumePrompt"].text }
  var discordChannel: String? { j["discordChannel"].text }
  var createRequestId: String? { j["createRequestId"].text }
  var wakeups: [Wakeup] { j["wakeups"].array.map(Wakeup.init) }
  var crons: [Cron] { j["crons"].array.map(Cron.init) }
  var hasSchedule: Bool { !wakeups.isEmpty || !crons.isEmpty }
  var isTaskLine: Bool { harness.hasPrefix("task:") }
  /// OpenCode and OpenClaw sessions aren't in the Claude app: their primary action is the Remote page
  var hasRemote: Bool { harness == "opencode" || harness == "openclaw" || harness == "paseo-claude" }
  /// what the Claude app calls it (router/discord.go sessionTitle): the app's title, a CLI name, the label, the AI title
  var title: String {
    for k in ["serverTitle", "userTitle", "label", "aiTitle", "title", "name"] { if let t = j[k].text { return t } }
    return id
  }
  /// the stores it was given, without the harness's own and the core's
  func stores(policy: [String: [String]]) -> [String] {
    var all = j["stores"].strings
    if all.isEmpty { all = (j["environment"].string ?? "").split(separator: ",").map(String.init) }
    let h = Set(policy[harness] ?? [])
    return all.filter { !h.contains($0) && $0 != StoreView.coreStore }
  }
  /// a memory-starvation episode the router is watching (absent once it is over)
  var memAlert: MemAlert? { j["memAlert"].object == nil ? nil : MemAlert(j: j["memAlert"]) }
  /// what a running session's harness has running besides itself (router/registry.go Workers, from Claude Code's
  /// hooks): subagents, and every other background job by Claude Code's type label; nil on an image from before
  var workers: (subagents: Int, jobs: [String: Int])? {
    guard j["workers"].object != nil else { return nil }
    var jobs: [String: Int] = [:]
    for (k, v) in j["workers"]["jobs"].object ?? [:] { if let n = v.int, n > 0 { jobs[k] = n } }
    return (j["workers"]["subagents"].int ?? 0, jobs)
  }
  /// the latest memory sample of a running machine
  var memory: (availMb: Int, totalMb: Int)? {
    guard let a = j["memory"]["availMb"].int, let t = j["memory"]["totalMb"].int, t > 0 else { return nil }
    return (a, t)
  }
  /// a low-disk episode the router is watching (router/disk.go; absent once it is over)
  var diskAlert: DiskAlert? { j["diskAlert"].object == nil ? nil : DiskAlert(j: j["diskAlert"]) }
  /// the latest disk sample of a running machine: its volume when it has one, else its root filesystem
  var disk: (availMb: Int, totalMb: Int, volume: Bool)? {
    guard let a = j["disk"]["availMb"].int, let t = j["disk"]["totalMb"].int, t > 0 else { return nil }
    return (a, t, j["disk"]["volume"].bool == true)
  }
  /// the volume size the line's next machine gets (0 = the core's default)
  var diskGB: Int { j["diskGb"].int ?? 0 }
  /// the line's last machine left no signed snapshot: Resume is refused (it would start empty)
  var noSnapshot: String? { j["noSnapshot"].text }
  /// the final snapshot failed and the machine (no volume) is kept: Pause again or Destroy anyway
  var snapshotFailed: String? { j["snapshotFailed"].text }
  /// the router's last restart / upgrade / account-switch job (kind, phase, error)
  var wakeKind: String? { j["wake"]["kind"].text }
  var wakePhase: String? { j["wake"]["phase"].text }
  var wakeError: String? { j["wake"]["error"].text }
  /// what the router is doing to it right now (its lifecycle lock, or a mode / restart job), seen on every device
  var serverBusy: String? {
    if j["busy"]["kind"].string == "growing-disk", j["wake"]["kind"].string == "disk", let p = j["wake"]["phase"].string, let l = Fmt.diskPhase[p] { return l }
    if j["busy"]["kind"].string == "account", j["wake"]["kind"].string == "account", let p = j["wake"]["phase"].string, let l = Fmt.accountPhase[p] { return l }
    if let k = j["busy"]["kind"].string { return Fmt.busyLabel[k] ?? "Working…" }
    if let k = j["wake"]["kind"].string, let p = j["wake"]["phase"].string, p != "done", p != "failed" {
      return (k == "account" ? Fmt.accountPhase[p] : nil) ?? Fmt.busyLabel[k] ?? "Working…"
    }
    return nil
  }
}

/// a memory-starvation episode (router memory watch): why, the memory now, and the size Upgrade moves it to
struct MemAlert: Equatable, Hashable {
  let j: JSON
  var since: Date? { j["since"].string?.isoDate }
  var reason: String { j["reason"].text ?? "memory is short" }
  var detail: String? { j["detail"].text }
  /// the size Upgrade moves to: always one (the memory doubles each step)
  var nextSize: String? { j["nextSize"].text }
  var nextGB: Int? { j["nextGb"].int }
  /// its Fly guest, "8×performance · 32 GB"
  var nextGuest: String? { j["nextGuest"].text }
}

/// a low-disk episode (router/disk.go): the disk now, and whether More disk can grow it
struct DiskAlert: Equatable, Hashable {
  let j: JSON
  var since: Date? { j["since"].string?.isoDate }
  var reason: String { j["reason"].text ?? "disk is short" }
  var detail: String? { j["detail"].text }
  var canGrow: Bool { j["canGrow"].bool == true }
  /// the volume size More disk moves to
  var nextGB: Int? { j["nextGb"].int }
  /// why it can't grow (a machine without a volume)
  var why: String? { j["why"].text }
}

struct Wakeup: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { name }
  var name: String { j["name"].string ?? "default" }
  var prompt: String { j["prompt"].string ?? "" }
  var at: Date? { j["at"].double.map { Date(timeIntervalSince1970: $0 / 1000) } ?? j["atIso"].string?.isoDate }
}

struct Cron: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { name }
  var name: String { j["name"].string ?? "" }
  var prompt: String { j["prompt"].string ?? "" }
  var everySeconds: Int { j["everySeconds"].int ?? 86400 }
  var tz: String? { j["tz"].text }
  var nextAt: Date? { j["nextAt"].double.map { Date(timeIntervalSince1970: $0 / 1000) } ?? j["nextAtIso"].string?.isoDate }
  var runs: Int { j["runs"].int ?? 0 }
  var until: Date? { j["untilIso"].string?.isoDate }
}

/// an approval the router holds (GET api/state `approvals`); the challenge is checked by Checks.review before anything
struct Approval: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  var kind: String { j["kind"].string ?? "" }
  var session: String? { j["session"].text }
}

/// an Inbox entry (router/inbox.go): a request waiting for the phone, or one of the router's approvals
struct InboxItem: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  var kind: String { j["kind"].string ?? "" }
  var isApproval: Bool { j["approval"].bool == true }
  var params: JSON { j["params"] }
  var session: String? { j["session"].text }
  var sessionName: String? { j["sessionName"].text }
  var callerText: String { j["callerText"].string ?? "someone" }
  var explanation: String { j["explanation"].string ?? "" }
  var created: Date? { j["created"].string?.isoDate }
  var expires: Date? { j["expires"].string?.isoDate }
  var openKind: String { j["open"]["kind"].string ?? "" }
  var openOptions: JSON { j["open"]["options"] }
  /// the batch it was filed in (router/batches.go)
  var batch: String? { j["batch"].text }
  /// api-call: what the call does, in words the router renders from the call (e.g. an account switch)
  var does: String? { j["does"].text }
  /// the call as one line: POST /api/requests/repo/add {"repo":"DE0CH/claude-env"}
  var callLine: String {
    let c = j["call"]
    guard let path = c["path"].text else { return "(no API call recorded)" }
    return SignedAction.call(method: c["method"].string ?? "", path: path, args: c["args"].object.map { $0.mapValues(\.any) })
  }
}

/// several Inbox items a caller filed together (router/batches.go): one Inbox entry, one review page, one Face ID
struct InboxBatch: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  /// the caller's words about the whole batch, unverified
  var summary: String { j["summary"].string ?? "" }
  var callerText: String { j["callerText"].string ?? "someone" }
  var items: [String] { j["items"].array.compactMap(\.text) }
  /// approvals still being made (a new session's challenge): Allow waits for them
  var preparing: Int { j["preparing"].int ?? 0 }
  var created: Date? { j["created"].string?.isoDate }
  var expires: Date? { j["expires"].string?.isoDate }
  var callLine: String {
    let c = j["call"]
    guard let path = c["path"].text else { return "(no API call recorded)" }
    return SignedAction.call(method: c["method"].string ?? "", path: path, args: c["args"].object.map { $0.mapValues(\.any) })
  }
}

/// a destroyed session on the Previous list (GET api/records)
struct Rec: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  var session: Session { Session(j: j) }
  var archive: JSON { j["archive"] }
  var hasArchive: Bool { !archive.isNull }
  /// an archive indexed by hand has no machine-signed snapshot: nothing Jarvis 4 can restore
  var restorable: Bool { archive["signer"].text != nil }
  var title: String { archive["title"].text ?? session.title }
  var destroyedAt: Date? { j["destroyedAt"].string?.isoDate }
  var restoredCount: Int { j["restored"].array.count }
  var lastRestored: Date? { j["restored"].array.last?["at"].string?.isoDate }
  var transcripts: Int { archive["transcripts"].array.count }
  var artifacts: Int { archive["artifacts"].int ?? 0 }
  var archiveError: String? { j["archiveError"].text }
  var last: TailMessage? { archive["last"].isNull ? nil : TailMessage(j: archive["last"]) }
}

struct TailMessage: Equatable, Hashable, Identifiable {
  let j: JSON
  var id: String { (j["at"].string ?? "") + role + text.prefix(32) }
  var role: String { j["role"].string ?? "assistant" }
  var text: String { j["text"].string ?? "" }
  var at: Date? { j["at"].string?.isoDate }
}

struct Grant: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  var holder: String { j["holder"].string ?? "" }
  var isRule: Bool { j["kind"].string == "rule" }
  var ends: Date? { j["ends"].string?.isoDate }
}

/// a message Jarvis wants to put into a session (a wakeup, a watchdog check-in, a peer's message, a resume prompt…),
/// waiting for Deyao to deliver it (signed by this phone, Face ID) or deny it. The router's record: what is signed is
/// checked against the router's draft (Checks.reviewMessages), never taken from here alone.
struct PendingMessage: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  var session: String { j["session"].string ?? "" }
  var sessionName: String? { j["sessionName"].text }
  /// the delivery kind (MessageKind)
  var kind: String { j["kind"].string ?? "" }
  var kindLabel: String { j["kindLabel"].text ?? MessageKind.label(kind) }
  /// the specific requester ("Jarvis's watchdog (the stall check)")
  var from: String { j["from"].text ?? "Jarvis 4" }
  /// the exact text that goes into the session
  var text: String { j["text"].string ?? "" }
  var note: String? { j["note"].text }
  var sha256: String { j["sha256"].string ?? "" }
  var created: Date? { j["created"].string?.isoDate }
  var expires: Date? { j["expires"].string?.isoDate }
  /// pending (waits for Deyao) | approved (signed, being delivered) | failed (approved but not delivered)
  var state: String { j["state"].string ?? "" }
  var isPending: Bool { state == "pending" }
  var error: String? { j["error"].text }
  /// a per-kind rule may be made for it (never for a peer's message or a resume prompt)
  var ruleable: Bool { j["ruleable"].bool == true && MessageKind.ruleable(kind) }
  var ruleText: String { j["ruleText"].text ?? "Always deliver \(kindLabel.lowercased()) messages to this session" }
}

/// a phone-signed per-kind rule: messages of this kind go into this session without asking
struct MessageRule: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  var session: String { j["session"].string ?? "" }
  var kind: String { j["kind"].string ?? "" }
  var kindLabel: String { j["kindLabel"].text ?? MessageKind.label(kind) }
  var text: String { j["text"].text ?? "Always deliver \(kindLabel.lowercased()) messages to this session" }
  var until: Date? { j["until"].string?.isoDate }
  var created: Date? { j["created"].string?.isoDate }
}

/// the delivery kinds a pending message can have, in words, and which may get a standing per-kind rule
enum MessageKind {
  static let labels: [String: String] = [
    "wakeup": "Wakeup", "cron": "Recurring wakeup", "watch": "Watch met", "watch-fail": "Watch gave up", "nudge": "Watchdog check-in",
    "continue": "Login “continue”", "upgraded": "Upgrade note", "lease-granted": "Lease granted", "lease-taken": "Lease taken over",
    "lease-back": "Lease handed back", "request-outcome": "Inbox outcome", "peer": "Peer message", "resume-prompt": "Resume prompt",
  ]
  /// never a rule: each of these is a message someone wrote, approved one by one
  static let neverRuled: Set<String> = ["peer", "resume-prompt"]
  static func label(_ k: String) -> String { labels[k] ?? k }
  static func ruleable(_ k: String) -> Bool { labels[k] != nil && !neverRuled.contains(k) }
}

struct RepoEntry: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { name }
  var name: String { j["name"].string ?? "" }
  var url: String { j["url"].string ?? "" }
  var repo: String { j["repo"].string ?? "" }
  var store: String { j["store"].string ?? "" }
  var sensitive: Bool { j["sensitive"].bool == true }
  var fingerprint: String? { j["fingerprint"].text }
}

struct GitHubRepo: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { fullName }
  var fullName: String { j["fullName"].string ?? "" }
  var htmlUrl: String { j["htmlUrl"].string ?? "" }
  var description: String? { j["description"].text }
  var language: String? { j["language"].text }
  var isPrivate: Bool { j["private"].bool == true }
  var isFork: Bool { j["fork"].bool == true }
  var archived: Bool { j["archived"].bool == true }
  var pushedAt: Date? { j["pushedAt"].string?.isoDate }
}

struct Machine: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  var name: String { j["name"].string ?? "" }
  var state: String { j["state"].string ?? "" }
  var region: String { j["region"].string ?? "" }
  var size: String { j["size"].string ?? "" }
  var guest: String { j["guest"].string ?? "" }
  var image: String { j["image"].string ?? "" }
  var created: Date? { j["created"].string?.isoDate }
  var sessionId: String? { j["sessionId"].text }
  var current: Bool { j["current"].bool == true }
  var routerUrl: String { j["routerUrl"].string ?? "" }
  var test: Bool { j["test"].bool == true }
  var noDestroy: String? { j["noDestroy"].text }
  /// what stands out about it ("" = nothing)
  var attention: String? { j["attention"].text }
  /// a Jarvis 1 session it belongs to (shown, never linked)
  var otherSession: String? { j["otherSession"].text }
}

/// a router list (sizes, models): id + label, a model also its harness
struct Choice: Identifiable, Equatable, Hashable {
  let id: String
  let label: String?
  let harness: String?
  init(j: JSON) { id = j["id"].string ?? ""; label = j["label"].text; harness = j["harness"].text }
}

// ---- tasks (docs/API.md "Tasks") ----
struct TaskField: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { name }
  var name: String { j["name"].string ?? "" }
  var label: String { j["label"].text ?? name }
  var type: String { j["type"].string ?? "text" }
  var required: Bool { j["required"].bool == true }
  var optionsFrom: String? { j["optionsFrom"].text }
  var help: String? { j["help"].text }
  var placeholder: String? { j["placeholder"].text }
  var defaultValue: JSON { j["default"] }
  /// the template's own options (a string or {value, label, sub})
  var options: [TaskOption] {
    j["options"].array.map { o in
      if let s = o.string { return TaskOption(value: s, label: s, sub: nil) }
      return TaskOption(value: o["value"].string ?? "", label: o["label"].text ?? o["value"].string ?? "", sub: o["sub"].text)
    }
  }
}
struct TaskOption: Identifiable, Equatable, Hashable { let value: String; let label: String; let sub: String?; var id: String { value } }

struct TaskTemplate: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { name }
  var name: String { j["name"].string ?? "" }
  var title: String { j["title"].text ?? name }
  var description: String? { j["description"].text }
  var stores: [String] { j["stores"].strings }
  var hasPrompt: Bool { j["prompt"].text != nil }
  var fields: [TaskField] { j["fields"].array.map(TaskField.init) }
  var error: String? { j["error"].text }
}

struct TaskRun: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { name }
  var name: String { j["name"].string ?? "" }
  var runId: String { j["id"].string ?? "" }
  var phase: String { j["phase"].string ?? "" }
  var active: Bool { ["queued", "starting", "running"].contains(phase) }
  var scheduled: Bool { j["trigger"].string == "schedule" }
  var upgrade: Bool { j["upgrade"].bool == true }
  var createdAt: Date? { j["createdAt"].string?.isoDate }
  var ranAt: Date? { j["ranAt"].string?.isoDate }
  var finishedAt: Date? { j["finishedAt"].string?.isoDate }
  var exitCode: Int? { j["exitCode"].int }
  var reason: String? { j["reason"].text }
  var waiting: String? { j["waiting"].text }
  /// the latest step and when: ("Finished", "5 min ago")
  var when: (label: String, value: String)? {
    if let d = finishedAt { return ("Finished", Fmt.ago(d)) }
    if let d = ranAt { return ("Started", Fmt.ago(d)) }
    if let d = createdAt { return ("Queued", Fmt.ago(d)) }
    return nil
  }
}

struct TaskInstance: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  var template: String { j["template"].string ?? "" }
  var name: String { j["name"].string ?? "" }
  var params: JSON { j["params"] }
  var size: String? { j["size"].text }
  var stores: [String] { j["stores"].strings }
  var session: String? { j["session"].text }
  var createdAt: Date? { j["createdAt"].string?.isoDate }
  var state: String { j["state"].string ?? "" }
  var detail: String? { j["detail"].text }
  var lastRun: TaskRun? { j["lastRun"].isNull ? nil : TaskRun(j: j["lastRun"]) }
  var activeRun: TaskRun? { j["activeRun"].isNull ? nil : TaskRun(j: j["activeRun"]) }
  var queued: Int { j["queued"].int ?? 0 }
  var schedules: Int { j["schedules"].int ?? 0 }
  /// the values as one line ("Message: hi · Count: 2")
  /// the task's parameters as (label, value) rows, in the template's field order
  func summary(_ t: TaskTemplate?) -> [(label: String, value: String)] {
    let fields: [(String, String, String)] = t.map { $0.fields.map { ($0.name, $0.label, $0.type) } }
      ?? (params.object ?? [:]).keys.sorted().map { ($0, $0, "text") }
    return fields.compactMap { name, label, type in
      let v = params[name]
      if v.isNull || v.string == "" || (v.object == nil && v.string == nil && v.array.isEmpty) { return nil }
      let s = type == "checkbox" ? (v.bool == true ? "yes" : "no") : (v.string ?? v.strings.joined(separator: ", "))
      return (label, s)
    }
  }
}

struct TaskSchedule: Identifiable, Equatable, Hashable {
  let j: JSON
  var id: String { j["id"].string ?? "" }
  var instance: String { j["instance"].string ?? "" }
  var time: String { j["time"].string ?? "09:00" }
  var tz: String { j["tz"].string ?? "UTC" }
  var enabled: Bool { j["enabled"].bool == true }
  var nextAt: Date? { j["nextAt"].double.map { Date(timeIntervalSince1970: $0 / 1000) } }
  var text: String { "Daily at \(time) · \(tz.replacing("_", with: " "))" }
}

struct TasksOverview: Equatable {
  var templates: [TaskTemplate] = []
  var instances: [TaskInstance] = []
  var schedules: [TaskSchedule] = []
  init() {}
  init(j: JSON) {
    templates = j["templates"].array.map(TaskTemplate.init)
    instances = j["instances"].array.map(TaskInstance.init)
    schedules = j["schedules"].array.map(TaskSchedule.init)
  }
}

/// one entry of a session's event stream (GET api/sessions/:id/events): a supervisor line, or a lifecycle operation's
/// start, router step, Fly entry or end
struct SessionEvent: Equatable, Hashable, Identifiable {
  let j: JSON
  var id: String { key }
  var key: String { j["key"].string ?? "" }
  var at: Date? { j["at"].string?.isoDate }
  /// supervisor | router | fly
  var source: String { j["source"].string ?? "" }
  var machine: String { j["machine"].string ?? "" }
  /// the operation's kind (pause, resume, …) when it belongs to one
  var op: String { j["op"].string ?? "" }
  /// start | end: the operation began / ended here
  var mark: String { j["mark"].string ?? "" }
  /// an end's state: done | failed | cut off
  var state: String { j["state"].string ?? "" }
  var text: String { j["text"].string ?? "" }
}
