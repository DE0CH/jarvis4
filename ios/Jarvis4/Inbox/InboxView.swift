// The Inbox: everything waiting for this iPhone's Face ID that was asked for elsewhere (a session, the web page, Claude's
// setup session), and the router's approvals. Each row: the action (a fixed name per kind), what it is about (repo,
// feature, session: the router's record; the review page renders the exact facts from the signed content), who asked,
// when, the call, and the caller's reason in its own words.
// Review opens the page for it; Deny (a swipe or the page's button) drops it. An API call a session's actions asked
// for (router/apicalls.go) opens its own sheet (APICallReviewView): the call, who asked, the reason; Approve runs it as
// Deyao (no Face ID), and the sheet stays up for the approvals the call brings about.
import SwiftUI

struct InboxView: View {
  @Environment(AppModel.self) private var model

  var body: some View {
    NavigationStack {
      List {
        if !model.inboxBatches.isEmpty {
          Section {
            ForEach(model.inboxBatches) { b in BatchRow(b: b) }
          } header: {
            Text("Batches")
          } footer: {
            Text("One Face ID allows every item of a batch.")
          }
        }
        if !model.inboxMessageGroups.isEmpty {
          Section {
            ForEach(model.inboxMessageGroups) { g in MessageGroupRow(g: g) }
          } header: {
            Text("Messages")
          } footer: {
            Text("Nothing goes into the session until you deliver it with Face ID.")
          }
        }
        if !model.inboxLoose.isEmpty {
          Section {
            ForEach(model.inboxLoose) { it in InboxRow(it: it) }
          } header: {
            Text("Requests")
          } footer: {
            Text("Nothing happens until you allow it with Face ID.")
          }
        }
      }
      .overlay {
        if model.inboxCount == 0 {
          ContentUnavailableView("Nothing waiting for you", systemImage: "tray", description: Text("Requests from sessions, the web page and Claude show up here."))
            .accessibilityIdentifier("inbox-empty")
        }
      }
      .navigationTitle("Inbox")
      .refreshable { await model.refresh() }
    }
  }
}

private struct InboxRow: View {
  @Environment(AppModel.self) private var model
  let it: InboxItem

  var body: some View {
    Button(action: review) {
      VStack(alignment: .leading, spacing: 4) {
        HStack(alignment: .firstTextBaseline) {
          Text(action).font(.headline).foregroundStyle(Color.primary).accessibilityIdentifier("request-title-\(it.id)")
          Spacer()
          if let p = model.pending["q:" + it.id] { StatusPill(text: p, color: .orange, spinning: true) } else { StatusPill(text: kindName, color: .blue) }
        }
        if !details.isEmpty { Text(details.joined(separator: " · ")).font(.subheadline).foregroundStyle(Color.primary) }
        HStack(spacing: 12) {
          Label(it.callerText, systemImage: "person")
          if let c = it.created { Label(Fmt.ago(c), systemImage: "clock") }
          if let e = it.expires { Label(Fmt.when(e), systemImage: "hourglass") }
          if it.params["sensitive"].bool == true { StatusPill(text: "Sensitive", color: .red) }
        }
        .font(.footnote).foregroundStyle(Color.secondary).labelStyle(.titleAndIcon)
        Text(it.callLine).font(.caption.monospaced()).foregroundStyle(Color.secondary).lineLimit(2)
        if !it.explanation.isEmpty {
          Text("“\(it.explanation)”").font(.subheadline).italic().foregroundStyle(Color.secondary).lineLimit(2)
            .accessibilityIdentifier("request-reason-\(it.id)")
        }
      }
    }
    .accessibilityIdentifier("request-review-\(it.id)")
    .swipeActions {
      Button("Deny", role: .destructive) { Task { await model.deny(it) } }
    }
    .contextMenu {
      Button(it.kind == "peer-message" ? "Deliver" : "Review", systemImage: it.kind == "api-call" || it.kind == "peer-message" ? "arrow.up.forward.app" : "faceid", action: review)
      Button("Deny", systemImage: "xmark", role: .destructive) { Task { await model.deny(it) } }
    }
  }

  private var callTarget: String { "\(it.params["method"].string ?? "") \(it.params["path"].string ?? "")" }

  private func review() {
    // an upward peer message (router/peermsg.go): one tap delivers it, no Face ID (nothing is signed)
    if it.kind == "peer-message" {
      Task {
        let to = it.sessionName ?? it.session ?? "the session"
        guard await model.confirm("Deliver to “\(to)”?", "From \(it.callerText):\n\n\(it.params["text"].string ?? "")", action: "Deliver") else { return }
        await model.pendUntil("q:" + it.id, "Delivering…", 30, action: { _ = try await RouterClient.shared.inboxApproveCall(it.id) },
                              until: { m in !m.inbox.contains { $0.id == it.id } })
      }
      return
    }
    guard let r = SecureRequest.fromInbox(it) else { model.say("This request can't be opened here."); return }
    model.present(r) { [model] ok in if ok { model.settle(60) } }
  }

  private var kindName: String {
    ["repo-key": "Repo key", "grant": "Grant", "unlock": "Unlock", "new-session": "New session", "resume-upgrade": "Resume", "add-store": "Add a store", "kernel-source": "Kernel source", "kernel-add-store": "Add a store", "api-call": "API call", "restore": "Restore store", "peer-message": "Peer message", "message": "Message"][it.kind] ?? it.kind
  }
  /// the list's title: the core action (or the phone grant) the entry leads to, a fixed name per kind
  private var action: String { it.actionTitle }
  /// what it is about, as values (repo, store, feature, session, length): the router's record, unverified
  private var details: [String] {
    let p = it.params, who = it.sessionName ?? it.session
    switch it.kind {
    case "repo-key":
      let repo = p["repo"].string ?? ""
      return [repo, Checks.repoStore(repo)]
    case "grant":
      let d = p["days"].int ?? 0
      return [Holder.title(p["holder"].string ?? ""), who, d > 0 ? "\(d) d" : "\(p["minutes"].int ?? 10) min"].compactMap { $0 }
    case "add-store": return [it.j["options"]["store"].string, who].compactMap { $0 }
    case "api-call": return [it.does, callTarget, p["body"].string].compactMap { $0 }
    case "peer-message": return ["to " + (who ?? "?"), p["text"].string].compactMap { $0 }
    case "restore": return [p["store"].string, p["seq"].int.map { "Version \($0)" }].compactMap { $0 }
    default:
      if let r = it.j["options"]["restore"].text { return [r] }
      return [who].compactMap { $0 }
    }
  }
}

/// one session's pending messages: one entry listing each message's kind and sender; Review opens the page that lists
/// them all in full (MessageReviewView), Deny all drops them (nothing signed)
private struct MessageGroupRow: View {
  @Environment(AppModel.self) private var model
  let g: MessageGroup

  var body: some View {
    Button(action: review) {
      VStack(alignment: .leading, spacing: 4) {
        HStack(alignment: .firstTextBaseline) {
          Text("\(Fmt.plural(g.items.count, "message")) for “\(g.name)”").font(.headline).foregroundStyle(Color.primary)
            .accessibilityIdentifier("msg-group-title-\(g.session)")
          Spacer()
          if let p = model.pending["m:" + g.session] { StatusPill(text: p, color: .orange, spinning: true) } else { StatusPill(text: "Message", color: .blue) }
        }
        ForEach(g.items) { it in
          VStack(alignment: .leading, spacing: 2) {
            // the router's plain headline: "Message from session “X” to session “Y”"
            Text(it.explanation.isEmpty ? "Message from \(it.callerText)" : it.explanation).font(.subheadline).foregroundStyle(Color.primary)
            if let t = it.params["text"].text { Text(t).font(.footnote).foregroundStyle(Color.secondary).lineLimit(2) }
          }
        }
        HStack(spacing: 12) {
          if let c = g.items.compactMap(\.created).min() { Label(Fmt.ago(c), systemImage: "clock") }
          if let e = g.items.compactMap(\.expires).min() { Label(Fmt.when(e), systemImage: "hourglass") }
        }
        .font(.footnote).foregroundStyle(Color.secondary).labelStyle(.titleAndIcon)
      }
    }
    .accessibilityIdentifier("msg-group-\(g.session)")
    .swipeActions {
      Button("Deny all", role: .destructive) { Task { await denyAll() } }
    }
    .contextMenu {
      Button("Review", systemImage: "faceid", action: review)
      Button("Deny all", systemImage: "xmark", role: .destructive) { Task { await denyAll() } }
    }
  }

  private func review() { model.present(.messages(session: g.session)) { [model] ok in if ok { model.settle(60) } } }
  private func denyAll() async {
    let ids = g.items.map(\.id)
    await model.pendUntil("m:" + g.session, "Denying…", 30, action: { try await RouterClient.shared.denyMessages(ids) },
                          until: { m in !m.inbox.contains { ids.contains($0.id) } })
  }
}

/// a batch: one entry, its summary (the caller's words), its items' actions; Review opens the batch page
private struct BatchRow: View {
  @Environment(AppModel.self) private var model
  let b: InboxBatch

  var body: some View {
    Button(action: review) {
      VStack(alignment: .leading, spacing: 4) {
        HStack(alignment: .firstTextBaseline) {
          Text("\(b.items.count + b.preparing) requests").font(.headline).foregroundStyle(Color.primary).accessibilityIdentifier("batch-title-\(b.id)")
          Spacer()
          if let p = model.pending["b:" + b.id] { StatusPill(text: p, color: .orange, spinning: true) } else { StatusPill(text: "Batch", color: .blue) }
        }
        let names = model.batchItems(b).map(\.actionTitle)
        if !names.isEmpty { Text(names.joined(separator: " · ")).font(.subheadline).foregroundStyle(Color.primary).lineLimit(3) }
        HStack(spacing: 12) {
          Label(b.callerText, systemImage: "person")
          if let c = b.created { Label(Fmt.ago(c), systemImage: "clock") }
          if let e = b.expires { Label(Fmt.when(e), systemImage: "hourglass") }
        }
        .font(.footnote).foregroundStyle(Color.secondary).labelStyle(.titleAndIcon)
        if !b.summary.isEmpty {
          Text("“\(b.summary)”").font(.subheadline).italic().foregroundStyle(Color.secondary).lineLimit(3)
            .accessibilityIdentifier("batch-summary-\(b.id)")
        }
      }
    }
    .accessibilityIdentifier("batch-review-\(b.id)")
    .swipeActions {
      Button("Deny all", role: .destructive) { Task { await model.denyBatch(b) } }
    }
    .contextMenu {
      Button("Review", systemImage: "faceid", action: review)
      Button("Deny all", systemImage: "xmark", role: .destructive) { Task { await model.denyBatch(b) } }
    }
  }

  private func review() { model.present(.batch(id: b.id)) { [model] ok in if ok { model.settle(60) } } }
}
