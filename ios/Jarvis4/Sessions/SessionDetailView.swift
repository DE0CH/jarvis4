// One session: its status, what waits on it (a grant, messages to deliver, a locked store, a queued prompt, schedules),
// its message rules (Remove), its details, and
// every action Jarvis 1's card had (Terminal or Remote, Pause / Resume, Transcript, Grants, Schedules, the switches,
// the Log (the supervisor's lines and the lifecycle operations in one stream, LogViews.swift),
// the permission mode, Resume with the latest image, Destroy).
import SwiftUI

enum SessionRoute: Hashable { case terminal, remote, transcript, grants, schedules, log }

struct SessionDetailView: View {
  @Environment(AppModel.self) private var model
  let id: String

  var body: some View {
    if let m = model.session(id) {
      SessionDetailList(m: m)
        .navigationTitle(m.title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
          ToolbarItem(placement: .primaryAction) {
            if m.state == "started" && m.hasRemote {
              NavigationLink(value: SessionRoute.remote) { Label("Remote", systemImage: "link") }.accessibilityIdentifier("remote-\(m.id)")
            } else if m.state == "started" || m.state == "initialising" {
              NavigationLink(value: SessionRoute.terminal) { Label("Terminal", systemImage: "terminal") }.accessibilityIdentifier("term-\(m.id)")
            }
          }
          ToolbarItem(placement: .topBarTrailing) {
            Menu("More", systemImage: "ellipsis.circle") { SessionMenu(m: m) }.accessibilityIdentifier("more-\(m.id)")
          }
        }
        .navigationDestination(for: SessionRoute.self) { r in
          switch r {
          case .terminal: TerminalView(sessionId: m.id, title: m.title)
          case .remote: RemoteView(sessionId: m.id, title: m.title)
          case .transcript: TranscriptView(title: m.title, noteLabel: "Paused", noteValue: m.pausedAt.map(Fmt.ago) ?? "", path: "api/sessions/\(m.id)/tail",
                                           actionTitle: "Resume", onAction: { Task { await model.resume(m.id) } })
          case .grants: GrantsView(sessionId: m.id)
          case .schedules: SchedulesView(sessionId: m.id)
          case .log: SessionLogView(sessionId: m.id, title: m.title)
          }
        }
      .task(id: id) {
        // remember which line this session id is (LinePins), so a later review page can't be handed another's cert
        if CoreTrust.pinned != nil, let c = try? await RouterClient.shared.sessionCert(id) { try? LinePins.check(session: id, line: c.line) }
      }
    } else {
      ContentUnavailableView("Session gone", systemImage: "rectangle.stack.badge.minus", description: Text("It was destroyed or isn't listed any more."))
    }
  }
}

private struct SessionDetailList: View {
  @Environment(AppModel.self) private var model
  let m: Session

  var body: some View {
    let busy = model.pending["s:" + m.id] ?? m.serverBusy
    let p = m.pill
    List {
      Section {
        HStack {
          if let busy { StatusPill(text: busy.lowercased(), color: .orange, spinning: true) } else { StatusPill(text: p.text, color: p.color, spinning: p.spin) }
          if m.permissionMode == "bypass" { StatusPill(text: "skip perms", color: .red) }
          if m.oneShot { StatusPill(text: "one-shot") }
          if m.state != "paused" && m.hasSchedule { StatusPill(text: "scheduled", color: .blue) }
        }
        .accessibilityIdentifier("status-\(m.id)")
        if let info = autoPauseInfo { LabeledContent(info.label, value: info.value).accessibilityIdentifier("autopause-\(m.id)") }
        if m.authFailed { ErrorRow(text: "Claude login failed") }
        if let e = m.error { ErrorRow(text: e, id: "session-error") }
        if busy == nil, m.wakeKind == "account", m.wakePhase == "failed" { ErrorRow(text: "Account switch failed: " + (m.wakeError ?? "no reason given"), id: "account-failed") }
        if let rp = m.resumePrompt {
          VStack(alignment: .leading, spacing: 2) {
            Label(m.state == "paused" ? "Queued for the next resume" : "Queued until it is up", systemImage: "text.bubble").font(.footnote).foregroundStyle(.secondary)
            Text(Fmt.clip(rp, 200)).font(.subheadline)
          }
          .accessibilityElement(children: .combine)
        }
      }

      if let a = m.memAlert { MemAlertSection(m: m, a: a, busy: busy) }
      if let a = m.diskAlert { DiskAlertSection(m: m, a: a, busy: busy) }
      if m.snapshotFailed != nil || m.noSnapshot != nil { SnapshotProblemSection(m: m, busy: busy) }

      if let h = m.needsGrant {
        Section {
          LabeledContent("Feature", value: Holder.title(h)).accessibilityIdentifier("turned-away-\(m.id)")
          LabeledContent("Allows", value: Holder.sub(h))
          LabeledContent("Why", value: "The session holds a sensitive store, so Jarvis can't do this without your approval.")
          Button("Allow for 10 minutes", systemImage: "checkmark.shield") { model.requestGrant(m.id, m.title, holder: h) }
            .accessibilityIdentifier("grant-\(m.id)")
          Button("Make a standing rule", systemImage: "calendar.badge.clock") { model.requestGrant(m.id, m.title, holder: h, rule: true) }
            .accessibilityIdentifier("rule-\(m.id)")
        } header: { Label("Needs your approval", systemImage: "hand.raised") }
      }
      if m.pendingMessages > 0 {
        Section {
          LabeledContent("Waiting", value: Fmt.plural(m.pendingMessages, "message")).accessibilityIdentifier("msg-count-\(m.id)")
          ForEach(model.messagesWaiting(for: m.id)) { pm in
            VStack(alignment: .leading, spacing: 2) {
              Text("\(pm.kindLabel) · \(pm.from)").font(.subheadline)
              Text(Fmt.clip(pm.text, 140)).font(.footnote).foregroundStyle(.secondary)
            }
            .accessibilityElement(children: .combine)
          }
          Button("Review…", systemImage: "faceid") { model.present(.messages(session: m.id)) { [model] ok in if ok { model.settle(60) } } }
            .accessibilityIdentifier("msg-review-\(m.id)")
        } header: { Label("Messages waiting for you", systemImage: "envelope.badge") } footer: {
          Text("Nothing goes into the session until you deliver it.")
        }
      }
      let rules = model.rules(for: m.id)
      if !rules.isEmpty {
        Section {
          ForEach(rules) { r in
            HStack {
              VStack(alignment: .leading, spacing: 2) {
                Text(r.text).font(.subheadline)
                if let u = r.until { Text("Until \(u.formatted(date: .abbreviated, time: .omitted))").font(.footnote).foregroundStyle(.secondary) }
              }
              .accessibilityElement(children: .combine)
              .accessibilityIdentifier("rule-row-\(r.kind)")
              Spacer()
              PendingButton(key: "mr:" + r.id, title: "Remove", role: .destructive) { await removeRule(r) }
                .buttonStyle(.borderless)
                .accessibilityIdentifier("rule-remove-\(r.kind)")
            }
          }
        } header: { Label("Message rules", systemImage: "checkmark.seal") }
      }
      if let lock = m.lockedStore {
        Section {
          LabeledContent("Store"){ Text(lock).font(.body.monospaced()) }
          Button("Unlock…", systemImage: "lock.open") { model.present(.unlock(session: m.id, label: m.title)) }
            .accessibilityIdentifier("unlock-\(m.id)")
        } header: { Label("Waiting on a locked store", systemImage: "lock") }
      }
      if m.hasSchedule {
        Section("Wakes by itself") {
          ForEach(m.wakeups) { w in
            WakeRow(symbol: "alarm", when: w.at.map(Fmt.when) ?? "", name: w.name == "default" ? nil : w.name, prompt: w.prompt)
          }
          ForEach(m.crons) { c in
            WakeRow(symbol: "repeat", when: Fmt.every(c.everySeconds), name: c.name, prompt: c.prompt, next: c.nextAt.map(Fmt.when))
          }
        }
      }

      Section {
        if busy == nil {
          if m.state == "started" || m.state == "initialising" {
            Button("Pause", systemImage: "pause.circle") { Task { await model.pause(m.id) } }.accessibilityIdentifier("pause-\(m.id)")
          }
          if m.resumable {
            Button("Resume", systemImage: "play.circle") { Task { await model.resume(m.id) } }.accessibilityIdentifier("resume-\(m.id)")
          }
          if m.state == "paused" {
            NavigationLink(value: SessionRoute.transcript) { Label("Transcript", systemImage: "text.alignleft") }.accessibilityIdentifier("tail-\(m.id)")
          }
        }
        // read only, kept for the session's life: beside the terminal, in every state
        NavigationLink(value: SessionRoute.log) { Label("Log", systemImage: "doc.plaintext") }.accessibilityIdentifier("log-\(m.id)")
        if !["approval", "destroying"].contains(m.state) {
          NavigationLink(value: SessionRoute.grants) { Label("Grants", systemImage: "checkmark.shield") }.accessibilityIdentifier("grants-\(m.id)")
          NavigationLink(value: SessionRoute.schedules) { Label("Schedules", systemImage: "alarm") }.accessibilityIdentifier("schedules-\(m.id)")
        }
        if let ch = m.discordChannel, let u = URL(string: "https://discord.com/channels/1482150592414486748/\(ch)") {
          Link(destination: u) { Label("Discord channel", systemImage: "bubble.left.and.bubble.right") }
        }
      }

      Section("Details") {
        let own = m.stores(policy: model.policy)
        LabeledContent("Stores", value: own.isEmpty ? "none" : own.joined(separator: ", "))
        LabeledContent("Harness", value: Fmt.harness(m.harness))
        if let acct = m.claudeAccount { LabeledContent("Claude account", value: acct).accessibilityIdentifier("session-claude-account") }
        if let mo = m.model { LabeledContent("Model", value: model.models.first { $0.id == mo }?.label ?? mo) }
        LabeledContent("Permission mode", value: m.permissionMode == "bypass" ? "bypass (no prompts)" : "auto")
        if let r = m.region { LabeledContent("Region", value: Fmt.region[r] ?? r) }
        let machine = [m.size, m.guest].compactMap { $0 }.joined(separator: " · ")
        if !machine.isEmpty { LabeledContent("Machine", value: machine) }
        if m.state == "started", let w = m.workers {
          LabeledContent("Workers", value: Fmt.workers(subagents: w.subagents, jobs: w.jobs))
            .accessibilityIdentifier("workers-\(m.id)")
        }
        if m.state == "started", let mem = m.memory {
          LabeledContent("Memory", value: "\(Fmt.bytes(mem.availMb * 1_048_576)) free of \(Fmt.bytes(mem.totalMb * 1_048_576))")
            .accessibilityIdentifier("memory-\(m.id)")
        }
        if m.state == "started", let d = m.disk {
          LabeledContent(d.volume ? "Disk (volume)" : "Disk", value: "\(Fmt.bytes(d.availMb * 1_048_576)) free of \(Fmt.bytes(d.totalMb * 1_048_576))")
            .accessibilityIdentifier("disk-\(m.id)")
        }
        if m.diskGB > 0 { LabeledContent("Next machine's disk", value: "\(m.diskGB) GB") }
        if let c = m.created { LabeledContent("Created", value: Fmt.ago(c)) }
        if m.state == "paused", let pa = m.pausedAt { LabeledContent("Paused", value: Fmt.ago(pa)) }
        LabeledContent("Session id") { Text(m.id).font(.footnote.monospaced()).textSelection(.enabled) }
      }

      Section {
        Button("Destroy", systemImage: "trash", role: .destructive) { Task { await model.destroy(m.id) } }
          .disabled(busy != nil || m.state == "destroying")
          .accessibilityIdentifier("destroy-\(m.id)")
      }
    }
    .refreshable { await model.refresh() }
  }

  /// revoke a message rule: the router stops using it at once
  private func removeRule(_ r: MessageRule) async {
    guard await model.confirm("Remove the rule?", "\(r.text). Messages of this kind wait for you again.", action: "Remove", destructive: true) else { return }
    await model.pendUntil("mr:" + r.id, "Removing…", 30, action: { try await RouterClient.shared.removeMessageRule(r.id) },
                          until: { m in !m.messageRules.contains { $0.id == r.id } })
  }

  /// the auto-pause line: off / counting down / generic; a paused session explains Resume
  /// what happens to it when idle, as one labelled row
  private var autoPauseInfo: (label: String, value: String)? {
    if m.oneShot { return m.state == "started" ? ("When done", "Archived and destroyed") : nil }
    guard m.state == "started" else { return nil }
    if !m.autoPause { return ("Auto-pause", "Off") }
    if let ms = m.pauseInMs { return ("Auto-pause", "In \(max(1, Int((ms / 60000).rounded()))) min") }
    return ("Auto-pause", "After 1 h idle")
  }
}

/// a memory-starvation episode: why, the memory now, and Upgrade (the next size up, same conversation)
private struct MemAlertSection: View {
  @Environment(AppModel.self) private var model
  let m: Session
  let a: MemAlert
  let busy: String?

  var body: some View {
    Section {
      Label("Running out of memory", systemImage: "exclamationmark.triangle.fill")
        .foregroundStyle(.red).font(.subheadline.weight(.semibold))
        .accessibilityIdentifier("memalert-\(m.id)")
      LabeledContent("Why", value: a.reason)
      if let d = a.detail { LabeledContent("Now", value: d) }
      if let since = a.since { LabeledContent("Since", value: Fmt.ago(since)) }
      if busy == nil, m.wakeKind == "upgrade", m.wakePhase == "failed" {
        ErrorRow(text: "Upgrade failed" + (m.wakeError.map { ": \($0)" } ?? ""), id: "upgrade-error-\(m.id)")
      }
      if a.nextSize != nil, busy == nil {
        Button(Fmt.upgradeTitle(a), systemImage: "arrow.up.circle") { Task { await model.upgrade(m.id) } }
          .tint(.red)
          .accessibilityIdentifier("upgrade-\(m.id)")
      }
    } header: {
      Label("Memory", systemImage: "memorychip")
    } footer: {
      if a.nextSize != nil { Text("Upgrade stops Claude and everything it runs, then brings the same conversation back on the bigger machine" + (a.nextGuest.map { " (\($0))" } ?? "") + ".") }
    }
  }
}

/// a low-disk episode: the disk now, and More disk (the volume twice as big, same conversation)
private struct DiskAlertSection: View {
  @Environment(AppModel.self) private var model
  let m: Session
  let a: DiskAlert
  let busy: String?

  var body: some View {
    Section {
      Label("Running out of disk", systemImage: "exclamationmark.triangle.fill")
        .foregroundStyle(.red).font(.subheadline.weight(.semibold))
        .accessibilityIdentifier("diskalert-\(m.id)")
      LabeledContent("Why", value: a.reason)
      if let d = a.detail { LabeledContent("Now", value: d) }
      if let since = a.since { LabeledContent("Since", value: Fmt.ago(since)) }
      if busy == nil, m.wakeKind == "disk", m.wakePhase == "failed" {
        ErrorRow(text: "More disk failed" + (m.wakeError.map { ": \($0)" } ?? ""), id: "disk-error-\(m.id)")
      }
      if a.canGrow, let gb = a.nextGB, busy == nil, m.state == "started" {
        Button("More disk (\(gb) GB)", systemImage: "externaldrive.badge.plus") { Task { await model.moreDisk(m.id) } }
          .tint(.red)
          .accessibilityIdentifier("moredisk-\(m.id)")
      } else if let why = a.why {
        LabeledContent("More disk", value: why)
      }
    } header: {
      Label("Disk", systemImage: "internaldrive")
    }
  }
}

/// the final snapshot failed (machine kept), or the line's last machine left none (Resume refused)
private struct SnapshotProblemSection: View {
  @Environment(AppModel.self) private var model
  let m: Session
  let busy: String?

  var body: some View {
    Section {
      if let f = m.snapshotFailed {
        ErrorRow(text: f, id: "snapshot-failed-\(m.id)")
        LabeledContent("Machine", value: "Kept")
        if busy == nil, m.state == "failed" {
          Button("Pause again", systemImage: "pause.circle") { Task { await model.pause(m.id) } }
            .accessibilityIdentifier("pause-again-\(m.id)")
        }
      }
      if let n = m.noSnapshot {
        ErrorRow(text: n, id: "no-snapshot-\(m.id)")
        LabeledContent("Resume", value: "Refused")
      }
    } header: {
      Label(m.snapshotFailed != nil ? "Final snapshot failed" : "No snapshot", systemImage: "externaldrive.badge.exclamationmark")
        .foregroundStyle(.red)
    }
  }
}
