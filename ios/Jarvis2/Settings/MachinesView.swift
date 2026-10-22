// Machines: every Fly machine and volume in every Fly org Jarvis can see (api/machines, router/flyorgs.go): this
// Jarvis's own app (jarvis4-sessions) with each machine's session or "No session", and the other apps read-only (an org
// read through Jarvis 1 says so). Whatever stands out is flagged in amber. Destroy only for a machine of this Jarvis's
// own app that belongs to no session; the router re-checks that and destroys it through the core's kill.
import SwiftUI

struct MachinesView: View {
  @Environment(AppModel.self) private var model

  private static let orgOrder = ["jarvis2-370", "kamyee", "personal"]
  private var orgs: [JSON] {
    model.machinesDoc["orgs"].array.sorted { a, b in
      let ia = Self.orgOrder.firstIndex(of: a["org"].string ?? "") ?? 99, ib = Self.orgOrder.firstIndex(of: b["org"].string ?? "") ?? 99
      return ia < ib
    }
  }

  var body: some View {
    let doc = model.machinesDoc
    List {
      if let e = model.machines.error { ErrorRow(text: e) }
      if model.machines.loaded {
        Section {
          let n = doc["attention"].int ?? 0
          if n > 0 {
            LabeledContent { Text(n, format: .number) } label: { Label("Stand out", systemImage: "exclamationmark.triangle.fill") }
              .foregroundStyle(.orange)
              .accessibilityElement(children: .combine).accessibilityIdentifier("machines-attention")
          } else {
            Label("Nothing stands out", systemImage: "checkmark.circle").foregroundStyle(.green)
              .accessibilityElement(children: .combine).accessibilityIdentifier("machines-attention")
          }
          let own = model.machines.items
          LabeledContent("Own machines", value: "\(own.count)")
          LabeledContent("With no session", value: "\(own.count { $0.sessionId == nil })")
          if let e = doc["configError"].text { ErrorRow(text: e) }
        } footer: {
          Text("A paused session has no machine.")
        }
        ForEach(Array(orgs.enumerated()), id: \.offset) { _, org in OrgSections(org: org) }
      }
    }
    .overlay { if !model.machines.loaded && model.machines.error == nil { ProgressView("Loading…") } }
    .navigationTitle("Machines")
    .refreshable { await model.loadMachines() }
    .task { while !Task.isCancelled { await model.loadMachines(); try? await Task.sleep(for: .seconds(15)) } }
  }
}

/// one org: a section per app (or one saying it has none, or its error)
private struct OrgSections: View {
  let org: JSON
  var body: some View {
    let name = org["org"].string ?? ""
    let via = org["via"].string ?? "fly"
    let apps = org["apps"].array
    if org["error"].text != nil || apps.isEmpty {
      Section {
        if let e = org["error"].text { ErrorRow(text: e) }
        else { Text("No apps").foregroundStyle(.secondary) }
      } header: { OrgHeader(org: name, via: via) }
    }
    ForEach(Array(apps.enumerated()), id: \.offset) { _, app in
      let own = app["own"].bool == true
      let machines = app["machines"].array.map(Machine.init)
      let volumes = app["volumes"].array
      Section {
        if let e = app["error"].text { ErrorRow(text: e) }
        ForEach(machines) { m in MachineRow(m: m, own: own) }
        ForEach(Array(volumes.enumerated()), id: \.offset) { _, v in VolumeRow(v: v) }
        if machines.isEmpty && volumes.isEmpty && app["error"].text == nil { Text("No machines or volumes").foregroundStyle(.secondary) }
      } header: {
        HStack {
          OrgHeader(org: name, via: via, app: app["app"].string)
          Spacer()
          StatusPill(text: own ? "this Jarvis" : "read-only", color: own ? .blue : .secondary)
        }
      } footer: {
        Text([app["label"].text ?? "Unused", Fmt.plural(machines.count, "machine"), Fmt.plural(volumes.count, "volume"), app["status"].text].compactMap { $0 }.joined(separator: " · "))
      }
      .accessibilityIdentifier("app-\(app["app"].string ?? "")")
    }
  }
}

private struct VolumeRow: View {
  let v: JSON
  var body: some View {
    VStack(alignment: .leading, spacing: 3) {
      HStack {
        Label(v["name"].text ?? v["id"].string ?? "", systemImage: "externaldrive").font(.headline)
        Spacer()
        StatusPill(text: v["state"].text ?? "volume", color: v["attachedTo"].text == nil ? .orange : .secondary)
      }
      Text([v["id"].string, v["sizeGb"].int.map { "\($0) GB" }, v["region"].text.map { Fmt.region[$0] ?? $0 }].compactMap { $0 }.joined(separator: " · "))
        .font(.footnote).foregroundStyle(.secondary)
      LabeledContent("Attached to", value: v["attachedTo"].text ?? "Nothing").font(.footnote)
      if let c = v["created"].string?.isoDate { LabeledContent("Created", value: Fmt.ago(c)).font(.footnote) }
      if let a = v["attention"].text { Label(a, systemImage: "exclamationmark.triangle").font(.footnote).foregroundStyle(.orange) }
    }
  }
}

private struct MachineRow: View {
  @Environment(AppModel.self) private var model
  let m: Machine
  let own: Bool
  private var canDestroy: Bool { own && m.sessionId == nil && m.noDestroy == nil }

  var body: some View {
    VStack(alignment: .leading, spacing: 3) {
      HStack {
        Text(m.id).font(.headline.monospaced())
        Spacer()
        if m.test { StatusPill(text: "test", color: .blue) }
        if let p = model.pending["machine:" + m.id] { StatusPill(text: p, color: .orange, spinning: true) }
        else { StatusPill(text: m.state.isEmpty ? "unknown" : m.state, color: m.state == "started" ? .green : ["starting", "created", "replacing"].contains(m.state) ? .orange : m.state == "failed" ? .red : .secondary) }
      }
      if let sid = m.sessionId {
        LabeledContent(m.current ? "Session" : "Earlier machine of", value: model.session(sid)?.title ?? sid).font(.subheadline)
          .accessibilityElement(children: .combine).accessibilityIdentifier("machine-session-\(m.id)")
      } else if let other = m.otherSession {
        LabeledContent("Jarvis 1 session", value: other).font(.subheadline)
      } else if own {
        Text("No session").font(.subheadline.weight(.medium)).foregroundStyle(.orange).accessibilityIdentifier("machine-orphan-\(m.id)")
      }
      if let a = m.attention { Label(a, systemImage: "exclamationmark.triangle").font(.footnote).foregroundStyle(.orange) }
      Text([Fmt.region[m.region].map { "\($0) (\(m.region))" } ?? m.region, m.size, m.guest].filter { !$0.isEmpty }.joined(separator: " · "))
        .font(.footnote).foregroundStyle(.secondary)
      LabeledContent("Created", value: m.created.map(Fmt.ago) ?? "Unknown").font(.footnote)
      if own { LabeledContent("Router", value: m.routerUrl.isEmpty ? "None" : URL(string: m.routerUrl)?.host() ?? m.routerUrl).font(.footnote) }
      Text(shortImage).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
      if own, m.sessionId == nil, let why = m.noDestroy { LabeledContent("No Destroy", value: why).font(.footnote).foregroundStyle(.secondary) }
    }
    .accessibilityElement(children: .contain)
    .accessibilityIdentifier("machine-\(m.id)")
    .swipeActions {
      if canDestroy { Button("Destroy", systemImage: "trash", role: .destructive) { Task { await destroy() } } }
    }
    .contextMenu {
      if canDestroy { Button("Destroy", systemImage: "trash", role: .destructive) { Task { await destroy() } } }
    }
  }
  private var shortImage: String {
    var s = m.image.replacing("ghcr.io/de0ch/", with: "")
    if let r = s.range(of: "@sha256:"), s.distance(from: r.upperBound, to: s.endIndex) > 12 { s = String(s[..<s.index(r.upperBound, offsetBy: 12)]) + "…" }
    return s.isEmpty ? "no image" : s
  }
  private func destroy() async {
    await model.exclusive("machine:" + m.id) {
      guard await model.confirm("Destroy machine \(m.id)?", "Its disk goes too; nothing is archived.", action: "Destroy machine", destructive: true) else { return }
      model.pend("machine:" + m.id, "Destroying…")
      defer { model.pend("machine:" + m.id, nil) }
      do {
        try await RouterClient.shared.call("POST", "api/machines/\(m.id)/destroy")
        for _ in 0..<20 { await model.loadMachines(); if !model.machines.items.contains(where: { $0.id == m.id }) { break }; try? await Task.sleep(for: .seconds(1.5)) }
      } catch { model.fail(error, "Could not destroy: ") }
    }
  }
}

/// a section header naming the org (and how it is read, when not directly) and the app
private struct OrgHeader: View {
  let org: String
  let via: String
  var app: String?
  var body: some View {
    HStack(spacing: 6) {
      Text(org)
      if via != "fly" { StatusPill(text: "via " + via) }
      if let app { Text(app).monospaced() }
    }
  }
}
