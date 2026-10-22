// A store's earlier versions, from the core's signed list (core/history.go; checked against the pinned core key): what
// made each one and its key names, never values. Restore… opens the review page, which shows exactly what the core
// will change and signs it with Face ID.
import SwiftUI

struct StoreVersionsView: View {
  @Environment(AppModel.self) private var model
  let store: String
  @State private var doc: StoreVersionsDoc?
  @State private var error: String?

  var body: some View {
    List {
      if let error { ErrorRow(text: error, id: "versions-error") }
      if let doc {
        if doc.versions.isEmpty { Text("None kept").foregroundStyle(.secondary) }
        ForEach(doc.versions) { v in
          VersionRow(v: v, current: v.version == doc.current) {
            model.present(.restore(store: store, seq: v.seq)) { ok in if ok { Task { await load() } } }
          }
        }
      } else if error == nil {
        ProgressView()
      }
    }
    .navigationTitle("Versions")
    .navigationBarTitleDisplayMode(.inline)
    .refreshable { await load() }
    .task { await load() }
  }

  private func load() async {
    do { doc = try await RouterClient.shared.storeVersions(store); error = nil } catch { self.error = errText(error) }
  }
}

private struct VersionRow: View {
  let v: StoreVersionsDoc.Version
  let current: Bool
  let restore: () -> Void

  private var cause: String {
    switch v.cause.kind {
    case "recover": "Recover"
    case "created": "Created"
    case "write": "Key written"
    case "delete": "Key deleted"
    case "deploy-key": "Deploy key"
    case "restore": "Restore"
    default: v.cause.kind
    }
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 4) {
      HStack(spacing: 6) {
        Text("Version \(v.seq)").font(.headline)
        if current { StatusPill(text: "Current", color: .green) }
        Spacer()
        if !current {
          Button("Restore…", action: restore).buttonStyle(.bordered).accessibilityIdentifier("version-restore-\(v.seq)")
        }
      }
      HStack(spacing: 6) {
        StatusPill(text: cause, color: v.cause.kind == "delete" ? .red : v.cause.kind == "restore" ? .blue : .secondary)
        if let k = v.cause.key { Text(k).font(.footnote.monospaced()) }
        if let f = v.cause.from { StatusPill(text: "From \(f)", color: .blue) }
        if v.cause.writer?.by == "machine" { StatusPill(text: "Session", color: .orange) }
        if v.cause.writer?.by == "router" { StatusPill(text: "Router", color: .secondary) }
      }
      if let at = v.at.isoDate { Text(Fmt.ago(at)).font(.caption).foregroundStyle(.secondary) }
      Text(v.keys.isEmpty ? "No keys" : v.keys.map(\.name).joined(separator: " "))
        .font(.footnote.monospaced()).foregroundStyle(.secondary).lineLimit(4)
    }
    .accessibilityElement(children: .contain)
    .accessibilityIdentifier("version-\(v.seq)")
  }
}
