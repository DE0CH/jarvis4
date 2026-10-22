// Previous sessions (GET api/records): the destroyed ones, from the router's index of what it archived. Restore starts a
// NEW line whose first machine restores the archived snapshot (the iPhone approves it like a new session); Transcript
// reads the archive's end; Remove takes it off the list; Delete also deletes its archive (the title is typed first).
import SwiftUI

struct PreviousView: View {
  @Environment(AppModel.self) private var model
  @State private var transcriptOf: Rec?

  private var list: [Rec] { model.records.items.sorted { ($0.destroyedAt ?? .distantPast) > ($1.destroyedAt ?? .distantPast) } }

  var body: some View {
    List {
      if let e = model.records.error { ErrorRow(text: e) }
      ForEach(list) { r in RecordRow(r: r, transcript: { transcriptOf = r }) }
    }
    .overlay {
      if !model.records.loaded && model.records.error == nil { ProgressView("Loading previous sessions…") }
      else if model.records.loaded && list.isEmpty {
        ContentUnavailableView("No previous sessions", systemImage: "archivebox", description: Text("Destroyed sessions show up here."))
      }
    }
    .navigationTitle("Previous")
    .refreshable { await model.loadRecords() }
    .task { await model.loadRecords() }
    .navigationDestination(item: $transcriptOf) { r in
      TranscriptView(title: r.title, noteLabel: "Destroyed", noteValue: r.destroyedAt.map(Fmt.ago) ?? "", path: "api/records/\(r.id)/tail",
                     actionTitle: r.restorable ? "Restore" : nil, onAction: { Task { await model.restore(r) } })
    }
  }
}

private struct RecordRow: View {
  @Environment(AppModel.self) private var model
  let r: Rec
  let transcript: () -> Void

  var body: some View {
    let m = r.session
    VStack(alignment: .leading, spacing: 4) {
      HStack(alignment: .firstTextBaseline) {
        Text(r.title).font(.headline)
        Spacer()
        if let p = model.pending["r:" + r.id] { StatusPill(text: p, color: .orange, spinning: true) }
        else if r.restoredCount > 0 { StatusPill(text: r.restoredCount > 1 ? "restored ×\(r.restoredCount)" : "restored", color: .green) }
        else { StatusPill(text: "destroyed") }
      }
      HStack(spacing: 12) {
        if let d = r.destroyedAt { Label(Fmt.ago(d), systemImage: "trash") }
        if let c = m.created { Label(c.formatted(date: .abbreviated, time: .omitted), systemImage: "calendar") }
      }
      .font(.subheadline).foregroundStyle(.secondary)
      Text(details(m)).font(.footnote).foregroundStyle(.secondary)
      if r.hasArchive {
        HStack(spacing: 12) {
          Label("\(r.transcripts)", systemImage: "text.alignleft").accessibilityLabel("Transcripts: \(r.transcripts)")
          Label("\(r.artifacts)", systemImage: "doc").accessibilityLabel("Artifact files: \(r.artifacts)")
          if !r.restorable { StatusPill(text: "No signed snapshot", color: .orange) }
        }
        .font(.footnote).foregroundStyle(.secondary)
      } else {
        HStack(spacing: 6) {
          StatusPill(text: "Not archived", color: .orange)
          if let e = r.archiveError { Text(e).font(.footnote).foregroundStyle(.secondary).lineLimit(2) }
        }
      }
      if let last = r.last {
        VStack(alignment: .leading, spacing: 1) {
          Text(last.role == "user" ? "You" : "Claude").font(.caption.bold()).foregroundStyle(.secondary)
          Text(last.text).font(.subheadline).lineLimit(3)
        }
      }
      HStack {
        if r.restorable { Button("Restore") { Task { await model.restore(r) } }.buttonStyle(.borderedProminent).accessibilityIdentifier("restore-\(r.id)") }
        if r.hasArchive { Button("Transcript", action: transcript).buttonStyle(.bordered).accessibilityIdentifier("rtail-\(r.id)") }
      }
      .padding(.top, 4)
      .disabled(model.pending["r:" + r.id] != nil)
    }
    .swipeActions {
      Button("Remove", role: .destructive) { Task { await model.removeRecord(r, purge: false) } }
      if r.hasArchive { Button("Delete", systemImage: "trash") { Task { await model.removeRecord(r, purge: true) } }.tint(.red) }
    }
    .contextMenu {
      if r.restorable { Button("Restore", systemImage: "arrow.counterclockwise") { Task { await model.restore(r) } } }
      if r.hasArchive { Button("Transcript", systemImage: "text.alignleft", action: transcript) }
      Button("Remove from the list", systemImage: "minus.circle") { Task { await model.removeRecord(r, purge: false) } }.accessibilityIdentifier("rremove-\(r.id)")
      if r.hasArchive { Button("Delete permanently", systemImage: "trash", role: .destructive) { Task { await model.removeRecord(r, purge: true) } } }
    }
    .accessibilityElement(children: .contain)
    .accessibilityIdentifier("record-\(r.id)")
  }

  private func details(_ m: Session) -> String {
    let own = m.stores(policy: model.policy)
    var parts = [own.isEmpty ? "No stores" : own.joined(separator: ", "), Fmt.harness(m.harness)]
    if let mo = m.model { parts.append(model.models.first { $0.id == mo }?.label ?? mo) }
    if let s = m.size { parts.append(s) }
    if m.permissionMode == "bypass" { parts.append("skip permissions") }
    if r.j["live"]["oneShot"].bool == true { parts.append("one-shot") }
    return parts.joined(separator: " · ")
  }
}
