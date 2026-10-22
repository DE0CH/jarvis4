// The end of a conversation that isn't running, so a session can be recognised before it is brought back: a paused
// session's (its pause snapshot, action Resume) or a destroyed one's (its archive, action Restore).
import SwiftUI

struct TranscriptView: View {
  @Environment(\.dismiss) private var dismiss
  let title: String
  /// when it stopped: "Paused" / "Destroyed", and how long ago
  let noteLabel: String
  let noteValue: String
  let path: String
  var actionTitle: String?
  var onAction: (() -> Void)?
  @State private var messages: [TailMessage]?
  @State private var error: String?

  var body: some View {
    ScrollViewReader { proxy in
      List {
        Section { LabeledContent(noteLabel, value: noteValue).font(.subheadline) } footer: { Text("The last messages of the conversation") }
        if let error { ErrorRow(text: error, id: "pt-error") }
        if let messages {
          if messages.isEmpty { Text("No recent messages").foregroundStyle(.secondary) }
          ForEach(messages) { m in
            VStack(alignment: .leading, spacing: 4) {
              HStack {
                Text(m.role == "user" ? "You" : "Claude").font(.caption.bold()).foregroundStyle(.secondary)
                if let at = m.at { Text(at.formatted(.dateTime.month(.abbreviated).day().hour().minute())).font(.caption).foregroundStyle(.secondary) }
              }
              Text(m.text).textSelection(.enabled)
            }
            .listRowBackground(m.role == "user" ? Color.accentColor.opacity(0.08) : nil)
            .id(m.id)
          }
        }
      }
      .overlay { if messages == nil && error == nil { ProgressView("Reading the transcript…") } }
      .task {
        do {
          messages = try await RouterClient.shared.get(path)["messages"].array.map(TailMessage.init)
          if let last = messages?.last { proxy.scrollTo(last.id, anchor: .bottom) }
        } catch { self.error = errText(error) }
      }
    }
    .navigationTitle(title)
    .navigationBarTitleDisplayMode(.inline)
    .accessibilityIdentifier("transcript")
    .toolbar {
      if let actionTitle, let onAction {
        ToolbarItem(placement: .primaryAction) {
          Button(actionTitle) { dismiss(); onAction() }.accessibilityIdentifier("pt-action")
        }
      }
    }
  }
}
