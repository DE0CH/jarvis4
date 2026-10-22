// A failure shown in place, in red, the way Settings shows a problem inside a list.
import SwiftUI

struct ErrorRow: View {
  let text: String
  var id = "inline-error"
  var body: some View {
    Label { Text(text) } icon: { Image(systemName: "exclamationmark.triangle.fill") }
      .foregroundStyle(.red)
      .font(.subheadline)
      .accessibilityElement(children: .combine)
      .accessibilityIdentifier(id)
  }
}

/// a button that shows its action's pending label (and is off) while the action runs
struct PendingButton: View {
  @Environment(AppModel.self) private var model
  let key: String
  let title: String
  var systemImage: String?
  var role: ButtonRole?
  let action: () async -> Void
  var body: some View {
    if let p = model.pending[key] {
      Button {} label: { HStack(spacing: 6) { ProgressView(); Text(p) } }.disabled(true)
    } else {
      Button(role: role) { Task { await action() } } label: {
        if let systemImage { Label(title, systemImage: systemImage) } else { Text(title) }
      }
    }
  }
}
