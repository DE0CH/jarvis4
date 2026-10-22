// One wakeup or cron as rows: when (or how often), its name, the next run, and its prompt as written.
import SwiftUI

/// a wakeup or cron: when (and how often), its name, the next run, and its prompt as written
struct WakeRow: View {
  let symbol: String
  let when: String
  var name: String?
  let prompt: String
  var next: String?
  /// short tags: a time zone, the number of runs
  var tags: [String] = []
  var body: some View {
    VStack(alignment: .leading, spacing: 2) {
      HStack {
        Label(when, systemImage: symbol).font(.subheadline.weight(.medium))
        Spacer()
        if let name { StatusPill(text: name) }
        ForEach(tags, id: \.self) { StatusPill(text: $0) }
      }
      if let next { LabeledContent("Next", value: next).font(.footnote) }
      Text(Fmt.clip(prompt, 200)).font(.subheadline).foregroundStyle(.secondary)
    }
    .accessibilityElement(children: .combine)
  }
}
