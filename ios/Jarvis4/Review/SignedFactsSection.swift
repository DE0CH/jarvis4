// "What you sign (exact)" as a section of labelled rows, each rendered from the signed content (SignedAction): no
// sentence is assembled here. Each row carries the accessibility id `signed-<fact id>` (e.g. signed-repo, signed-store).
import SwiftUI

struct SignedFactsSection: View {
  /// nil while the page is still reading the signed content
  let facts: [SignedFact]?
  var body: some View {
    Section {
      if let facts {
        ForEach(facts) { SignedFactRow(fact: $0) }
      } else {
        LabeledContent("Reading") { ProgressView() }.accessibilityIdentifier("request-signed-reading")
      }
    } header: {
      Label("What you sign (exact)", systemImage: "signature")
    } footer: {
      Text("Rendered by this iPhone from the signed content.")
    }
  }
}

struct SignedFactRow: View {
  let fact: SignedFact
  var body: some View {
    LabeledContent {
      HStack(spacing: 4) {
        if fact.style == .warning { Image(systemName: "exclamationmark.triangle.fill").accessibilityHidden(true) }
        Text(fact.value)
          .font(fact.style == .code ? .footnote.monospaced() : .body)
          .multilineTextAlignment(.trailing)
          .textSelection(.enabled)
      }
      .foregroundStyle(fact.style == .warning ? AnyShapeStyle(.orange) : AnyShapeStyle(.primary))
    } label: {
      Text(fact.label)
    }
    .accessibilityElement(children: .combine)
    .accessibilityIdentifier("signed-\(fact.id)")
  }
}
