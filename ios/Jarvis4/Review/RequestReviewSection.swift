// A request from the Inbox on its review page (docs/DESIGN.md "Requests"): three fields at the top, in decreasing trust
// and increasing explanation:
//   1. What you sign (exact): labelled rows rendered by this app from the signed content (SignedAction, set by the
//      page once it has checked that content). The one that matters.
//   2. Requested via (router): who called which endpoint with which arguments, as the router recorded it.
//   3. Reason (unverified): the caller's own words, shown as its text, checked by no one.
// Deny drops the request (an approval is rejected). Allow is the page's own button.
import SwiftUI

struct RequestReviewSection: View {
  @Environment(AppModel.self) private var model
  let inboxId: String
  /// what this page signs, rendered from the signed content; nil while the page is still reading it
  let signed: [SignedFact]?
  let request: SecureRequest
  @State private var item: InboxItem?
  @State private var gone = false
  @State private var error: String?
  @State private var denying = false

  var body: some View {
    SignedFactsSection(facts: signed)
      .task { await load() }
    if let error { Section { ErrorRow(text: error) } }
    else if gone {
      Section { Label("No longer in the Inbox", systemImage: "tray").foregroundStyle(.orange).accessibilityElement(children: .combine).accessibilityIdentifier("request-gone") }
    } else if let item {
      Section {
        LabeledContent("Caller", value: item.callerText).accessibilityIdentifier("request-caller")
        Text(item.callLine).font(.footnote.monospaced()).textSelection(.enabled)
          .accessibilityIdentifier("request-call")
        if let k = mismatch(item) {
          LabeledContent {
            Text(k).font(.footnote.monospaced())
          } label: {
            Label("Differs from what you sign", systemImage: "exclamationmark.triangle.fill")
          }
          .foregroundStyle(.red)
          .accessibilityElement(children: .combine)
          .accessibilityIdentifier("request-mismatch")
        }
      } header: { Label("Requested via (router)", systemImage: "arrow.left.arrow.right") }
      Section {
        if item.explanation.isEmpty {
          Text("None given").foregroundStyle(.secondary).accessibilityIdentifier("request-explanation")
        } else {
          Text(item.explanation)
            .italic()
            .padding(.leading, 10)
            .overlay(alignment: .leading) { Rectangle().fill(.orange.opacity(0.6)).frame(width: 2) }
            .textSelection(.enabled)
            .accessibilityIdentifier("request-explanation")
        }
        if !item.isApproval {
          Button(denying ? "Denying…" : "Deny request", role: .destructive) { Task { await deny() } }
            .disabled(denying)
            .accessibilityIdentifier("request-deny")
        }
      } header: {
        Label("Reason (unverified)", systemImage: "quote.bubble")
      } footer: {
        Text("Written by the caller.")
      }
    }
  }

  private func mismatch(_ it: InboxItem) -> String? {
    let k = SignedAction.mismatch(page: request.options, request: it.openOptions.anyObject)
    return k.isEmpty ? nil : k
  }
  private func load() async {
    do { if let x = try await RouterClient.shared.inboxItem(inboxId) { item = x } else { gone = true } }
    catch { self.error = errText(error) }
  }
  private func deny() async {
    denying = true
    do { try await RouterClient.shared.inboxDeny(inboxId); model.secureCompleted(false) }
    catch { denying = false; self.error = errText(error) }
  }
}
