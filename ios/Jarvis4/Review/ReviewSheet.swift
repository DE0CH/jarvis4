// The review sheets: everything the phone signs is signed on one of these pages, under Face ID. Each page reads what it
// shows from the signed content (the core's signed documents, or the session's core-signed cert for a grant), checks
// the answer that comes back, and closes through AppModel.secureCompleted. Opened from the Inbox, a page first shows the
// request's three fields (RequestReviewSection).
import SwiftUI

struct ReviewSheet: View {
  let request: SecureRequest
  var body: some View {
    NavigationStack {
      switch request {
      case .newSession: NewSessionView()
      case .approval(let id, let inbox): ApprovalView(approvalId: id, inbox: inbox, request: request)
      case .grant(let g, let inbox): GrantReviewView(ask: g, inbox: inbox, request: request)
      case .unlock(let s, let label, let inbox): UnlockReviewView(sessionId: s, label: label, inbox: inbox, request: request)
      case .repoKey(let a, let r, let sens, let inbox, let into): RepoKeyView(action: a, repo: r, sensitiveAsked: sens, inbox: inbox, into: into, request: request)
      case .batch(let id): BatchReviewView(batchId: id)
      case .restore(let st, let q, let inbox): RestoreReviewView(store: st, seq: q, inbox: inbox, request: request)
      case .apiCall(let id): APICallReviewView(callId: id)
      case .messages(let s): MessageReviewView(sessionId: s)
      }
    }
    .interactiveDismissDisabled(false)
  }
}

/// the key that signs, in words: under every review page
struct SigningFooter: View {
  var body: some View {
    Label(PhoneKeys.shared.usesEnclave ? "Signed in this iPhone's Secure Enclave, with Face ID." : "Signed with a software key (simulator).",
          systemImage: PhoneKeys.shared.usesEnclave ? "lock.shield" : "lock.trianglebadge.exclamationmark")
      .font(.footnote)
      .foregroundStyle(.secondary)
      .accessibilityElement(children: .combine)
      .accessibilityIdentifier("secure-banner")
  }
}

/// the store names a signed document carries, sensitive ones and the harness's own marked
struct StoreLines: View {
  let stores: [String]
  var sensitive: [String] = []
  var harness: [String] = []
  var body: some View {
    if stores.isEmpty { Text("No stores.").foregroundStyle(.secondary) }
    ForEach(stores, id: \.self) { s in
      HStack {
        Label(s, systemImage: "shippingbox").font(.body.weight(.medium))
        Spacer()
        if sensitive.contains(s) { StatusPill(text: "Sensitive", color: .red) }
        if harness.contains(s) { StatusPill(text: "Harness", color: .blue) }
      }
      .accessibilityElement(children: .combine)
      .accessibilityIdentifier("store-line-\(s)")
    }
  }
}
