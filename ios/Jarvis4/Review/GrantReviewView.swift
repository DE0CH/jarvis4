// The grant review (docs/DESIGN.md "Grants"): a router feature may run commands in one session for up to 10 minutes (a
// grant) or until a date (a standing rule). What was asked for is shown as labelled rows (SignedAction.grant), the
// session in them from its core-signed cert (its line, stores, whether it is sensitive, the phone it trusts); the router's draft is checked
// field for field against exactly that (Checks.reviewGrant) before the Secure Enclave key signs it under one Face ID.
// Nothing on the page can be changed: Allow or Deny.
import SwiftUI

struct GrantReviewView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
  let ask: GrantAsk
  let inbox: String?
  let request: SecureRequest
  /// opened inside another page (an approved API call's follow-up): it closes back to that page instead
  var onFinish: ((Bool) -> Void)? = nil
  @State private var cert: SessionCert?
  /// the session as its core-signed cert names it (audit findings 3, 4: never the router's or the request's label)
  @State private var ident: LineIdentity?
  @State private var holderKeys: [String: String] = [:]
  @State private var signed: [SignedFact]?
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?

  private var holder: String { Holder.all.contains { $0.id == ask.holder } ? ask.holder : "" }
  private var isRule: Bool { ask.kind == "rule" }
  private var minutes: Int { (1...10).contains(ask.minutes) ? ask.minutes : 10 }
  /// a standing rule's end, kept between an hour and a year from now
  private var until: Date {
    let asked = ask.until ?? .now.addingTimeInterval(Double(GrantAsk.ruleDays) * 86400)
    return min(max(asked, .now.addingTimeInterval(3600)), .now.addingTimeInterval(366 * 86400))
  }
  /// why nothing can be signed: a short fixed label
  private var refusal: String? {
    if holder.isEmpty { return "Unknown feature" }
    if isRule && cert?.sensitive == true { return "Sensitive session: no standing rule" }
    if cert != nil && holderKeys[holder] == nil { return "No key listed for this feature" }
    return nil
  }

  var body: some View {
    Form {
      if let inbox { RequestReviewSection(inboxId: inbox, signed: signed, request: request) }
      if let loadError { Section { ErrorRow(text: loadError, id: "secure-error") } }
      if loadError != nil, let failure { Section { ErrorRow(text: failure, id: "secure-deny-error") } }
      else if let cert {
        if inbox == nil { SignedFactsSection(facts: signed) }
        if let refusal {
          Section {
            Label(refusal, systemImage: "hand.raised").foregroundStyle(.orange).accessibilityElement(children: .combine).accessibilityIdentifier("grant-refused")
          } header: { Text("Can't be signed") }
        }
        Section("Session (as signed)") {
          if let ident { IdentityRows(ident: ident) }
          if !ask.label.isEmpty && ask.label != ident?.label {
            LabeledContent { Text(ask.label) } label: { HStack { Text("Asked for as"); StatusPill(text: "Unverified", color: .orange) } }
              .accessibilityElement(children: .combine)
          }
        }
        Section("Stores (signed cert)") {
          StoreLines(stores: (cert.stores ?? []).filter { $0 != StoreView.coreStore })
        }
        Section {
          if let failure { ErrorRow(text: failure, id: "secure-error") }
          SigningFooter()
        }
      } else { Section { ProgressView() } }
    }
    .navigationTitle(isRule ? "Standing rule" : "Allow a feature")
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .cancellationAction) { Button("Deny") { deny() }.disabled(busy != nil).accessibilityIdentifier("secure-back") }
      ToolbarItem(placement: .confirmationAction) {
        Button(busy ?? "Allow") { Task { await allow() } }.disabled(cert == nil || refusal != nil || busy != nil).accessibilityIdentifier("secure-grant-allow")
      }
    }
    .interactiveDismissDisabled(busy != nil)
    .task { await load() }
  }

  /// Deny: opened from the Inbox, the request is dropped (the session that asked hears "denied") and the page closes;
  /// opened from the app itself, nothing was asked for, so the page just closes. An error stays on the page.
  private func deny() {
    guard let inbox else { dismiss(); return }
    Task {
      failure = nil
      busy = "Denying…"
      do { try await RouterClient.shared.inboxDeny(inbox); finish(false) }
      catch { busy = nil; failure = errText(error) }
    }
  }

  private func load() async {
    do {
      let c = try await RouterClient.shared.sessionCert(ask.session)
      try LinePins.check(session: ask.session, line: c.line)
      let id = LineIdentity(cert: c)
      try Checks.sameSession(id, expectedLabel: model.session(ask.session)?.j["label"].text)
      holderKeys = try await RouterClient.shared.holders()
      ident = id
      cert = c
      signed = SignedAction.grant(feature: Holder.title(holder), allows: Holder.sub(holder), minutes: isRule ? nil : minutes,
                                  until: isRule ? until : .now.addingTimeInterval(Double(minutes * 60)), line: c.line, of: id)
    } catch { loadError = errText(error) }
  }

  private func allow() async {
    guard let cert, refusal == nil, let hk = holderKeys[holder] else { return }
    failure = nil
    do {
      busy = "Preparing…"
      let phone = try PhoneKeys.shared.publicKeys().signingKey
      let end = until
      var body: [String: Any] = ["holder": holder, "kind": ask.kind]
      if isRule {
        let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime]
        body["until"] = f.string(from: end)
      } else { body["minutes"] = minutes }
      let text = try await RouterClient.shared.draftGrant(ask.session, body)
      // what is signed is exactly what this page shows: the draft checked field for field against it
      _ = try Checks.reviewGrant(text: text, cert: cert, phoneKey: phone, holderKey: hk, kind: ask.kind, minutes: minutes, until: end)
      busy = "Signing…"
      let reason = "Allow \(Holder.title(holder))"
      let sig = try await offMain { try PhoneKeys.shared.sign(text, reason: reason) }
      busy = "Saving…"
      let g = try await RouterClient.shared.addGrant(ask.session, payload: text, sig: sig)
      guard g.holder == holder, g.kind == ask.kind else { throw TrustError.stale("the stored grant") }
      finish(true)
    } catch { busy = nil; failure = errText(error) }
  }
  private func finish(_ ok: Bool) {
    if let onFinish { onFinish(ok); dismiss() } else { model.secureCompleted(ok) }
  }
}
