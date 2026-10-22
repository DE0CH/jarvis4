// A session's pending messages (router: per-message delivery approval): every message Jarvis wants to put into a session
// holding a sensitive store (and every resume prompt) waits here until Deyao delivers or denies THAT message. The page
// lists all of the session's pending ones, each with its kind, who asks for it (the specific requester), the exact text
// in full, a note and when it expires. The session is shown from its core-signed cert.
// Deliver all: the router drafts one batch text with every listed message; it is checked item for item against what
// the page shows (Checks.reviewMessages: the ids, each kind, sender and text, the cert's line, issued now, at most an
// hour) and signed under ONE Face ID. A message can be delivered or denied on its own. Deny signs nothing.
// A ruleable kind offers its rule ("Always deliver Jarvis's watchdog check-ins to this session"): one kind, this
// session, phone-signed (Checks.reviewMessageRule), revocable on the session's page.
import SwiftUI

struct MessageReviewView: View {
  @Environment(AppModel.self) private var model
  let sessionId: String
  @State private var cert: SessionCert?
  /// the session as its core-signed cert names it (never the router's or the message's label)
  @State private var ident: LineIdentity?
  /// this session's pending messages (nil until loaded)
  @State private var list: [PendingMessage]?
  /// approved but not delivered: shown with the router's error
  @State private var failed: [PendingMessage] = []
  @State private var rules: [MessageRule] = []
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?

  /// the kinds a rule may be made for here: ruleable, among the listed messages, not already ruled (one button each)
  private var ruleKinds: [PendingMessage] {
    var seen = Set(rules.map(\.kind))
    var out: [PendingMessage] = []
    for m in list ?? [] where m.ruleable && !seen.contains(m.kind) { seen.insert(m.kind); out.append(m) }
    return out
  }

  var body: some View {
    Form {
      if let loadError { Section { ErrorRow(text: loadError, id: "secure-error") } }
      else if cert != nil, let list {
        Section("Session (as signed)") {
          if let ident { IdentityRows(ident: ident) }
        }
        if list.isEmpty {
          Section { Text("Nothing waiting").foregroundStyle(.secondary).accessibilityIdentifier("msg-none") }
        }
        ForEach(Array(list.enumerated()), id: \.element.id) { i, m in
          Section {
            MessageRows(m: m, to: model.session(sessionId)?.title ?? sessionId)
            HStack {
              Button("Deliver", systemImage: "faceid") { Task { await deliver([m]) } }
                .disabled(busy != nil)
                .accessibilityIdentifier("msg-deliver-\(m.id)")
              Spacer()
              Button("Deny", role: .destructive) { Task { await deny([m]) } }
                .disabled(busy != nil)
                .accessibilityIdentifier("msg-deny-\(m.id)")
            }
            .buttonStyle(.borderless)
          } header: {
            Text(list.count == 1 ? "Message" : "Message \(i + 1) of \(list.count)")
          }
        }
        if !ruleKinds.isEmpty {
          Section {
            ForEach(ruleKinds) { m in
              Button(m.ruleText, systemImage: "checkmark.seal") { Task { await addRule(m) } }
                .disabled(busy != nil)
                .accessibilityIdentifier("msg-rule-\(m.kind)")
            }
          } header: { Text("Rules") } footer: {
            Text("A rule delivers every message of that kind into this session without asking, until you remove it on the session's page.")
          }
        }
        if !failed.isEmpty {
          Section("Not delivered") {
            ForEach(failed) { m in
              VStack(alignment: .leading, spacing: 4) {
                Text(m.kindLabel).font(.headline)
                Text(Fmt.clip(m.text, 200)).font(.subheadline)
                ErrorRow(text: m.error ?? "Delivery failed", id: "msg-failed-\(m.id)")
              }
            }
          }
        }
        Section {
          if let failure { ErrorRow(text: failure, id: "secure-error") }
          SigningFooter()
        }
      } else { Section { ProgressView() } }
    }
    .navigationTitle(navTitle)
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .cancellationAction) {
        Button(busy == nil && (list ?? []).count > 1 ? "Deny all" : "Deny") { Task { await deny(list ?? []) } }
          .disabled(busy != nil || (list ?? []).isEmpty)
          .accessibilityIdentifier("msg-deny-all")
      }
      ToolbarItem(placement: .confirmationAction) {
        Button(busy ?? ((list ?? []).count > 1 ? "Deliver all" : "Deliver")) { Task { await deliver(list ?? []) } }
          .disabled(cert == nil || busy != nil || (list ?? []).isEmpty)
          .accessibilityIdentifier("msg-deliver-all")
      }
    }
    .interactiveDismissDisabled(busy != nil)
    .task { await load() }
  }

  private var navTitle: String {
    guard let n = list?.count, n > 0 else { return "Messages" }
    return n == 1 ? "1 message" : "\(n) messages"
  }

  private func load() async {
    do {
      let c = try await RouterClient.shared.sessionCert(sessionId)
      try LinePins.check(session: sessionId, line: c.line)
      let id = LineIdentity(cert: c)
      try Checks.sameSession(id, expectedLabel: model.session(sessionId)?.j["label"].text)
      ident = id
      cert = c
      try await reload()
    } catch { loadError = errText(error) }
  }
  private func reload() async throws {
    let all = try await RouterClient.shared.messages()
    list = all.messages.filter { $0.session == sessionId && $0.isPending }
    failed = all.messages.filter { $0.session == sessionId && $0.state == "failed" }
    rules = all.rules.filter { $0.session == sessionId }
  }
  /// after a delivery, a denial or a rule: read the list again; nothing left waiting closes the page
  private func after() async {
    do { try await reload() } catch { failure = errText(error) }
    await model.refresh()
    if list?.isEmpty == true { model.secureCompleted(true) }
  }

  /// what the page shows of each message: what the signed item must say (the router's raw fields, compared exactly)
  private func shown(_ ms: [PendingMessage]) -> [ShownMessage] {
    ms.map { ShownMessage(id: $0.id, kind: $0.kind, from: $0.j["from"].string ?? "", text: $0.text) }
  }

  /// the router drafts the batch text, checked item for item against what is shown, then signed under one Face ID
  private func deliver(_ ms: [PendingMessage]) async {
    guard let cert, !ms.isEmpty, busy == nil else { return }
    failure = nil
    do {
      busy = "Preparing…"
      let phone = try PhoneKeys.shared.publicKeys().signingKey
      let d = try await RouterClient.shared.draftMessages(ms.map(\.id))
      if !d.session.isEmpty && d.session != sessionId { throw TrustError.stale("the messages' session") }
      _ = try Checks.reviewMessages(text: d.text, cert: cert, phoneKey: phone, shown: shown(ms))
      busy = "Signing…"
      let text = d.text
      let reason = ms.count == 1 ? "Deliver: \(ms[0].kindLabel)" : "Deliver \(ms.count) messages"
      let sig = try await offMain { try PhoneKeys.shared.sign(text, reason: reason) }
      busy = "Delivering…"
      try await RouterClient.shared.approveMessages(payload: text, sig: sig)
      busy = nil
      model.say(ms.count == 1 ? "Delivering" : "Delivering \(ms.count) messages")
      await after()
    } catch { busy = nil; failure = errText(error) }
  }

  /// no signature: the router drops them
  private func deny(_ ms: [PendingMessage]) async {
    guard !ms.isEmpty, busy == nil else { return }
    failure = nil
    do {
      busy = "Denying…"
      try await RouterClient.shared.denyMessages(ms.map(\.id))
      busy = nil
      await after()
    } catch { busy = nil; failure = errText(error) }
  }

  /// the rule for this message's kind: drafted by the router, checked (this kind, the cert's line, at most a year),
  /// signed under Face ID; the router then also delivers this session's pending messages of that kind
  private func addRule(_ m: PendingMessage) async {
    guard let cert, m.ruleable, busy == nil else { return }
    failure = nil
    do {
      busy = "Preparing…"
      let phone = try PhoneKeys.shared.publicKeys().signingKey
      let text = try await RouterClient.shared.draftMessageRule(sessionId, kind: m.kind)
      _ = try Checks.reviewMessageRule(text: text, cert: cert, phoneKey: phone, delivery: m.kind)
      busy = "Signing…"
      let reason = "Always deliver: \(MessageKind.label(m.kind))"
      let sig = try await offMain { try PhoneKeys.shared.sign(text, reason: reason) }
      busy = "Saving…"
      let r = try await RouterClient.shared.addMessageRule(sessionId, payload: text, sig: sig)
      guard r.kind == m.kind else { throw TrustError.stale("the stored rule") }
      busy = nil
      model.say("Rule saved")
      await after()
    } catch { busy = nil; failure = errText(error) }
  }
}

/// one pending message: its kind, who asks for it, the exact text in full (line breaks kept, selectable), the note
/// and when it expires
struct MessageRows: View {
  let m: PendingMessage
  /// the receiving session's title
  let to: String
  var body: some View {
    VStack(alignment: .leading, spacing: 6) {
      HStack {
        Text(m.kindLabel).font(.headline).accessibilityIdentifier("msg-kind-\(m.id)")
        Spacer()
        if !m.ruleable { StatusPill(text: "Asked each time", color: .secondary) }
      }
      // who sends what to whom, plainly: "From: Session “X” (s…)", "To: session “Y”", then the exact text
      LabeledContent("From", value: m.from).accessibilityIdentifier("msg-from-\(m.id)")
      LabeledContent("To", value: "Session “\(to)”").accessibilityIdentifier("msg-to-\(m.id)")
      Text(m.text)
        .font(.body)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(8)
        .background(Color.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
        .textSelection(.enabled)
        .accessibilityIdentifier("msg-text-\(m.id)")
      if let n = m.note { Text(n).font(.footnote).foregroundStyle(.secondary).accessibilityIdentifier("msg-note-\(m.id)") }
      HStack(spacing: 12) {
        if let c = m.created { Label(Fmt.ago(c), systemImage: "clock") }
        if let e = m.expires { Label("Expires \(Fmt.when(e))", systemImage: "hourglass") }
      }
      .font(.footnote).foregroundStyle(.secondary).labelStyle(.titleAndIcon)
    }
    .accessibilityElement(children: .contain)
    .accessibilityIdentifier("msg-row-\(m.id)")
  }
}
