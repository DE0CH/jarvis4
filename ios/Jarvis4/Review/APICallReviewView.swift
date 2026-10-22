// An API call a session's actions asked to run as Deyao (router/apicalls.go, kind "api-call"), on its own review sheet
// (Deyao, 2026-10-15): the call itself (method, path, body), who asked, and the caller's reason. Approve runs it as
// him, with no Face ID (Face ID signs only what the core verifies). The sheet then stays up for the core requests the
// call brought about (a resume call → the resume-upgrade approval for that session): the router links each to the call
// (GET api/requests/calls/:id) and says while one may still come and until when, so the sheet waits on exactly that.
// Each follow-up opens its own approval page (What you sign (exact), Face ID) inside this sheet and comes back here.
import SwiftUI

struct APICallReviewView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
  let callId: String
  @State private var item: InboxItem?
  @State private var gone = false
  @State private var busy: String?
  @State private var failure: String?
  /// Approve's answer: {ok, state, status, error}
  @State private var outcome: JSON?
  /// GET api/requests/calls/:id: {state, status, followups: [{id, open, item}], awaiting: {session, until}}
  @State private var follow: JSON?

  init(callId: String) { self.callId = callId }
  /// approved already (a batch's Allow all): the sheet opens on what the call brings about
  init(callId: String, approved: (item: InboxItem, outcome: JSON)) {
    self.callId = callId
    _item = State(initialValue: approved.item)
    _outcome = State(initialValue: approved.outcome)
  }

  private var p: JSON { item?.params ?? .null }
  private var awaiting: Date? { follow?["awaiting"]["until"].string?.isoDate }
  private var followups: [JSON] { follow?["followups"].array ?? [] }
  private var openFollowups: [InboxItem] { followups.filter { $0["open"].bool == true }.map { InboxItem(j: $0["item"]) } }
  /// approved, and nothing waits or may still come
  private var finished: Bool { outcome != nil && follow != nil && awaiting == nil && openFollowups.isEmpty }

  var body: some View {
    Form {
      if gone && outcome == nil {
        Section { Label("No longer in the Inbox", systemImage: "tray").foregroundStyle(.orange).accessibilityElement(children: .combine).accessibilityIdentifier("request-gone") }
      } else if let item {
        Section {
          if let d = item.does { LabeledContent("Does", value: d).accessibilityIdentifier("call-does") }
          LabeledContent("Method") { Text(p["method"].string ?? "").font(.body.monospaced()) }.accessibilityIdentifier("call-method")
          LabeledContent("Path") { Text(p["path"].string ?? "").font(.footnote.monospaced()).textSelection(.enabled) }
            .accessibilityElement(children: .combine).accessibilityIdentifier("call-path")
          if let b = p["body"].text {
            VStack(alignment: .leading, spacing: 4) {
              Text(p["contentType"].text.map { "Body (\($0))" } ?? "Body").font(.footnote).foregroundStyle(.secondary)
              Text(Self.pretty(b)).font(.footnote.monospaced()).textSelection(.enabled)
            }
            .accessibilityElement(children: .combine).accessibilityIdentifier("call-body")
          } else {
            LabeledContent("Body", value: "None").accessibilityIdentifier("call-body")
          }
        } header: { Label("Runs as you", systemImage: "arrow.up.forward.app") } footer: { Text("No Face ID: a step that needs the core's signature asks for it below.") }
        Section {
          LabeledContent("Caller", value: item.callerText).accessibilityIdentifier("request-caller")
          if let c = item.created { LabeledContent("Asked", value: Fmt.ago(c)) }
          if outcome == nil, let e = item.expires { LabeledContent("Expires", value: Fmt.when(e)) }
        } header: { Label("Who asked", systemImage: "person") }
        Section {
          if item.explanation.isEmpty {
            Text("None given").foregroundStyle(.secondary).accessibilityIdentifier("request-explanation")
          } else {
            Text(item.explanation).italic()
              .padding(.leading, 10)
              .overlay(alignment: .leading) { Rectangle().fill(.orange.opacity(0.6)).frame(width: 2) }
              .textSelection(.enabled)
              .accessibilityIdentifier("request-explanation")
          }
        } header: { Label("Reason (unverified)", systemImage: "quote.bubble") } footer: { Text("Written by the caller.") }
      } else if failure == nil {
        Section { ProgressView() }
      }
      if let outcome {
        Section {
          let status = outcome["status"].int ?? 0
          if outcome["ok"].bool == true {
            Label("HTTP \(status)", systemImage: status < 400 ? "checkmark.circle.fill" : "xmark.octagon.fill")
              .foregroundStyle(status < 400 ? .green : .red).accessibilityElement(children: .combine).accessibilityIdentifier("call-result")
          } else {
            ErrorRow(text: outcome["error"].text ?? "The call didn't run", id: "call-result")
          }
        } header: { Text("Result") }
        Section {
          ForEach(openFollowups, id: \.id) { f in
            NavigationLink {
              // a core approval (a resume, an add-store) or a phone grant (a switch to bypass waits on the terminal grant)
              if f.openKind == "grant", let r = SecureRequest.fromInbox(f), case .grant(let g, let inbox) = r {
                GrantReviewView(ask: g, inbox: inbox, request: r, onFinish: { _ in Task { await load() } })
              } else {
                ApprovalView(approvalId: f.openOptions["approvalId"].text ?? f.id, inbox: f.id, request: .approval(id: f.openOptions["approvalId"].text ?? f.id, inbox: f.id),
                             onFinish: { _ in Task { await load() } })
              }
            } label: {
              VStack(alignment: .leading, spacing: 2) {
                Text(f.actionTitle).font(.headline)
                if let s = f.sessionName ?? f.session { Text(s).font(.subheadline).foregroundStyle(.secondary) }
              }
            }
            .accessibilityIdentifier("call-followup-\(f.id)")
          }
          ForEach(followups.filter { $0["open"].bool != true }, id: \.self) { f in
            Label("Answered, denied or lapsed", systemImage: "checkmark.seal").foregroundStyle(.secondary)
              .accessibilityElement(children: .combine).accessibilityIdentifier("call-followup-done-\(f["id"].string ?? "")")
          }
          if let until = awaiting {
            HStack { ProgressView(); Text("Waiting for what this call brings about (until \(until.formatted(date: .omitted, time: .shortened)))") }
              .accessibilityElement(children: .combine).accessibilityIdentifier("call-awaiting")
          } else if finished {
            Text(followups.isEmpty ? "Nothing more to approve." : "Nothing more waits.").foregroundStyle(.secondary).accessibilityIdentifier("call-finished")
          }
        } header: { Text("What it brings about") } footer: {
          if !openFollowups.isEmpty { Text("Each opens its own page: what you sign, under Face ID.") }
        }
      }
      Section {
        if outcome == nil && item != nil {
          Button(busy == "Denying…" ? "Denying…" : "Deny", role: .destructive) { Task { await deny() } }
            .disabled(busy != nil).accessibilityIdentifier("request-deny")
        }
        if let failure { ErrorRow(text: failure, id: "secure-error") }
      }
    }
    .navigationTitle("API call")
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .cancellationAction) {
        Button(outcome == nil ? "Cancel" : "Close") { if outcome == nil { dismiss() } else { model.secureCompleted(true) } }
          .disabled(busy != nil).accessibilityIdentifier("secure-back")
      }
      ToolbarItem(placement: .confirmationAction) {
        if outcome == nil {
          Button(busy ?? "Approve") { Task { await approve() } }.disabled(item == nil || busy != nil).accessibilityIdentifier("request-approve-\(callId)")
        } else if finished {
          Button("Done") { model.secureCompleted(true) }.accessibilityIdentifier("call-done")
        }
      }
    }
    .interactiveDismissDisabled(busy != nil)
    .task { if outcome == nil { await loadItem() } }
    .task(id: outcome != nil) { await watchFollowups() }
  }

  /// a JSON body indented for reading; anything else as it is
  static func pretty(_ s: String) -> String {
    guard let d = s.data(using: .utf8), let o = try? JSONSerialization.jsonObject(with: d, options: [.fragmentsAllowed]),
          let out = try? JSONSerialization.data(withJSONObject: o, options: [.prettyPrinted, .sortedKeys, .fragmentsAllowed]) else { return s }
    return String(decoding: out, as: UTF8.self)
  }

  private func loadItem() async {
    do { if let x = try await RouterClient.shared.inboxItem(callId) { item = x } else { gone = true } }
    catch { failure = errText(error) }
  }
  private func load() async {
    do { if let f = try await RouterClient.shared.callFollowups(callId) { follow = f } }
    catch { failure = errText(error) }
  }
  /// after Approve: follow the call's follow-ups while one waits or may still come (the router says until when)
  private func watchFollowups() async {
    guard outcome != nil else { return }
    while !Task.isCancelled {
      await load()
      if finished { return }
      try? await Task.sleep(for: .seconds(1.5))
    }
  }
  private func approve() async {
    failure = nil
    busy = "Running…"
    do { outcome = try await RouterClient.shared.inboxApproveCall(callId); busy = nil }
    catch { busy = nil; failure = errText(error) }
  }
  private func deny() async {
    failure = nil
    busy = "Denying…"
    do { try await RouterClient.shared.inboxDeny(callId); model.secureCompleted(false) }
    catch { busy = nil; failure = errText(error) }
  }
}
