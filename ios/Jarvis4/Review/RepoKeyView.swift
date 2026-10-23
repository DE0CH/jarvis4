// A repo's deploy key: add (the core makes an SSH key, puts it on GitHub as a read/write deploy key, keeps the private
// half in the store github-<repo>) or remove. What the page shows comes from the core's signed begin document (asked
// for when the page opens, and again when "Sensitive store" changes); one Face ID signs it and opens
// github-deploy-keys for this one request. The core's refusals (e.g. a 409 when another repo already owns the store
// name) are shown as the core words them. A repo a session asked for (into): the router files the add-store that puts
// the repo's store into that session once the key exists, and this page signs it under the same Face ID, after checking
// it is exactly that store for that session (BatchPrepare.repoFollowups; router DECISIONS 182).
import SwiftUI

struct RepoKeyView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
  let action: String
  let repo: String
  let sensitiveAsked: Bool
  let inbox: String?
  var into: RepoInto? = nil
  let request: SecureRequest
  @State private var b: DeployKeyBegin?
  @State private var doc: SignedDoc?
  @State private var sensitive = false
  @State private var forced = false
  @State private var signed: [SignedFact]?
  @State private var busy: String?
  @State private var failure: String?

  private var title: String { action == "add" ? "Add repo" : "Remove repo" }

  var body: some View {
    Form {
      if let inbox { RequestReviewSection(inboxId: inbox, signed: signed, request: request) }
      if inbox == nil, b != nil || failure == nil { SignedFactsSection(facts: signed) }
      if let b, action == "add" {
        Section {
          if b.replaces {
            Label("Replaces the earlier key", systemImage: "exclamationmark.triangle.fill")
              .foregroundStyle(.orange).accessibilityElement(children: .combine).accessibilityIdentifier("secure-repo-replaces")
          }
          Toggle("Sensitive store", isOn: Binding(get: { b.sensitive }, set: { v in if !forced && busy == nil { Task { await begin(sensitive: v) } } }))
            .disabled(forced || busy != nil)
            .accessibilityIdentifier("secure-repo-sensitive")
        } footer: {
          Text(forced ? "Always on for this repo." : "One way: it can't be turned off later.")
        }
      }
      Section {
        if let failure { ErrorRow(text: failure, id: "secure-error") }
        SigningFooter()
      }
    }
    .navigationTitle(title)
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy != nil).accessibilityIdentifier("secure-back") }
      ToolbarItem(placement: .confirmationAction) {
        Button(busy ?? (action == "add" ? "Add" : "Remove"), role: action == "add" ? nil : .destructive) { Task { await go() } }
          .disabled(b == nil || busy != nil).accessibilityIdentifier("secure-repo-go")
      }
    }
    .interactiveDismissDisabled(busy != nil)
    .task {
      // Jarvis 4's own repo is always asked for as sensitive (Checks.deployKeyBegin refuses it otherwise)
      let want = sensitiveAsked || Checks.alwaysSensitive(repo)
      sensitive = want
      await begin(sensitive: want)
    }
  }

  private func begin(sensitive want: Bool) async {
    failure = nil
    if b != nil { busy = "Checking…" }
    defer { busy = nil }
    do {
      let r = try await RouterClient.shared.deployKeyBegin(action: action, repo: repo, sensitive: want)
      doc = r.doc; b = r.begin; sensitive = want
      signed = SignedAction.deployKey(r.begin) + (follow(r.begin).map { SignedAction.repoInto($0, store: r.begin.store) } ?? [])
      forced = r.begin.sensitive && !want
    } catch { failure = errText(error) }
  }

  /// the session the store goes into, when it is this begin's store
  private func follow(_ b: DeployKeyBegin) -> RepoInto? { action == "add" && into?.store == b.store ? into : nil }

  private func go() async {
    guard let b, let doc else { return }
    failure = nil
    do {
      busy = action == "add" ? "Adding…" : "Removing…"
      let payload = doc.payload, e = b.e, reason = "\(title): \(b.repo)"
      if let into = follow(b) {
        // one Face ID for the key and the add-store that follows it
        let auth = try await offMain { try PhoneKeys.shared.authorize(reason: reason) }
        defer { auth.invalidate() }
        let r = try await offMain { try PhoneKeys.shared.signAndShare(payload, e: e, reason: reason, auth: auth) }
        let f = try await RouterClient.shared.deployKeyFinish(b, signature: r.signature, share: r.share, inbox: inbox)
        do { try await BatchPrepare.repoFollowups(f.followups, into: into, model: model, auth: auth, progress: BatchProgress()) }
        catch {
          // the key is made; only the store's add-store failed: it stays in the Inbox
          busy = nil
          model.say("Deploy key added; adding the store to the session failed: " + errText(error))
          model.secureCompleted(true)
          return
        }
        busy = nil
        model.say(f.followups.isEmpty ? "Deploy key added" : "Deploy key added and its store added to the session")
        model.secureCompleted(true)
        return
      }
      let r = try await offMain { try PhoneKeys.shared.signAndShare(payload, e: e, reason: reason) }
      _ = try await RouterClient.shared.deployKeyFinish(b, signature: r.signature, share: r.share)
      busy = nil
      model.say(action == "add" ? "Deploy key added" : "Deploy key and store removed")
      model.secureCompleted(true)
    } catch {
      busy = nil
      let keep = errText(error)
      // the pending request is spent either way: ask the core again so the button works on the next tap
      await begin(sensitive: sensitive)
      failure = keep
    }
  }
}
