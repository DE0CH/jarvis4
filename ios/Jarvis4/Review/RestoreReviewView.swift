// Put a store back to an earlier version (core/history.go): what the page shows comes from the core's signed begin
// document only — the version put back and the one it replaces, every key put back with who wrote it, every key
// removed. Allow signs that document and gives this phone's share of each key put back under ONE Face ID; the core
// opens them, seals their backups to the master key, the router writes those, and the core commits. No recovery kit.
import SwiftUI

struct RestoreReviewView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
  let store: String
  let seq: Int
  let inbox: String?
  let request: SecureRequest
  @State private var doc: SignedDoc?
  @State private var b: RestoreBegin?
  @State private var signed: [SignedFact]?
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?

  var body: some View {
    Form {
      if let inbox { RequestReviewSection(inboxId: inbox, signed: signed, request: request) }
      if let loadError { Section { ErrorRow(text: loadError, id: "secure-error") } }
      else if let b {
        if inbox == nil { SignedFactsSection(facts: signed) }
        Section {
          ForEach(b.put, id: \.key) { p in
            LabeledContent {
              Text(p.writer.by == "machine" ? "Session" : p.writer.by == "setup" ? "Setup" : p.writer.by == "router" ? "Router" : "Core")
                .foregroundStyle(p.writer.by == "machine" ? Color.orange : Color.secondary)
            } label: {
              VStack(alignment: .leading, spacing: 2) {
                Text(p.key).font(.body.monospaced())
                if let at = p.at?.isoDate { Text(Fmt.ago(at)).font(.footnote).foregroundStyle(.secondary) }
              }
            }
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("restore-put-\(p.key)")
          }
          if b.put.isEmpty { Text("None").foregroundStyle(.secondary) }
        } header: { Text("Put back (signed)") } footer: { Text("Written by: who the core names for each value.") }
        if !b.remove.isEmpty {
          Section {
            ForEach(b.remove, id: \.self) { k in
              Text(k).font(.body.monospaced()).accessibilityIdentifier("restore-remove-\(k)")
            }
          } header: { Label("Removed", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange) }
        }
      }
      if loadError == nil && b == nil { Section { ProgressView() } }
      Section {
        if let failure { ErrorRow(text: failure, id: loadError == nil ? "secure-error" : "secure-deny-error") }
        SigningFooter()
      }
    }
    .navigationTitle("Restore store")
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .cancellationAction) { Button(inbox == nil ? "Cancel" : "Deny") { deny() }.disabled(busy != nil).accessibilityIdentifier("secure-back") }
      ToolbarItem(placement: .confirmationAction) {
        Button(busy ?? "Restore") { Task { await allow() } }.disabled(b == nil || busy != nil).accessibilityIdentifier("secure-restore-allow")
      }
    }
    .interactiveDismissDisabled(busy != nil)
    .task { await load() }
  }

  /// Deny: opened from the Inbox, the request is dropped and the page closes; opened from the app, it just closes
  private func deny() {
    guard let inbox else { dismiss(); return }
    Task {
      failure = nil
      busy = "Denying…"
      do { try await RouterClient.shared.inboxDeny(inbox); model.secureCompleted(false) }
      catch { busy = nil; failure = errText(error) }
    }
  }

  private func load() async {
    do {
      let r = try await RouterClient.shared.restoreBegin(store, seq: seq)
      doc = r.doc; b = r.begin
      signed = SignedAction.restore(r.begin)
    } catch { loadError = errText(error) }
  }

  private func allow() async {
    guard let b, let doc else { return }
    failure = nil
    do {
      busy = "Restoring…"
      let payload = doc.payload, es = b.es, reason = "Restore \(b.store) to version \(b.to.seq)"
      let out = try await offMain { try PhoneKeys.shared.signAndShares(payload, es: es, reason: reason) }
      guard let sig = out.signature, out.shares.count == es.count else { throw TrustError.stale("the restore's signature") }
      _ = try await RouterClient.shared.restoreFinish(b, signature: sig, shares: out.shares)
      busy = nil
      model.say("Store restored")
      model.secureCompleted(true)
    } catch {
      busy = nil
      let keep = errText(error)
      // the begin is spent either way: ask the core again so the button works on the next tap
      self.b = nil; self.doc = nil
      await load()
      failure = keep
    }
  }
}
