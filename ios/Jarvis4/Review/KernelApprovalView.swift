// An approval on the kernel (router/kernelline.go): a new source for a session (a new session, a restore, a resume on
// another image) or an add-store (two certs: the store into a new source, that source onto the running machine). The
// page reads what it shows from the certs themselves (KernelChecks: strictly, against the approval's session and
// store), signs them under ONE Face ID with the phone's key, and in the same Face ID unlocks in the kernel's secrets
// the stores the session gets that are locked (an unlock there stays open until locked).
import SwiftUI

struct KernelApprovalView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
  let a: RouterClient.ApprovalDTO
  let inbox: String?
  let request: SecureRequest
  var onFinish: ((Bool) -> Void)? = nil
  @State private var source: KernelChecks.SourceReview?
  @State private var add: KernelChecks.AddReview?
  @State private var attest: ImageAttestation?
  @State private var toUnlock: [String] = []
  @State private var sens: [String] = []
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?

  private var isAdd: Bool { a.kind == "kernel-add-store" }
  private var title: String { isAdd ? "Add a store" : source?.snapshot != nil ? "Approve restore" : "Approve new source" }

  var body: some View {
    Form {
      if let loadError {
        Section {
          ErrorRow(text: loadError, id: "secure-error")
          Text("This page can't be approved on this iPhone. Reject it, or ask for it again.").font(.footnote).foregroundStyle(.secondary)
        }
      }
      if let s = source {
        Section {
          Text(s.config["label"]?.string ?? a.label ?? "Untitled").font(.headline).accessibilityIdentifier("secure-session")
          LabeledContent("Action", value: s.snapshot != nil ? "New source restoring a snapshot" : "New source").accessibilityIdentifier("secure-action")
          if let snap = s.snapshot {
            LabeledContent("Snapshot sha256") { Text(String(snap.prefix(12)) + "…").font(.footnote.monospaced()) }.accessibilityIdentifier("secure-restore")
          }
          if let rs = a.options?["restore"], !rs.isEmpty { LabeledContent("Restores") { Text(rs).font(.footnote) } }
          LabeledContent("Session") { Text(a.session ?? "").font(.footnote.monospaced()) }
        } header: { Text("On the kernel (as signed)") }
        Section("Secret stores") { StoreLines(stores: s.stores, sensitive: sens) }
        Section("What the machine takes (signed)") {
          if let p = s.config["prompt"]?.string, !p.isEmpty {
            VStack(alignment: .leading) { Text("First prompt").font(.footnote).foregroundStyle(.secondary); Text(p).textSelection(.enabled) }
              .accessibilityElement(children: .combine).accessibilityIdentifier("signed-prompt")
          }
          if let m = s.config["model"]?.string, !m.isEmpty { LabeledContent("Model", value: m) }
          LabeledContent("Harness", value: Harness.name(s.harness))
          LabeledContent {
            Text(s.permissionMode)
          } label: {
            if s.permissionMode == "bypass" { Label("Permission mode", systemImage: "exclamationmark.shield") } else { Text("Permission mode") }
          }
          .foregroundStyle(s.permissionMode == "bypass" ? AnyShapeStyle(.orange) : AnyShapeStyle(.primary))
          .accessibilityElement(children: .combine).accessibilityIdentifier("secure-mode")
          LabeledContent("Session image") { Text(s.image).font(.footnote.monospaced()).textSelection(.enabled) }
          if let attest {
            LabeledContent("Image build") { StatusPill(text: attest.badge, color: attest == .attested ? .green : .orange) }
              .accessibilityElement(children: .combine).accessibilityIdentifier("secure-image-attest")
          }
        }
      }
      if let add {
        Section("Add this store") { StoreLines(stores: [add.store], sensitive: sens) }
        Section { LabeledContent("Running machine") { Text(add.machine).font(.footnote.monospaced()) } } header: { Text("Onto (as signed)") }
      }
      if source != nil || add != nil {
        Section {
          let warn = (source?.stores ?? [add?.store ?? ""]).filter { sens.contains($0) }
          if !warn.isEmpty {
            LabeledContent { Text(warn.joined(separator: "\n")).multilineTextAlignment(.trailing) } label: { Label("Sensitive", systemImage: "exclamationmark.triangle.fill") }
              .foregroundStyle(.orange).accessibilityElement(children: .combine).accessibilityIdentifier("secure-sensitive-warning")
          }
          if !toUnlock.isEmpty {
            LabeledContent { Text(toUnlock.joined(separator: "\n")).multilineTextAlignment(.trailing) } label: { Label("Also unlocks", systemImage: "lock.open") }
              .accessibilityElement(children: .combine).accessibilityIdentifier("secure-unlocks")
            LabeledContent("Open until", value: "You lock it")
          }
        }
      }
      Section {
        Button(busy == "Rejecting…" ? "Rejecting…" : "Reject", role: .destructive) { Task { await reject() } }.disabled(busy != nil).accessibilityIdentifier("secure-reject")
        if let failure { ErrorRow(text: failure, id: "secure-error") }
        SigningFooter()
      }
    }
    .navigationTitle(title)
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy != nil).accessibilityIdentifier("secure-back") }
      ToolbarItem(placement: .confirmationAction) {
        Button(busy ?? "Approve") { Task { await approve() } }.disabled((source == nil && add == nil) || busy != nil).accessibilityIdentifier("secure-approve")
      }
    }
    .interactiveDismissDisabled(busy != nil)
    .task { await load() }
  }

  private func load() async {
    do {
      guard let sid = a.session else { throw TrustError.mismatch("an approval for no session") }
      let wanted: [String]
      if isAdd {
        guard let second = a.earlier?.first, let store = a.options?["store"] else { throw TrustError.mismatch("an add-store without its second cert") }
        let r = try KernelChecks.add(first: a.challenge.payload, second: second.payload, session: sid, store: store)
        add = r
        wanted = [r.store]
      } else {
        let r = try KernelChecks.source(payload: a.challenge.payload, session: sid)
        attest = try await ImageAttestation.check(image: r.image, sig: a.imageSig)
        source = r
        wanted = r.stores
      }
      let doc = try await RouterClient.shared.kernelStores()
      sens = doc.stores.filter(\.sensitive).map(\.name)
      toUnlock = wanted.filter { n in doc.stores.contains { $0.name == n && !$0.unlocked && !$0.empty } }
    } catch { loadError = errText(error) }
  }

  private func approve() async {
    failure = nil
    do {
      busy = "Signing…"
      let reason = title + (toUnlock.isEmpty ? "" : " and unlock \(toUnlock.joined(separator: ", "))")
      let payloads = [a.challenge.payload] + (isAdd ? (a.earlier ?? []).prefix(1).map(\.payload) : [])
      let auth = try await offMain { try PhoneKeys.shared.authorize(reason: reason) }
      defer { auth.invalidate() }
      var sigs: [Data] = []
      for p in payloads { sigs.append(try await offMain { try PhoneKeys.shared.sign(p, reason: reason, auth: auth) }) }
      for s in toUnlock {
        busy = "Unlocking \(s)…"
        try await RouterClient.shared.kernelUnlock(s, reason: reason, auth: auth)
      }
      busy = "Approving…"
      _ = try await RouterClient.shared.respond(a.id, signatures: sigs)
      finish(true)
    } catch { busy = nil; failure = errText(error) }
  }
  private func finish(_ ok: Bool) {
    if let onFinish { onFinish(ok); dismiss() } else { model.secureCompleted(ok) }
  }
  private func reject() async {
    failure = nil
    do { busy = "Rejecting…"; try await RouterClient.shared.reject(a.id); finish(false) }
    catch { busy = nil; failure = errText(error) }
  }
}
