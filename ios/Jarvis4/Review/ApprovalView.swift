// An approval the router holds (a new line made elsewhere: the web page, a restore, a task; a resume on the latest
// image or in another mode; adding a store to a running machine). The kind comes from the core-signed challenge's own
// fields, never the router's label; the page shows what the challenge carries and signs it under one Face ID (which
// also unlocks the stores a new line gets, for that session only); the core's answer must be for this challenge.
import SwiftUI

struct ApprovalView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
  let approvalId: String
  let inbox: String?
  let request: SecureRequest
  /// opened inside another sheet (an API call's, APICallReviewView): it is told, and this page goes back to it,
  /// instead of closing the whole sheet
  var onFinish: ((Bool) -> Void)? = nil
  @State private var a: RouterClient.ApprovalDTO?
  @State private var r: Checks.Reviewed?
  /// the session it continues, from the predecessor's core-signed cert (nil for a new line)
  @State private var ident: LineIdentity?
  /// whether CI signed the image the challenge names (nil: the challenge names no new image)
  @State private var attest: ImageAttestation?
  @State private var harnessStores: [String] = []
  @State private var toUnlock: [String] = []
  /// keys sessions wrote into the stores it unlocks (shown before Face ID; the unlock refuses one not shown)
  @State private var writes: [SessionWrite] = []
  /// sensitive stores: the core's signed store list's marks joined with the challenge's (a newer core drops the latter)
  @State private var sens: [String] = []
  @State private var signed: [SignedFact]?
  /// an approval on the kernel: its own page (KernelApprovalView)
  @State private var kernel: RouterClient.ApprovalDTO?
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?

  private var title: String {
    switch r?.kind {
    case .resumeUpgrade: "Approve resume"
    case .addStore: "Add a store"
    case .newSession: "Approve new session"
    default: "Approve"
    }
  }

  var body: some View {
    if let kernel {
      KernelApprovalView(a: kernel, inbox: inbox, request: request, onFinish: onFinish)
    } else {
      coreForm
    }
  }

  private var coreForm: some View {
    Form {
      if let inbox { RequestReviewSection(inboxId: inbox, signed: signed, request: request) }
      if let loadError {
        // nothing can be signed, but the approval can still be rejected here (Deyao, 2026-10-13: a resume's page showed
        // no Approve and no way out, so another session had to deny it)
        Section {
          ErrorRow(text: loadError, id: "secure-error")
          Text("This page can't be approved on this iPhone. Reject it, or ask for it again after updating the app.")
            .font(.footnote).foregroundStyle(.secondary).accessibilityIdentifier("secure-cant-approve")
        }
        Section {
          Button(busy == "Rejecting…" ? "Rejecting…" : "Reject", role: .destructive) { Task { await reject() } }
            .disabled(busy != nil).accessibilityIdentifier("secure-reject")
          if let failure { ErrorRow(text: failure, id: "secure-reject-error") }
        }
      }
      else if let r, let a {
        Section {
          if let ident { IdentityRows(ident: ident) }
          else if r.kind == .newSession { Text(Self.signedLabel(r) ?? "Untitled").font(.headline).accessibilityIdentifier("secure-session") }
          if let l = a.label, !l.isEmpty {
            LabeledContent { Text(l) } label: { HStack { Text("Router's label"); StatusPill(text: "Unverified", color: .orange) } }
              .accessibilityElement(children: .combine)
          }
          LabeledContent("Action", value: Self.actionName(r.kind)).accessibilityIdentifier("secure-action")
          if r.kind == .newSession {
            if let rs = a.options?["restore"], !rs.isEmpty {
              LabeledContent("Restores") { Text(rs).font(.footnote.monospaced()) }
                .accessibilityElement(children: .combine).accessibilityIdentifier("secure-restore")
              if r.config?["restore"] == nil {
                Label("Snapshot not signed", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
              }
            } else {
              Label("Requested outside this app", systemImage: "arrow.down.app").foregroundStyle(.secondary)
            }
          }
          if r.kind == .resumeUpgrade { LabeledContent("Stores and harness", value: "Unchanged") }
          if r.kind == .addStore { LabeledContent("Keeps its keys", value: "Yes") }
        } header: { Text("Session (as signed)") }
        if r.kind == .addStore {
          Section("Add this store") { StoreLines(stores: [r.addedStore ?? ""], sensitive: sens) }
          Section("It already has") { StoreLines(stores: r.stores.filter { $0 != r.addedStore }, sensitive: sens, harness: harnessStores) }
        } else {
          Section("Secret stores") { StoreLines(stores: r.stores, sensitive: sens, harness: harnessStores) }
        }
        SignedSettingsSection(r: r, session: a.session)
        let warn = r.kind == .addStore ? sens.filter { $0 == r.addedStore } : r.stores.filter { sens.contains($0) }
        Section {
          if !warn.isEmpty {
            LabeledContent {
              Text(warn.joined(separator: "\n")).multilineTextAlignment(.trailing)
            } label: {
              Label("Sensitive", systemImage: "exclamationmark.triangle.fill")
            }
            .foregroundStyle(.orange).accessibilityElement(children: .combine).accessibilityIdentifier("secure-sensitive-warning")
          }
          LabeledContent("Harness", value: Harness.name(r.harness))
          if r.kind != .addStore {
            LabeledContent {
              Text(r.permissionMode)
            } label: {
              if r.permissionMode == "bypass" { Label("Permission mode", systemImage: "exclamationmark.shield") } else { Text("Permission mode") }
            }
            .foregroundStyle(r.permissionMode == "bypass" ? AnyShapeStyle(.orange) : AnyShapeStyle(.primary))
            .accessibilityElement(children: .combine).accessibilityIdentifier("secure-mode")
          }
          LabeledContent("Session image") { Text(r.image).font(.footnote.monospaced()).textSelection(.enabled) }
          if let attest {
            LabeledContent("Image build") {
              StatusPill(text: attest.badge, color: attest == .attested ? .green : .orange)
            }
            .accessibilityElement(children: .combine).accessibilityIdentifier("secure-image-attest")
          }
          if r.kind == .other { LabeledContent("The challenge", value: r.challenge.request.kind) }
        }
        SessionWritesSection(writes: writes)
        Section {
          if !toUnlock.isEmpty {
            LabeledContent {
              Text(toUnlock.joined(separator: "\n")).multilineTextAlignment(.trailing)
            } label: {
              Label("Also unlocks", systemImage: "lock.open")
            }
            .accessibilityElement(children: .combine).accessibilityIdentifier("secure-unlocks")
            LabeledContent("Open to", value: "This session only")
          }
          Button("Reject", role: .destructive) { Task { await reject() } }.disabled(busy != nil).accessibilityIdentifier("secure-reject")
          if let failure { ErrorRow(text: failure, id: "secure-error") }
          SigningFooter()
        }
      } else {
        Section { ProgressView() }
        Section {
          Button(busy == "Rejecting…" ? "Rejecting…" : "Reject", role: .destructive) { Task { await reject() } }
            .disabled(busy != nil).accessibilityIdentifier("secure-reject")
          if let failure { ErrorRow(text: failure, id: "secure-reject-error") }
        } footer: { Text("Approve shows once the page has read and checked the approval.") }
      }
    }
    .navigationTitle(title)
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy != nil).accessibilityIdentifier("secure-back") }
      ToolbarItem(placement: .confirmationAction) {
        Button(busy ?? "Approve") { Task { await approve() } }.disabled(r == nil || busy != nil).accessibilityIdentifier("secure-approve")
      }
    }
    .interactiveDismissDisabled(busy != nil)
    .task { await load() }
  }

  static func actionName(_ k: Checks.Kind) -> String {
    switch k {
    case .newSession: "New session"
    case .resumeUpgrade: "Continue on a new machine"
    case .addStore: "Add a store"
    case .other: "Sign a challenge"
    }
  }
  static func signedLabel(_ r: Checks.Reviewed) -> String? { (r.config?["label"] as? String).flatMap { $0.isEmpty ? nil : $0 } }

  private func load() async {
    do {
      guard let x = try await RouterClient.shared.approval(approvalId) else { loadError = "This approval is gone (answered or rejected elsewhere)."; return }
      if x.kind.hasPrefix("kernel-") { kernel = x; return }
      let rv = try Checks.review(challenge: x.challenge, coreKey: try CoreTrust.key())
      // which session this continues comes from the signed predecessor, never the router's label (audit findings 1, 5)
      let id = try Checks.continues(rv, coreKey: try CoreTrust.key())
      if let id, let sid = x.session {
        try LinePins.check(session: sid, line: id.line)
        try Checks.sameSession(id, expectedLabel: model.session(sid)?.j["label"].text)
      }
      if (rv.kind == .resumeUpgrade || rv.kind == .addStore) && id == nil { throw TrustError.mismatch("a resume or added store that names no predecessor") }
      ident = id
      if rv.kind == .newSession || rv.kind == .resumeUpgrade { attest = try await ImageAttestation.check(image: rv.image, sig: x.imageSig) }
      harnessStores = PinnedPolicy.stores(rv.harness, router: model.policy)
      let doc = try await RouterClient.shared.storesDoc()
      // a resume on a new image or mode already asks for Face ID: it brings the line's stores as they are now too
      let want: [String] = rv.kind == .addStore ? [rv.addedStore ?? ""] : (rv.kind == .newSession || rv.kind == .resumeUpgrade) ? rv.stores : []
      sens = Array(Set(rv.sensitive + doc.stores.filter(\.sensitive).map(\.name)))
      // unlocked for this session only (its pull locks them again)
      toUnlock = want.filter { n in doc.stores.contains { $0.name == n && !$0.unlocked && !$0.empty } }
      writes = await SessionWrites.load(toUnlock)
      r = rv; a = x
      signed = SignedAction.approval(rv, of: id) + SignedAction.alsoUnlocks(toUnlock, scoped: true) + SessionWrites.fact(writes)
    } catch { loadError = errText(error) }
  }
  private func approve() async {
    guard let a, let r else { return }
    failure = nil
    do {
      busy = "Signing…"
      let payload = a.challenge.payload, reason = title + (toUnlock.isEmpty ? "" : " and unlock \(toUnlock.joined(separator: ", "))")
      let sig: Data
      if toUnlock.isEmpty {
        sig = try await offMain { try PhoneKeys.shared.sign(payload, reason: reason) }
      } else {
        guard let s = try await StoreUnlock.signAndUnlock(payload: payload, stores: toUnlock, reason: reason, for: r.challenge.nonce, shown: writes) else { throw TrustError.stale("signature") }
        sig = s
      }
      busy = "Approving…"
      let ans = try await RouterClient.shared.respond(a.id, signature: sig)
      try Checks.answerFor(r, answer: ans.answer, coreKey: try CoreTrust.key())
      finish(true)
    } catch { busy = nil; failure = errText(error) }
  }
  private func finish(_ ok: Bool) {
    if let onFinish { onFinish(ok); dismiss() } else { model.secureCompleted(ok) }
  }
  /// Reject needs no signature: it works even when the page couldn't read or check the approval
  private func reject() async {
    failure = nil
    do { busy = "Rejecting…"; try await RouterClient.shared.reject(a?.id ?? approvalId); finish(false) }
    catch { busy = nil; failure = errText(error) }
  }
}

/// the signed settings and one-time inputs of a challenge (core Options.Config / Once), as signed: what the machine takes
struct SignedSettingsSection: View {
  let r: Checks.Reviewed
  /// the session the approval is for: its staged attachments are read back and checked against the signed hashes
  var session: String? = nil
  var body: some View {
    let c = r.config ?? [:], o = r.once ?? [:]
    let s = { (k: String) -> String in (c[k] as? String) ?? "" }
    if r.kind == .newSession || !o.isEmpty {
      Section("What the machine takes (signed)") {
        if r.kind == .newSession {
          if !s("label").isEmpty { LabeledContent("Title", value: s("label")).accessibilityIdentifier("signed-label") }
          if !s("prompt").isEmpty {
            VStack(alignment: .leading) { Text("First prompt").font(.footnote).foregroundStyle(.secondary); Text(s("prompt")).textSelection(.enabled) }
              .accessibilityElement(children: .combine).accessibilityIdentifier("signed-prompt")
          }
          if let atts = Checks.attachments(c), !atts.isEmpty {
            Text("Images").font(.footnote).foregroundStyle(.secondary)
              .accessibilityIdentifier("signed-attachments")
            ForEach(atts, id: \.name) { SignedAttachmentRow(session: session, ref: $0) }
          }
          if let rs = c["restore"] as? [String: Any] {
            LabeledContent("Restores machine") { Text((rs["machine"] as? String) ?? "?").font(.footnote.monospaced()) }
              .accessibilityElement(children: .combine).accessibilityIdentifier("signed-restore")
            LabeledContent("Snapshot sha256") { Text(String(((rs["sha256"] as? String) ?? "").prefix(12)) + "…").font(.footnote.monospaced()) }
          }
          if let repos = c["repos"] as? [String], !repos.isEmpty { LabeledContent("Repos", value: repos.joined(separator: "\n")).accessibilityIdentifier("signed-repos") }
          if let cs = Checks.content(c), !cs.isEmpty { LabeledContent("Content stores", value: cs.joined(separator: "\n")).accessibilityIdentifier("signed-content") }
          if !s("model").isEmpty { LabeledContent("Model", value: s("model")) }
          if !s("claudeAccount").isEmpty { LabeledContent("Claude account", value: s("claudeAccount")).accessibilityIdentifier("signed-claude-account") }
          if (c["oneShot"] as? Bool) == true { LabeledContent("One-shot", value: "Yes").accessibilityIdentifier("signed-one-shot") }
          if (c["apiProxy"] as? Bool) == true { LabeledContent("API proxy log", value: "Yes").accessibilityIdentifier("signed-api-proxy") }
          if let t = c["task"] as? [String: Any] {
            LabeledContent("Task", value: (t["name"] as? String) ?? "").accessibilityIdentifier("signed-task")
            LabeledContent("Task parameters") { Text(Checks.compact(t["params"])).font(.footnote.monospaced()) }
          }
          if r.config == nil { LabeledContent("Settings in the cert", value: "None").foregroundStyle(.secondary) }
        }
        if let p = o["prompt"] as? String, !p.isEmpty {
          VStack(alignment: .leading) { Text("Resume prompt").font(.footnote).foregroundStyle(.secondary); Text(p).textSelection(.enabled) }
            .accessibilityElement(children: .combine).accessibilityIdentifier("signed-once-prompt")
        }
        if let m = o["rollback"] as? String, !m.isEmpty {
          LabeledContent {
            Text(m)
          } label: {
            Label("Roll back from", systemImage: "arrow.uturn.backward")
          }
          .foregroundStyle(.orange).accessibilityElement(children: .combine).accessibilityIdentifier("signed-once-rollback")
        }
      }
    }
  }
}

/// a session as its core-signed cert names it: the title and first prompt Deyao gave it, its line and machine, when the
/// cert was issued, and whether it holds a sensitive store
struct IdentityRows: View {
  let ident: LineIdentity
  var body: some View {
    Text(ident.label ?? "Untitled").font(.headline).accessibilityIdentifier("secure-session")
    if let p = ident.prompt { LabeledContent("First prompt", value: Fmt.clip(p, 140)) }
    LabeledContent("Line") { Text(ident.line).font(.footnote.monospaced()).textSelection(.enabled) }
    if let m = ident.machine, m != ident.line { LabeledContent("Machine") { Text(m).font(.footnote.monospaced()) } }
    if let at = ident.issuedAt?.isoDate { LabeledContent("Cert issued", value: Fmt.ago(at)) }
    if ident.sensitive {
      Label("Holds a sensitive store", systemImage: "exclamationmark.octagon.fill").foregroundStyle(.red).accessibilityElement(children: .combine).accessibilityIdentifier("secure-session-sensitive")
    }
    if ident.label == nil {
      Label("Title not signed", systemImage: "questionmark.circle").font(.footnote).foregroundStyle(.orange)
    }
  }
}
