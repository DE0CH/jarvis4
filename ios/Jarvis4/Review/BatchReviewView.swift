// A batch from the Inbox (docs/DESIGN.md "Requests", router/batches.go): several items a caller filed together,
// reviewed on one page and allowed under ONE Face ID. On top, the caller's summary (unverified, its words); below it
// every item with its own "What you sign (exact)", rendered from that item's signed content exactly as its own page
// renders it, and the call and reason the router recorded. Allow all: one Face ID (PhoneKeys.authorize), then every
// item is signed and sent on its own, exactly as from its own page (each approval's own core challenge, each grant's
// own text, each deploy key's own begin document): the core and the grant store verify each one unchanged. An item
// that fails is shown failed; the ones before it already went through (they left the Inbox), so Retry reads the
// failed ones again and asks for one more Face ID. Deny all drops the batch; an item can be denied on its own.
//
// Items of one batch can depend on each other through the session's cert: an add-store is a challenge made from the
// session's cert, and when another item puts a store in first, the router makes the waiting add-store again from the
// new cert (router flows.go rebaseAddStores). So an add-store reads its challenge again right before it is signed,
// and signs the new one only when it is the same ask (Checks.sameAddStore); an unlock reads the session's cert again
// for the nonce it is for. Before this (2026-10-15), every add-store after the first of a session failed with "another
// store was added to this session while this approval waited" on the live core.
import SwiftUI

/// what the items signed so far in this Allow all did, for the ones after them
@MainActor
final class BatchProgress {
  /// stores added to the session by this batch's add-stores (a later add-store's challenge may name them)
  var addedStores: Set<String> = []
  /// the API calls this batch approved: their answers {ok, state, status, followups, awaiting}
  var calls: [String: JSON] = [:]
}

/// one item, read and checked: what it signs and how to sign it under the batch's Face ID
struct BatchPrepared {
  let facts: [SignedFact]
  /// why it can't be signed (a short fixed label), as its own page would refuse it
  var refusal: String?
  let run: @MainActor (PhoneAuth, BatchProgress) async throws -> Void
}

@MainActor
enum BatchPrepare {
  static func load(_ it: InboxItem, model: AppModel) async throws -> BatchPrepared {
    if it.kind == "peer-message" { return peerMessage(it) }
    guard let req = SecureRequest.fromInbox(it) else { throw TrustError.mismatch("an item this app can't open") }
    switch req {
    case .approval(let id, _): return try await approval(id, model: model)
    case .grant(let g, _): return try await grant(g, model: model)
    case .unlock(let s, _, _): return try await unlock(s, model: model)
    case .repoKey(let a, let r, let sens, let inbox, let into): return try await repoKey(a, r, sens, inbox: inbox, into: into, model: model)
    case .apiCall(let id): return apiCall(it, id: id)
    case .newSession, .batch, .restore, .messages: throw TrustError.mismatch("an item this app can't open")
    }
  }

  /// as ApprovalView.load / approve
  /// expectAddStore: the approval must be exactly this add-store (a repo's follow-up, shown before the Face ID)
  static func approval(_ approvalId: String, model: AppModel, expectAddStore: RepoInto? = nil) async throws -> BatchPrepared {
    guard let x = try await RouterClient.shared.approval(approvalId) else { throw TrustError.stale("the approval (answered or rejected elsewhere)") }
    if x.kind.hasPrefix("kernel-") { return try await kernelApproval(x, expectAddStore: expectAddStore) }
    let rv = try Checks.review(challenge: x.challenge, coreKey: try CoreTrust.key())
    if let e = expectAddStore, rv.kind != .addStore || rv.addedStore != e.store || x.session != e.session {
      throw TrustError.mismatch("the follow-up isn't the add-store of \(e.store) to \(e.session)")
    }
    let id = try Checks.continues(rv, coreKey: try CoreTrust.key())
    if let id, let sid = x.session {
      try LinePins.check(session: sid, line: id.line)
      try Checks.sameSession(id, expectedLabel: model.session(sid)?.j["label"].text)
    }
    if (rv.kind == .resumeUpgrade || rv.kind == .addStore) && id == nil { throw TrustError.mismatch("a resume or added store that names no predecessor") }
    var facts = SignedAction.approval(rv, of: id)
    if rv.kind == .newSession || rv.kind == .resumeUpgrade {
      let attest = try await ImageAttestation.check(image: rv.image, sig: x.imageSig)
      facts.append(.init(id: "image-build", label: "Image build", value: attest.badge, style: attest == .attested ? .plain : .warning))
    }
    if rv.kind == .newSession, let rs = x.options?["restore"], !rs.isEmpty {
      facts.append(.init(id: "restore-router", label: "Restores (router's words)", value: rs, style: .code))
    }
    let doc = try await RouterClient.shared.storesDoc()
    // a resume on a new image or mode brings the line's stores as they are now (as ApprovalView)
    let want: [String] = rv.kind == .addStore ? [rv.addedStore ?? ""] : (rv.kind == .newSession || rv.kind == .resumeUpgrade) ? rv.stores : []
    let toUnlock = want.filter { n in doc.stores.contains { $0.name == n && !$0.unlocked && !$0.empty } }
    let writes = await SessionWrites.load(toUnlock)
    facts += SignedAction.alsoUnlocks(toUnlock, scoped: true) + SessionWrites.fact(writes)
    let payload = x.challenge.payload
    return BatchPrepared(facts: facts) { auth, progress in
      /// one signature over this challenge and its answer
      func answer(_ r: Checks.Reviewed, _ text: String) async throws {
        let reason = "Approve"
        let sig: Data
        if toUnlock.isEmpty {
          sig = try await offMain { try PhoneKeys.shared.sign(text, reason: reason, auth: auth) }
        } else {
          guard let s = try await StoreUnlock.signAndUnlock(payload: text, stores: toUnlock, reason: reason, for: r.challenge.nonce, shown: writes, auth: auth) else { throw TrustError.stale("signature") }
          sig = s
        }
        let ans = try await RouterClient.shared.respond(approvalId, signature: sig)
        try Checks.answerFor(r, answer: ans.answer, coreKey: try CoreTrust.key())
      }
      guard rv.kind == .addStore else { return try await answer(rv, payload) }
      // an add-store: the challenge as it is now (another item may have put a store in first), if it is the same ask
      var (r, text) = try await currentAddStore(approvalId, read: rv, of: id, readPayload: payload, addedHere: progress.addedStores)
      do { try await answer(r, text) }
      catch {
        // made again while this one was being signed (an older router files it again only on a stale answer): once more
        guard let again = try? await currentAddStore(approvalId, read: rv, of: id, readPayload: payload, addedHere: progress.addedStores),
              again.1 != text else { throw error }
        (r, text) = again
        try await answer(r, text)
      }
      if let a = rv.addedStore { progress.addedStores.insert(a) }
    }
  }

  /// as KernelApprovalView.load / approve: the certs read strictly (KernelChecks), signed under the batch's Face ID,
  /// the session's locked stores unlocked in the kernel's secrets
  static func kernelApproval(_ x: RouterClient.ApprovalDTO, expectAddStore: RepoInto?) async throws -> BatchPrepared {
    guard let sid = x.session else { throw TrustError.mismatch("an approval for no session") }
    var facts: [SignedFact] = []
    var payloads = [x.challenge.payload]
    let want: [String]
    if x.kind == "kernel-add-store" {
      guard let second = x.earlier?.first, let store = x.options?["store"] else { throw TrustError.mismatch("an add-store without its second cert") }
      let r = try KernelChecks.add(first: x.challenge.payload, second: second.payload, session: sid, store: store)
      if let e = expectAddStore, e.store != r.store || e.session != sid { throw TrustError.mismatch("the follow-up isn't the add-store of \(e.store) to \(e.session)") }
      facts += [.init(id: "action", label: "Action", value: "Add a store (kernel)", style: .plain), .init(id: "store", label: "Store", value: r.store, style: .plain),
                .init(id: "machine", label: "Onto machine", value: r.machine, style: .code)]
      payloads.append(second.payload)
      want = [r.store]
    } else {
      if expectAddStore != nil { throw TrustError.mismatch("not the add-store asked for") }
      let r = try KernelChecks.source(payload: x.challenge.payload, session: sid)
      let attest = try await ImageAttestation.check(image: r.image, sig: x.imageSig)
      facts += [.init(id: "action", label: "Action", value: r.snapshot != nil ? "Restore (kernel)" : "New source (kernel)", style: .plain),
                .init(id: "title", label: "Title", value: r.config["label"]?.string ?? "Untitled", style: .plain),
                .init(id: "stores", label: "Stores", value: r.stores.joined(separator: ", "), style: .plain),
                .init(id: "mode", label: "Permission mode", value: r.permissionMode, style: r.permissionMode == "bypass" ? .warning : .plain),
                .init(id: "image-build", label: "Image build", value: attest.badge, style: attest == .attested ? .plain : .warning)]
      if let s = r.snapshot { facts.append(.init(id: "snapshot", label: "Snapshot sha256", value: String(s.prefix(12)) + "…", style: .code)) }
      want = r.stores
    }
    let doc = try await RouterClient.shared.kernelStores()
    let toUnlock = want.filter { n in doc.stores.contains { $0.name == n && !$0.unlocked && !$0.empty } }
    if !toUnlock.isEmpty { facts.append(.init(id: "unlocks", label: "Also unlocks (until locked)", value: toUnlock.joined(separator: ", "), style: .warning)) }
    let ps = payloads
    return BatchPrepared(facts: facts) { auth, _ in
      var sigs: [Data] = []
      for p in ps { sigs.append(try await offMain { try PhoneKeys.shared.sign(p, reason: "Approve", auth: auth) }) }
      for s in toUnlock { try await RouterClient.shared.kernelUnlock(s, reason: "Approve", auth: auth) }
      _ = try await RouterClient.shared.respond(x.id, signatures: sigs)
    }
  }

  /// an add-store's challenge as the router has it now: the one reviewed, or one made again from the session's newer
  /// cert that asks exactly the same (Checks.sameAddStore)
  static func currentAddStore(_ approvalId: String, read rv: Checks.Reviewed, of id: LineIdentity?, readPayload: String,
                              addedHere: Set<String>) async throws -> (Checks.Reviewed, String) {
    guard let x = try await RouterClient.shared.approval(approvalId) else { throw TrustError.stale("the approval (answered or rejected elsewhere)") }
    if x.challenge.payload == readPayload { return (rv, readPayload) }
    let r = try Checks.review(challenge: x.challenge, coreKey: try CoreTrust.key())
    let fid = try Checks.continues(r, coreKey: try CoreTrust.key())
    if let fid, let sid = x.session { try LinePins.check(session: sid, line: fid.line) }
    try Checks.sameAddStore(read: rv, of: id, fresh: r, of: fid, addedHere: addedHere)
    return (r, x.challenge.payload)
  }

  /// as GrantReviewView.load / allow
  static func grant(_ ask: GrantAsk, model: AppModel) async throws -> BatchPrepared {
    let c = try await RouterClient.shared.sessionCert(ask.session)
    try LinePins.check(session: ask.session, line: c.line)
    let id = LineIdentity(cert: c)
    try Checks.sameSession(id, expectedLabel: model.session(ask.session)?.j["label"].text)
    let holderKeys = try await RouterClient.shared.holders()
    let holder = Holder.all.contains { $0.id == ask.holder } ? ask.holder : ""
    let isRule = ask.kind == "rule"
    let minutes = (1...10).contains(ask.minutes) ? ask.minutes : 10
    let asked = ask.until ?? .now.addingTimeInterval(Double(GrantAsk.ruleDays) * 86400)
    let until = isRule ? min(max(asked, .now.addingTimeInterval(3600)), .now.addingTimeInterval(366 * 86400)) : .now.addingTimeInterval(Double(minutes * 60))
    var refusal: String?
    if holder.isEmpty { refusal = "Unknown feature" }
    else if isRule && c.sensitive == true { refusal = "Sensitive session: no standing rule" }
    else if holderKeys[holder] == nil { refusal = "No key listed for this feature" }
    let facts = SignedAction.grant(feature: Holder.title(holder), allows: Holder.sub(holder), minutes: isRule ? nil : minutes, until: until, line: c.line, of: id)
    return BatchPrepared(facts: facts, refusal: refusal) { auth, _ in
      guard let hk = holderKeys[holder] else { throw TrustError.stale("the feature's key") }
      let phone = try PhoneKeys.shared.publicKeys().signingKey
      var body: [String: Any] = ["holder": holder, "kind": ask.kind]
      if isRule {
        let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime]
        body["until"] = f.string(from: until)
      } else { body["minutes"] = minutes }
      let text = try await RouterClient.shared.draftGrant(ask.session, body)
      _ = try Checks.reviewGrant(text: text, cert: c, phoneKey: phone, holderKey: hk, kind: ask.kind, minutes: minutes, until: until)
      let reason = "Allow \(Holder.title(holder))"
      let sig = try await offMain { try PhoneKeys.shared.sign(text, reason: reason, auth: auth) }
      let g = try await RouterClient.shared.addGrant(ask.session, payload: text, sig: sig)
      guard g.holder == holder, g.kind == ask.kind else { throw TrustError.stale("the stored grant") }
    }
  }

  /// as UnlockReviewView.load / allow
  static func unlock(_ sessionId: String, model: AppModel) async throws -> BatchPrepared {
    let c = try await RouterClient.shared.sessionCert(sessionId)
    try LinePins.check(session: sessionId, line: c.line)
    let id = LineIdentity(cert: c)
    try Checks.sameSession(id, expectedLabel: model.session(sessionId)?.j["label"].text)
    let doc = try await RouterClient.shared.storesDoc()
    let scoped = !(c.nonce ?? "").isEmpty
    let nonce = scoped ? c.nonce : nil
    let certStores = (c.stores ?? []).filter { $0 != StoreView.coreStore }
    let locked = certStores.filter { n in doc.stores.contains { $0.name == n && !$0.unlocked && !$0.empty } }
    let writes = await SessionWrites.load(locked)
    return BatchPrepared(facts: SignedAction.unlock(stores: locked, session: id, scoped: scoped) + SessionWrites.fact(writes), refusal: locked.isEmpty ? "Nothing locked" : nil) { auth, _ in
      // for the session's cert as it is now: an add-store earlier in the batch gives it a new cert (and nonce)
      var forNonce = nonce, stores = locked
      if scoped {
        let now = try await RouterClient.shared.sessionCert(sessionId)
        guard now.line == c.line else { throw TrustError.stale("the session's cert") }
        forNonce = now.nonce
        stores = locked.filter { (now.stores ?? []).contains($0) }
      }
      guard !stores.isEmpty else { return }
      _ = try await StoreUnlock.signAndUnlock(payload: nil, stores: stores, reason: "Unlock \(stores.joined(separator: ", "))", for: forNonce, shown: writes, auth: auth)
    }
  }

  /// as RepoKeyView.begin / go (the sensitivity asked for; Jarvis 4's own repo always sensitive). A repo a session asked
  /// for (into): the add-store the router files once the key is made is signed under the same Face ID
  static func repoKey(_ action: String, _ repo: String, _ sensitiveAsked: Bool, inbox: String? = nil, into: RepoInto? = nil,
                      model: AppModel) async throws -> BatchPrepared {
    let want = sensitiveAsked || repo.lowercased() == "de0ch/jarvis2"
    let r = try await RouterClient.shared.deployKeyBegin(action: action, repo: repo, sensitive: want)
    let payload = r.doc.payload, b = r.begin
    let e = b.e
    let into = action == "add" && into?.store == b.store ? into : nil
    return BatchPrepared(facts: SignedAction.deployKey(b) + (into.map { SignedAction.repoInto($0, store: b.store) } ?? [])) { auth, progress in
      let reason = (action == "add" ? "Add repo" : "Remove repo") + ": \(b.repo)"
      let x = try await offMain { try PhoneKeys.shared.signAndShare(payload, e: e, reason: reason, auth: auth) }
      let f = try await RouterClient.shared.deployKeyFinish(b, signature: x.signature, share: x.share, inbox: into == nil ? nil : inbox)
      if let into { try await repoFollowups(f.followups, into: into, model: model, auth: auth, progress: progress) }
    }
  }

  /// the add-store a repo's finish brought about, checked to be exactly the one shown, signed under the same Face ID
  static func repoFollowups(_ ids: [String], into: RepoInto, model: AppModel, auth: PhoneAuth, progress: BatchProgress) async throws {
    for id in ids {
      let p = try await approval(id, model: model, expectAddStore: into)
      try await p.run(auth, progress)
    }
  }

  /// an API call (router apicalls.go): no signature, Approve runs it as Deyao. What it brings about (a resume's
  /// approval) wasn't shown before the batch's Face ID, so it opens on its own page afterwards (BatchReviewView)
  static func apiCall(_ it: InboxItem, id: String) -> BatchPrepared {
    let p = it.params
    var facts: [SignedFact] = [.init(id: "kind", label: "Kind", value: "API call, runs as you (no signature)"),
                               .init(id: "call", label: "Runs", value: "\(p["method"].string ?? "") \(p["path"].string ?? "")", style: .code)]
    if let d = it.does { facts.insert(.init(id: "does", label: "Does", value: d), at: 0) }
    if let b = p["body"].text { facts.append(.init(id: "body", label: "Body", value: APICallReviewView.pretty(b), style: .code)) }
    return BatchPrepared(facts: facts) { _, progress in
      let out = try await RouterClient.shared.inboxApproveCall(id)
      guard out["ok"].bool == true else { throw RouterError(message: out["error"].text ?? "The call didn't run.") }
      progress.calls[id] = out
    }
  }
}

@MainActor
extension BatchPrepare {
  /// an upward peer message a session filed in its batch (router peermsg.go): nothing signed; Allow delivers it, as
  /// the Inbox row's Deliver does (POST api/requests/:id/approve)
  static func peerMessage(_ it: InboxItem) -> BatchPrepared {
    let o = it.openOptions
    let facts: [SignedFact] = [
      .init(id: "kind", label: "Kind", value: "Peer message, delivered as is (no signature)"),
      .init(id: "from", label: "From", value: o["fromName"].text ?? o["from"].text ?? it.callerText),
      .init(id: "to", label: "To", value: it.sessionName ?? it.session ?? "?"),
      .init(id: "text", label: "Message", value: it.params["text"].string ?? ""),
    ]
    return BatchPrepared(facts: facts) { _, _ in
      let out = try await RouterClient.shared.inboxApproveCall(it.id)
      guard out["ok"].bool == true else { throw RouterError(message: out["error"].text ?? "The message wasn't delivered.") }
    }
  }
}

/// an API call this batch approved that brought about (or may still bring about) a core request
struct BatchCallRun: Identifiable {
  let item: InboxItem
  let out: JSON
  var id: String { item.id }
}

struct BatchReviewView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
  let batchId: String
  @State private var batch: InboxBatch?
  @State private var items: [InboxItem] = []
  @State private var prepared: [String: BatchPrepared] = [:]
  @State private var loadErrors: [String: String] = [:]
  /// per item after Allow all: "Allowed" or the error
  @State private var outcome: [String: Result<Void, Error>] = [:]
  @State private var gone = false
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?
  /// the API calls Allow all approved whose follow-ups wait: each opens its sheet in place (its own Face ID)
  @State private var calls: [BatchCallRun] = []

  private var open: [InboxItem] { items.filter { !isDone($0) } }
  private func isDone(_ it: InboxItem) -> Bool { if case .success? = outcome[it.id] { return true }; return false }
  /// every item still to sign is read and signable, and no approval is still being made
  private var ready: Bool {
    !open.isEmpty && (batch?.preparing ?? 0) == 0 && open.allSatisfy { prepared[$0.id] != nil && prepared[$0.id]?.refusal == nil && loadErrors[$0.id] == nil }
  }
  private var allowTitle: String { outcome.values.contains { if case .failure = $0 { return true }; return false } ? "Retry" : "Allow all" }

  var body: some View {
    Form {
      if let loadError { Section { ErrorRow(text: loadError, id: "secure-error") } }
      else if gone {
        Section { Label("No longer in the Inbox", systemImage: "tray").foregroundStyle(.orange).accessibilityElement(children: .combine).accessibilityIdentifier("request-gone") }
      } else if let batch {
        Section {
          LabeledContent("Caller", value: batch.callerText).accessibilityIdentifier("batch-caller")
          Text(batch.callLine).font(.footnote.monospaced()).textSelection(.enabled).accessibilityIdentifier("batch-call")
          LabeledContent("Items", value: "\(items.count)").accessibilityIdentifier("batch-count")
          if batch.preparing > 0 {
            LabeledContent("Being prepared") { HStack { Text("\(batch.preparing)"); ProgressView() } }
              .accessibilityElement(children: .combine).accessibilityIdentifier("batch-preparing")
          }
          if let e = batch.expires { LabeledContent("Expires", value: Fmt.when(e)) }
        } header: { Label("Requested via (router)", systemImage: "arrow.left.arrow.right") }
        Section {
          if batch.summary.isEmpty {
            Text("None given").foregroundStyle(.secondary).accessibilityIdentifier("batch-summary")
          } else {
            Text(batch.summary)
              .italic()
              .padding(.leading, 10)
              .overlay(alignment: .leading) { Rectangle().fill(.orange.opacity(0.6)).frame(width: 2) }
              .textSelection(.enabled)
              .accessibilityIdentifier("batch-summary")
          }
        } header: {
          Label("Summary (unverified)", systemImage: "quote.bubble")
        } footer: {
          Text("Written by the caller. Each item below shows what you sign.")
        }
        ForEach(Array(items.enumerated()), id: \.element.id) { n, it in itemSection(n + 1, it) }
        if !calls.isEmpty {
          Section {
            ForEach(calls) { c in
              NavigationLink {
                APICallReviewView(callId: c.item.id, approved: (c.item, c.out))
              } label: {
                Text("\(c.item.params["method"].string ?? "") \(c.item.params["path"].string ?? "")").font(.footnote.monospaced())
              }
              .accessibilityIdentifier("batch-call-followups-\(c.item.id)")
            }
          } header: { Text("What the API calls bring about") } footer: {
            Text("Each opens its own page: what you sign, under Face ID (it wasn't shown before this batch's Face ID).")
          }
        }
        Section {
          Button(busy == "Denying…" ? "Denying…" : "Deny all", role: .destructive) { Task { await denyAll() } }
            .disabled(busy != nil).accessibilityIdentifier("batch-deny")
          if let failure { ErrorRow(text: failure, id: "secure-error") }
          SigningFooter()
        } footer: {
          Text("Allow all signs every item, each on its own, under one Face ID.")
        }
      } else {
        Section { ProgressView() }
      }
    }
    .navigationTitle("Batch")
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy != nil).accessibilityIdentifier("secure-back") }
      ToolbarItem(placement: .confirmationAction) {
        if open.isEmpty && !calls.isEmpty {
          Button("Done") { model.secureCompleted(true) }.accessibilityIdentifier("batch-done")
        } else {
          Button(busy ?? allowTitle) { Task { await allowAll() } }.disabled(!ready || busy != nil).accessibilityIdentifier("batch-allow")
        }
      }
    }
    .interactiveDismissDisabled(busy != nil)
    .task { await load() }
  }

  @ViewBuilder private func itemSection(_ n: Int, _ it: InboxItem) -> some View {
    Section {
      if let e = loadErrors[it.id] { ErrorRow(text: e, id: "batch-item-error-\(n)") }
      else if let p = prepared[it.id] {
        if let r = p.refusal {
          Label(r, systemImage: "hand.raised").foregroundStyle(.orange).accessibilityElement(children: .combine).accessibilityIdentifier("batch-item-refused-\(n)")
        }
        DisclosureGroup {
          ForEach(p.facts) { SignedFactRow(fact: $0) }
        } label: {
          Label("What you sign (exact)", systemImage: "signature")
        }
        .accessibilityIdentifier("batch-item-signed-\(n)")
      } else {
        LabeledContent("Reading") { ProgressView() }
      }
      Text(it.callLine).font(.footnote.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
      if !it.explanation.isEmpty {
        Text(it.explanation).italic().foregroundStyle(.secondary).accessibilityIdentifier("batch-item-reason-\(n)")
      }
      if !isDone(it) {
        Button("Deny this one", role: .destructive) { Task { await denyOne(it) } }.disabled(busy != nil).accessibilityIdentifier("batch-item-deny-\(n)")
      }
    } header: {
      HStack {
        Text("\(n). \(it.actionTitle)")
        Spacer()
        switch outcome[it.id] {
        case .some(.success): StatusPill(text: "Allowed", color: .green)
        case .some(.failure): StatusPill(text: "Failed", color: .red)
        case .none: EmptyView()
        }
      }
      .accessibilityElement(children: .combine)
      .accessibilityIdentifier("batch-item-\(n)")
    } footer: {
      if case .failure(let e)? = outcome[it.id] { Text(errText(e)).foregroundStyle(.red).accessibilityIdentifier("batch-item-failure-\(n)") }
    }
  }

  /// the batch and its items; each item still to sign is read and checked as its own page would (again on Retry)
  private func load() async {
    do {
      // a new session's approval comes a moment after it was filed: wait for it (up to a minute)
      var got = try await RouterClient.shared.inboxBatch(batchId)
      let until = Date.now.addingTimeInterval(60)
      while let g = got, g.batch.preparing > 0, Date.now < until {
        batch = g.batch; items = g.items
        try? await Task.sleep(for: .seconds(2))
        got = try await RouterClient.shared.inboxBatch(batchId)
      }
      guard let g = got else { if outcome.isEmpty { gone = true } else { model.secureCompleted(true) }; return }
      batch = g.batch
      // items that went through stay listed (Allowed) until the page closes
      let done = items.filter(isDone)
      items = done + g.items.filter { x in !done.contains { $0.id == x.id } }
      for it in g.items where !isDone(it) {
        loadErrors[it.id] = nil
        do { prepared[it.id] = try await BatchPrepare.load(it, model: model) }
        catch { prepared[it.id] = nil; loadErrors[it.id] = errText(error) }
      }
    } catch { loadError = errText(error) }
  }

  private func allowAll() async {
    failure = nil
    let todo = open
    guard !todo.isEmpty else { return }
    if outcome.values.contains(where: { if case .failure = $0 { return true }; return false }) {
      // Retry: the failed items read and checked afresh first (a deploy key's begin is spent on any failure)
      busy = "Reading…"
      for it in todo { outcome[it.id] = nil }
      await load()
      busy = nil
      guard ready else { return }
    }
    let runs = open.compactMap { it in prepared[it.id].map { (it, $0) } }
    do {
      busy = "Face ID…"
      let n = runs.count
      let auth = try await offMain { try PhoneKeys.shared.authorize(reason: "Allow \(n) requests") }
      defer { auth.invalidate() }
      let progress = BatchProgress()
      for (i, (it, p)) in runs.enumerated() {
        busy = "Signing \(i + 1) of \(n)…"
        do {
          try await p.run(auth, progress)
          outcome[it.id] = .success(())
          if !it.isApproval { await RouterClient.shared.inboxDone(it.id) }
        } catch { outcome[it.id] = .failure(error) }
      }
      busy = nil
      calls += runs.compactMap { run -> BatchCallRun? in
        let it = run.0
        guard let o = progress.calls[it.id], !o["followups"].array.isEmpty || o["awaiting"]["until"].string != nil else { return nil }
        return BatchCallRun(item: it, out: o)
      }
      if open.isEmpty && calls.isEmpty { model.secureCompleted(true) }
      else if !open.isEmpty { failure = "Some items failed; the others went through." }
    } catch { busy = nil; failure = errText(error) }
  }

  private func denyAll() async {
    do { busy = "Denying…"; try await RouterClient.shared.inboxDenyBatch(batchId); busy = nil; model.secureCompleted(true) }
    catch { busy = nil; failure = errText(error) }
  }

  private func denyOne(_ it: InboxItem) async {
    do {
      busy = "Denying…"
      try await RouterClient.shared.inboxDeny(it.id)
      busy = nil
      items.removeAll { $0.id == it.id }
      prepared[it.id] = nil
      if items.isEmpty { model.secureCompleted(true) }
    } catch { busy = nil; failure = errText(error) }
  }
}

extension InboxItem {
  /// the core action (or phone grant) the entry leads to: a fixed name per kind
  var actionTitle: String {
    let p = params
    switch kind {
    case "repo-key": return p["action"].string == "remove" ? "Remove deploy key" : "Add deploy key"
    case "grant": return (p["days"].int ?? 0) > 0 ? "Standing rule" : "Grant"
    case "unlock": return "Unlock stores"
    case "add-store": return "Add a store"
    case "kernel-source": return j["options"]["restore"].text != nil ? "Restore (kernel)" : "New source (kernel)"
    case "kernel-add-store": return "Add a store (kernel)"
    case "resume-upgrade": return "Resume on the latest image"
    case "api-call": return "API call"
    case "restore": return "Restore store"
    case "peer-message": return "Peer message"
    case "message": return "Deliver a message"
    case "new-session": return j["options"]["restore"].text != nil ? "Restore" : "New session"
    // a kind this build doesn't know (router/inbox_kinds_test.go keeps the list in step): say so, never guess
    default: return "Unknown request (\(kind)): update the app"
    }
  }
}
