// Settings → Kernel (DESIGN "Target design", docs/PLAN-cluster.md "The roster", docs/PLAN-grants.md §5): the kernel's
// components make fresh keys in RAM at every start; nobody vouches for them until the root key (a second Secure Enclave
// key of this iPhone) signs the kernel's roster. Setting it up on this iPhone:
//   0. Register the root key: its public half goes to the router (no Face ID), and a setup session commits it as
//      keys/root.pub, which every component checks the roster against.
//   1. Recover its secrets from the recovery kit (Jarvis 2's backups, the same kit): every store, wrapped here to
//      secrets' store key; secrets' keys derived from the kit (kernel labels), so a later Recover brings back the same
//      secrets. Before the claim, secrets' boot keys are checked against the setup session's pending roster; after it,
//      the root key signs that roster with secrets' derived keys in place of its boot keys (its own Face ID).
//   2. Sign the kernel's components: whenever the setup session files a new roster (a component restarted, a release),
//      the root key signs it after this page checked the setup key's signature and shows the members, the retired keys
//      (earlier keys whose signatures still count) and, for the copy a release landed on, the empty secrets that takes
//      over; that signature is the release's one Face ID (the router then flips the kernel to that copy).
//   3. Sign the root grant (⊤ on the sink) with the root key, behind its own warning: every kernel session's
//      permissions narrow from it. From then on new sessions start on the kernel.
import SwiftUI

struct KernelSetupView: View {
  @Environment(AppModel.self) private var model
  @State private var status: RouterClient.KernelStatus?
  @State private var keys: PublicKeys?
  @State private var state: KernelSetup.State?
  @State private var kitText = ""
  @State private var busy: String?
  @State private var failure: String?
  @State private var warnRoot = false
  @State private var warnRoster = false
  /// the root key's public half; whether keys/root.pub in git is it
  @State private var rootKey: String?
  @State private var rootInGit: Bool?
  /// the roster the components hold (root-signed) and the one the setup session filed (setup-signed), both checked
  @State private var roster: KernelRoster.Roster?
  @State private var pending: KernelRoster.Roster?
  /// secrets that answer unclaimed (serving, next), with the keys they name
  @State private var unclaimed: [PublicKeys] = []

  private var mine: Bool { state.map { !$0.master.isEmpty } ?? false && KernelTrust.pinned == keys }
  /// a pending roster the root key hasn't signed yet
  private var pendingNew: KernelRoster.Roster? { pending.flatMap { $0 == roster ? nil : $0 } }

  var body: some View {
    Form {
      Section {
        LabeledContent("On this box") { StatusPill(text: status?.configured == true ? "Yes" : "Not yet", color: status?.configured == true ? .green : .secondary) }
          .accessibilityElement(children: .combine).accessibilityIdentifier("kernel-configured")
        LabeledContent("Components") {
          StatusPill(text: roster != nil ? "Signed (\(roster!.copy))" : pending != nil ? "Waiting for you" : "Not read yet",
                     color: roster != nil ? .green : pending != nil ? .orange : .secondary)
        }
        .accessibilityElement(children: .combine).accessibilityIdentifier("kernel-roster")
        if let serving = status?.roster?.serving {
          LabeledContent("Serving copy") { Text(status?.roster?.next.map { "\(serving), \($0.copy) taking over" } ?? serving) }
            .accessibilityElement(children: .combine).accessibilityIdentifier("kernel-copy")
        }
        if let state {
          LabeledContent("Secrets") { StatusPill(text: state.master.isEmpty ? "Empty" : mine ? "Set up" : "Set up elsewhere", color: mine ? .green : .orange) }
            .accessibilityElement(children: .combine).accessibilityIdentifier("kernel-secrets")
        }
        LabeledContent("Root grant") { StatusPill(text: status?.root == true ? "Signed" : "Not yet", color: status?.root == true ? .green : .secondary) }
          .accessibilityElement(children: .combine).accessibilityIdentifier("kernel-root")
        LabeledContent("New sessions") { Text(status?.serves == true ? "On the kernel" : status?.core == false ? "Not yet" : "On the core") }
      } footer: {
        Text((status?.core == false ? "Jarvis 4 runs the kernel only. " : "The kernel runs beside the core. ") +
             "Its components make new keys whenever they start, and work only once this iPhone's root key has signed them.")
      }

      Section {
        LabeledContent("Root key") { Text(rootKey.map(Self.fingerprint) ?? "…").font(.footnote.monospaced()) }
        LabeledContent("In git (keys/root.pub)") {
          StatusPill(text: rootInGit == true ? "Yes" : rootInGit == false ? "Not yet" : "…", color: rootInGit == true ? .green : .secondary)
        }
        .accessibilityElement(children: .combine).accessibilityIdentifier("kernel-root-key-git")
        LabeledContent("With the router") {
          StatusPill(text: status?.roster?.rootKey == true ? "Registered" : "Not yet", color: status?.roster?.rootKey == true ? .green : .secondary)
        }
        .accessibilityElement(children: .combine).accessibilityIdentifier("kernel-root-key-router")
        if rootInGit == false {
          Button(busy == "Registering…" ? "Registering…" : status?.roster?.rootKey == true ? "Register the root key again" : "Register the root key") { Task { await registerRoot() } }
            .disabled(busy != nil || rootKey == nil).accessibilityIdentifier("kernel-root-register")
        }
      } header: { Text("Root key") } footer: {
        Text(rootInGit == true ? "Every component checks its roster against this key." :
             "The router passes the root key's public half to a setup session, which commits it to git. Every component checks its roster against it.")
      }

      if status?.configured == true, KernelTrust.pinned == nil, state?.master.isEmpty ?? true {
        Section {
          SecureField("Recovery kit", text: $kitText).textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityIdentifier("kernel-kit")
          Button(busy ?? "Recover the kernel's secrets") { Task { await recover() } }
            .disabled(kitText.isEmpty || busy != nil || pending == nil || keys == nil || rootInGit != true).accessibilityIdentifier("kernel-recover")
        } header: { Text("Step 1") } footer: {
          Text(rootInGit != true ? "Waiting for the root key to be in git." : pending == nil ? "Waiting for a setup session to read the kernel's components." :
               "Every store comes back from the backups, opened here with your kit. The kit never leaves this iPhone. Then the root key signs the kernel's components, with its own Face ID.")
        }
      }

      // an empty secrets is signed into the roster by its Recover (with the keys the kit derives), not before
      if let p = pendingNew, KernelTrust.pinned != nil || state?.master.isEmpty == false { rosterSection(p) }

      if mine, roster != nil, status?.root == false {
        Section {
          Button(busy ?? "Sign the root grant…", systemImage: "exclamationmark.octagon") { warnRoot = true }.disabled(busy != nil).accessibilityIdentifier("kernel-root-sign")
        } header: { Text("Step 2") } footer: {
          Text("The root key is a second key in this iPhone's Secure Enclave. It signs the one grant every kernel session's permissions come from.")
        }
      }
      if let failure { Section { ErrorRow(text: failure, id: "kernel-error") } }
    }
    .navigationTitle("Kernel")
    .task { await load() }
    .refreshable { await load() }
    .confirmationDialog("Sign with the root key?", isPresented: $warnRoot, titleVisibility: .visible) {
      Button("Sign the root grant", role: .destructive) { Task { await signRoot() } }.accessibilityIdentifier("kernel-root-confirm")
    } message: {
      Text("The root key can approve anything on the kernel. This grant is everything the kernel's sessions may ever be given; each session gets only what you approve for it.")
    }
    .confirmationDialog("Sign the kernel's components?", isPresented: $warnRoster, titleVisibility: .visible) {
      Button("Sign with the root key") { Task { await signRoster() } }.accessibilityIdentifier("kernel-roster-confirm")
    } message: {
      Text("The components trust each other, and this iPhone trusts them, only with the keys listed here. A setup session read them from the cluster and signed the list with the setup key.")
    }
  }

  @ViewBuilder private func rosterSection(_ p: KernelRoster.Roster) -> some View {
    Section {
      ForEach(p.members, id: \.role) { m in
        LabeledContent {
          Text(Self.fingerprint(m.signingKey)).font(.footnote.monospaced())
        } label: {
          VStack(alignment: .leading) {
            Text(m.role)
            if m.role == "secrets" { Text(m.keys == KernelTrust.pinned ? "the keys your kit derives" : "an empty secrets").font(.caption).foregroundStyle(.secondary) }
          }
        }
        .accessibilityElement(children: .combine).accessibilityIdentifier("kernel-member-\(m.role)")
      }
      if let b = p.secretsBoot {
        LabeledContent {
          Text(Self.fingerprint(b.signingKey)).font(.footnote.monospaced())
        } label: {
          VStack(alignment: .leading) { Text("secrets (empty)"); Text("takes over from the serving copy").font(.caption).foregroundStyle(.secondary) }
        }
        .accessibilityElement(children: .combine).accessibilityIdentifier("kernel-secrets-boot")
      }
      ForEach(p.retired, id: \.signingKey) { m in
        LabeledContent {
          Text(Self.fingerprint(m.signingKey)).font(.footnote.monospaced())
        } label: {
          VStack(alignment: .leading) { Text(m.role); Text("retired: what it signed still counts").font(.caption).foregroundStyle(.secondary) }
        }
        .accessibilityElement(children: .combine).accessibilityIdentifier("kernel-retired-\(m.role)")
      }
      Button(busy ?? "Sign the kernel's components…") { warnRoster = true }
        .disabled(busy != nil || rootInGit != true || (try? KernelSetup.signable(p, pinned: KernelTrust.pinned, unclaimed: unclaimed, current: roster)) == nil)
        .accessibilityIdentifier("kernel-roster-sign")
    } header: { Text("Kernel components (\(p.copy))") } footer: {
      Text(roster.map { $0.copy != p.copy } == true ?
           "A release landed on the \(p.copy) copy. Once signed, the \(roster?.copy ?? "") copy hands everything over to it and the router switches to it; nothing stops. Checked against the setup key in git; the root key signs exactly this list, with its own Face ID." :
           "Checked against the setup key in git. The root key signs exactly this list, with its own Face ID.")
    }
  }

  /// a key as a short fingerprint: its sha256, first 12 hex digits
  static func fingerprint(_ key: String) -> String { String(CoreCrypto.sha256hex(Data(key.utf8)).prefix(12)) }

  private func load() async {
    failure = nil
    do {
      let rk = try await offMain { try RootKey.shared.publicKey() }
      rootKey = rk
      rootInGit = (try? await KeySource.optionalKey("root.pub")).map { $0 == rk } ?? false
      status = try await RouterClient.shared.kernelStatus()
      guard status?.configured == true else { return }
      let setupKey = try await KeySource.key("setup.pub")
      // a roster the root key signed is read only once git has the root key the components check it against
      if rootInGit == true { roster = try await RouterClient.shared.kernelRoster(rootKey: rk) } else { roster = nil }
      pending = try await RouterClient.shared.kernelPendingRoster().map { try KernelRoster.pending($0, setupKey: setupKey) }
      // secrets' identity: only once something vouches for it (this iPhone's pin, the root key's roster, the setup
      // session's pending roster); until then the page waits on the steps above
      let anchors = KernelSetup.Anchors(pinned: KernelTrust.pinned, roster: roster, pending: pending)
      if anchors.pinned != nil || anchors.roster != nil || anchors.pending != nil {
        let r = try await RouterClient.shared.kernelIdentity(anchors)
        keys = r.keys; state = r.state
      } else { keys = nil; state = nil }
      var u: [PublicKeys] = []
      for next in [false, true] {
        if let id = try? await RouterClient.shared.json("GET", "api/kernel/secrets/identity" + (next ? "?secrets=next" : ""), as: KernelSetup.Identity.self),
           let k = KernelSetup.unclaimed(id) { u.append(k) }
      }
      unclaimed = u
    } catch { failure = errText(error) }
  }

  private func registerRoot() async {
    failure = nil
    do {
      busy = "Registering…"
      guard let rk = rootKey else { return }
      try await RouterClient.shared.kernelRegisterRootKey(rk)
      busy = nil
      await load()
    } catch { busy = nil; failure = errText(error) }
  }

  /// the root key signs exactly r's payload (its own Face ID) and the router hands it to every component
  private func sign(_ r: KernelRoster.Roster) async throws {
    try KernelSetup.signable(r, pinned: KernelTrust.pinned, unclaimed: unclaimed, current: roster)
    let payload = r.payload
    busy = "Signing the kernel's components…"
    let sig = try await offMain { try RootKey.shared.sign(payload, reason: "Sign the kernel's components") }
    try await RouterClient.shared.kernelPostRoster(payload, rootSig: sig)
    roster = r
  }

  private func signRoster() async {
    failure = nil
    do {
      guard let p = pendingNew else { return }
      try await sign(p)
      busy = nil
      await load()
    } catch { busy = nil; failure = errText(error) }
  }

  private func recover() async {
    failure = nil
    do {
      guard let k = keys else { return }
      guard let p = pending, p.member("secrets") == k else {
        throw TrustError.mismatch("the setup session's roster doesn't name this secrets: ask a setup session to read the kernel's components again")
      }
      busy = "Checking the kit…"
      let m = try RecoveryKit.parse(kitText).master
      if let cm = CoreTrust.master, !m.matches(cm) { throw TrustError.badKit("This isn't the recovery kit Jarvis 4 is set up with.") }
      busy = "Reading the backups…"
      // Jarvis 2's backups: the setup key signed them, the box key vouched for the core that wrote them (keys/*.pub);
      // every store's backup opens only with the kit they were sealed to, which is how a box with no core checks the kit
      let setupKey = try await KeySource.key("setup.pub"), boxKey = try await KeySource.key("box.pub")
      let stores = try CoreSetup.readBackups(try await RouterClient.shared.backups(), master: m, setupKey: setupKey, boxKey: boxKey)
      guard !stores.isEmpty else { throw TrustError.backup("The backups hold no store, so this kit can't be checked against them.") }
      busy = "Setting up the kernel…"
      let seed = KernelContinuity.seed(m)
      let derived = try KernelContinuity.keys(seed: seed)
      // the deploy-key stores an earlier secrets from the same kit kept (no backup): its line state, checked as the core's
      var line: CoreSetup.LineStateDoc?
      if let l = try await RouterClient.shared.kernelLineState(), CoreSetup.lineStateSigned(l, coreKey: derived.signingKey) {
        _ = try CoreSetup.checkLineState(l, coreKey: derived.signingKey, atLeast: LineWitness.seen(derived.signingKey))
        line = l
      }
      let sk = try RouterClient.shared.kernelStoreKey(secrets: derived.agreementKey)
      let bundle = try KernelSetup.bundle(stores, storeKey: sk, seed: seed, lineState: line)
      let body = try KernelSetup.claim(secrets: k, phone: try PhoneKeys.shared.publicKeys(), root: try RootKey.shared.publicKey(), master: m, bundle: bundle,
                                       identity: derived)
      try await RouterClient.shared.kernelClaim(body, derived: derived)
      KernelTrust.pin(derived) // the same kit derives the same keys: both kernel copies' secrets are one identity
      if CoreTrust.master == nil { CoreTrust.setMaster(m.publicKey) }
      // the root key signs the setup session's roster with the keys secrets serves with now
      let r = try KernelRoster.replacing(p, role: "secrets", with: derived)
      try await sign(r)
      // the spawner's Fly token comes with the Recover, as the old core's did (the core store's backup)
      if let tok = stores.first(where: { $0.name == StoreView.coreStore })?.values["FLY_API_TOKEN"] {
        busy = "Giving the spawner its Fly token…"
        try await RouterClient.shared.kernelSpawnerToken(tok, roster: r)
      }
      LineWitness.saw(derived.signingKey, try? await RouterClient.shared.kernelIdentity(KernelSetup.Anchors(pinned: derived)).state.lineSeq)
      kitText = ""; busy = nil
      await load()
    } catch { busy = nil; failure = errText(error) }
  }

  private func signRoot() async {
    failure = nil
    do {
      busy = "Signing…"
      let payload = try await RouterClient.shared.rootGrantDraft()
      let sig = try await offMain { try RootKey.shared.sign(payload, reason: "Sign the kernel's root grant") }
      try await RouterClient.shared.postRootGrant(payload, signature: sig)
      busy = nil
      await load()
    } catch { busy = nil; failure = errText(error) }
  }
}
