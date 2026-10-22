// Settings → Kernel (DESIGN "Target design", docs/PLAN-grants.md §5): the kernel runs beside the old core with keys of
// its own. Setting it up takes two steps on this iPhone:
//   1. Recover its secrets from the recovery kit: every store from the backups, wrapped here to secrets' store key; its
//      keys derived from the kit (kernel labels), so a later Recover brings back the same secrets; this iPhone's keys
//      and the root key's public half named in the claim the master key signs.
//   2. Sign the root grant (⊤ on the sink) with the root key, behind its own warning: every kernel session's
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
  /// the next secrets (blue/green): its state, when it answers
  @State private var nextState: KernelSetup.State?
  @State private var nextKeys: PublicKeys?

  private var mine: Bool { state.map { !$0.master.isEmpty } ?? false && KernelTrust.pinned == keys }

  var body: some View {
    Form {
      Section {
        LabeledContent("On this box") { StatusPill(text: status?.configured == true ? "Yes" : "Not yet", color: status?.configured == true ? .green : .secondary) }
          .accessibilityElement(children: .combine).accessibilityIdentifier("kernel-configured")
        if let state {
          LabeledContent("Secrets") { StatusPill(text: state.master.isEmpty ? "Empty" : mine ? "Set up" : "Set up elsewhere", color: mine ? .green : .orange) }
            .accessibilityElement(children: .combine).accessibilityIdentifier("kernel-secrets")
        }
        LabeledContent("Root grant") { StatusPill(text: status?.root == true ? "Signed" : "Not yet", color: status?.root == true ? .green : .secondary) }
          .accessibilityElement(children: .combine).accessibilityIdentifier("kernel-root")
        LabeledContent("New sessions") { Text(status?.serves == true ? "On the kernel" : "On the core") }
      } footer: {
        Text("The kernel runs beside the core, with keys of its own. Sessions already on the core stay there until they are destroyed.")
      }
      if status?.configured == true, let state, state.master.isEmpty {
        Section {
          SecureField("Recovery kit", text: $kitText).textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityIdentifier("kernel-kit")
          Button(busy ?? "Recover the kernel's secrets") { Task { await recover() } }.disabled(kitText.isEmpty || busy != nil).accessibilityIdentifier("kernel-recover")
        } header: { Text("Step 1") } footer: {
          Text("Every store comes back from the backups, opened here with your kit. The kit never leaves this iPhone.")
        }
      }
      if mine, let ns = nextState, ns.master.isEmpty {
        Section {
          SecureField("Recovery kit", text: $kitText).textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityIdentifier("kernel-next-kit")
          Button(busy ?? "Recover alongside") { Task { await recover(next: true) } }.disabled(kitText.isEmpty || busy != nil).accessibilityIdentifier("kernel-recover-next")
        } header: { Text("Next secrets") } footer: {
          Text("A release of the kernel's secrets runs next to the serving one. Recovered alongside with the same kit, it takes over when the router flips, with the stores' unlocks as they are.")
        }
      } else if mine, let ns = nextState, ns.serving == "standby" {
        Section("Next secrets") { LabeledContent("State") { StatusPill(text: "Standby", color: .green) } }
      }
      if mine, status?.root == false {
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
  }

  private func load() async {
    failure = nil
    do {
      status = try await RouterClient.shared.kernelStatus()
      if status?.configured == true {
        let box = try await KeySource.key("box.pub")
        let r = try await RouterClient.shared.kernelIdentity(boxKey: box)
        keys = r.keys; state = r.state
        if let n = try? await RouterClient.shared.kernelIdentity(boxKey: box, next: true) { nextKeys = n.keys; nextState = n.state } else { nextKeys = nil; nextState = nil }
      }
    } catch { failure = errText(error) }
  }

  private func recover(next: Bool = false) async {
    failure = nil
    do {
      guard let k = next ? nextKeys : keys else { return }
      busy = "Checking the kit…"
      let m = try RecoveryKit.parse(kitText).master
      guard let cm = CoreTrust.master, m.matches(cm) else { throw TrustError.badKit("This isn't the recovery kit Jarvis 4 is set up with.") }
      busy = "Reading the backups…"
      let setupKey = try await KeySource.key("setup.pub"), boxKey = try await KeySource.key("box.pub")
      let stores = try CoreSetup.readBackups(try await RouterClient.shared.backups(), master: m, setupKey: setupKey, boxKey: boxKey)
      busy = "Setting up the kernel…"
      let seed = KernelContinuity.seed(m)
      let derived = try KernelContinuity.keys(seed: seed)
      // the deploy-key stores an earlier secrets from the same kit kept (no backup): its line state, checked as the core's
      var line: CoreSetup.LineStateDoc?
      if let l = try await RouterClient.shared.kernelLineState(), CoreSetup.lineStateSigned(l, coreKey: derived.signingKey) {
        _ = try CoreSetup.checkLineState(l, coreKey: derived.signingKey, atLeast: LineWitness.seen(derived.signingKey))
        line = l
      }
      let sk = try await RouterClient.shared.kernelStoreKey(signedBy: k.signingKey, secrets: derived.agreementKey, next: next)
      let bundle = try KernelSetup.bundle(stores, storeKey: sk, seed: seed, lineState: line)
      let body = try KernelSetup.claim(secrets: k, phone: try PhoneKeys.shared.publicKeys(), root: try RootKey.shared.publicKey(), master: m, bundle: bundle,
                                       identity: derived, standby: next)
      try await RouterClient.shared.kernelClaim(body, derived: derived, next: next)
      KernelTrust.pin(derived) // the same kit derives the same keys: the serving and the next secrets are one identity
      // the spawner's Fly token comes with the Recover, as the old core's did (the core store's backup)
      if let tok = stores.first(where: { $0.name == StoreView.coreStore })?.values["FLY_API_TOKEN"] {
        busy = "Giving the spawner its Fly token…"
        try await RouterClient.shared.kernelSpawnerToken(tok, boxKey: boxKey)
      }
      LineWitness.saw(derived.signingKey, try? await RouterClient.shared.kernelIdentity(boxKey: boxKey).state.lineSeq)
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
