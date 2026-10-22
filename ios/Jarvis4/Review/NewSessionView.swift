// New session: ONE page (Deyao, 2026-10-10) with everything Jarvis 1's New session page has: prompt, title, stores,
// harness, repos, permission mode, model, auto-pause, API proxy and size. Start asks the router for the session, checks
// the core's challenge carries exactly the stores picked here (plus the harness's own), the harness, the permission
// mode and (with a core that vouches) these settings, then under ONE Face ID signs it AND unlocks every store the
// session gets that is locked, for that session only, so it never waits at boot on a locked store.
// Images (AttachmentsSection) go up to the router before the request; Start then checks the signed config names exactly
// these files, by the sha256 and size of the bytes hashed here (docs/DECISIONS.md 94, 95, 97).
// DE0CH/claude-env comes pre-selected with its store when it is on the repo list (Deyao, 2026-10-11); sensitive stores
// are never pre-selected, and picking one shows a warning.
// Every new session starts in bypass, the only start mode (Deyao, 2026-10-22; docs/DECISIONS.md): no picker, the page
// shows it and Start checks the signed challenge names it. A running session can still switch (SessionDetailView).
import SwiftUI

struct NewSessionView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
  @State private var stores: [StoreView] = []
  @State private var picked: Set<String> = []
  @State private var harness = "claude"
  private let perm = "bypass" // the only start mode
  @State private var oneShot = false
  @State private var prompt = ""
  @State private var label = ""
  @State private var modelId = ""
  @State private var size = "medium"
  @State private var repos: Set<String> = []
  @State private var repoDefaulted = false
  @State private var autoPause = true
  @State private var apiProxy = false
  @State private var loaded = false
  @State private var loadError: String?
  @State private var busy: String?
  @State private var failure: String?
  @State private var images: [PickedImage] = []
  @State private var contentStores: [RouterClient.ContentStoreDTO] = []
  @State private var content: Set<String> = []
  /// the router's store rows (each key's writer): the keys sessions wrote into the stores Start unlocks are shown
  @State private var storeRows: [StoreRowDTO] = []
  /// the Claude accounts (GET api/claude-accounts, router/claudeaccounts.go): the default pre-picked; the session keeps it
  @State private var accounts: [JSON]?
  @State private var account = ""

  static let defaultRepo = "DE0CH/claude-env"
  private var hidden: Set<String> { model.harnessHidden }
  /// not the core's own, not a harness's, and not `claude`, the one shared login's old store (accounts replaced it)
  private var offered: [StoreView] { stores.filter { !$0.isCore && !hidden.contains($0.name) && $0.name != "claude" } }
  /// the harnesses that run on a Claude account (policy/stores.json `claudeAccount`)
  private var takesAccount: Bool { harness == "claude" || harness == "openclaw" || harness == "paseo-claude" }
  /// every sensitive store the session would get: picked here, or brought by the harness
  private var pickedSensitive: [String] { stores.filter { $0.sensitive && allStores.contains($0.name) }.map(\.name) }
  private var models: [Choice] { model.models.filter { ($0.harness ?? "claude") == harness } }
  private var allStores: [String] { Array(picked.union(PinnedPolicy.stores(harness, router: model.policy))).sorted() }
  private var toUnlock: [String] { allStores.filter { n in stores.contains { $0.name == n && !$0.unlocked && !$0.empty } } }
  private var trimmedPrompt: String { prompt.trimmingCharacters(in: .whitespacesAndNewlines) }
  private var canStart: Bool { loaded && busy == nil && !(oneShot && trimmedPrompt.isEmpty) }

  var body: some View {
    Form {
      promptSection
      AttachmentsSection(images: $images, disabled: busy != nil)
      storesSection
      harnessStoresSection
      SessionWritesSection(writes: SessionWrites.from(storeRows, stores: toUnlock))
      harnessSection
      accountSection
      reposSection
      contentSection
      modeSection
      optionsSection
      startSection
    }
    .navigationTitle("New session")
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy != nil).accessibilityIdentifier("secure-back") }
      ToolbarItem(placement: .confirmationAction) {
        Button(busy ?? "Start") { Task { await start() } }.disabled(!canStart).accessibilityIdentifier("secure-create")
      }
    }
    .interactiveDismissDisabled(busy != nil)
    .task { await load() }
    .onChange(of: harness) { pickModel() }
    .onChange(of: model.models) { pickModel() }
    .onChange(of: model.repos) { defaultRepo() }
  }

  @ViewBuilder private var promptSection: some View {
    Section {
      Picker("Kind", selection: $oneShot) { Text("Session").tag(false); Text("One-shot").tag(true) }
        .pickerStyle(.segmented)
        .accessibilityIdentifier("ns-mode")
      TextField(oneShot ? "The one job for this session" : "First prompt (optional)", text: $prompt, axis: .vertical)
        .lineLimit(3...10)
        .accessibilityIdentifier("ns-prompt")
      TextField("Title (optional)", text: $label).accessibilityIdentifier("ns-title")
    } footer: {
      Text(oneShot ? "Runs the prompt, then archives and destroys the session." : "Typed into the session once it is up.")
    }
  }

  @ViewBuilder private var storesSection: some View {
    Section {
      if let loadError { ErrorRow(text: loadError) }
      else if !loaded { ProgressView() }
      else if offered.isEmpty { Text("No stores to add.").foregroundStyle(.secondary) }
      ForEach(offered) { s in
        CheckRow(on: picked.contains(s.name), id: "secure-store-\(s.name)", action: { toggle(s.name) }) {
          HStack(spacing: 6) {
            Text(s.name)
            if s.sensitive { StatusPill(text: "Sensitive", color: .red) }
            if !s.unlocked { StatusPill(text: "Locked") }
            if s.empty { StatusPill(text: "empty") }
          }
        }
      }
      if !pickedSensitive.isEmpty {
        LabeledContent {
          Text(pickedSensitive.joined(separator: "\n")).multilineTextAlignment(.trailing)
        } label: {
          Label("Sensitive", systemImage: "exclamationmark.triangle.fill")
        }
        .foregroundStyle(.orange)
          .accessibilityElement(children: .combine).accessibilityIdentifier("secure-sensitive-warning")
      }
    } header: { Text("Secret stores") }
  }

  @ViewBuilder private var harnessStoresSection: some View {
    let brought = PinnedPolicy.stores(harness, router: model.policy)
    if !brought.isEmpty {
      Section {
        ForEach(brought, id: \.self) { n in
          let st = stores.first(where: { $0.name == n })
          HStack(spacing: 6) {
            Label(n, systemImage: "shippingbox")
            Spacer()
            if st?.sensitive == true { StatusPill(text: "Sensitive", color: .red) }
            if st?.unlocked == false { StatusPill(text: "Locked") }
          }
          .accessibilityElement(children: .combine)
          .accessibilityIdentifier("ns-harness-store-\(n)")
        }
      } header: { Text("The harness brings") } footer: {
        Text("Added by the router for this harness.")
      }
    }
  }

  @ViewBuilder private var harnessSection: some View {
    Section("Harness") {
      ForEach(Harness.all) { h in
        CheckRow(on: harness == h.id, id: "secure-harness-\(h.id)", action: { harness = h.id }) {
          VStack(alignment: .leading) { Text(h.title); Text(h.sub).font(.footnote).foregroundStyle(Color.secondary) }
        }
      }
    }
  }

  @ViewBuilder private var accountSection: some View {
    if takesAccount {
      Section {
        if let accounts {
          if accounts.isEmpty { Text("No Claude account yet (Settings): the session starts logged out.").foregroundStyle(.secondary) }
          ForEach(accounts, id: \.self) { a in
            let store = a["store"].string ?? ""
            CheckRow(on: account == store, id: "ns-account-\(store)", action: { account = store }) {
              VStack(alignment: .leading) {
                Text(store + (a["default"].bool == true ? " (default)" : ""))
                Text([a["email"].text ?? "not signed in", a["needLogin"].bool == true ? "Re-login needed" : ""].filter { !$0.isEmpty }.joined(separator: " · "))
                  .font(.footnote).foregroundStyle(Color.secondary)
              }
            }
          }
        } else { ProgressView() }
      } header: { Text("Claude account") } footer: {
        Text(harness == "claude" ? "The session keeps this account; it shows up in that account's Claude app." : "The session keeps this account until you switch it.")
      }
    }
  }

  @ViewBuilder private var reposSection: some View {
    Section {
      ForEach(model.repos) { r in
        CheckRow(on: repos.contains(r.name), id: "ns-repo-\(r.name)", action: { toggleRepo(r) }) {
          VStack(alignment: .leading) { Text(r.repo); Text(r.store).font(.footnote).foregroundStyle(Color.secondary) }
        }
      }
    } header: { Text("Repos") } footer: {
      if model.repos.isEmpty { Text("No repos yet: add some in Settings → Repos.") }
      else if repos.isEmpty { Text("No repo selected: the session starts with an empty workspace.") }
    }
  }

  /// content stores (router/content.go): each pulled into ~/content/<name>/ at every start; signed with the session
  @ViewBuilder private var contentSection: some View {
    if !contentStores.isEmpty {
      Section {
        ForEach(contentStores) { c in
          CheckRow(on: content.contains(c.name), id: "ns-content-\(c.name)", action: { if content.contains(c.name) { content.remove(c.name) } else { content.insert(c.name) } }) {
            VStack(alignment: .leading) { Text(c.name); Text("\(c.files) file\(c.files == 1 ? "" : "s") · ~/content/\(c.name)").font(.footnote).foregroundStyle(Color.secondary) }
          }
        }
      } header: { Text("Content stores") }
    }
  }

  @ViewBuilder private var modeSection: some View {
    Section {
      LabeledContent("Permission mode", value: "bypass").accessibilityIdentifier("ns-permission-mode")
    } footer: {
      Text("Every session starts with no prompts at all (--dangerously-skip-permissions). A running session can switch to auto.")
    }
  }

  @ViewBuilder private var optionsSection: some View {
    Section {
      if !models.isEmpty {
        Picker("Model", selection: $modelId) { ForEach(models) { m in Text(m.label ?? m.id).tag(m.id) } }
          .accessibilityIdentifier("ns-model")
      }
      if !model.sizes.isEmpty {
        Picker("Machine size", selection: $size) { ForEach(model.sizes) { s in Text("\(s.id.capitalized) · \(s.label ?? "")").tag(s.id) } }
          .accessibilityIdentifier("ns-size")
      }
      if !oneShot {
        Toggle("Auto-pause when idle", isOn: $autoPause).accessibilityIdentifier("ns-autopause")
      }
      Toggle("API proxy", isOn: $apiProxy).accessibilityIdentifier("ns-apiproxy")
    } header: { Text("Options") } footer: {
      Text("API proxy: every Anthropic API call logged to ~/artifacts/api-log.")
    }
  }

  @ViewBuilder private var startSection: some View {
    Section {
      if loaded && !toUnlock.isEmpty {
        LabeledContent {
          Text(toUnlock.joined(separator: "\n")).multilineTextAlignment(.trailing)
        } label: {
          Label("Also unlocks", systemImage: "lock.open")
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("ns-unlocks")
        LabeledContent("Open to", value: "This session only")
      }
      if let failure { ErrorRow(text: failure, id: "secure-error") }
      SigningFooter()
    }
  }

  private func toggle(_ n: String) { if picked.contains(n) { picked.remove(n) } else { picked.insert(n) } }
  /// picking a repo picks its deploy-key store too when that is offered and not sensitive
  private func toggleRepo(_ r: RepoEntry) {
    repoDefaulted = true
    if repos.contains(r.name) { repos.remove(r.name); return }
    repos.insert(r.name)
    if let s = offered.first(where: { $0.name == r.store }), !s.sensitive { picked.insert(s.name) }
  }
  /// DE0CH/claude-env, once, when the page first has both the repo list and the stores
  private func defaultRepo() {
    guard !repoDefaulted, !stores.isEmpty, !model.repos.isEmpty else { return }
    repoDefaulted = true
    if let r = model.repos.first(where: { $0.repo.caseInsensitiveCompare(Self.defaultRepo) == .orderedSame }), !repos.contains(r.name) { toggleRepo(r) }
  }
  private func pickModel() { if !models.contains(where: { $0.id == modelId }) { modelId = models.first?.id ?? "" } }
  private func apply(_ list: [StoreView]) {
    let first = stores.isEmpty
    stores = list
    if first && picked.isEmpty, offered.contains(where: { $0.name == "default" && !$0.sensitive }) { picked = ["default"] }
    picked = picked.intersection(offered.map(\.name))
    defaultRepo()
  }
  private func load() async {
    pickModel()
    if model.stores.loaded { apply(model.stores.items); loaded = true }
    if model.repos.isEmpty { await model.refresh() }
    do {
      let d = try await RouterClient.shared.storesDoc()
      apply(d.stores)
      loaded = true
    } catch { if !loaded { loadError = errText(error) } }
    if model.models.isEmpty { await model.loadLists() }
    contentStores = (try? await RouterClient.shared.contentStores()) ?? []
    if let l = try? await RouterClient.shared.get("api/claude-accounts") {
      accounts = l["accounts"].array
      if account.isEmpty { account = l["default"].string ?? "" }
    } else { accounts = [] }
    storeRows = (try? await RouterClient.shared.storeRows()) ?? []
    pickModel()
    defaultRepo()
  }

  private func start() async {
    failure = nil
    let want = picked.sorted(), rid = CoreCrypto.nonce()
    let title = label.trimmingCharacters(in: .whitespacesAndNewlines)
    do {
      let key = try CoreTrust.key()
      busy = "Requesting…"
      let chosen = model.repos.filter { repos.contains($0.name) }
      let attached = try await upload(rid)
      var body: [String: Any] = ["requestId": rid, "stores": want, "harness": harness, "permissionMode": perm, "label": title,
                                 "prompt": trimmedPrompt, "model": modelId, "size": size, "oneShot": oneShot,
                                 "autoPause": !oneShot && autoPause, "repos": chosen.map(\.url).joined(separator: ","), "apiProxy": apiProxy]
      if !content.isEmpty { body["content"] = content.sorted() }
      if takesAccount && !account.isEmpty { body["account"] = account }
      if !attached.isEmpty { body["attachments"] = ["uploadId": rid, "files": attached.map { ["name": $0.name] }] }
      busy = "Requesting…"
      try await RouterClient.shared.call("POST", "api/sessions", body)
      // the core's challenge comes before any machine exists
      var found: RouterClient.ApprovalDTO?
      let until = Date.now.addingTimeInterval(60)
      while found == nil && Date.now < until {
        let st = try await RouterClient.shared.approvalsState()
        if let s = st.sessions.first(where: { $0.createRequestId == rid }) {
          if s.state == "failed" { throw RouterError(message: "The router couldn't make the request.") }
          found = st.approvals.first { $0.session == s.id && $0.kind == "new-session" }
        }
        if found == nil { try await Task.sleep(for: .milliseconds(700)) }
      }
      guard let a = found else { throw RouterError(message: "No approval yet: it will wait in the Inbox.") }
      let r = try Checks.review(challenge: a.challenge, coreKey: key)
      // sign only what was chosen here
      try Checks.matchesPicked(r, stores: want, harnessStores: model.policy[harness] ?? [], harness: harness, permissionMode: perm)
      // what the router added beyond the picks must be the harness's own by this app's pinned policy, and never
      // sensitive (audit finding 2: a lying api/policy could otherwise slip a sensitive store into the signature)
      _ = try await ImageAttestation.check(image: r.image, sig: a.imageSig)
      let signedList = try await RouterClient.shared.storesDoc()
      _ = try Checks.onlyHarnessExtras(r, picked: want, pinnedHarness: PinnedPolicy.stores(harness, router: model.policy),
                                       sensitive: signedList.stores.filter(\.sensitive).map(\.name))
      // …and, with a core that vouches, exactly these settings: the cert carries them to the machine (DESIGN "Inputs")
      try Checks.matchesSettings(r, .init(label: title, prompt: trimmedPrompt, model: modelId, repos: chosen.map(\.url), oneShot: oneShot, apiProxy: apiProxy,
                                              attachments: attached, content: content.sorted(), claudeAccount: takesAccount ? account : ""))
      // the stores the challenge carries that are locked now (fresh from the core): opened under the same Face ID
      let now = try await RouterClient.shared.stores()
      let locked = r.stores.filter { n in now.contains { $0.name == n && !$0.unlocked && !$0.empty } }
      busy = "Signing…"
      let reason = "Start \"\(title.isEmpty ? "New session" : title)\"" + (locked.isEmpty ? "" : " and unlock \(locked.joined(separator: ", "))")
      guard let sig = try await StoreUnlock.signAndUnlock(payload: a.challenge.payload, stores: locked, reason: reason, for: r.challenge.nonce,
                                                          shown: SessionWrites.from(storeRows, stores: locked)) else {
        throw TrustError.stale("signature")
      }
      busy = "Starting…"
      let ans = try await RouterClient.shared.respond(a.id, signature: sig)
      try Checks.answerFor(r, answer: ans.answer, coreKey: key)
      model.secureCompleted(true)
    } catch {
      busy = nil
      failure = errText(error)
    }
  }
}

extension NewSessionView {
  /// each image up to the router under this Start's own upload id (a retry is a new request: it uploads them again);
  /// what will be signed: the name the router gave it, and the sha256 and size of the bytes this phone holds
  fileprivate func upload(_ uploadId: String) async throws -> [Checks.Attachment] {
    var out: [Checks.Attachment] = []
    for (i, img) in images.enumerated() {
      busy = "Uploading \(i + 1) of \(images.count)…"
      let u = try await RouterClient.shared.upload(id: uploadId, name: img.name, data: img.data)
      guard u.size == img.size else { throw RouterError(message: "The router stored \(u.size) bytes of \(img.name), not \(img.size).") }
      out.append(.init(name: u.name, sha256: img.sha256, size: img.size))
    }
    return out
  }
}

/// a row that is picked or not (a checkmark), as Settings lists choices; VoiceOver and UI tests see it as selected
struct CheckRow<Content: View>: View {
  let on: Bool
  let id: String
  let action: () -> Void
  @ViewBuilder let content: () -> Content
  var body: some View {
    Button(action: action) {
      HStack {
        content()
        Spacer()
        Image(systemName: "checkmark").foregroundStyle(.tint).opacity(on ? 1 : 0).accessibilityHidden(true)  // the row carries .isSelected
      }
      .contentShape(.rect)
    }
    .foregroundStyle(Color.primary)
    .accessibilityIdentifier(id)
    .accessibilityAddTraits(on ? .isSelected : [])
  }
}
