// Settings: the Claude accounts (the router holds each: Refresh, Re-login, Make default, Remove, Add) and their usage, Stores, Repos and Machines, the Fly spend against the
// cap, and Jarvis 4 itself with Reset or recover and the encrypted backup (an offline copy of the stores).
import SwiftUI

enum SettingsRoute: Hashable { case stores, repos, addRepo, machines, backup, content, pairedApps, kernel }

struct SettingsView: View {
  @Environment(AppModel.self) private var model
  @State private var path: [SettingsRoute] = []

  var body: some View {
    NavigationStack(path: $path) {
      List {
        Section {
          NavigationLink(value: SettingsRoute.stores) {
            LabeledContent { Text(model.stores.loaded ? "\(model.stores.items.count)" : "") } label: { Label("Stores", systemImage: "shippingbox") }
          }
          .accessibilityElement(children: .combine).accessibilityIdentifier("open-stores")
          NavigationLink(value: SettingsRoute.repos) {
            LabeledContent { Text("\(model.repos.count)") } label: { Label("Repos", systemImage: "chevron.left.forwardslash.chevron.right") }
          }
          .accessibilityElement(children: .combine).accessibilityIdentifier("open-repos")
          NavigationLink(value: SettingsRoute.content) { Label("Content", systemImage: "folder") }
            .accessibilityIdentifier("open-content")
          NavigationLink(value: SettingsRoute.machines) { Label("Machines", systemImage: "server.rack") }
            .accessibilityIdentifier("open-machines")
          NavigationLink(value: SettingsRoute.pairedApps) { Label("Paired apps", systemImage: "iphone.and.arrow.forward") }
            .accessibilityIdentifier("open-paired-apps")
        }
        ClaudeAccountsSections()
        FlySection()
        Section {
          LabeledContent("Core", value: model.coreUp ? "Running" : "Not answering")
          Button("Reset or recover…", systemImage: "key.horizontal") { model.showSetup = true }.accessibilityIdentifier("open-setup")
          NavigationLink(value: SettingsRoute.backup) { Label("Encrypted backup", systemImage: "arrow.down.doc") }
            .accessibilityIdentifier("open-backup")
          NavigationLink(value: SettingsRoute.kernel) { Label("Kernel", systemImage: "cpu") }
            .accessibilityIdentifier("open-kernel")
        } header: { Text("Jarvis 4") } footer: {
          Text("Either pairs this iPhone again.")
        }
        if model.coreNext != .null { NextCoreSection() }
      }
      .navigationTitle("Settings")
      .refreshable { await model.refresh(); await model.loadStores() }
      .navigationDestination(for: SettingsRoute.self) { r in
        switch r {
        case .stores: StoresView()
        case .repos: ReposView(path: $path)
        case .addRepo: AddRepoView(path: $path)
        case .machines: MachinesView()
        case .backup: BackupView()
        case .content: ContentStoresView()
        case .pairedApps: PairedAppsView()
        case .kernel: KernelSetupView()
        }
      }
    }
  }
}

/// the next core (blue/green, router/nextcore.go): a core release runs next to the serving core; it is Recovered alongside
/// with the same kit (a standby) and serves once the router flips to it
private struct NextCoreSection: View {
  @Environment(AppModel.self) private var model
  private var serving: String { model.coreNext["up"].bool == true ? (model.coreNext["serving"].text ?? "empty") : "down" }
  private var label: String {
    switch serving {
    case "empty": "Empty"
    case "standby": "Standby"
    case "serving": "Serving"
    case "handed-off": "Handed off"
    case "down": "Not answering"
    default: serving
    }
  }
  var body: some View {
    Section {
      LabeledContent("Next core") { StatusPill(text: label, color: serving == "standby" || serving == "serving" ? .green : serving == "empty" ? .orange : .secondary) }
        .accessibilityElement(children: .combine).accessibilityIdentifier("next-core-\(serving)")
      if serving == "empty" {
        Button("Recover alongside…", systemImage: "arrow.left.arrow.right") { model.showNextSetup = true }.accessibilityIdentifier("open-next-setup")
      }
    } header: { Text("Next core") } footer: {
      if serving == "standby" { Text("Waiting for the running core to hand over.") }
    }
  }
}

/// the Claude accounts (GET api/claude-accounts, router/claudeaccounts.go): one Claude key store per account
/// (claude-<name>), each refreshed by the router; a section per account (its login, usage, Refresh token, Re-login,
/// Make default, Remove) and Add (a name, then the account's sign-in: open the page, sign in, paste the code it shows)
private struct ClaudeAccountsSections: View {
  @State private var l: JSON?
  @State private var error: String?
  var body: some View {
    Group {
      if let l {
        ForEach(l["accounts"].array, id: \.self) { a in
          ClaudeAccountSection(a: a) { Task { await load() } }
          if a["hasLogin"].bool == true { UsageSection(store: a["store"].string ?? "") }
        }
      } else {
        Section { if let error { ErrorRow(text: error) } else { ProgressView() } } header: { Text("Claude accounts") }
      }
      AddClaudeAccountSection { Task { await load() } }
    }
    .task { await load() }
  }
  private func load() async {
    do { l = try await RouterClient.shared.get("api/claude-accounts"); error = nil } catch { self.error = errText(error) }
  }
}

/// the sign-in's second half: paste "code#state" into the account's code route
private struct SignInRows: View {
  let store: String
  let done: () -> Void
  @State private var code = ""
  @State private var busy = false
  @State private var error: String?
  @State private var note: String?
  var body: some View {
    if let note {
      Text(note).accessibilityIdentifier("claude-code-note-" + store)
      Button("OK") { self.note = nil; done() }
    }
    TextField("code#state", text: $code).textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityIdentifier("claude-code-" + store)
    Button(busy ? "Signing in…" : "Sign in") { Task { await finish() } }
      .disabled(busy || !code.contains("#")).accessibilityIdentifier("claude-code-submit-" + store)
    if let error { ErrorRow(text: error) }
  }
  private func finish() async {
    busy = true; defer { busy = false }
    do {
      let out = try await RouterClient.shared.call("POST", "api/claude-accounts/\(store)/code", ["code": code.trimmingCharacters(in: .whitespacesAndNewlines)])
      code = ""; error = nil
      if let n = out["note"].string { note = n } // another Claude account: added as a new account (shown until dismissed)
      else { done() }
    } catch { self.error = errText(error) }
  }
}

private struct ClaudeAccountSection: View {
  let a: JSON
  let reload: () -> Void
  @Environment(\.openURL) private var openURL
  @State private var busy: String?
  @State private var error: String?
  @State private var signing = false
  @State private var confirmRemove = false
  private var store: String { a["store"].string ?? "" }
  var body: some View {
    let isDefault = a["default"].bool == true, sessions = a["sessions"].array.count
    Section {
      LabeledContent("Account", value: a["email"].text ?? "—")
      LabeledContent("Login") {
        if a["needLogin"].bool == true { StatusPill(text: "Re-login needed", color: .red) }
        else if a["expired"].bool == true { StatusPill(text: "Expired", color: .red) }
        else { StatusPill(text: "OK", color: .green) }
      }
      if let ms = a["expiresAt"].double { LabeledContent("Token valid", value: Fmt.fromNow(Date(timeIntervalSince1970: ms / 1000))) }
      if let r = a["refreshedAt"].string?.isoDate { LabeledContent("Last refresh", value: Fmt.fromNow(r)) }
      LabeledContent("Sessions", value: sessions == 0 ? "None" : "\(sessions)")
      if let e = a["error"].string { ErrorRow(text: e) }
      if let error { ErrorRow(text: error) }
      if a["hasLogin"].bool == true {
        Button(busy == "refresh" ? "Refreshing…" : "Refresh token", systemImage: "arrow.clockwise") { Task { await run("refresh", "api/claude-accounts/\(store)/refresh") } }
          .disabled(busy != nil).accessibilityIdentifier("claude-refresh-" + store)
      }
      Button(busy == "login" ? "Opening…" : a["hasLogin"].bool == true ? "Re-login" : "Sign in", systemImage: "person.badge.key") { Task { await relogin() } }
        .disabled(busy != nil).accessibilityIdentifier("claude-relogin-" + store)
      if signing { SignInRows(store: store) { signing = false; reload() } }
      if !isDefault {
        Button(busy == "default" ? "Saving…" : "Make default", systemImage: "star") { Task { await run("default", "api/claude-accounts/\(store)/default") } }
          .disabled(busy != nil).accessibilityIdentifier("claude-default-" + store)
        Button("Remove", systemImage: "trash", role: .destructive) { confirmRemove = true }
          .disabled(busy != nil || sessions > 0).accessibilityIdentifier("claude-remove-" + store)
      }
    } header: {
      HStack { Text(store); if isDefault { Text("· default") } }
    } footer: {
      if signing { Text("Paste the code the sign-in page shows.") }
      else if !isDefault && sessions > 0 { Text("Remove needs it unused: \(sessions) session(s) run on it.") }
    }
    .confirmationDialog("Remove \(store)?", isPresented: $confirmRemove, titleVisibility: .visible) {
      Button("Remove", role: .destructive) { Task { await remove() } }
    } message: { Text("Jarvis 4 forgets this account's login and stops refreshing it.") }
  }
  private func run(_ key: String, _ path: String) async {
    busy = key; defer { busy = nil }
    do { try await RouterClient.shared.call("POST", path); error = nil; reload() } catch { self.error = errText(error) }
  }
  private func relogin() async {
    busy = "login"; defer { busy = nil }
    do {
      let r = try await RouterClient.shared.call("POST", "api/claude-accounts/\(store)/login")
      if let s = r["url"].string, let u = URL(string: s) { signing = true; openURL(u) }
    } catch { self.error = errText(error) }
  }
  private func remove() async {
    busy = "remove"; defer { busy = nil }
    do { try await RouterClient.shared.call("DELETE", "api/claude-accounts/\(store)"); error = nil; reload() } catch { self.error = errText(error) }
  }
}

private struct AddClaudeAccountSection: View {
  let reload: () -> Void
  @Environment(\.openURL) private var openURL
  @State private var name = ""
  @State private var adding: String?
  @State private var busy = false
  @State private var error: String?
  var body: some View {
    Section {
      TextField("Name, e.g. work", text: $name).textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityIdentifier("claude-add-name")
      Button(busy ? "Opening…" : "Add", systemImage: "plus") { Task { await add() } }
        .disabled(busy || name.trimmingCharacters(in: .whitespaces).isEmpty).accessibilityIdentifier("claude-add")
      if let adding { SignInRows(store: adding) { self.adding = nil; reload() } }
      if let error { ErrorRow(text: error) }
    } header: { Text("Add a Claude account") } footer: {
      Text(adding != nil ? "Paste the code the sign-in page shows." : "Each account is a Claude key store, claude-<name>. New sessions pick one; a session keeps its account.")
    }
  }
  private func add() async {
    busy = true; defer { busy = false }
    do {
      let r = try await RouterClient.shared.call("POST", "api/claude-accounts", ["name": name.trimmingCharacters(in: .whitespaces)])
      adding = r["store"].string; name = ""; error = nil; reload()
      if let s = r["url"].string, let u = URL(string: s) { openURL(u) }
    } catch { self.error = errText(error) }
  }
}

/// one Claude account's quota (GET api/claude-accounts/{store}/usage, from its login)
private struct UsageSection: View {
  let store: String
  @State private var u: JSON?
  @State private var error: String?
  @State private var busy = false
  var body: some View {
    Section {
      if let u {
        let limits = u["limits"].array
        if limits.isEmpty { Text("No limits reported").foregroundStyle(.secondary) }
        ForEach(Array(limits.enumerated()), id: \.offset) { _, l in
          let used = max(0, min(100, l["percent"].int ?? 0))
          VStack(alignment: .leading, spacing: 4) {
            LabeledContent(label(l)) { Text(Double(used) / 100, format: .percent).bold().foregroundStyle(used >= 90 ? .red : used >= 75 ? .orange : .green) }
            ProgressView(value: Double(used), total: 100).tint(used >= 90 ? .red : used >= 75 ? .orange : .green)
            if let r = l["resetsAt"].string?.isoDate { LabeledContent("Resets", value: Fmt.fromNow(r)).font(.footnote).foregroundStyle(.secondary) }
          }
        }
        let x = u["extraUsage"]
        if !x.isNull {
          if x["enabled"].bool == true {
            LabeledContent("Extra usage this month", value: money(x["usedCredits"], x)).font(.footnote)
            LabeledContent("Monthly limit", value: money(x["monthlyLimit"], x)).font(.footnote)
            if x["spendLimitReached"].bool == true { StatusPill(text: "Spend limit reached", color: .red) }
          } else {
            LabeledContent("Extra usage") { Text(x["disabledReason"].text?.replacing("_", with: " ") ?? "Off") }.font(.footnote)
          }
        }
        if let at = u["fetchedAt"].string?.isoDate { LabeledContent("Fetched", value: Fmt.fromNow(at)).font(.footnote).foregroundStyle(.secondary) }
        if u["stale"].bool == true {
          StatusPill(text: "Last good reading", color: .orange)
          if let e = u["error"].string { ErrorRow(text: e) }
        }
      } else if let error { ErrorRow(text: error) } else { ProgressView() }
      Button(busy ? "Refreshing…" : "Refresh") { Task { await load(force: true) } }.disabled(busy).accessibilityIdentifier("usage-refresh-" + store)
    } header: { Text("Usage · " + store) }
    .task { await load(force: false) }
  }
  private func load(force: Bool) async {
    busy = force
    defer { busy = false }
    do { u = try await RouterClient.shared.get("api/claude-accounts/\(store)/usage" + (force ? "?refresh=1" : "")); error = nil } catch { self.error = errText(error) }
  }
  private func label(_ l: JSON) -> String {
    let scope = l["model"].text ?? l["surface"].text
    switch l["group"].string {
    case "session": return "Session (5 h)"
    case "weekly": return scope.map { "Weekly · " + $0 } ?? "Weekly · all models"
    default: return (scope.map { $0 + " · " } ?? "") + (l["kind"].string ?? "").replacing("_", with: " ")
    }
  }
  private func money(_ v: JSON, _ x: JSON) -> String {
    let dp = x["decimalPlaces"].int ?? 2
    let amount = (v.double ?? 0) / pow(10, Double(dp))
    return amount.formatted(.currency(code: x["currency"].string ?? "USD"))
  }
}

/// the Fly spend against the cap (the router's own estimate from the machines' sizes and running time)
private struct FlySection: View {
  @Environment(AppModel.self) private var model
  var body: some View {
    let b = model.budget
    Section {
      if b.isNull {
        if let e = model.fly["error"].text { ErrorRow(text: e) } else { Text("No reading yet").foregroundStyle(.secondary) }
      } else {
        let cap = b["capUsd"].double ?? 0, spent = b["spentUsd"].double ?? 0
        let pct = cap > 0 ? min(100, Int((spent / cap * 100).rounded())) : 0
        let color: Color = b["capped"].bool == true ? .red : b["warned"].bool == true ? .orange : .green
        LabeledContent(b["month"].string ?? "Month") { Text(Double(pct) / 100, format: .percent).bold().foregroundStyle(color) }
        ProgressView(value: Double(pct), total: 100).tint(color)
        LabeledContent("Spent", value: Fmt.usd(spent)).accessibilityIdentifier("budget-spent")
        LabeledContent("Cap · sessions pause", value: Fmt.usd(cap))
        LabeledContent("DM at", value: Fmt.usd(b["warnUsd"].double ?? 0))
        LabeledContent("Rate now", value: Fmt.usd(b["ratePerHour"].double ?? 0) + "/h")
        LabeledContent("A month at this rate", value: Fmt.usd(b["perMonth"].double ?? 0))
        LabeledContent("Running machines", value: "\(b["running"].int ?? 0)")
        LabeledContent("Volumes", value: "\(b["volumes"].int ?? 0)")
      }
      LabeledContent("Fly app") { Text(model.flyApp ?? "jarvis4-sessions").font(.footnote.monospaced()) }
    } header: { Text("Fly spend") } footer: {
      Text("An estimate, not Fly's invoice.")
    }
  }
}
