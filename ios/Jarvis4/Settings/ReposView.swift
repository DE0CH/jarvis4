// Deyao's repos (GET api/state `repos`), each with its own deploy key on GitHub (read and push, that repo only) kept in
// its store github-<repo>. Add and Remove open the Face ID review (Review/RepoKeyView.swift), where one Face ID lets the
// core make or delete the key with the token in github-deploy-keys. A repo whose store is missing from the core (after
// a Recover) shows "No key" with Make key.
import SwiftUI

struct ReposView: View {
  @Environment(AppModel.self) private var model
  @Binding var path: [SettingsRoute]

  var body: some View {
    List {
      Section {
        if model.repos.isEmpty { Text("No repos").foregroundStyle(.secondary).accessibilityIdentifier("repos-none") }
        ForEach(model.repos) { x in RepoRow(x: x) }
      } footer: {
        Text("A session with a repo's store can clone, pull and push it.")
      }
    }
    .navigationTitle("Repos")
    .toolbar {
      ToolbarItem(placement: .primaryAction) {
        Button("Add repo", systemImage: "plus") { path.append(.addRepo) }.accessibilityIdentifier("repo-add")
      }
    }
    .refreshable { await model.refresh(); await model.loadStores() }
    .task { await model.loadStores() }
  }
}

private struct RepoRow: View {
  @Environment(AppModel.self) private var model
  let x: RepoEntry
  var body: some View {
    let store = model.stores.items.first { $0.name == x.store }
    let missing = model.stores.loaded && store == nil
    let sensitive = store?.sensitive ?? x.sensitive
    HStack {
      VStack(alignment: .leading, spacing: 3) {
        HStack(spacing: 6) {
          Text(x.repo).font(.headline)
          if sensitive { StatusPill(text: "Sensitive", color: .red) }
          if missing { StatusPill(text: "No key", color: .orange) }
        }
        VStack(alignment: .leading, spacing: 1) {
          LabeledContent(missing ? "Store missing" : "Key store") { Text(x.store).monospaced() }
          if !missing, let f = x.fingerprint { Text(f).monospaced().lineLimit(1).truncationMode(.middle) }
        }
        .font(.footnote).foregroundStyle(.secondary)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("repo-key-\(x.name)")
      }
      Spacer()
      if missing {
        Button("Make key") { open("add") }.buttonStyle(.borderedProminent).accessibilityIdentifier("repo-makekey-\(x.name)")
      }
    }
    .swipeActions { Button("Remove", role: .destructive) { open("remove") } }
    .contextMenu {
      if missing { Button("Make key", systemImage: "key") { open("add") } }
      Button("Remove", systemImage: "trash", role: .destructive) { open("remove") }.accessibilityIdentifier("repo-remove-\(x.name)")
    }
    .overlay(alignment: .trailing) {
      if !missing {
        Button("Remove", role: .destructive) { open("remove") }.buttonStyle(.borderless).font(.subheadline).accessibilityIdentifier("repo-remove-\(x.name)")
      }
    }
  }
  private func open(_ action: String) {
    model.present(.repoKey(action: action, repo: x.repo, sensitive: false)) { ok in if ok { Task { await model.refresh(); await model.loadStores() } } }
  }
}

/// Add repo: pick one of the repos the router's read-only GitHub token can see, or type owner/name or a GitHub URL
struct AddRepoView: View {
  @Environment(AppModel.self) private var model
  @Binding var path: [SettingsRoute]
  @State private var query = ""
  @State private var typed = ""
  @State private var repos: [GitHubRepo]?
  @State private var error: String?

  private var added: Set<String> { Set(model.repos.map { $0.url.lowercased().replacing(".git", with: "") }) }
  private var shown: [GitHubRepo] {
    let words = query.lowercased().split(separator: " ").map(String.init)
    let all = (repos ?? []).filter { r in words.allSatisfy { w in r.fullName.lowercased().contains(w) || (r.description ?? "").lowercased().contains(w) || (r.language ?? "").lowercased().contains(w) } }
    return Array(all.prefix(60))
  }

  var body: some View {
    List {
      Section {
        TextField("owner/name or https://github.com/owner/name", text: $typed)
          .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
          .onSubmit(addTyped)
          .accessibilityIdentifier("repo-url")
        Button("Add", systemImage: "faceid", action: addTyped).disabled(typed.isEmpty).accessibilityIdentifier("repo-add-go")
      } header: { Text("Type it") } footer: {
        Text("Adding asks for Face ID.")
      }
      Section {
        if let error { ErrorRow(text: error); Button("Try again") { Task { await load(fresh: true) } } }
        else if repos == nil { ProgressView() }
        ForEach(shown) { r in
          let isAdded = added.contains(r.htmlUrl.lowercased())
          Button { pick(r.fullName) } label: {
            VStack(alignment: .leading, spacing: 2) {
              HStack(spacing: 6) {
                Text(r.fullName).font(.headline).foregroundStyle(Color.primary)
                if r.isPrivate { StatusPill(text: "private") }
                if r.isFork { StatusPill(text: "fork") }
                if r.archived { StatusPill(text: "archived") }
                if isAdded { StatusPill(text: "added", color: .green) }
              }
              if let d = r.description { Text(d).font(.footnote).foregroundStyle(Color.secondary).lineLimit(1) }
              HStack(spacing: 12) {
                if let l = r.language { Text(l) }
                if let p = r.pushedAt { Label(Fmt.ago(p), systemImage: "arrow.up.circle") }
              }
              .font(.footnote).foregroundStyle(Color.secondary)
            }
          }
          .disabled(isAdded)
          .accessibilityIdentifier("repo-item-\(r.fullName)")
        }
        if let repos, repos.isEmpty == false, shown.isEmpty { Text("No match").foregroundStyle(.secondary) }
      } header: { Text("Your GitHub repos") }
    }
    .searchable(text: $query, prompt: "Search your GitHub repos")
    .navigationTitle("Add repo")
    .navigationBarTitleDisplayMode(.inline)
    .refreshable { await load(fresh: true) }
    .task { await load(fresh: false) }
  }

  private func load(fresh: Bool) async {
    do { repos = try await RouterClient.shared.get("api/github/repos" + (fresh ? "?refresh=1" : ""))["repos"].array.map(GitHubRepo.init); error = nil }
    catch { self.error = errText(error) }
  }
  private func addTyped() {
    guard let r = Self.githubRepo(typed) else { model.failure = "A GitHub repo: owner/name or its URL."; return }
    pick(r)
  }
  private func pick(_ repo: String) {
    model.present(.repoKey(action: "add", repo: repo, sensitive: false)) { ok in
      if ok { typed = ""; if !path.isEmpty { path.removeLast() } }
    }
  }
  /// owner/name from what was typed: "owner/name", a GitHub https URL or git@github.com:owner/name
  static func githubRepo(_ s: String) -> String? {
    var t = s.trimmingCharacters(in: .whitespacesAndNewlines)
    for p in ["https://github.com/", "git@github.com:"] where t.hasPrefix(p) { t = String(t.dropFirst(p.count)) }
    if t.hasSuffix("/") { t.removeLast() }
    if t.hasSuffix(".git") { t.removeLast(4) }
    let parts = t.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
    guard parts.count == 2 else { return nil }
    let ownerOK = !parts[0].isEmpty && parts[0].count <= 39 && parts[0].allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") } && parts[0].first != "-"
    let nameOK = !parts[1].isEmpty && parts[1].count <= 100 && parts[1] != "." && !parts[1].contains("..") && parts[1].allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || "._-".contains($0)) }
    return ownerOK && nameOK ? parts[0] + "/" + parts[1] : nil
  }
}
