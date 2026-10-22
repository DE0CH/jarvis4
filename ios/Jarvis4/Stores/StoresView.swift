// The core's secret stores, from its signed list (checked against the pinned core key): unlock (Face ID → this phone's
// share of every key, sealed to the core's one-off key), lock, mark sensitive (one way), and a new empty store. The
// core's signed list of open unlocks, each with Lock. What each store and key is for comes from the router
// (GET api/stores: each key's name, its writer and its explanation, the store's about text; never values), each text
// edited in place on the store's own page (PUT api/stores/{store}/docs; app/DECISIONS.md 67, 68). A key a session wrote is always in view with the
// session's title: Unlock opens only the session-written keys this page shows (StoreUnlock).
import SwiftUI

struct StoresView: View {
  @Environment(AppModel.self) private var model
  /// the router's rows (keys, writers, explanations, about); nil until read
  @State private var rows: [String: StoreRowDTO] = [:]
  @State private var creating = false
  @State private var newName = ""
  @State private var markAsk: String?
  /// the store whose keys and texts are open
  @State private var detail: String?

  var body: some View {
    List {
      if let e = model.stores.error { ErrorRow(text: e, id: "secure-error") }
      Section {
        ForEach(model.stores.items) { s in
          StoreRow(s: s, row: rows[s.name], harness: model.harnessHidden.contains(s.name), mark: { markAsk = s.name },
                   open: { detail = s.name }, reload: reload)
        }
      } header: { Text("Stores") } footer: {
        Text("Unlocked: open to every session until locked. Tap a store for its keys.")
      }
      Section {
        if model.stores.loaded && model.openUnlocks.isEmpty { Text("None").foregroundStyle(.secondary).accessibilityIdentifier("unlocks-none") }
        ForEach(model.openUnlocks) { u in
          HStack {
            VStack(alignment: .leading, spacing: 3) {
              HStack(spacing: 6) {
                Text(u.store).font(.headline)
                StatusPill(text: (u.forNonce ?? "").isEmpty ? "Every session" : "One session", color: (u.forNonce ?? "").isEmpty ? .orange : .blue)
              }
              HStack(spacing: 12) {
                Label(u.since.isoDate.map { $0.formatted(date: .abbreviated, time: .shortened) } ?? u.since, systemImage: "clock")
                Text(u.id.prefix(8)).monospaced()
              }
              .font(.footnote).foregroundStyle(.secondary)
            }
            Spacer()
            PendingButton(key: "lock:" + u.id, title: "Lock", role: .destructive) { await lock(u) }
              .buttonStyle(.borderless).accessibilityIdentifier("lock-\(u.store)")
          }
        }
      } header: { Text("Open unlocks") } footer: {
        Text("From the core's signed list.")
      }
    }
    .overlay { if !model.stores.loaded && model.stores.error == nil { ProgressView("Loading stores…") } }
    .navigationTitle("Stores")
    .toolbar {
      ToolbarItem(placement: .primaryAction) {
        Button("New store", systemImage: "plus") { newName = ""; creating = true }.accessibilityIdentifier("store-new")
      }
    }
    .alert("New store", isPresented: $creating) {
      TextField("name (a–z, 0–9, -)", text: $newName).textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityIdentifier("store-new-name")
      Button("Create") { Task { await create() } }.accessibilityIdentifier("store-create")
      Button("Cancel", role: .cancel) {}
    } message: {
      Text("Empty and not sensitive.")
    }
    .confirmationDialog("Mark \(markAsk ?? "") sensitive?", isPresented: Binding(get: { markAsk != nil }, set: { if !$0 { markAsk = nil } }), titleVisibility: .visible) {
      Button("Mark sensitive", role: .destructive) { if let n = markAsk { Task { await mark(n) } } }.accessibilityIdentifier("mark-confirm")
    } message: { Text("The mark can never be removed.") }
    .refreshable { await reload() }
    .task { await reload() }
    .navigationDestination(item: $detail) { name in StoreDetailView(store: name) }
  }

  private func reload() async {
    await model.loadStores()
    if let list = try? await RouterClient.shared.storeRows() {
      rows = Dictionary(list.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a })
    }
  }
  private func run(_ key: String, _ label: String, _ fn: () async throws -> Void) async {
    await model.exclusive(key) {
      model.pend(key, label)
      defer { model.pend(key, nil) }
      do { try await fn() } catch { model.fail(error) }
      await model.loadStores()
    }
  }
  /// keyed by the unlock's id, not the store: a store's unlock still finishing (its trailing reload) never turns its
  /// open unlocks' Lock into a disabled "Unlocking…" that drops the tap (replica runs 38399852797, 38407156816)
  private func lock(_ u: UnlockRow) async { await run("lock:" + u.id, "Locking…") { try await RouterClient.shared.lock(u.id) } }
  private func mark(_ n: String) async { markAsk = nil; await run("store:" + n, "Marking…") { try await RouterClient.shared.markSensitive(n) } }
  private func create() async {
    let n = newName.trimmingCharacters(in: .whitespaces).lowercased()
    guard !n.isEmpty else { return }
    await run("store:new", "Creating…") { try await RouterClient.shared.createStore(n) }
  }
}

private struct StoreRow: View {
  @Environment(AppModel.self) private var model
  let s: StoreView
  let row: StoreRowDTO?
  let harness: Bool
  let mark: () -> Void
  let open: () -> Void
  let reload: @MainActor () async -> Void

  /// the keys a session wrote, in view on this row (Unlock opens only these)
  private var writes: [SessionWrite] { row.map { SessionWrites.from([$0], stores: [s.name]) } ?? [] }

  var body: some View {
    HStack {
      Button(action: open) { info }
        .buttonStyle(.plain)
        .accessibilityIdentifier("store-open-\(s.name)")
      Spacer()
      if let p = model.pending["store:" + s.name] {
        HStack { ProgressView(); Text(p).font(.footnote) }
      } else {
        Button(s.unlocked ? "Unlock again" : "Unlock") { Task { await unlock() } }
          .buttonStyle(.bordered).disabled(s.empty)
          .accessibilityIdentifier("unlock-\(s.name)")
      }
    }
    .accessibilityElement(children: .contain)
    .accessibilityIdentifier("store-\(s.name)")
    .swipeActions {
      if !s.sensitive { Button("Mark sensitive…", action: mark).tint(.red) }
    }
    .contextMenu {
      if !s.sensitive { Button("Mark sensitive…", systemImage: "exclamationmark.shield", action: mark) }
    }
  }

  private var info: some View {
      VStack(alignment: .leading, spacing: 3) {
        HStack(spacing: 6) {
          Text(s.name).font(.headline)
          if s.sensitive { StatusPill(text: "Sensitive", color: .red).accessibilityIdentifier("sensitive-\(s.name)") }
          StatusPill(text: s.unlocked ? "Unlocked" : "Locked", color: s.unlocked ? .blue : .secondary)
        }
        if s.empty || harness {
          HStack(spacing: 6) {
            if s.empty { StatusPill(text: "Empty") }
            if harness { StatusPill(text: "Harness", color: .blue) }
          }
        }
        if let n = row?.keyInfo.count, n > 0 {
          Text(n == 1 ? "1 key" : "\(n) keys").font(.footnote).foregroundStyle(.secondary)
        }
        ForEach(writes, id: \.self) { w in
          Label { Text("\(w.key) · \(w.label)") } icon: { Image(systemName: "exclamationmark.triangle.fill") }
            .font(.footnote).foregroundStyle(.orange)
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("store-written-\(s.name)-\(w.key)")
        }
      }
      .contentShape(Rectangle())
  }

  /// "Unlocking…" lasts until the core's lists show the outcome; the router's key rows are read after it, outside the
  /// store's key, so the new unlock's Lock works the moment its row shows
  private func unlock() async {
    let key = "store:" + s.name
    await model.exclusive(key) {
      model.pend(key, "Unlocking…")
      defer { model.pend(key, nil) }
      do {
        try await StoreUnlock.signAndUnlock(payload: nil, stores: [s.name], reason: "Unlock \(s.name)", for: nil, shown: writes)
      } catch { model.fail(error) }
      await model.loadStores()
    }
    await reload()
  }
}

/// one store's about text and its keys (name, when, who wrote it, explanation), each text edited in place
struct StoreDetailView: View {
  let store: String
  @State private var row: StoreRowDTO?
  @State private var error: String?

  var body: some View {
    List {
      if let error { ErrorRow(text: error, id: "store-detail-error") }
      if let row {
        Section {
          DocText(id: "store-about-\(store)", label: nil, text: row.about ?? "", empty: "No description yet") { t in
            try await RouterClient.shared.setStoreDocs(store, about: t, keys: [:])
            await load()
          }
        } header: { Text("About") }
        Section {
          if row.keyInfo.isEmpty { Text("No keys").foregroundStyle(.secondary) }
          ForEach(row.keyInfo) { k in KeyDocRow(store: store, k: k, saved: load) }
        } header: { Text("Keys") } footer: {
          Text("Names and who wrote each key; never values.")
        }
        if !store.hasPrefix("github-") || store == "github-deploy-keys" {
          Section {
            NavigationLink { StoreVersionsView(store: store) } label: { Label("Versions", systemImage: "clock.arrow.circlepath") }
              .accessibilityIdentifier("store-versions-\(store)")
          } footer: { Text("Earlier versions the core keeps. Restore puts one back with Face ID.") }
        }
      } else if error == nil {
        ProgressView()
      }
    }
    .navigationTitle(store)
    .navigationBarTitleDisplayMode(.inline)
    .refreshable { await load() }
    .task { await load() }
  }

  private func load() async {
    do {
      row = try await RouterClient.shared.storeRows().first { $0.name == store }
      error = row == nil ? "No store \(store)." : nil
    } catch { self.error = errText(error) }
  }
}

private struct KeyDocRow: View {
  let store: String
  let k: StoreRowDTO.Key
  let saved: @MainActor () async -> Void
  var body: some View {
    VStack(alignment: .leading, spacing: 4) {
      Text(k.name).font(.body.monospaced()).textSelection(.enabled)
      if let w = k.writer, w.by == "machine" {
        Label("Written by session \(w.sessionName)", systemImage: "exclamationmark.triangle.fill")
          .font(.footnote).foregroundStyle(.orange)
          .accessibilityIdentifier("key-writer-\(store)-\(k.name)")
      }
      if let at = k.at?.isoDate { Text(Fmt.ago(at)).font(.caption).foregroundStyle(.secondary) }
      DocText(id: "key-doc-\(store)-\(k.name)", label: nil, text: k.explanation ?? "", empty: "No explanation yet") { t in
        try await RouterClient.shared.setStoreDocs(store, about: nil, keys: [k.name: t])
        await saved()
      }
    }
    .accessibilityElement(children: .contain)
    .accessibilityIdentifier("key-\(store)-\(k.name)")
  }
}

/// a text with an inline Edit: a text box with Save / Cancel, "Saving…", the router's error under it and "Saved" for a
/// moment; saving an empty text removes it (app/DECISIONS.md 67)
struct DocText: View {
  let id: String
  let label: String?
  let text: String
  let empty: String
  let save: @MainActor (String) async throws -> Void
  @State private var editing = false
  @State private var draft = ""
  @State private var saving = false
  @State private var error: String?
  @State private var savedAt: Date?

  var body: some View {
    VStack(alignment: .leading, spacing: 6) {
      if editing {
        TextField(label ?? "Explanation", text: $draft, axis: .vertical)
          .lineLimit(2...8)
          .disabled(saving)
          .accessibilityIdentifier("\(id)-field")
        HStack {
          Button(saving ? "Saving…" : "Save") { Task { await commit() } }
            .buttonStyle(.borderedProminent).disabled(saving)
            .accessibilityIdentifier("\(id)-save")
          Button("Cancel") { editing = false; error = nil }
            .buttonStyle(.bordered).disabled(saving)
            .accessibilityIdentifier("\(id)-cancel")
        }
      } else {
        HStack(alignment: .firstTextBaseline) {
          VStack(alignment: .leading, spacing: 2) {
            if let label { Text(label).font(.caption).foregroundStyle(.secondary) }
            if text.isEmpty { Text(empty).font(.footnote).foregroundStyle(.secondary) }
            else { Text(text).font(.footnote) }
          }
          .accessibilityElement(children: .combine)
          .accessibilityIdentifier(id)
          Spacer()
          if let savedAt, savedAt.timeIntervalSinceNow > -3 {
            Text("Saved").font(.caption).foregroundStyle(.green).accessibilityIdentifier("\(id)-saved")
          }
          Button("Edit") { draft = text; error = nil; editing = true }
            .buttonStyle(.borderless)
            .accessibilityIdentifier("\(id)-edit")
        }
      }
      if let error { ErrorRow(text: error, id: "\(id)-error") }
    }
  }

  private func commit() async {
    saving = true
    defer { saving = false }
    error = nil
    do {
      try await save(draft.trimmingCharacters(in: .whitespacesAndNewlines))
      editing = false
      savedAt = .now
      try? await Task.sleep(for: .seconds(3))
      savedAt = nil
    } catch { self.error = errText(error) }
  }
}
