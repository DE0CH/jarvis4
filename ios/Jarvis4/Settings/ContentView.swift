// Content stores (api/content, router/content.go): folders of files on the Storage Box that a session gets in
// ~/content/<name>/. Here: the list, a store's files (swipe to delete one), a new store, deleting a store. Uploading is
// the web page's. Paired apps (api/devices, router/devices.go): Deyao's OpenClaw and Paseo apps, swipe to remove.
import SwiftUI

struct ContentStoresView: View {
  @State private var stores: [RouterClient.ContentStoreDTO]?
  @State private var error: String?
  @State private var naming = false
  @State private var newName = ""

  var body: some View {
    List {
      if let error { ErrorRow(text: error) }
      if let stores {
        if stores.isEmpty { Text("No content stores").foregroundStyle(.secondary) }
        ForEach(stores) { s in
          NavigationLink { ContentFilesView(name: s.name, changed: { Task { await load() } }) } label: {
            LabeledContent(s.name) { Text("\(s.files) · \(Fmt.bytes(s.bytes))") }
          }
          .accessibilityIdentifier("content-store-\(s.name)")
        }
      }
    }
    .overlay { if stores == nil && error == nil { ProgressView("Loading…") } }
    .navigationTitle("Content")
    .toolbar {
      ToolbarItem(placement: .primaryAction) {
        Button("New store", systemImage: "plus") { newName = ""; naming = true }.accessibilityIdentifier("content-new")
      }
    }
    .alert("New content store", isPresented: $naming) {
      TextField("Name", text: $newName).textInputAutocapitalization(.never).autocorrectionDisabled()
      Button("Make") { Task { await make() } }
      Button("Cancel", role: .cancel) {}
    } message: { Text("Lowercase letters, digits and dashes.") }
    .refreshable { await load() }
    .task { await load() }
  }

  private func load() async {
    do { stores = try await RouterClient.shared.contentStores(); error = nil } catch { self.error = errText(error) }
  }
  private func make() async {
    do { try await RouterClient.shared.call("POST", "api/content", ["name": newName.trimmingCharacters(in: .whitespaces)]); await load() }
    catch { self.error = errText(error) }
  }
}

private struct ContentFile: Decodable, Identifiable { let path: String; let size: Int; var id: String { path } }
private struct ContentFiles: Decodable { let files: [ContentFile] }

struct ContentFilesView: View {
  let name: String
  let changed: () -> Void
  @Environment(\.dismiss) private var dismiss
  @State private var files: [ContentFile]?
  @State private var error: String?
  @State private var confirmDelete = false

  var body: some View {
    List {
      if let error { ErrorRow(text: error) }
      if let files {
        Section {
          if files.isEmpty { Text("No files").foregroundStyle(.secondary) }
          ForEach(files) { f in
            LabeledContent { Text(Fmt.bytes(f.size)) } label: { Text(f.path).font(.body.monospaced()).lineLimit(2) }
              .swipeActions { Button("Delete", role: .destructive) { Task { await delete(f) } } }
          }
        } footer: { Text("~/content/\(name)/ in a session; content-sync push \(name) sends changes back.") }
        Section {
          Button("Delete store…", role: .destructive) { confirmDelete = true }.accessibilityIdentifier("content-delete-store")
        }
      }
    }
    .overlay { if files == nil && error == nil { ProgressView("Loading…") } }
    .navigationTitle(name)
    .refreshable { await load() }
    .task { await load() }
    .confirmationDialog("Delete \(name) and every file in it?", isPresented: $confirmDelete, titleVisibility: .visible) {
      Button("Delete store", role: .destructive) { Task { await deleteStore() } }
    }
  }

  private var base: String { "api/content/\(RouterClient.escaped(name))" }
  private func load() async {
    do { files = try await RouterClient.shared.json("GET", base + "/files", as: ContentFiles.self).files; error = nil }
    catch { self.error = errText(error) }
  }
  private func delete(_ f: ContentFile) async {
    let q = RouterClient.escaped(f.path)
    do { try await RouterClient.shared.call("DELETE", base + "/file?path=" + q); await load(); changed() } catch { self.error = errText(error) }
  }
  private func deleteStore() async {
    do { try await RouterClient.shared.call("DELETE", base); changed(); dismiss() } catch { self.error = errText(error) }
  }
}

private struct PairedApp: Decodable, Identifiable { let id: String; let name: String; let model: String; let app: String; let lastSeenAt: String }
private struct PairedApps: Decodable { let devices: [PairedApp] }

struct PairedAppsView: View {
  @State private var apps: [PairedApp]?
  @State private var error: String?
  var body: some View {
    List {
      if let error { ErrorRow(text: error) }
      if let apps {
        Section {
          if apps.isEmpty { Text("None").foregroundStyle(.secondary) }
          ForEach(apps) { a in
            LabeledContent(a.app == "openclaw" ? "OpenClaw" : a.app == "paseo" ? "Paseo" : a.app) {
              Text(a.name + (a.model.isEmpty ? "" : " · " + a.model))
            }
            .swipeActions { Button("Remove", role: .destructive) { Task { await remove(a) } } }
          }
        } footer: { Text("Paired from the OpenClaw or Paseo app (Settings → Jarvis). Remove deletes its access token.") }
      }
    }
    .overlay { if apps == nil && error == nil { ProgressView("Loading…") } }
    .navigationTitle("Paired apps")
    .refreshable { await load() }
    .task { await load() }
  }
  private func load() async {
    do { apps = try await RouterClient.shared.json("GET", "api/devices", as: PairedApps.self).devices; error = nil } catch { self.error = errText(error) }
  }
  private func remove(_ a: PairedApp) async {
    do { try await RouterClient.shared.call("DELETE", "api/devices/\(RouterClient.escaped(a.id))"); await load() } catch { self.error = errText(error) }
  }
}
