// One iCloud Drive file as the index read it (api/icloud/file): its path (Copy: a session fetches it with
// `rclone copy "icloud:<path>" …`), what kind it is, and the text taken from it, each part labelled.
import SwiftUI

struct IcloudFileView: View {
  @Environment(AppModel.self) private var model
  let path: String
  let terms: [String]
  @State private var f: JSON?
  @State private var error: String?

  var body: some View {
    List {
      Section {
        Text(path).font(.footnote.monospaced()).textSelection(.enabled)
        Button("Copy path", systemImage: "doc.on.doc") { model.copy(path, "Path") }.accessibilityIdentifier("if-copy-path")
      }
      if let error { ErrorRow(text: error) }
      if let f {
        Section {
          Text([f["kind"].text, f["size"].int.map(Fmt.bytes), f["mtime"].text.map { "modified " + $0.prefix(10) }, f["state"].text.flatMap { $0 == "done" ? nil : $0 }, f["note"].text].compactMap { $0 }.joined(separator: " · "))
            .font(.footnote).foregroundStyle(.secondary)
          if let e = f["error"].text { ErrorRow(text: e) }
        }
        Section("What the index read") {
          if f["chunks"].array.isEmpty { Text("Nothing yet.").foregroundStyle(.secondary) }
          ForEach(Array(f["chunks"].array.enumerated()), id: \.offset) { _, c in
            VStack(alignment: .leading, spacing: 4) {
              let label = [c["part"].text, c["src"].text].compactMap { $0 }.joined(separator: " · ")
              if !label.isEmpty { Text(label).font(.caption.bold()).foregroundStyle(.secondary) }
              Text(marked(c["text"].string ?? "", terms)).textSelection(.enabled)
            }
          }
        }
      }
    }
    .overlay { if f == nil && error == nil { ProgressView("Reading…") } }
    .navigationTitle(path.split(separator: "/").last.map(String.init) ?? path)
    .navigationBarTitleDisplayMode(.inline)
    .task {
      var c = URLComponents(); c.queryItems = [URLQueryItem(name: "path", value: path)]
      do { f = try await RouterClient.shared.get("api/icloud/file?" + (c.percentEncodedQuery ?? "")) } catch { self.error = errText(error) }
    }
  }
}
