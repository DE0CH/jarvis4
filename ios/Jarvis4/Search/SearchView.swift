// Search: Deyao's iCloud Drive by name and content. The router forwards it to the iCloud index (api/icloud/search); a
// file hit opens what the index read from the file. Transcript search is not Jarvis's: DE0CH/services, its own page at
// https://search.deyaochen.com.
import SwiftUI

struct FileRoute: Hashable { let path: String; let terms: [String] }

struct SearchView: View {
  @State private var query = ""
  @State private var files: JSON?
  @State private var busy = false
  @State private var error: String?
  @State private var seq = 0

  var body: some View {
    NavigationStack {
      List {
        if let error { ErrorRow(text: error, id: "search-error") }
        if let files { FileResults(files: files, terms: Self.queryTerms(files["query"].string ?? "")) }
      }
      .overlay {
        if busy { ProgressView("Searching…") }
        else if files == nil && error == nil {
          ContentUnavailableView {
            Label("Search iCloud Drive", systemImage: "icloud")
          } description: {
            Text("Names, folders and content.")
          }
          .accessibilityIdentifier("search-intro")
        } else if let r = files, r["total"].int == 0 || r["hits"].array.isEmpty {
          ContentUnavailableView.search(text: r["query"].string ?? query)
        }
      }
      .navigationTitle("Search")
      .searchable(text: $query, prompt: "iCloud Drive")
      .onSubmit(of: .search) { Task { await run() } }
      .navigationDestination(for: FileRoute.self) { r in IcloudFileView(path: r.path, terms: r.terms) }
    }
  }

  /// latest query wins: a slower earlier one never lands over it
  private func run() async {
    let q = query.trimmingCharacters(in: .whitespaces)
    guard !q.isEmpty else { return }
    seq += 1
    let n = seq
    busy = true; error = nil
    defer { if n == seq { busy = false } }
    var c = URLComponents()
    c.queryItems = [URLQueryItem(name: "q", value: q), URLQueryItem(name: "limit", value: "30")]
    do {
      let r = try await RouterClient.shared.get("api/icloud/search?" + (c.percentEncodedQuery ?? ""))
      if n == seq { files = r }
    } catch { if n == seq { self.error = errText(error) } }
  }

  /// terms for marking an iCloud snippet (its index returns none): the query's words and quoted phrases
  static func queryTerms(_ q: String) -> [String] {
    var out: [String] = []
    var cur = "", quoted = false
    for ch in q {
      if ch == "\"" { if !cur.isEmpty { out.append(cur) }; cur = ""; quoted.toggle() }
      else if ch == " " && !quoted { if !cur.isEmpty { out.append(cur) }; cur = "" }
      else { cur.append(ch) }
    }
    if !cur.isEmpty { out.append(cur) }
    return out.filter { $0.count > 1 }
  }
}

/// the snippet with the query's terms marked
func marked(_ text: String, _ terms: [String]) -> AttributedString {
  var a = AttributedString(text)
  for t in terms.filter({ !$0.isEmpty }).sorted(by: { $0.count > $1.count }) {
    var from = a.startIndex
    while from < a.endIndex, let r = a[from...].range(of: t, options: .caseInsensitive) {
      a[r].backgroundColor = .accentColor.opacity(0.25)
      from = r.upperBound
    }
  }
  return a
}

private struct FileResults: View {
  let files: JSON
  let terms: [String]
  var body: some View {
    Section {
      LabeledContent("Candidates", value: "\(files["total"].int ?? 0)").font(.footnote)
    }
    Section {
      ForEach(Array(files["hits"].array.enumerated()), id: \.offset) { _, h in
        let path = h["path"].string ?? ""
        let name = path.split(separator: "/").last.map(String.init) ?? path
        NavigationLink(value: FileRoute(path: path, terms: terms)) {
          VStack(alignment: .leading, spacing: 3) {
            Label(name, systemImage: "doc").font(.headline)
            Text([String(path.dropLast(name.count + 1)).isEmpty ? "/" : String(path.dropLast(name.count + 1)), h["kind"].text, h["size"].int.map(Fmt.bytes), h["mtime"].text.map { String($0.prefix(10)) }, h["part"].text, h["src"].text].compactMap { $0 }.joined(separator: " · "))
              .font(.caption).foregroundStyle(.secondary)
            if let s = h["snippet"].text { Text(marked(s, terms)).font(.subheadline).lineLimit(4) }
          }
        }
        .accessibilityIdentifier("file-\(path)")
      }
    }
  }
}
