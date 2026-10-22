// Search: every conversation with Claude (archived, paused and running sessions of both Jarvises, what Claude did in
// them, the task records) and Deyao's iCloud Drive by name and content. The router forwards both to Jarvis 1's
// services (api/search, api/icloud/search). A conversation hit opens the conversation around it; a file hit opens what
// the index read from the file.
import SwiftUI

enum SearchScope: Hashable { case chats, files }
struct ContextRoute: Hashable { let hit: JSON; let terms: [String] }
struct FileRoute: Hashable { let path: String; let terms: [String] }

struct SearchView: View {
  @State private var query = ""
  @State private var scope: SearchScope = .chats
  @State private var kind = "all"
  @State private var since = 0
  @State private var group = true
  @State private var result: JSON?
  @State private var files: JSON?
  @State private var busy = false
  @State private var error: String?
  @State private var seq = 0

  var body: some View {
    NavigationStack {
      List {
        if let error { ErrorRow(text: error, id: "search-error") }
        if scope == .chats, let result { ChatResults(result: result) }
        if scope == .files, let files { FileResults(files: files, terms: Self.queryTerms(files["query"].string ?? "")) }
      }
      .overlay {
        if busy { ProgressView("Searching…") }
        else if (scope == .chats ? result : files) == nil && error == nil {
          ContentUnavailableView {
            Label(scope == .chats ? "Search conversations" : "Search iCloud Drive", systemImage: scope == .chats ? "text.bubble" : "icloud")
          } description: {
            Text(scope == .chats ? "Every session of Jarvis 1 and 2. “Quotes” match exactly." : "Names, folders and content.")
          }
          .accessibilityIdentifier("search-intro")
        } else if let r = scope == .chats ? result : files, r["total"].int == 0 || (scope == .chats ? (r["hits"].array.isEmpty && r["sessions"].array.isEmpty) : r["hits"].array.isEmpty) {
          ContentUnavailableView.search(text: r["query"].string ?? query)
        }
      }
      .navigationTitle("Search")
      .searchable(text: $query, prompt: scope == .chats ? "Every conversation" : "iCloud Drive")
      .searchScopes($scope) {
        Text("Conversations").tag(SearchScope.chats)
        Text("iCloud files").tag(SearchScope.files)
      }
      .onSubmit(of: .search) { Task { await run() } }
      .onChange(of: scope) { if !query.isEmpty { Task { await run() } } }
      .toolbar {
        if scope == .chats {
          ToolbarItem(placement: .primaryAction) {
            Menu("Filter", systemImage: "line.3.horizontal.decrease.circle") {
              Picker("Kind", selection: $kind) {
                Text("All").tag("all"); Text("Chat").tag("msg"); Text("Actions").tag("tool"); Text("Records").tag("doc")
              }
              Picker("Time", selection: $since) {
                Text("Any time").tag(0); Text("Past week").tag(7); Text("Past month").tag(30); Text("Past 3 months").tag(90)
              }
              Toggle("By session", isOn: $group)
            }
            .accessibilityIdentifier("search-filter")
          }
        }
      }
      .onChange(of: kind) { if !query.isEmpty { Task { await run() } } }
      .onChange(of: since) { if !query.isEmpty { Task { await run() } } }
      .onChange(of: group) { if !query.isEmpty { Task { await run() } } }
      .navigationDestination(for: ContextRoute.self) { r in SearchContextView(hit: r.hit, terms: r.terms) }
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
    do {
      if scope == .files {
        c.queryItems = [URLQueryItem(name: "q", value: q), URLQueryItem(name: "limit", value: "30")]
        let r = try await RouterClient.shared.get("api/icloud/search?" + (c.percentEncodedQuery ?? ""))
        if n == seq { files = r }
      } else {
        var items = [URLQueryItem(name: "q", value: q), URLQueryItem(name: "limit", value: group ? "12" : "20"), URLQueryItem(name: "group", value: group ? "1" : "0")]
        if kind != "all" { items.append(URLQueryItem(name: "kind", value: kind)) }
        if since > 0 { items.append(URLQueryItem(name: "after", value: String(Date.now.addingTimeInterval(-Double(since) * 86400).formatted(.iso8601).prefix(10)))) }
        c.queryItems = items
        let r = try await RouterClient.shared.get("api/search?" + (c.percentEncodedQuery ?? ""))
        if n == seq { result = r }
      }
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

private struct ChatResults: View {
  let result: JSON
  var body: some View {
    let terms = result["terms"].strings
    Section {
      LabeledContent("Candidates", value: "\(result["total"].int ?? 0)").font(.footnote)
      LabeledContent("Took") { Text(Duration.milliseconds(Int(result["tookMs"].double ?? 0)), format: .units(allowed: [.seconds, .milliseconds], width: .abbreviated)) }.font(.footnote)
    }
    ForEach(Array(result["sessions"].array.enumerated()), id: \.offset) { _, g in
      Section {
        ForEach(Array(g["hits"].array.enumerated()), id: \.offset) { _, h in HitRow(h: h, terms: terms, bare: true) }
      } header: {
        HStack {
          Text(g["title"].string ?? "")
          Spacer()
          Text(["live": "running", "paused": "paused", "archive": "archived"][g["state"].string ?? ""] ?? "")
        }
      } footer: {
        if (g["count"].int ?? 0) > g["hits"].array.count { LabeledContent("Shown", value: "\(g["hits"].array.count) of \(g["count"].int ?? 0)") }
      }
    }
    if !result["hits"].array.isEmpty {
      Section { ForEach(Array(result["hits"].array.enumerated()), id: \.offset) { _, h in HitRow(h: h, terms: terms, bare: false) } }
    }
  }
}

private struct HitRow: View {
  let h: JSON
  let terms: [String]
  let bare: Bool
  var body: some View {
    NavigationLink(value: ContextRoute(hit: h, terms: terms)) {
      VStack(alignment: .leading, spacing: 3) {
        if !bare { Text(h["title"].string ?? "").font(.headline) }
        Text([h["date"].text, ["msg": "conversation", "tool": "action", "doc": "record"][h["kind"].string ?? ""], h["via"].strings.joined(separator: " + ")].compactMap { $0 }.joined(separator: " · "))
          .font(.caption).foregroundStyle(.secondary)
        Text(marked(h["snippet"].string ?? "", terms)).font(h["kind"].string == "tool" ? .footnote.monospaced() : .subheadline).lineLimit(5)
      }
    }
    .accessibilityIdentifier("hit-\(h["id"].string ?? "")")
  }
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
