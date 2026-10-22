// The conversation around a search hit (api/search/context): the chunks before and after it in the same transcript,
// with the hit marked. Earlier / Later widen the window. The action brings the session back when it is Jarvis 4's:
// Resume for a paused session, Restore for an archive on the Previous list.
import SwiftUI

struct SearchContextView: View {
  @Environment(AppModel.self) private var model
  let hit: JSON
  let terms: [String]
  @State private var ctx: JSON?
  @State private var error: String?
  @State private var before = 3
  @State private var after = 3
  @State private var busy = false
  @State private var scrolled = false

  var body: some View {
    ScrollViewReader { proxy in
      List {
        Section {
          Text([hit["date"].text, hit["dir"].text.map { $0.replacing("claude-records/", with: "") } ?? (hit["state"].string == "live" ? "running session" : "paused session")].compactMap { $0 }.joined(separator: " · "))
            .font(.footnote).foregroundStyle(.secondary)
        }
        if let error { ErrorRow(text: error) }
        if let ctx {
          let chunks = ctx["chunks"].array
          let at = chunks.firstIndex { $0["hit"].bool == true } ?? 0
          if at >= before && before < 30 {
            Button("Earlier") { before = min(30, before + 6) }.disabled(busy)
          }
          ForEach(Array(chunks.enumerated()), id: \.offset) { i, c in
            ChunkView(c: c, terms: c["hit"].bool == true ? terms : [])
              .listRowBackground(c["hit"].bool == true ? Color.accentColor.opacity(0.1) : nil)
              .id(i)
          }
          if chunks.count - at - 1 >= after && after < 30 {
            Button("Later") { after = min(30, after + 6) }.disabled(busy)
          }
        }
      }
      .overlay { if ctx == nil && error == nil { ProgressView("Reading…") } }
      .task(id: "\(before)-\(after)") {
        busy = true
        defer { busy = false }
        do {
          let j = try await RouterClient.shared.get("api/search/context?id=\(hit["id"].string ?? "")&before=\(before)&after=\(after)")
          ctx = j
          // opens with the hit in view; widening the window afterwards doesn't move the page
          if !scrolled, let i = j["chunks"].array.firstIndex(where: { $0["hit"].bool == true }) { scrolled = true; proxy.scrollTo(i, anchor: .top) }
        } catch { self.error = errText(error) }
      }
    }
    .navigationTitle(hit["title"].string ?? "")
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      if let (title, run) = action {
        ToolbarItem(placement: .primaryAction) { Button(title, action: run).accessibilityIdentifier("sc-action") }
      }
    }
  }

  /// how the hit's session comes back, if it is Jarvis 4's
  private var action: (String, () -> Void)? {
    if let mid = hit["machineId"].text, let m = model.session(mid), m.state == "paused" {
      return ("Resume", { model.tab = .sessions; Task { await model.resume(m.id) } })
    }
    if let dir = hit["dir"].text, let r = model.records.items.first(where: { $0.archive["dir"].string == dir && $0.restorable }) {
      return ("Restore", { Task { await model.restore(r) } })
    }
    return nil
  }
}

/// a chunk is "[Deyao] …\n\n[Claude] …" (Jarvis 1's search/extract.js): back to labelled parts
private struct ChunkView: View {
  let c: JSON
  let terms: [String]
  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      ForEach(Array(parts(c["text"].string ?? "").enumerated()), id: \.offset) { _, p in
        VStack(alignment: .leading, spacing: 2) {
          if !p.who.isEmpty { Text(p.who == "Deyao" ? "You" : p.who).font(.caption.bold()).foregroundStyle(.secondary) }
          Text(marked(p.body, terms)).font(c["kind"].string == "tool" ? .footnote.monospaced() : .body).textSelection(.enabled)
        }
      }
    }
  }
  private func parts(_ text: String) -> [(who: String, body: String)] {
    var out: [(String, String)] = []
    for seg in text.components(separatedBy: "\n\n[") .enumerated().map({ $0.offset == 0 ? $0.element : "[" + $0.element }) {
      if seg.hasPrefix("["), let close = seg.firstIndex(of: "]"), seg.distance(from: seg.startIndex, to: close) <= 41,
         seg.index(after: close) < seg.endIndex, seg[seg.index(after: close)] == " " {
        out.append((String(seg[seg.index(after: seg.startIndex)..<close]), String(seg[seg.index(close, offsetBy: 2)...])))
      } else { out.append(("", seg)) }
    }
    return out
  }
}
