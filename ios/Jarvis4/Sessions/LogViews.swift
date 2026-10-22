// A session's Log, read only, beside the terminal: ONE stream, in time order, of everything the router keeps about the
// session's machines (GET api/sessions/:id/events, router/sessionevents.go): the supervisor's lines (boot, commands it
// ran, prompts it delivered, the snapshot, with no secrets in it) and each boot, pause, resume, upgrade and destroy
// from its start to its end, with the router's steps and what Fly did. Each entry has its time and a source tag
// (Supervisor, Router, Fly) and, inside an operation, the operation's kind. Kept for the session's life, so it opens for
// running, paused and failed sessions alike; while open it polls every 2 s with the cursor. It opens at the tail (newest
// at the bottom, like the terminal) and stays there as lines arrive while the reader is at the bottom; scrolled up, it
// leaves them where they are and offers Latest (app/DECISIONS.md 78). A plain native list, wrapped text (no sideways scrolling on a phone), semantic
// colours only (readable in light and dark).
import SwiftUI

/// "12:04:31" today, "Oct 15 12:04:31" on another day
private func clock(_ d: Date?) -> String {
  guard let d else { return "" }
  return Calendar.current.isDateInToday(d)
    ? d.formatted(.dateTime.hour().minute().second())
    : d.formatted(.dateTime.month(.abbreviated).day().hour().minute().second())
}

private let pollEvery: Duration = .seconds(2)
private let keep = 5000

/// the held events plus the new ones (by key), in time order, the oldest dropped past `keep`
func mergeEvents(_ held: [SessionEvent], _ got: [SessionEvent]) -> [SessionEvent] {
  if got.isEmpty { return held }
  var by = Dictionary(held.map { ($0.key, $0) }, uniquingKeysWith: { _, b in b })
  for e in got { by[e.key] = e }
  var out = Array(by.values)
  out.sort { ($0.at ?? .distantPast, $0.key) < ($1.at ?? .distantPast, $1.key) }
  return out.count > keep ? Array(out.suffix(keep)) : out
}

struct SessionLogView: View {
  let sessionId: String
  let title: String
  @State private var events: [SessionEvent] = []
  @State private var next = ""
  @State private var running: String?
  @State private var loaded = false
  @State private var error: String?
  /// the reader is at the tail (within a line of the bottom): new lines keep it there; scrolled up, nothing moves it
  @State private var atEnd = true
  @State private var jump = false
  private let endID = "log-end"

  var body: some View {
    ScrollViewReader { proxy in
      List {
        if let error { ErrorRow(text: error, id: "log-error") }
        if let running {
          HStack { Text("Now").foregroundStyle(.secondary); Spacer(); StatusPill(text: "\(running) running", color: .orange, spinning: true) }
            .accessibilityIdentifier("log-running")
        }
        if loaded && events.isEmpty {
          Text("Nothing recorded yet.").foregroundStyle(.secondary).accessibilityIdentifier("log-empty")
        }
        ForEach(events) { e in
          EventRow(e: e)
            .listRowInsets(EdgeInsets(top: e.mark == "start" ? 10 : 3, leading: 12, bottom: 3, trailing: 12))
            .listRowSeparator(e.mark == "start" ? .visible : .hidden, edges: .top)
            .listRowSeparator(.hidden, edges: .bottom)
            .id(e.key)
        }
        // the tail's marker: the scroll target, and the replica's proof that the log opened (and stays) at its end
        Color.clear.frame(height: 4)
          .listRowSeparator(.hidden)
          .listRowInsets(EdgeInsets())
          .id(endID)
          .accessibilityElement()
          .accessibilityLabel("End of the log")
          .accessibilityIdentifier("log-end")
      }
      .listStyle(.plain)
      .defaultScrollAnchor(.bottom)
      .onScrollGeometryChange(for: Bool.self) { g in
        g.contentOffset.y + g.containerSize.height - g.contentInsets.bottom >= g.contentSize.height - 40
      } action: { _, now in atEnd = now }
      .onChange(of: jump) { _, go in
        guard go else { return }
        withAnimation(.easeOut(duration: 0.2)) { proxy.scrollTo(endID, anchor: .bottom) }
        atEnd = true; jump = false
      }
      .overlay { if !loaded && error == nil { ProgressView("Reading the log…") } }
      .task(id: sessionId) {
        events = []; next = ""; loaded = false; atEnd = true
        var first = true
        while !Task.isCancelled {
          let stick = atEnd  // decided before the new lines grow the list (which reads as "not at the end" for a moment)
          let before = events.last?.key
          let more = await poll()
          if stick && (first || events.last?.key != before) {
            withAnimation(nil) { proxy.scrollTo(endID, anchor: .bottom) }
            if first {  // the first page lays out over a few frames: once more after it has
              try? await Task.sleep(for: .milliseconds(150))
              withAnimation(nil) { proxy.scrollTo(endID, anchor: .bottom) }
            }
            atEnd = true
          }
          first = false
          if !more { try? await Task.sleep(for: pollEvery) }
        }
      }
    }
    .navigationTitle("Log")
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .primaryAction) {
        if !atEnd { Button("Latest", systemImage: "arrow.down.to.line") { jump = true }.accessibilityIdentifier("log-latest") }
      }
    }
    .accessibilityIdentifier("session-log")
  }

  /// one read; true when the router has more right away (a backlog past the limit)
  private func poll() async -> Bool {
    let q = next.isEmpty ? "limit=2000" : "after=\(next)&limit=1000"
    do {
      let r = try await RouterClient.shared.get("api/sessions/\(RouterClient.escaped(sessionId))/events?\(q)")
      events = mergeEvents(events, r["events"].array.map(SessionEvent.init))
      running = r["running"]["kind"].string
      let incremental = !next.isEmpty
      if let n = r["next"].string { next = n }
      loaded = true
      error = nil
      return incremental && r["more"].bool == true
    } catch {
      self.error = errText(error)
      loaded = true
      return false
    }
  }
}

private struct EventRow: View {
  let e: SessionEvent
  var body: some View {
    VStack(alignment: .leading, spacing: 2) {
      HStack(spacing: 6) {
        Text(clock(e.at)).font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
        SourceTag(source: e.source)
        if !e.op.isEmpty { OpTag(text: e.op) }
        if !e.machine.isEmpty { Text(e.machine).font(.caption2.monospaced()).foregroundStyle(.tertiary).lineLimit(1) }
      }
      Text(e.text)
        .font(e.mark.isEmpty ? Font.caption.monospaced() : Font.caption.monospaced().bold())
        .foregroundStyle(e.mark == "end" && !e.state.isEmpty && e.state != "done" ? AnyShapeStyle(Color.red) : AnyShapeStyle(HierarchicalShapeStyle.primary))
        .textSelection(.enabled)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
    .accessibilityElement(children: .combine)
    .accessibilityIdentifier("ev-\(e.key)")
  }
}

private struct SourceTag: View {
  let source: String
  var body: some View {
    let (t, c): (String, Color) = switch source {
    case "fly": ("Fly", .purple)
    case "router": ("Router", .blue)
    case "supervisor": ("Supervisor", .teal)
    default: (source.isEmpty ? "—" : source, .secondary)
    }
    Text(t).font(.caption2.weight(.semibold)).padding(.horizontal, 5).padding(.vertical, 1)
      .foregroundStyle(c).background(c.opacity(0.14), in: .capsule)
  }
}

private struct OpTag: View {
  let text: String
  var body: some View {
    Text(text).font(.caption2.weight(.medium)).padding(.horizontal, 5).padding(.vertical, 1)
      .foregroundStyle(.secondary).background(Color(.tertiarySystemFill), in: .capsule)
  }
}
