// What each store and key is for (router/storedocs.go GET /api/stores): each store's keys with who wrote them and when,
// the store's about text and each key's explanation. Not a secret and in no trust decision by itself: the names and
// writers come from the core's signed store list (the router passes them on), the texts are the router's own record.
// What a review page shows of it is checked against the core's signed unlock_begin before Face ID: a key a session
// wrote that the page didn't show is refused (StoreUnlock), so a session-written value is never released unseen.
import SwiftUI

/// one store as the router lists it
struct StoreRowDTO: Decodable, Identifiable, Equatable {
  struct Writer: Decodable, Equatable {
    let by: String
    var machine: String? = nil
    var line: String? = nil
    var session: String? = nil
    var sessionLabel: String? = nil
  }
  struct Key: Decodable, Identifiable, Equatable {
    let name: String
    var explanation: String? = nil
    var at: String? = nil
    var writer: Writer? = nil
    var id: String { name }
    var bySession: Bool { writer?.by == "machine" }
  }
  let name: String
  var sensitive: Bool? = nil
  var empty: Bool? = nil
  var unlocked: Bool? = nil
  var about: String? = nil
  var version: String? = nil
  /// each key (from the core's signed list) with its explanation and writer
  let keyInfo: [Key]
  var id: String { name }
}

extension StoreRowDTO.Writer {
  /// the session that wrote a key, as the router knows its line (its title, else the line)
  var sessionName: String {
    if let l = sessionLabel, !l.isEmpty { return l }
    return line ?? machine ?? "a session"
  }
}

enum SessionWrites {
  /// the keys sessions wrote into `stores`, from the router's rows (what a page shows before it unlocks them)
  static func from(_ rows: [StoreRowDTO], stores: [String]) -> [SessionWrite] {
    rows.filter { stores.contains($0.name) }.flatMap { r in
      r.keyInfo.filter(\.bySession).map { SessionWrite(store: r.name, key: $0.name, line: $0.writer?.line ?? "", label: $0.writer?.sessionName ?? "") }
    }
  }
  /// the same, read now (an unreadable list shows none: then an unlock that opens a session-written key is refused)
  static func load(_ stores: [String]) async -> [SessionWrite] {
    guard !stores.isEmpty, let rows = try? await RouterClient.shared.storeRows() else { return [] }
    return from(rows, stores: stores)
  }
  /// "STORE · KEY" lines for a signed-facts row
  static func lines(_ ws: [SessionWrite]) -> String { ws.map { "\($0.store) · \($0.key) · \($0.label)" }.joined(separator: "\n") }
  /// a review page's facts row for them (none when no session wrote any)
  static func fact(_ ws: [SessionWrite]) -> [SignedFact] {
    ws.isEmpty ? [] : [.init(id: "session-written", label: "Written by a session", value: lines(ws), style: .warning)]
  }
}

/// the keys a session wrote into the stores a page unlocks: shown before Face ID, each with the session that wrote it
struct SessionWritesSection: View {
  let writes: [SessionWrite]
  var body: some View {
    if !writes.isEmpty {
      Section {
        ForEach(writes, id: \.self) { w in
          LabeledContent {
            Text(w.label.isEmpty ? w.line : w.label).multilineTextAlignment(.trailing)
          } label: {
            VStack(alignment: .leading, spacing: 2) {
              Text(w.key).font(.body.monospaced())
              Text(w.store).font(.footnote).foregroundStyle(.secondary)
            }
          }
          .accessibilityElement(children: .combine)
          .accessibilityIdentifier("session-written-\(w.store)-\(w.key)")
        }
      } header: {
        Label("Written by a session", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
      } footer: {
        Text("Values a session chose. Unlocking gives them to the session that gets these stores.")
      }
    }
  }
}
