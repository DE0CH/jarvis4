// Which line each session id is (audit 2026-10-11, findings 3-5). The router maps its session ids to certs; a lying
// router could answer "session A" with session B's genuine cert and steer a Face ID meant for A to B. The pages show
// the identity from the cert itself (LineIdentity), and on top of that the app remembers the line it first saw for each
// session id (a session's line never changes: a resume keeps it, a restore is a new session) and refuses a cert, or a
// challenge's predecessor, that names another line for the same id. The first sighting is still the router's word.
import Foundation

enum LinePins {
  private static let key = "line-pins"
  private static var pins: [String: String] {
    get { UserDefaults.standard.dictionary(forKey: key) as? [String: String] ?? [:] }
    set { UserDefaults.standard.set(newValue, forKey: key) }
  }
  /// the line for this session id: recorded the first time, refused when it differs later
  static func check(session: String, line: String) throws {
    guard !session.isEmpty, !line.isEmpty else { return }
    if let known = pins[session] {
      if known != line { throw TrustError.mismatch("the router named another session's cert for this one (line \(line), not \(known))") }
    } else {
      var p = pins
      p[session] = line
      if p.count > 500 { p = Dictionary(uniqueKeysWithValues: p.suffix(400).map { ($0.key, $0.value) }) }
      pins = p
    }
  }
  /// a Reset or Recover is a new core: its lines are new
  static func clear() { UserDefaults.standard.removeObject(forKey: key) }
}

/// Which stores each harness brings, as this app was built with them (policy/stores.json, bundled from git: the same
/// push path as the app's code). The router's api/policy is only a hint for hiding stores in pickers; what may be
/// signed beyond the stores picked on New session is decided here (audit finding 2). A CI build also takes the
/// router's list, since its throwaway router runs a test policy.
enum PinnedPolicy {
  static let harnessStores: [String: [String]] = {
    guard let u = Bundle.main.url(forResource: "stores", withExtension: "json"), let d = try? Data(contentsOf: u),
          let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any], let h = j["harnesses"] as? [String: Any] else { return [:] }
    return h.compactMapValues { ($0 as? [String: Any])?["stores"] as? [String] }
  }()
  static func stores(_ harness: String, router: [String: [String]]) -> [String] {
    var s = harnessStores[harness] ?? []
    #if JARVIS_CI
    s += router[harness] ?? []
    #endif
    return Array(Set(s)).sorted()
  }
}
