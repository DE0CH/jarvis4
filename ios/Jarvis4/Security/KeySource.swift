// Where the app gets what it trusts besides the router: the public keys in DE0CH/jarvis4's git (keys/box.pub vouches
// for a core's identity and for the core named in Jarvis 2's backups, keys/setup.pub for the backups and the kernel's
// pending roster, keys/root.pub is checked against this iPhone's own root key), fetched from GitHub — never from the
// router. A CI build
// (compiled with JARVIS_CI, simulator walkthrough only) may point at a local stand-in through its Info.plist.
// Any build may name another git ref of the same repo (JarvisKeysRef, a branch name only): the phone replica's
// Release build reads its throwaway stack's keys from a branch replica-keys-<run> (ios.yml job `replica`). The
// TestFlight archive must leave it empty (ios.yml checks).
import Foundation

enum KeySource {
  static let githubKeys = "https://raw.githubusercontent.com/DE0CH/jarvis4/main/keys/"

  private static func plist(_ k: String) -> String? {
    #if JARVIS_CI
    if let s = Bundle.main.object(forInfoDictionaryKey: k) as? String, !s.isEmpty { return s }
    #endif
    return nil
  }
  /// the git ref the keys come from: main, or the Info.plist's JarvisKeysRef (letters, digits, - _ . / only)
  static var keysRef: String {
    let r = (Bundle.main.object(forInfoDictionaryKey: "JarvisKeysRef") as? String ?? "").trimmingCharacters(in: .whitespaces)
    let ok = !r.isEmpty && !r.contains("..") && r.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || "-_./".contains($0)) }
    return ok ? r : "main"
  }
  static var keysBase: String {
    let b = plist("JarvisCIKeysBase") ?? githubKeys.replacingOccurrences(of: "/main/keys/", with: "/\(keysRef)/keys/")
    return b.hasSuffix("/") ? b : b + "/"
  }

  /// keys/<name> from git (base64 X9.63), no cache
  static func key(_ name: String) async throws -> String {
    var r = URLRequest(url: URL(string: keysBase + name)!)
    r.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
    r.timeoutInterval = 30
    let (d, resp) = try await URLSession.shared.data(for: r)
    guard (resp as? HTTPURLResponse)?.statusCode == 200 else { throw RouterError(message: "Couldn't fetch keys/\(name) from \(keysBase).") }
    return String(decoding: d, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
  }

  /// keys/<name> from git, or nil when git doesn't have it (404): a key that isn't in use yet (keys/ci.pub)
  static func optionalKey(_ name: String) async throws -> String? {
    guard let u = URL(string: keysBase + name) else { return nil }
    var r = URLRequest(url: u)
    r.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
    r.timeoutInterval = 30
    let (d, resp) = try await URLSession.shared.data(for: r)
    let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
    if status == 404 { return nil }
    guard status == 200 else { throw RouterError(message: "Couldn't fetch keys/\(name) from \(keysBase).") }
    return String(decoding: d, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
  }
}
