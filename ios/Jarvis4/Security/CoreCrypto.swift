// The app's side of the core's formats (core/crypto.go, core/core.go), with no UI, network or Keychain in
// it, so the same file is compiled into the interop test (ios/interop) that runs it against the real core.
//   - a signed document is {payload, sig}: sig = base64 DER ECDSA-P256-SHA256 over the payload's bytes;
//   - public keys are base64 of the 65-byte uncompressed X9.63 point;
//   - Sealed {e, data}: ephemeral P-256 e, x(e·R) → HKDF-SHA256(salt empty, info, 32 bytes) → AES-256-GCM
//     combined (nonce‖ct‖tag). Infos: "jarvis2/unlock-share" (the phone's share x(p·E) to the core's one-off
//     key T), "jarvis2/claim" (the claim's bundle to the core), "jarvis2/backup" (a backup to the master key: a
//     key's with "<store>\n<key>" as associated data, an older whole-store backup's with the store's name).
//   - a store is a set of keys (core/keys.go): each value under its own data key ("<store>\n<key>" as associated
//     data), the data key wrapped to the store key P + K ("jarvis2/store-data-key").
// The core's identity: "jarvis2-core-identity <signingKey> <agreementKey>", signed by the box key (keys/box.pub),
// which the app checks itself before it trusts a core.
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

struct SignedDoc: Codable, Equatable { let payload: String; let sig: String }

enum TrustError: LocalizedError, Equatable {
  case notSetUp, badKit(String), badSignature(String), mismatch(String), stale(String), backup(String)
  var errorDescription: String? {
    switch self {
    case .notSetUp: return "Jarvis 4 isn't set up on this iPhone yet — open Settings → Reset or recover."
    case .badKit(let s): return s
    case .badSignature(let s): return "The signature on \(s) didn't check out — refusing to continue."
    case .mismatch(let s): return "The core's answer doesn't match what you chose (\(s)) — refusing to sign."
    case .stale(let s): return "The core's answer isn't for this request (\(s)) — refusing to continue."
    case .backup(let s): return s
    }
  }
}

/// a P-256 key pair's public halves (the core's, the phone's)
struct PublicKeys: Codable, Equatable {
  let signingKey: String, agreementKey: String
  static func valid(_ k: PublicKeys) -> Bool {
    guard let s = Data(base64Encoded: k.signingKey), (try? P256.Signing.PublicKey(x963Representation: s)) != nil,
          let a = Data(base64Encoded: k.agreementKey), (try? P256.KeyAgreement.PublicKey(x963Representation: a)) != nil else { return false }
    return true
  }
}

enum CoreCrypto {
  static func hex(_ d: some Sequence<UInt8>) -> String { d.map { String(format: "%02x", $0) }.joined() }
  static func sha256hex(_ d: Data) -> String { hex(SHA256.hash(data: d)) }

  /// a DER signature by `key` (base64 X9.63) over exactly `payload`
  static func valid(_ payload: Data, sig: String, by key: String) -> Bool {
    guard let k = Data(base64Encoded: key.trimmingCharacters(in: .whitespacesAndNewlines)).flatMap({ try? P256.Signing.PublicKey(x963Representation: $0) }),
          let s = Data(base64Encoded: sig).flatMap({ try? P256.Signing.ECDSASignature(derRepresentation: $0) }) else { return false }
    return k.isValidSignature(s, for: payload)
  }
  /// the payload's bytes, only if `key` (base64 X9.63) signed them
  static func verified(_ doc: SignedDoc, by key: String, what: String) throws -> Data {
    let p = Data(doc.payload.utf8)
    guard valid(p, sig: doc.sig, by: key) else { throw TrustError.badSignature(what) }
    return p
  }
  static func decode<T: Decodable>(_ doc: SignedDoc, by key: String, as: T.Type, what: String) throws -> T {
    try JSONDecoder().decode(T.self, from: verified(doc, by: key, what: what))
  }

  // ---- sealing ----
  static let shareInfo = "jarvis2/unlock-share", claimInfo = "jarvis2/claim", backupInfo = "jarvis2/backup"
  static func seal(_ plain: Data, to recipient: String, info: String, aad: Data? = nil) throws -> [String: String] {
    guard let rb = Data(base64Encoded: recipient) else { throw TrustError.badSignature("the recipient key") }
    let rk = try P256.KeyAgreement.PublicKey(x963Representation: rb)
    let e = P256.KeyAgreement.PrivateKey()
    let key = try e.sharedSecretFromKeyAgreement(with: rk)
      .hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: Data(info.utf8), outputByteCount: 32)
    let box: AES.GCM.SealedBox
    if let aad { box = try AES.GCM.seal(plain, using: key, authenticating: aad) } else { box = try AES.GCM.seal(plain, using: key) }
    guard let combined = box.combined else { throw TrustError.badSignature("sealing") }
    return ["e": e.publicKey.x963Representation.base64EncodedString(), "data": combined.base64EncodedString()]
  }
  static func open(_ sealed: [String: String], with priv: P256.KeyAgreement.PrivateKey, info: String, aad: Data? = nil) throws -> Data {
    guard let eb = Data(base64Encoded: sealed["e"] ?? ""), let e = try? P256.KeyAgreement.PublicKey(x963Representation: eb),
          let d = Data(base64Encoded: sealed["data"] ?? "") else { throw TrustError.backup("a sealed value is malformed") }
    let key = try priv.sharedSecretFromKeyAgreement(with: e)
      .hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: Data(info.utf8), outputByteCount: 32)
    let box = try AES.GCM.SealedBox(combined: d)
    if let aad { return try AES.GCM.open(box, using: key, authenticating: aad) }
    return try AES.GCM.open(box, using: key)
  }
  /// seal the phone's 32-byte share x(p·E) to the core's one-off key T → {e, data}
  static func sealShare(_ x: Data, to t: String) throws -> [String: String] { try seal(x, to: t, info: shareInfo) }

  static func nonce() -> String {
    var g = SystemRandomNumberGenerator()
    return hex((0..<16).map { _ in UInt8.random(in: 0...255, using: &g) })
  }

  // ---- the core's identity ----
  static func identityText(_ k: PublicKeys) -> String { "jarvis2-core-identity \(k.signingKey) \(k.agreementKey)" }
  /// the box key (keys/box.pub, from GitHub) vouches for this core's keys
  static func identityVouched(_ k: PublicKeys, boxSig: String, boxKey: String) -> Bool {
    PublicKeys.valid(k) && valid(Data(identityText(k).utf8), sig: boxSig, by: boxKey)
  }
}

// ---- the recovery kit: what Deyao keeps in his password manager --------------------------------------
/// The master private key. It exists only inside the recovery kit: Reset makes it and shows the kit, Recover
/// reads it from the pasted kit; either way the app keeps it in memory just long enough to set the core up.
struct MasterKey {
  let signing: P256.Signing.PrivateKey
  var agreement: P256.KeyAgreement.PrivateKey { try! P256.KeyAgreement.PrivateKey(rawRepresentation: signing.rawRepresentation) }
  var publicKey: String { signing.publicKey.x963Representation.base64EncodedString() }
  /// a fresh pair, made in software so the private half can go into the recovery kit
  static func generate() -> MasterKey { MasterKey(signing: P256.Signing.PrivateKey()) }
  /// the kit's master part: base64 PKCS#8 DER (the body of a PEM "PRIVATE KEY" block)
  var pkcs8: String { signing.pemRepresentation.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined() }
  init(signing: P256.Signing.PrivateKey) { self.signing = signing }
  init(pkcs8 b64: String) throws {
    guard let d = Data(base64Encoded: b64.filter { !$0.isWhitespace }), let k = try? P256.Signing.PrivateKey(derRepresentation: d) else {
      throw TrustError.badKit("That isn't a recovery kit.")
    }
    signing = k
  }
  func sign(_ text: String) throws -> String { try signing.signature(for: Data(text.utf8)).derRepresentation.base64EncodedString() }
  /// the public half is `pub` (base64 X9.63)
  func matches(_ pub: String) -> Bool { MasterKey.same(publicKey, pub) }
  static func same(_ a: String, _ b: String) -> Bool {
    guard let x = Data(base64Encoded: a.trimmingCharacters(in: .whitespacesAndNewlines)), !x.isEmpty else { return false }
    return x == Data(base64Encoded: b.trimmingCharacters(in: .whitespacesAndNewlines))
  }
}

/// The recovery kit: the ONE string Deyao keeps in his password manager — `jarvis2-kit:2:<master private key,
/// base64 PKCS#8 DER>`. Reset shows it; Recover takes it. Version 1 (which carried the backup bucket's read keys)
/// is refused: the router reads the backups now, and no core trusts a version-1 key.
struct RecoveryKit {
  let master: MasterKey
  static let prefix = "jarvis2-kit:2:"
  var string: String { RecoveryKit.prefix + master.pkcs8 }
  static func parse(_ raw: String) throws -> RecoveryKit {
    let s = raw.filter { !$0.isWhitespace }
    if s.hasPrefix("jarvis2-kit:1:") { throw TrustError.badKit("This recovery kit is from an older Jarvis 4 and doesn't work any more.") }
    guard s.hasPrefix(prefix), let m = try? MasterKey(pkcs8: String(s.dropFirst(prefix.count))) else { throw TrustError.badKit("That isn't a recovery kit.") }
    return RecoveryKit(master: m)
  }
}

// ---- the core's documents (core/core.go) ----
struct StartedMachine: Codable, Equatable { let id: String; let requested: String?; let image: String; let encryptionKey: String; let signingKey: String }
/// the core's signed options: the harness, the permission mode ("auto" | "bypass"), and from a core that vouches for
/// inputs (docs/DESIGN.md "Inputs to a machine") the session's settings (config: a JSON object) and one machine's
/// one-time inputs (once: a resume's prompt, a rollback)
struct Options: Codable, Equatable { let harness: String?; var permissionMode: String? = nil; var config: String? = nil; var once: String? = nil }
struct SuccessionRequest: Codable {
  let kind: String
  let predecessor: SignedDoc?
  let predecessorId: String?
  /// the line's first machine ("" or nil = a new line)
  var line: String? = nil
  let machine: StartedMachine?
  let image: String?
  let stores: [String]?
  let sensitive: [String]?
  let options: Options
  let addedStore: String?
  let downgrade: Bool?
}
struct Challenge: Codable { let kind: String; let nonce: String; let request: SuccessionRequest }
/// the core's answer to an approved challenge: an "approval" (a new line, bound to a machine later) or a
/// "succession-cert" (a running machine with one more store)
struct Answer: Codable { let kind: String; let nonce: String; let machine: StartedMachine?; var stores: [String]? = nil }
struct StoreView: Codable, Identifiable, Equatable {
  let name: String; let sensitive: Bool; let empty: Bool; let unlocked: Bool; var id: String { name }
  /// the store named `core` holds the core's own Fly token: it never shows for sessions
  static let coreStore = "core"
  var isCore: Bool { name == StoreView.coreStore }
}
struct StoresDoc: Codable { let kind: String; let nonce: String; let stores: [StoreView] }
/// who wrote a store's key (core/keys.go EntryWriter): "setup" (its key's signature over Checks.writerText, checked here),
/// "machine" (a session's machine and line: the core checked its signature; the page names the session), "router" (a
/// Claude account store's pair) or "core".
struct StoreWriter: Codable, Equatable {
  let by: String; var sig: String? = nil
  var machine: String? = nil; var line: String? = nil
}
/// forNonce: the one challenge or cert the unlock is for ("" or nil = standing, open to every session)
struct UnlockRow: Codable, Identifiable, Equatable {
  let id: String; let store: String; let since: String; let forNonce: String?
  enum CodingKeys: String, CodingKey { case id, store, since, forNonce = "for" }
}
struct UnlockedDoc: Codable { let kind: String; let nonce: String; let unlocked: [UnlockRow] }
/// one key of an unlock (core/keys.go UnlockBegin): its name, E, who wrote it, its data and backup hashes, when
struct KeyBegin: Codable, Equatable {
  let key: String; let e: String; let writer: StoreWriter; let dataSha256: String; var backupSha256: String = ""; var at: String? = nil
}
/// unlock_begin: every key of the store (`keys`), each opened with its own share
struct UnlockBegin: Codable {
  let kind: String; let pending: String; let store: String; let t: String; let forNonce: String?
  let keys: [KeyBegin]
  var version: String? = nil
  enum CodingKeys: String, CodingKey { case kind, pending, store, t, forNonce = "for", keys, version }
  /// the E of every share this unlock needs, in order (one per key)
  var es: [String] { keys.map(\.e) }
}
struct KindDoc: Codable { let kind: String; let id: String?; let store: String?; let name: String?; let stores: Int?; let core: String? }

/// What a secure page shows for a challenge — read from the core-signed challenge itself, never from the
/// router's label — and the checks that what comes back answers it.
enum Checks {
  enum Kind: String { case newSession = "new-session", resumeUpgrade = "resume-upgrade", addStore = "add-store", other }
  struct Reviewed {
    let kind: Kind; let challenge: Challenge; let stores: [String]; let sensitive: [String]; let harness: String; let image: String; let addedStore: String?
    /// from the signed challenge itself: "bypass" or "auto" (an absent mode is auto, as the core normalises it)
    var permissionMode: String { challenge.request.options.permissionMode == "bypass" ? "bypass" : "auto" }
    /// the signed settings (nil: none — an older core, or a burn)
    var config: [String: Any]? { Checks.object(challenge.request.options.config) }
    var once: [String: Any]? { Checks.object(challenge.request.options.once) }
  }

  /// a JSON value as one line, keys sorted (what the page shows of a signed value it has no field for)
  static func compact(_ v: Any?) -> String {
    guard let v, JSONSerialization.isValidJSONObject(v),
          let d = try? JSONSerialization.data(withJSONObject: v, options: [.sortedKeys, .withoutEscapingSlashes]) else { return v.map { "\($0)" } ?? "none" }
    return String(decoding: d, as: UTF8.self)
  }

  static func object(_ s: String?) -> [String: Any]? {
    guard let s, !s.isEmpty, let d = s.data(using: .utf8) else { return nil }
    return (try? JSONSerialization.jsonObject(with: d)) as? [String: Any]
  }

  /// the keys a session's settings may have (machine/vouch.go SessionConfig) and a one-time input (OnceInputs);
  /// a challenge with anything else is refused: the phone must show all that it signs
  static let configKeys: Set<String> = ["v", "label", "prompt", "model", "repos", "content", "oneShot", "apiProxy", "attachments", "restore", "task", "claudeAccount"]
  static let onceKeys: Set<String> = ["prompt", "rollback"]

  static func checkKnown(_ r: Reviewed) throws {
    if let c = r.config, !Set(c.keys).isSubset(of: configKeys) { throw TrustError.mismatch("settings this app can't show") }
    if let c = r.config, attachments(c) == nil { throw TrustError.mismatch("attachments this app can't show") }
    if let c = r.config, content(c) == nil { throw TrustError.mismatch("content stores this app can't show") }
    if let o = r.once, !Set(o.keys).isSubset(of: onceKeys) { throw TrustError.mismatch("one-time inputs this app can't show") }
    if r.challenge.request.options.config?.isEmpty == false && r.config == nil { throw TrustError.mismatch("settings that aren't a JSON object") }
    if r.challenge.request.options.once?.isEmpty == false && r.once == nil { throw TrustError.mismatch("one-time inputs that aren't a JSON object") }
  }

  /// the challenge is core-signed; what it asks for comes from its own fields
  static func review(challenge doc: SignedDoc, coreKey: String) throws -> Reviewed {
    let ch = try CoreCrypto.decode(doc, by: coreKey, as: Challenge.self, what: "the challenge")
    guard ch.kind == "challenge" else { throw TrustError.mismatch("not a challenge") }
    let r = ch.request, pred = r.predecessorId ?? ""
    let kind: Kind
    if let added = r.addedStore, !added.isEmpty, r.machine != nil { kind = .addStore }
    else if r.downgrade == true || r.machine != nil || (r.image ?? "").isEmpty || r.image == "null" { kind = .other }
    else if !pred.isEmpty { kind = .resumeUpgrade }
    else { kind = .newSession }
    let image = r.machine?.image ?? r.image ?? ""
    let rv = Reviewed(kind: kind, challenge: ch, stores: r.stores ?? [], sensitive: r.sensitive ?? [], harness: r.options.harness ?? "", image: image, addedStore: r.addedStore)
    try checkKnown(rv)
    return rv
  }

  /// an attached file as the signed config names it (router/vouch.go AttachmentRef): the sha256 and size are of the
  /// bytes this phone uploaded, hashed here
  struct Attachment: Equatable { var name: String; var sha256: String; var size: Int }

  /// the signed config's attachments, as signed (nil: not a list of {name, sha256, size})
  static func attachments(_ c: [String: Any]) -> [Attachment]? {
    guard let v = c["attachments"] else { return [] }
    guard let list = v as? [[String: Any]] else { return nil }
    var out: [Attachment] = []
    for a in list {
      guard Set(a.keys) == ["name", "sha256", "size"], let n = a["name"] as? String, let h = a["sha256"] as? String,
            let z = a["size"] as? Int else { return nil }
      out.append(Attachment(name: n, sha256: h, size: z))
    }
    return out
  }

  /// the signed config's content stores (router/content.go: ~/content/<name>/ on the machine), as signed (nil: not a
  /// list of store names)
  static func content(_ c: [String: Any]) -> [String]? {
    guard let v = c["content"] else { return [] }
    guard let list = v as? [String] else { return nil }
    for n in list where n.range(of: "^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$", options: .regularExpression) == nil { return nil }
    return list
  }

  /// what the New session page chose besides stores, harness and mode: with a core that vouches, the signed settings
  /// must be exactly these (nil = not checked: an older caller). No restore or task from this page; attachments only
  /// the ones this phone uploaded, each with the hash and size of its own bytes, in order.
  struct Settings {
    var label: String; var prompt: String; var model: String; var repos: [String]; var oneShot: Bool; var apiProxy: Bool
    var attachments: [Attachment] = []
    var content: [String] = []
    /// the Claude account picked (router/claudeaccounts.go; "" = none picked here): a config that names one must name it
    var claudeAccount: String = ""
  }

  static func matchesSettings(_ r: Reviewed, _ s: Settings) throws {
    guard let c = r.config else { // an older core: no settings travel in the cert (the machine takes none)
      if !s.attachments.isEmpty { throw TrustError.mismatch("attachments (this core doesn't carry them)") }
      return
    }
    func str(_ k: String) -> String { (c[k] as? String) ?? "" }
    guard str("label") == s.label else { throw TrustError.mismatch("title") }
    guard str("prompt") == s.prompt else { throw TrustError.mismatch("first prompt") }
    if !s.model.isEmpty { guard str("model") == s.model else { throw TrustError.mismatch("model") } }
    guard ((c["repos"] as? [String]) ?? []) == s.repos else { throw TrustError.mismatch("repos") }
    guard ((c["oneShot"] as? Bool) ?? false) == s.oneShot else { throw TrustError.mismatch("one-shot") }
    guard ((c["apiProxy"] as? Bool) ?? false) == s.apiProxy else { throw TrustError.mismatch("API proxy") }
    guard attachments(c) == s.attachments else { throw TrustError.mismatch("attachments") }
    guard content(c) == s.content.sorted() else { throw TrustError.mismatch("content stores") }
    if !s.claudeAccount.isEmpty, let a = c["claudeAccount"] { guard (a as? String) == s.claudeAccount else { throw TrustError.mismatch("Claude account") } }
    for k in ["restore", "task"] where c[k] != nil { throw TrustError.mismatch(k) }
    guard r.once == nil else { throw TrustError.mismatch("one-time inputs") }
  }

  /// the secure New session page: the challenge carries exactly the stores picked there (plus the harness's
  /// own, which the router adds), the harness and the permission mode picked there
  static func matchesPicked(_ r: Reviewed, stores picked: [String], harnessStores: [String], harness: String, permissionMode: String) throws {
    guard r.kind == .newSession else { throw TrustError.mismatch("not a new session") }
    guard r.stores == Array(Set(picked + harnessStores)).sorted() else { throw TrustError.mismatch("stores") }
    guard r.harness == harness else { throw TrustError.mismatch("harness") }
    guard r.permissionMode == (permissionMode == "bypass" ? "bypass" : "auto") else { throw TrustError.mismatch("permission mode") }
  }

  /// the answer that came back is the core's, for this challenge
  static func answerFor(_ r: Reviewed, answer doc: SignedDoc, coreKey: String) throws {
    let a = try CoreCrypto.decode(doc, by: coreKey, as: Answer.self, what: "the core's answer")
    guard a.nonce == r.challenge.nonce else { throw TrustError.stale("answer") }
    if r.kind == .addStore {
      // the same running machine, now holding the added store. Not the challenge's whole machine and store list: when
      // another add-store or a downgrade was answered after this challenge was made, the core adds the store to the
      // machine's newest cert (its keys after a downgrade, its stores), core/core.go addOnto
      guard a.kind == "succession-cert", let m = a.machine, m.id == r.challenge.request.machine?.id,
            let added = r.addedStore, (a.stores ?? []).contains(added) else { throw TrustError.stale("cert") }
    } else {
      guard a.kind == "approval" || a.kind == "succession-cert" else { throw TrustError.stale("answer kind \(a.kind)") }
    }
  }
}

// ---- deploy keys (core/deploykeys.go): adding or removing a repo's key, approved by the phone ------------
/// the core's signed begin document: exactly what will happen, with the token store's E and a one-off T
struct DeployKeyBegin: Codable, Equatable {
  let kind: String, pending: String, action: String, repo: String, store: String
  let sensitive: Bool, replaces: Bool, title: String, tokenStore: String, e: String, t: String
  /// add: the app's public key, and each key of the store the app sent (name, E, sha256 of its data); a remove has none
  var publicKey: String? = nil
  var keys: [DeployKeyItem]? = nil
  /// who wrote the token key (as unlock-begin's writer), its name, data and backup hashes
  var tokenWriter: StoreWriter? = nil
  let tokenDataSha256: String
  let tokenKey: String
  let tokenBackupSha256: String
}
struct DeployKeyItem: Codable, Equatable { let key: String; let e: String; let dataSha256: String }
/// what the app sent with a deploy-key add: the public key, and the store's keys
struct DeployKeySent { let publicKey: String; let keys: [KeyEntry] }
/// the core's answer once it is done: "deploy-key-added" (with the key's fingerprint) or "deploy-key-removed"
struct DeployKeyAnswer: Codable {
  let kind: String, pending: String, repo: String, store: String
  let sensitive: Bool?, fingerprint: String?, deleted: Int?
  var publicKey: String? = nil
}

extension Checks {
  /// the only store this flow opens: its GitHub token may manage deploy keys, nothing else
  static let deployKeyTokenStore = "github-deploy-keys"

  /// the store a repo's key lives in (the core's RepoStore): github-<name> for DE0CH's repos, else
  /// github-<owner>-<name>; lower case, anything outside [a-z0-9-] as "-"
  static func repoStore(_ repo: String) -> String {
    let parts = repo.lowercased().split(separator: "/", maxSplits: 1).map(String.init)
    guard parts.count == 2 else { return "" }
    let slug = parts[0] == "de0ch" ? parts[1] : parts[0] + "-" + parts[1]
    let mapped = String(slug.unicodeScalars.map { s -> Character in
      (s >= "a" && s <= "z") || (s >= "0" && s <= "9") ? Character(s) : "-"
    })
    return "github-" + mapped.trimmingCharacters(in: CharacterSet(charactersIn: "-"))
  }

  /// the begin document is the core's, for exactly this action on this repo: its store, its title on GitHub,
  /// the one token store it opens; asked-for sensitivity is kept (the core may only add it)
  /// `sent`: the key and the store's keys the app sent (the core must echo exactly these)
  static func deployKeyBegin(_ doc: SignedDoc, coreKey: String, action: String, repo: String, sensitive: Bool,
                             sent: DeployKeySent? = nil) throws -> DeployKeyBegin {
    let b = try CoreCrypto.decode(doc, by: coreKey, as: DeployKeyBegin.self, what: "the deploy-key request")
    if let sent {
      let made = TrustError.mismatch("the key the core holds isn't the one this iPhone made")
      guard b.publicKey == sent.publicKey else { throw made }
      let want = sent.keys.sorted { $0.key < $1.key }.map { DeployKeyItem(key: $0.key, e: $0.wrapped.e, dataSha256: CoreCrypto.sha256hex(Data($0.data.utf8))) }
      guard b.keys == want else { throw made }
    }
    if action == "remove", b.keys?.isEmpty == false { throw TrustError.mismatch("a remove that brings a key") }
    guard b.kind == "deploy-key-begin", b.action == action else { throw TrustError.mismatch("action") }
    guard b.repo.lowercased() == repo.lowercased() else { throw TrustError.mismatch("repo") }
    guard b.store == repoStore(repo), b.title == deployKeyTitle(b.store) else { throw TrustError.mismatch("store") }
    guard b.tokenStore == deployKeyTokenStore else { throw TrustError.mismatch("the store it opens") }
    if action == "add", sensitive, !b.sensitive { throw TrustError.mismatch("sensitive") }
    // Jarvis's own repos can push code that changes Jarvis: their stores are always sensitive (checked here, not only
    // by the core)
    if action == "add", alwaysSensitive(repo), !b.sensitive { throw TrustError.mismatch("\(repo)'s store must be sensitive") }
    return b
  }
  /// the repos whose code runs Jarvis (DE0CH/jarvis2 and DE0CH/jarvis4): their stores are always sensitive
  static func alwaysSensitive(_ repo: String) -> Bool { ["de0ch/jarvis2", "de0ch/jarvis4"].contains(repo.lowercased()) }
  /// the deploy key's title on GitHub: Jarvis 4's own ("jarvis4 <store>"), so a re-add here replaces only Jarvis 4's key
  /// for the repo, never the one Jarvis 2 added ("jarvis2 <store>")
  static func deployKeyTitle(_ store: String) -> String { "jarvis4 " + store }

  /// the core's answer is for this request and says it was done
  static func deployKeyAnswer(_ doc: SignedDoc, coreKey: String, begin b: DeployKeyBegin) throws -> DeployKeyAnswer {
    let a = try CoreCrypto.decode(doc, by: coreKey, as: DeployKeyAnswer.self, what: "the core's answer")
    guard a.pending == b.pending, a.repo == b.repo, a.store == b.store else { throw TrustError.stale("deploy key") }
    guard a.kind == (b.action == "add" ? "deploy-key-added" : "deploy-key-removed") else { throw TrustError.stale("answer kind \(a.kind)") }
    if b.action == "add", a.sensitive != b.sensitive { throw TrustError.mismatch("sensitive") }
    return a
  }
}

// ---- grants (docs/DESIGN.md "Grants"): what the phone signs to let a router feature into a session --------
/// a line's succession cert (core/core.go Cert): the line grants name, the phone key the machine checks them
/// against, and the stores the session holds
struct SessionCert: Codable {
  let kind: String
  var machine: StartedMachine? = nil
  let stores: [String]?
  let options: Options?
  let phone: String?
  let sensitive: Bool?
  let line: String
  let issuedAt: String?
  /// what an unlock for this session names (unlock_begin's "for")
  let nonce: String?
}
/// the grant text (router/grants.go grantText) — exactly the router's draft, field for field
struct GrantText: Codable, Equatable {
  let kind: String, holder: String, session: String, scope: String, issued: String
  let expires: String?, until: String?
}

extension Checks {
  static let grantFields: Set<String> = ["kind", "holder", "session", "scope", "issued", "expires", "until"]
  static func isoDate(_ s: String?) -> Date? {
    guard let s else { return nil }
    let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime]
    return f.date(from: s)
  }

  /// the session's cert, core-signed; it must name a line
  static func cert(_ doc: SignedDoc, coreKey: String) throws -> SessionCert {
    let c = try CoreCrypto.decode(doc, by: coreKey, as: SessionCert.self, what: "the session's cert")
    guard c.kind == "succession-cert", !c.line.isEmpty else { throw TrustError.mismatch("not a session cert") }
    return c
  }

  /// The router's draft must say exactly what was chosen on the grant page: this kind, this holder's key, the
  /// cert's line, scope "shell", issued now, and `minutes` (1–10) for a grant or `until` for a standing rule.
  /// The cert must name this phone (the machine checks the signature against it). Nothing else may be in it.
  static func reviewGrant(text: String, cert: SessionCert, phoneKey: String, holderKey: String, kind: String,
                          minutes: Int, until: Date?, now: Date = Date()) throws -> GrantText {
    guard let obj = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
          Set(obj.keys).isSubset(of: grantFields),
          let g = try? JSONDecoder().decode(GrantText.self, from: Data(text.utf8)) else { throw TrustError.mismatch("the grant text") }
    guard cert.phone == phoneKey else { throw TrustError.mismatch("this session's cert names another phone") }
    guard g.kind == kind else { throw TrustError.mismatch("kind") }
    guard g.holder == holderKey else { throw TrustError.mismatch("feature") }
    guard g.session == cert.line else { throw TrustError.mismatch("session") }
    guard g.scope == "shell" else { throw TrustError.mismatch("scope") }
    guard let issued = isoDate(g.issued), abs(issued.timeIntervalSince(now)) < 300 else { throw TrustError.mismatch("issued time") }
    switch kind {
    case "grant":
      guard (1...10).contains(minutes), g.until == nil, let end = isoDate(g.expires),
            abs(end.timeIntervalSince(issued) - Double(minutes * 60)) < 1 else { throw TrustError.mismatch("duration") }
    case "rule":
      guard cert.sensitive != true else { throw TrustError.mismatch("a sensitive session takes only a phone grant") }
      guard g.expires == nil, let end = isoDate(g.until), let until, abs(end.timeIntervalSince(until)) < 2, end > now else { throw TrustError.mismatch("end date") }
    default: throw TrustError.mismatch("kind")
    }
    return g
  }
}

// ---- messages into a session, delivered one by one on the phone's signature (router: per-message approval) -------
/// one message of a signed delivery batch, exactly as the router drafted it
struct MessageItemText: Codable, Equatable {
  let id: String, delivery: String, sha256: String, from: String, text: String
}
/// the signed delivery batch: {"kind":"messages","session":<line>,"items":[…],"issued","expires"}
struct MessagesText: Codable, Equatable {
  let kind: String, session: String, items: [MessageItemText], issued: String, expires: String
}
/// the signed per-kind rule: {"kind":"message-rule","session":<line>,"delivery":<kind>,"issued","until"}
struct MessageRuleText: Codable, Equatable {
  let kind: String, session: String, delivery: String, issued: String, until: String
}
/// a message as the review page shows it: what the signed item must say
struct ShownMessage: Equatable {
  let id: String, kind: String, from: String, text: String
}

extension Checks {
  static let messagesFields: Set<String> = ["kind", "session", "items", "issued", "expires"]
  static let messageItemFields: Set<String> = ["id", "delivery", "sha256", "from", "text"]
  static let messageRuleFields: Set<String> = ["kind", "session", "delivery", "issued", "until"]
  /// the deliveries that never get a standing rule: someone's own words, approved one at a time
  static let unruledDeliveries: Set<String> = ["peer", "resume-prompt"]
  /// an RFC 3339 time, with or without fractional seconds
  static func msgDate(_ s: String) -> Date? {
    if let d = isoDate(s) { return d }
    let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f.date(from: s)
  }

  /// The router's draft for delivering messages must be exactly the messages the page shows: kind "messages", the
  /// session's line from its core-signed cert (which names this phone), the shown ids and no others (each once), each
  /// item's delivery kind, sender and text exactly as shown, issued now, expiring in the future and at most an hour
  /// after it was issued. Nothing else may be in it.
  static func reviewMessages(text: String, cert: SessionCert, phoneKey: String, shown: [ShownMessage], now: Date = Date()) throws -> MessagesText {
    guard let obj = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
          Set(obj.keys).isSubset(of: messagesFields),
          let items = obj["items"] as? [[String: Any]], items.allSatisfy({ Set($0.keys).isSubset(of: messageItemFields) }),
          let m = try? JSONDecoder().decode(MessagesText.self, from: Data(text.utf8)) else { throw TrustError.mismatch("the messages text") }
    guard cert.phone == phoneKey else { throw TrustError.mismatch("this session's cert names another phone") }
    guard m.kind == "messages" else { throw TrustError.mismatch("kind") }
    guard m.session == cert.line else { throw TrustError.mismatch("session") }
    guard !shown.isEmpty, m.items.count == shown.count, Set(m.items.map(\.id)).count == m.items.count,
          Set(m.items.map(\.id)) == Set(shown.map(\.id)) else { throw TrustError.mismatch("the messages (other ids than the ones shown)") }
    for it in m.items {
      guard let s = shown.first(where: { $0.id == it.id }) else { throw TrustError.mismatch("message \(it.id)") }
      guard it.delivery == s.kind else { throw TrustError.mismatch("the kind of message \(it.id)") }
      guard it.from == s.from else { throw TrustError.mismatch("the sender of message \(it.id)") }
      guard it.text == s.text else { throw TrustError.mismatch("the text of message \(it.id)") }
      guard it.sha256.count == 64, it.sha256.allSatisfy({ $0.isHexDigit }) else { throw TrustError.mismatch("the hash of message \(it.id)") }
    }
    guard let issued = msgDate(m.issued), abs(issued.timeIntervalSince(now)) < 300 else { throw TrustError.mismatch("issued time") }
    guard let end = msgDate(m.expires), end > now, end > issued, end.timeIntervalSince(issued) <= 3600 + 120 else { throw TrustError.mismatch("expiry") }
    return m
  }

  /// The router's draft for a per-kind rule must be exactly the rule the page offers: kind "message-rule", the
  /// session's line from its core-signed cert (which names this phone), this delivery kind (never a peer's message or
  /// a resume prompt), issued now, ending in the future and at most a year (366 days) away. A sensitive session may
  /// have one: it is the explicit per-kind opt-in.
  static func reviewMessageRule(text: String, cert: SessionCert, phoneKey: String, delivery: String, now: Date = Date()) throws -> MessageRuleText {
    guard let obj = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
          Set(obj.keys).isSubset(of: messageRuleFields),
          let r = try? JSONDecoder().decode(MessageRuleText.self, from: Data(text.utf8)) else { throw TrustError.mismatch("the rule text") }
    guard cert.phone == phoneKey else { throw TrustError.mismatch("this session's cert names another phone") }
    guard r.kind == "message-rule" else { throw TrustError.mismatch("kind") }
    guard r.session == cert.line else { throw TrustError.mismatch("session") }
    guard r.delivery == delivery, !unruledDeliveries.contains(r.delivery) else { throw TrustError.mismatch("the kind of message") }
    guard let issued = msgDate(r.issued), abs(issued.timeIntervalSince(now)) < 300 else { throw TrustError.mismatch("issued time") }
    guard let until = msgDate(r.until), until > now, until.timeIntervalSince(now) <= 366 * 86400 + 300 else { throw TrustError.mismatch("end date") }
    return r
  }
}

// ---- which session a signed document is about (audit 2026-10-11: never the router's word) ------------------------
/// A session line as the core signed it: the identity a review page shows and binds to. From a cert (the session's
/// own, or the predecessor a succession challenge carries); `label` and `prompt` are the settings Deyao gave it on New
/// session, which a core that vouches puts in every cert (options.config); an earlier core's certs carry none.
struct LineIdentity: Equatable {
  let line: String
  let machine: String?
  let issuedAt: String?
  let label: String?
  let prompt: String?
  let sensitive: Bool
  let stores: [String]

  init(cert c: SessionCert) {
    line = c.line
    machine = c.machine?.id
    issuedAt = c.issuedAt
    let cfg = Checks.object(c.options?.config)
    label = (cfg?["label"] as? String).flatMap { $0.isEmpty ? nil : $0 }
    prompt = (cfg?["prompt"] as? String).flatMap { $0.isEmpty ? nil : $0 }
    sensitive = c.sensitive == true
    stores = c.stores ?? []
  }
}

extension Checks {
  /// The session a succession challenge continues: its predecessor's cert, checked against the core key; the
  /// challenge's own line (when it names one) must be that cert's. nil for a new line (no predecessor).
  static func continues(_ r: Reviewed, coreKey: String) throws -> LineIdentity? {
    guard let p = r.challenge.request.predecessor else { return nil }
    let c = try cert(p, coreKey: coreKey)
    if let l = r.challenge.request.line, !l.isEmpty, l != c.line { throw TrustError.mismatch("the challenge's line isn't its predecessor's") }
    if let pid = r.challenge.request.predecessorId, !pid.isEmpty, let m = c.machine, m.id != pid { throw TrustError.mismatch("the predecessor named isn't the cert's machine") }
    if r.kind == .addStore, let m = r.challenge.request.machine, let cm = c.machine, cm.id != m.id { throw TrustError.mismatch("the machine isn't the predecessor's") }
    return LineIdentity(cert: c)
  }

  /// An add-store's challenge made again while its batch was being signed (router flows.go rebaseAddStores: another
  /// item of the batch put a store in the session first, so the router asks the core again from the session's new
  /// cert): `fresh` must be the very ask Deyao reviewed (`read`) — the same store added, to the same running machine of
  /// the same session, with the same settings — continuing a newer cert of that session, and every other store it
  /// names one the reviewed challenge already named or one this batch has just added (`addedHere`). The core makes it
  /// only as "that cert's stores plus one".
  static func sameAddStore(read: Reviewed, of readId: LineIdentity?, fresh: Reviewed, of freshId: LineIdentity?, addedHere: Set<String>) throws {
    guard read.kind == .addStore, fresh.kind == .addStore, let added = read.addedStore, !added.isEmpty else { throw TrustError.mismatch("not an added store") }
    guard fresh.addedStore == added else { throw TrustError.mismatch("another store than the one reviewed") }
    guard let m = read.challenge.request.machine?.id, fresh.challenge.request.machine?.id == m else { throw TrustError.mismatch("another machine than the one reviewed") }
    guard let a = readId, let b = freshId, a.line == b.line, a.machine == b.machine, a.label == b.label, a.prompt == b.prompt else {
      throw TrustError.mismatch("another session than the one reviewed")
    }
    let ro = read.challenge.request.options, fo = fresh.challenge.request.options
    guard fresh.harness == read.harness, fresh.permissionMode == read.permissionMode, (fo.config ?? "") == (ro.config ?? ""), (fo.once ?? "") == (ro.once ?? "") else {
      throw TrustError.mismatch("other settings than the ones reviewed")
    }
    guard fresh.sensitive.contains(added) == read.sensitive.contains(added) else { throw TrustError.mismatch("the store's sensitivity changed") }
    guard fresh.stores.contains(added), Set(fresh.stores).subtracting([added]).isSubset(of: Set(read.stores).union(addedHere)) else {
      throw TrustError.mismatch("stores this page didn't show")
    }
  }

  /// The page was opened for a session the app knows by its New-session title (unsigned, the router's record); the
  /// signed identity must not name another one. Both untitled: nothing to compare (the page shows the line instead).
  static func sameSession(_ id: LineIdentity, expectedLabel: String?) throws {
    guard let want = expectedLabel, !want.isEmpty, let got = id.label else { return }
    if want != got { throw TrustError.mismatch("the signed session is “\(got)”, not “\(want)”") }
  }

  /// New session: every store the challenge carries beyond those picked on the page must be one the harness brings
  /// by the app's own (pinned) policy. Returns those extra stores; the page warns about any that is sensitive (a
  /// harness store Deyao marked sensitive himself), so nothing sensitive is signed unseen.
  /// `sensitive`: the stores the core's signed store list marks sensitive (preferred; a newer core drops the
  /// challenge's own `sensitive`), joined with the challenge's
  static func onlyHarnessExtras(_ r: Reviewed, picked: [String], pinnedHarness: [String], sensitive: [String] = []) throws -> [String] {
    let extra = r.stores.filter { !picked.contains($0) }
    let marked = Set(sensitive + r.sensitive)
    for n in extra where !pinnedHarness.contains(n) {
      throw TrustError.mismatch("store \(n) wasn't picked and isn't the harness's\(marked.contains(n) ? " (and it is sensitive)" : "")")
    }
    return extra
  }
}

// ---- who wrote a store, and which image CI built (agreed with the R1 server fixes, 2026-10-11) ------------------
extension Checks {
  /// what a key's writer signs (core/keys.go WriterText): the store, the key, its E, the sha256 of its data and of its
  /// backup ("" for each of a delete)
  static func writerText(store: String, key: String, e: String, dataSha256: String, backupSha256: String) -> String {
    "jarvis2-store-key\n\(store)\n\(key)\n\(e)\n\(dataSha256)\n\(backupSha256)"
  }

  /// A key the phone's share opens: written by the setup session (its key's signature over writerText, checked here
  /// against keys/setup.pub), by a session's machine (the core checked that machine's signature; the page must name
  /// the session: StoreUnlock refuses one it didn't show), by the router (a Claude account store's pair only), or
  /// vouched for by the core (a Recover's key, a deploy key).
  /// Anything else is refused.
  static func keyWriter(_ w: StoreWriter, store: String, key: String, e: String, dataSha256: String, backupSha256: String, setupKey: String?) throws {
    switch w.by {
    case "core": return
    case "machine":
      guard let l = w.line, !l.isEmpty else { throw TrustError.mismatch("key \(key) of \(store) was written by a machine the core doesn't name") }
    case "router":
      // the router writes only the Claude account stores (core/keys.go, DECISIONS 190): their pair, which it holds anyway
      guard Checks.isClaudeAccountStore(store) else { throw TrustError.mismatch("key \(key) of \(store) was written by the router, which writes only the Claude account stores") }
    case "setup":
      guard let sig = w.sig, let k = setupKey else { throw TrustError.mismatch("key \(key) of \(store)'s writer can't be checked") }
      let text = writerText(store: store, key: key, e: e, dataSha256: dataSha256, backupSha256: backupSha256)
      guard CoreCrypto.valid(Data(text.utf8), sig: sig, by: k) else { throw TrustError.badSignature("key \(key) of \(store)'s writer (not the setup key)") }
    default: throw TrustError.mismatch("key \(key) of \(store) was written by \(w.by)")
    }
  }

  /// claude-<name>: a Claude account's store, the only kind the router writes (core/keys.go routerStoreRE)
  static func isClaudeAccountStore(_ store: String) -> Bool {
    store.range(of: "^claude-[a-z0-9]+(-[a-z0-9]+)*$", options: .regularExpression) != nil
  }

  /// every key of an unlock: its writer checked (an unlock of an empty store is refused: there is nothing to open)
  static func unlockKeys(_ b: UnlockBegin, setupKey: String?) throws {
    let keys = b.keys
    guard !keys.isEmpty else { throw TrustError.mismatch("store \(b.store) has no keys to unlock") }
    guard Set(keys.map(\.key)).count == keys.count else { throw TrustError.mismatch("a key of \(b.store) named twice") }
    for k in keys {
      try keyWriter(k.writer, store: b.store, key: k.key, e: k.e, dataSha256: k.dataSha256, backupSha256: k.backupSha256, setupKey: setupKey)
    }
  }

  /// the keys a session's machine wrote, as the core names them in these unlocks
  static func sessionWrites(_ begins: [UnlockBegin]) -> [SessionWrite] {
    begins.flatMap { b in b.keys.filter { $0.writer.by == "machine" }.map { SessionWrite(store: b.store, key: $0.key, line: $0.writer.line ?? "") } }
  }
  /// the session-written keys these unlocks would open that the page didn't show (a value a session wrote is never
  /// released unseen: Deyao, 2026-10-13)
  static func unseen(_ begins: [UnlockBegin], shown: [SessionWrite]) -> [SessionWrite] {
    let s = Set(shown)
    return sessionWrites(begins).filter { !s.contains($0) }
  }

  /// CI's signature over the session image (keys/ci.pub): "jarvis2-session-image <ref>"
  static func imageAttested(_ image: String, sig: String?, ciKey: String) -> Bool {
    guard let sig, !image.isEmpty else { return false }
    return CoreCrypto.valid(Data("jarvis2-session-image \(image)".utf8), sig: sig, by: ciKey)
  }
}

// ---- the app wraps stores itself (R2, 2026-10-11): to the core's signed store key, and a repo's deploy key ----------
/// one key of a store as the app writes it (core/keys.go KeyEntry): the value under its own data key (the store's and the
/// key's names as associated data), the data key wrapped to the store key C = P + K (the phone's and the core's
/// agreement keys), which only the phone's share and the core together open
struct KeyEntry: Codable, Equatable {
  struct Wrapped: Codable, Equatable { let e: String; let wrapped: String }
  let store: String
  let key: String
  let wrapped: Wrapped
  let data: String
  var json: [String: Any] { ["store": store, "key": key, "wrapped": ["e": wrapped.e, "wrapped": wrapped.wrapped], "data": data] }
}
/// a key a session's machine wrote: the store, the key and the session's line (the page names the session by it)
struct SessionWrite: Hashable {
  let store: String; let key: String; let line: String
  /// the session's title as the router knows the line (shown only; not compared)
  var label: String = ""
  static func == (a: SessionWrite, b: SessionWrite) -> Bool { a.store == b.store && a.key == b.key && a.line == b.line }
  func hash(into h: inout Hasher) { h.combine(store); h.combine(key); h.combine(line) }
}
/// the core's signed answer to POST /store-key: C = P + K for this phone
/// core: the core point the store key was made for when the app named one (a Recover's derived K: CoreContinuity)
struct StoreKeyDoc: Codable { let kind: String; let phone: String; let storeKey: String; var core: String? = nil }

extension CoreCrypto {
  static let storeDataKeyInfo = "jarvis2/store-data-key"

  /// the store key for this phone's agreement key, from the core's signed answer (`coreKey`: that core's signing key)
  static func storeKey(_ doc: SignedDoc, coreKey: String, phone: String, core: String? = nil) throws -> String {
    let d = try decode(doc, by: coreKey, as: StoreKeyDoc.self, what: "the store key")
    guard d.kind == "store-key", MasterKey.same(d.phone, phone) else { throw TrustError.stale("store key") }
    if let core { guard let got = d.core, MasterKey.same(got, core) else { throw TrustError.stale("store key for another core") } }
    guard let b = Data(base64Encoded: d.storeKey), (try? P256.KeyAgreement.PublicKey(x963Representation: b)) != nil else { throw TrustError.badSignature("the store key") }
    return d.storeKey
  }

  /// a key's associated data: its store and its name (a value doesn't decrypt under another)
  static func keyAAD(store: String, key: String) -> Data { Data("\(store)\n\(key)".utf8) }

  /// one key's value under a fresh data key, the data key wrapped to the store key (core/keys.go)
  static func wrapKey(store: String, key: String, value: Data, storeKey: String) throws -> KeyEntry {
    guard let cb = Data(base64Encoded: storeKey) else { throw TrustError.badSignature("the store key") }
    let c = try P256.KeyAgreement.PublicKey(x963Representation: cb)
    let dk = SymmetricKey(size: .bits256)
    let e = P256.KeyAgreement.PrivateKey()
    let kek = try e.sharedSecretFromKeyAgreement(with: c)
      .hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: Data(storeDataKeyInfo.utf8), outputByteCount: 32)
    guard let wrapped = try AES.GCM.seal(dk.withUnsafeBytes { Data($0) }, using: kek).combined,
          let data = try AES.GCM.seal(value, using: dk, authenticating: keyAAD(store: store, key: key)).combined else { throw TrustError.badSignature("sealing") }
    return KeyEntry(store: store, key: key, wrapped: .init(e: e.publicKey.x963Representation.base64EncodedString(), wrapped: wrapped.base64EncodedString()),
                    data: data.base64EncodedString())
  }
  /// every value of a store as its keys, sorted by name
  static func wrapKeys(store: String, values: [String: String], storeKey: String) throws -> [KeyEntry] {
    try values.keys.sorted().map { try wrapKey(store: store, key: $0, value: Data(values[$0]!.utf8), storeKey: storeKey) }
  }
}

/// A repo's deploy key, made by the app (R2): an ed25519 pair in OpenSSH's formats, as core/deploykeys.go wrote them.
enum OpenSSH {
  private static func string(_ d: Data) -> Data { var n = UInt32(d.count).bigEndian; return Data(bytes: &n, count: 4) + d }
  private static func uint32(_ v: UInt32) -> Data { var n = v.bigEndian; return Data(bytes: &n, count: 4) }

  struct KeyPair { let publicKey: String; let privateKeyFile: String; let wire: Data }

  /// `seed` and `checkint` fixed only by tests; a real key takes fresh randomness
  static func ed25519(comment: String, seed: Data? = nil, checkint: UInt32? = nil) throws -> KeyPair {
    let k = try seed.map { try Curve25519.Signing.PrivateKey(rawRepresentation: $0) } ?? Curve25519.Signing.PrivateKey()
    let pub = k.publicKey.rawRepresentation
    let wire = string(Data("ssh-ed25519".utf8)) + string(pub)
    let ci = checkint ?? UInt32.random(in: .min ... .max)
    var priv = uint32(ci) + uint32(ci) + string(Data("ssh-ed25519".utf8)) + string(pub) + string(k.rawRepresentation + pub) + string(Data(comment.utf8))
    var pad: UInt8 = 1
    while priv.count % 8 != 0 { priv.append(pad); pad += 1 }
    let body = Data("openssh-key-v1".utf8) + Data([0]) + string(Data("none".utf8)) + string(Data("none".utf8)) + string(Data())
      + uint32(1) + string(wire) + string(priv)
    let b64 = body.base64EncodedString()
    var lines: [String] = []
    var i = b64.startIndex
    while i < b64.endIndex { let j = b64.index(i, offsetBy: 70, limitedBy: b64.endIndex) ?? b64.endIndex; lines.append(String(b64[i..<j])); i = j }
    let file = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + lines.joined(separator: "\n") + "\n-----END OPENSSH PRIVATE KEY-----\n"
    return KeyPair(publicKey: "ssh-ed25519 " + wire.base64EncodedString(), privateKeyFile: file, wire: wire)
  }
  /// GitHub's fingerprint: SHA256:<base64 of the wire bytes' sha256, no padding>
  static func fingerprint(wire: Data) -> String {
    "SHA256:" + Data(SHA256.hash(data: wire)).base64EncodedString().replacingOccurrences(of: "=", with: "")
  }
  /// DE0CH/china-train → DE0CH_CHINA_TRAIN
  static func slug(_ repo: String) -> String {
    String(repo.uppercased().unicodeScalars.map { s -> Character in (s >= "A" && s <= "Z") || (s >= "0" && s <= "9") ? Character(s) : "_" })
  }
  /// the repo store's values, as machines read them (machine/deploykeys.go)
  static func storeValues(repo: String, privateKeyFile: String) -> [String: String] {
    let s = slug(repo)
    return ["GITHUB_DEPLOY_REPO_\(s)": repo, "GITHUB_DEPLOY_KEY_\(s)": Data(privateKeyFile.utf8).base64EncodedString()]
  }
}

// ---- core continuity (core/continuity.go) ----------------------------------------------------------------------
// The core's keys come from the master key: the app derives a seed from the kit's master private key and sends it in
// the claim bundle; the core derives its signing key, its store share K and its other keys from it. So a Recover with
// the same kit brings back the same core, and the sessions' certs, carried secrets and store keys stay valid. The
// derivation here must match core/continuity.go exactly (the core refuses a claim whose statement names other keys).
enum CoreContinuity {
  static let seedInfo = "jarvis2/core-seed", keyInfo = "jarvis2/core/"

  /// HKDF-SHA256 with no salt, 32 bytes
  static func hkdf(_ ikm: Data, info: String) -> Data {
    let k = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: Data(), info: Data(info.utf8), outputByteCount: 32)
    return k.withUnsafeBytes { Data($0) }
  }
  /// the seed: from the master private key's 32-byte scalar
  static func seed(_ master: MasterKey) -> Data { hkdf(master.signing.rawRepresentation, info: seedInfo) }
  /// the first of label, label/1, label/2, … that is a valid P-256 scalar
  static func scalar(_ seed: Data, _ label: String) throws -> Data {
    for i in 0..<16 {
      let d = hkdf(seed, info: keyInfo + label + (i > 0 ? "/\(i)" : ""))
      if (try? P256.Signing.PrivateKey(rawRepresentation: d)) != nil { return d }
    }
    throw TrustError.mismatch("no core key from the seed")
  }
  /// the public keys of the core the seed derives
  static func keys(seed: Data) throws -> PublicKeys {
    let s = try P256.Signing.PrivateKey(rawRepresentation: try scalar(seed, "signing"))
    let a = try P256.KeyAgreement.PrivateKey(rawRepresentation: try scalar(seed, "agreement"))
    return PublicKeys(signingKey: s.publicKey.x963Representation.base64EncodedString(), agreementKey: a.publicKey.x963Representation.base64EncodedString())
  }
}
