// The kernel (DESIGN "Target design", docs/PLAN-grants.md, docs/PLAN-cluster.md "The roster") as the app sees it, with
// no UI, network or Keychain in it (compiled into the interop test too, which runs it against the real kernel binaries):
//   - the roster: the kernel's components and their RAM-only keys, which the setup session reads and signs with the
//     setup key (keys/setup.pub), and the root key signs here (KernelRoster, the exact payload kernel/sig
//     RosterPayload makes);
//   - secrets' identity, checked against the roster (or, once claimed, the keys this iPhone pinned), and its claim
//     (Recover: every store from the backups, wrapped to secrets' store key; its keys derived from the kit like the
//     old core's, under the kernel's own labels);
//   - the certs the phone signs (a new source, an add-store's two), read strictly and checked against what the
//     approval is for before Face ID.
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

// ---- secrets' keys from the kit (kernel/secrets/continuity.go: the same derivation, its own labels) ----
enum KernelContinuity {
  static let seedInfo = "jarvis2/kernel-secrets-seed", keyInfo = "jarvis2/kernel-secrets/"

  static func seed(_ master: MasterKey) -> Data { CoreContinuity.hkdf(master.signing.rawRepresentation, info: seedInfo) }
  static func scalar(_ seed: Data, _ label: String) throws -> Data {
    for i in 0..<16 {
      let d = CoreContinuity.hkdf(seed, info: keyInfo + label + (i > 0 ? "/\(i)" : ""))
      if (try? P256.Signing.PrivateKey(rawRepresentation: d)) != nil { return d }
    }
    throw TrustError.mismatch("no secrets key from the seed")
  }
  /// the public keys of the secrets the seed derives
  static func keys(seed: Data) throws -> PublicKeys {
    let s = try P256.Signing.PrivateKey(rawRepresentation: try scalar(seed, "signing"))
    let a = try P256.KeyAgreement.PrivateKey(rawRepresentation: try scalar(seed, "agreement"))
    return PublicKeys(signingKey: s.publicKey.x963Representation.base64EncodedString(), agreementKey: a.publicKey.x963Representation.base64EncodedString())
  }
}

enum KernelSetup {
  // ---- secrets' identity and state (kernel/secrets: GET /identity) ----
  struct Identity: Decodable { var role: String? = nil; let signingKey: String; let agreementKey: String; let state: SignedDoc }
  struct State: Decodable {
    let kind: String; let master: String; let phone: PublicKeys?; let root: String?; var lineSeq: Int? = nil; var derived: Bool? = nil; var serving: String? = nil
  }
  /// what vouches for secrets' keys: the keys this iPhone pinned when it claimed secrets, the root key's roster, and
  /// before a claim the setup session's pending roster (setup-signed: trusted for an empty secrets only)
  struct Anchors { var pinned: PublicKeys? = nil; var roster: KernelRoster.Roster? = nil; var pending: KernelRoster.Roster? = nil }
  /// secrets' keys are vouched for and it signed its state: or nothing goes on
  static func check(_ id: Identity, _ anchors: Anchors) throws -> (keys: PublicKeys, state: State) {
    let k = PublicKeys(signingKey: id.signingKey, agreementKey: id.agreementKey)
    guard PublicKeys.valid(k), id.role == nil || id.role == "secrets" else { throw TrustError.mismatch("not the kernel's secrets") }
    let byPhone = anchors.pinned == k || anchors.roster?.member("secrets") == k
    let bySetup = anchors.pending?.member("secrets") == k
    guard byPhone || bySetup else { throw TrustError.badSignature("the kernel's secrets keys (not the roster's)") }
    let st = try CoreCrypto.decode(id.state, by: k.signingKey, as: State.self, what: "the kernel's secrets state")
    guard st.kind == "secrets-state" else { throw TrustError.mismatch("not the kernel's secrets state") }
    // the setup key vouches only for a secrets nobody has claimed yet (the claim seals the stores to these keys)
    guard byPhone || st.master.isEmpty else { throw TrustError.badSignature("the kernel's secrets keys (claimed, but not in the root key's roster)") }
    return (k, st)
  }

  /// a secrets nobody has claimed: its state, signed by the keys it names, has no master key (what lets the root key
  /// sign a roster naming a secrets other than the one this iPhone pinned: an empty kernel copy)
  static func unclaimed(_ id: Identity) -> PublicKeys? {
    let k = PublicKeys(signingKey: id.signingKey, agreementKey: id.agreementKey)
    guard PublicKeys.valid(k), let st = try? CoreCrypto.decode(id.state, by: k.signingKey, as: State.self, what: "secrets' state"),
          st.kind == "secrets-state", st.master.isEmpty else { return nil }
    return k
  }
  /// whether the root key may sign this roster as it stands: its secrets is the one this iPhone pinned, or (none pinned,
  /// or another kernel copy) a secrets that answers unclaimed with those keys
  static func signable(_ r: KernelRoster.Roster, pinned: PublicKeys?, unclaimed: [PublicKeys]) throws {
    guard let s = r.member("secrets") else { return }
    guard s == pinned || unclaimed.contains(s) else {
      throw TrustError.mismatch("the roster names a secrets that is neither this iPhone's nor an empty one")
    }
  }

  // ---- the claim (kernel/secrets Claim) ----
  static let claimInfo = "jarvis2/kernel-claim"

  /// the bundle: every store but the old core's own, each key wrapped to secrets' store key, the seed and the record
  /// of the stores an earlier secrets from the same kit left
  static func bundle(_ stores: [RecoveredStore], storeKey: String, seed: Data?, lineState: CoreSetup.LineStateDoc? = nil) throws -> Data {
    struct B: Encodable {
      let format = "keys"; let keys: [KeyEntry]; let lineState: CoreSetup.LineStateDoc?; let notSensitive: [String]; let owners: [String: String]
      let secretsSeed: String?; let stores: [String]
    }
    let rest = stores.filter { $0.name != StoreView.coreStore }
    let keys = try rest.flatMap { try CoreCrypto.wrapKeys(store: $0.name, values: $0.values, storeKey: storeKey) }
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try e.encode(B(keys: keys, lineState: lineState, notSensitive: rest.filter { !$0.sensitive }.map(\.name), owners: CoreSetup.owners(rest),
                          secretsSeed: seed?.base64EncodedString(), stores: rest.map(\.name)))
  }
  /// the statement the master key signs: these secrets, this iPhone, this root key, this bundle
  static func statement(master: String, secrets: PublicKeys, phone: PublicKeys, root: String, bundle: Data, identity: PublicKeys?, standby: Bool = false) throws -> String {
    struct St: Encodable {
      let kind = "kernel-claim"; let master: String; let secrets: PublicKeys; let phone: PublicKeys; let root: String; let bundleSha256: String
      let identity: PublicKeys?; let standby: Bool?
    }
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return String(decoding: try e.encode(St(master: master, secrets: secrets, phone: phone, root: root, bundleSha256: CoreCrypto.sha256hex(bundle),
                                            identity: identity, standby: standby ? true : nil)), as: UTF8.self)
  }
  /// the body of POST /api/kernel/secrets/claim
  static func claim(secrets: PublicKeys, phone: PublicKeys, root: String, master: MasterKey, bundle: Data, identity: PublicKeys?, standby: Bool = false) throws -> [String: Any] {
    let st = try statement(master: master.publicKey, secrets: secrets, phone: phone, root: root, bundle: bundle, identity: identity, standby: standby)
    return ["statement": st, "masterSig": try master.sign(st), "bundle": try CoreCrypto.seal(bundle, to: secrets.agreementKey, info: claimInfo)]
  }
  /// a component's identity document (kernel/internal/serve: GET /identity, signed by the component), checked: signed by
  /// the keys it names, which the root key's roster names for this role
  static func component(_ doc: SignedDoc, role: String, roster: KernelRoster.Roster) throws -> PublicKeys {
    struct I: Decodable { let role: String; let signingKey: String; let agreementKey: String }
    guard let i = try? JSONDecoder().decode(I.self, from: Data(doc.payload.utf8)) else { throw TrustError.mismatch("not a component's identity") }
    let k = PublicKeys(signingKey: i.signingKey, agreementKey: i.agreementKey)
    guard i.role == role, roster.member(role) == k, CoreCrypto.valid(Data(doc.payload.utf8), sig: doc.sig, by: i.signingKey) else {
      throw TrustError.badSignature("the kernel's \(role) (not the roster's)")
    }
    return k
  }
  /// the body of POST /api/kernel/spawner/fly-token: the Fly token sealed to the spawner
  static func flyToken(_ token: String, to spawner: PublicKeys) throws -> [String: Any] {
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys]
    return ["sealed": try CoreCrypto.seal(try e.encode(["FLY_API_TOKEN": token]), to: spawner.agreementKey, info: "jarvis2/fly-token")]
  }
  /// the body of POST /api/kernel/secrets/wipe
  static func wipe(secrets: PublicKeys, master: MasterKey) throws -> [String: Any] {
    struct W: Encodable { let kind = "kernel-wipe"; let secrets: String }
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let st = String(decoding: try e.encode(W(secrets: secrets.signingKey)), as: UTF8.self)
    return ["statement": st, "masterSig": try master.sign(st)]
  }
}

// ---- the roster (kernel/sig Roster, docs/PLAN-cluster.md "The roster") ----
enum KernelRoster {
  struct Member: Codable, Equatable { let role: String; let signingKey: String; let agreementKey: String
    var keys: PublicKeys { PublicKeys(signingKey: signingKey, agreementKey: agreementKey) }
  }
  struct Roster: Equatable {
    let copy: String; let members: [Member]
    func member(_ role: String) -> PublicKeys? { members.first { $0.role == role }?.keys }
    /// the exact payload the setup key and the root key sign
    var payload: String { KernelRoster.payload(copy: copy, members: members) }
  }
  /// what the setup session filed (GET /api/kernel/roster/pending)
  struct Pending: Codable, Equatable { let copy: String; let payload: String; let setupSig: String }

  static func validRole(_ r: String) -> Bool { !r.isEmpty && r.allSatisfy { ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "-" } }
  /// kernel/sig RosterPayload, byte for byte: Go's json.Marshal of {kind, copy, members[{role, signingKey,
  /// agreementKey}]}, members sorted by role. Roles are [a-z0-9-] and keys base64, so nothing needs escaping.
  static func payload(copy: String, members: [Member]) -> String {
    let ms = members.sorted { $0.role < $1.role }.map { "{\"role\":\"\($0.role)\",\"signingKey\":\"\($0.signingKey)\",\"agreementKey\":\"\($0.agreementKey)\"}" }
    return "{\"kind\":\"kernel-roster\",\"copy\":\"\(copy)\",\"members\":[\(ms.joined(separator: ","))]}"
  }
  /// a roster read strictly: kind, copy blue or green, one member per role sorted, every key a P-256 key, and the
  /// payload exactly the one this app would sign (so what is shown is what is signed)
  static func parse(_ payload: String) throws -> Roster {
    struct R: Decodable { let kind: String; let copy: String; let members: [Member] }
    guard let r = try? JSONDecoder().decode(R.self, from: Data(payload.utf8)), r.kind == "kernel-roster", r.copy == "blue" || r.copy == "green", !r.members.isEmpty else {
      throw TrustError.mismatch("not a kernel roster")
    }
    for (i, m) in r.members.enumerated() {
      guard validRole(m.role), PublicKeys.valid(m.keys) else { throw TrustError.mismatch("a roster member without valid keys") }
      if i > 0, r.members[i - 1].role >= m.role { throw TrustError.mismatch("the roster's members aren't sorted by role, one each") }
    }
    let out = Roster(copy: r.copy, members: r.members)
    guard out.payload == payload else { throw TrustError.mismatch("the roster isn't in its canonical form") }
    return out
  }
  /// the setup session's roster: the setup key (keys/setup.pub from GitHub) signed exactly this payload
  static func pending(_ p: Pending, setupKey: String) throws -> Roster {
    guard CoreCrypto.valid(Data(p.payload.utf8), sig: p.setupSig, by: setupKey) else { throw TrustError.badSignature("the kernel's roster (not the setup key's)") }
    let r = try parse(p.payload)
    guard r.copy == p.copy else { throw TrustError.mismatch("the roster is for another kernel copy") }
    return r
  }
  /// a roster the root key signed
  static func signed(_ d: SignedDoc, rootKey: String) throws -> Roster {
    guard CoreCrypto.valid(Data(d.payload.utf8), sig: d.sig, by: rootKey) else { throw TrustError.badSignature("the kernel's roster (not this iPhone's root key)") }
    return try parse(d.payload)
  }
  /// the same roster with secrets' keys replaced (a claim with a seed: secrets serves with the keys the kit derives)
  static func replacing(_ r: Roster, role: String, with k: PublicKeys) throws -> Roster {
    guard r.members.contains(where: { $0.role == role }) else { throw TrustError.mismatch("the roster has no \(role)") }
    return Roster(copy: r.copy, members: r.members.map { $0.role == role ? Member(role: role, signingKey: k.signingKey, agreementKey: k.agreementKey) : $0 })
  }
}

// ---- the certs the phone signs (kernel/doc Cert), read strictly ----
struct KernelPair: Codable, Equatable {
  struct Allowed: Codable, Equatable { var only: [String]? = nil; var except: [String]? = nil }
  let allowed: Allowed; let conditions: [String]
  /// the stores it allows (a finite set only)
  var stores: [String] { (allowed.only ?? []).compactMap { $0.hasPrefix("store:") ? String($0.dropFirst(6)) : nil } }
  var isTop: Bool { allowed.only == nil && (allowed.except ?? ["x"]).isEmpty && conditions.isEmpty }
}
struct KernelSource: Codable, Equatable {
  let image: String; let settings: [String: KernelJSON]; var snapshot: String? = nil
}
struct KernelMachine: Codable, Equatable { let signingKey: String; let encryptionKey: String; let image: String }
struct KernelCert: Codable, Equatable {
  let kind: String; let pred: String; let succ: String; let pair: KernelPair
  var source: KernelSource? = nil; var machine: KernelMachine? = nil
  let signer: String; let issuedAt: String
}
/// any JSON value, kept as it was (the settings' config is shown, not interpreted)
enum KernelJSON: Codable, Equatable {
  case string(String), number(Double), bool(Bool), array([KernelJSON]), object([String: KernelJSON]), null
  init(from d: Decoder) throws {
    let c = try d.singleValueContainer()
    if c.decodeNil() { self = .null }
    else if let b = try? c.decode(Bool.self) { self = .bool(b) }
    else if let n = try? c.decode(Double.self) { self = .number(n) }
    else if let s = try? c.decode(String.self) { self = .string(s) }
    else if let a = try? c.decode([KernelJSON].self) { self = .array(a) }
    else { self = .object(try c.decode([String: KernelJSON].self)) }
  }
  func encode(to e: Encoder) throws {
    var c = e.singleValueContainer()
    switch self {
    case .string(let s): try c.encode(s)
    case .number(let n): try c.encode(n)
    case .bool(let b): try c.encode(b)
    case .array(let a): try c.encode(a)
    case .object(let o): try c.encode(o)
    case .null: try c.encodeNil()
    }
  }
  var string: String? { if case .string(let s) = self { return s }; return nil }
  var object: [String: KernelJSON]? { if case .object(let o) = self { return o }; return nil }
}

enum KernelChecks {
  static let sessionImageRepo = "ghcr.io/de0ch/jarvis4-session"

  /// a cert into a new source the phone signs (a new session, a restore, a resume on another image): from the sink, by
  /// the phone, its stores for exactly this session, the session image pinned by digest
  struct SourceReview: Equatable {
    let cert: KernelCert; let stores: [String]; let image: String; let harness: String; let permissionMode: String
    let config: [String: KernelJSON]; let snapshot: String?
  }
  static func source(payload: String, session: String) throws -> SourceReview {
    guard let c = try? JSONDecoder().decode(KernelCert.self, from: Data(payload.utf8)) else { throw TrustError.mismatch("not a kernel cert") }
    guard c.kind == "succession", c.pred == "sink", c.signer == "iphone", isSource(c.succ), c.machine == nil, let src = c.source else {
      throw TrustError.mismatch("not a new source the phone signs")
    }
    guard c.pair.conditions == ["session:" + session] else { throw TrustError.mismatch("the cert is for another session") }
    guard c.pair.allowed.except == nil, let only = c.pair.allowed.only, only.allSatisfy({ $0.hasPrefix("store:") }) else {
      throw TrustError.mismatch("the cert allows more than stores")
    }
    guard pinned(src.image) else { throw TrustError.mismatch("the image isn't the session image pinned by digest") }
    guard src.settings["v"] == .number(1), let h = src.settings["harness"]?.string, let m = src.settings["permissionMode"]?.string,
          m == "auto" || m == "bypass" else { throw TrustError.mismatch("the source's settings") }
    if let s = src.snapshot, !s.isEmpty, !isHex64(s) { throw TrustError.mismatch("the snapshot isn't a sha256") }
    return SourceReview(cert: c, stores: c.pair.stores, image: src.image, harness: h, permissionMode: m,
                        config: src.settings["config"]?.object ?? [:], snapshot: src.snapshot.flatMap { $0.isEmpty ? nil : $0 })
  }

  /// an add-store's two certs: (sink → source-a, the one store for this session) and (source-a → the running machine, ⊤)
  struct AddReview: Equatable { let store: String; let machine: String }
  static func add(first: String, second: String, session: String, store: String) throws -> AddReview {
    let d = JSONDecoder()
    guard let a = try? d.decode(KernelCert.self, from: Data(first.utf8)), let b = try? d.decode(KernelCert.self, from: Data(second.utf8)) else {
      throw TrustError.mismatch("not kernel certs")
    }
    guard a.kind == "succession", a.pred == "sink", a.signer == "iphone", isSource(a.succ), a.source != nil,
          a.pair.allowed.only == ["store:" + store], a.pair.conditions == ["session:" + session] else {
      throw TrustError.mismatch("the first cert isn't this one store for this session")
    }
    guard b.kind == "succession", b.pred == a.succ, b.signer == "iphone", b.succ.hasPrefix("fly-"), b.machine != nil, b.pair.isTop else {
      throw TrustError.mismatch("the second cert doesn't take that source onto a machine")
    }
    return AddReview(store: store, machine: String(b.succ.dropFirst(4)))
  }

  static func isSource(_ o: String) -> Bool { o.hasPrefix("source-") && o.count == 39 && isHex(o.dropFirst(7)) }
  static func isHex64(_ s: String) -> Bool { s.count == 64 && isHex(s[...]) }
  static func isHex(_ s: Substring) -> Bool { s.allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) } }
  static func pinned(_ image: String) -> Bool {
    guard let at = image.range(of: "@sha256:") else { return false }
    let repo = image[..<at.lowerBound], digest = image[at.upperBound...]
    let name = repo.split(separator: ":", maxSplits: 1).first.map(String.init) ?? ""
    return name == sessionImageRepo && digest.count == 64 && isHex(digest)
  }
}
