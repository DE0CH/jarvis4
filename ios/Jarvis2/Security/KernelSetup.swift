// The kernel (DESIGN "Target design", docs/PLAN-grants.md) as the app sees it, with no UI, network or Keychain in it
// (compiled into the interop test too, which runs it against the real kernel binaries):
//   - secrets' identity, vouched for by the box key, and its claim (Recover: every store from the backups, wrapped to
//     secrets' store key; its keys derived from the kit like the old core's, under the kernel's own labels);
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
  struct Identity: Decodable { let signingKey: String; let agreementKey: String; let boxSig: String; let state: SignedDoc }
  struct State: Decodable {
    let kind: String; let master: String; let phone: PublicKeys?; let root: String?; var lineSeq: Int? = nil; var derived: Bool? = nil; var serving: String? = nil
  }
  /// what the box key signs for a kernel component's keys (kernel/sig IdentityText)
  static func identityText(role: String, _ k: PublicKeys) -> String { "jarvis2-kernel-\(role)-identity \(k.signingKey) \(k.agreementKey)" }
  static func vouched(role: String, _ k: PublicKeys, boxSig: String, boxKey: String) -> Bool {
    PublicKeys.valid(k) && CoreCrypto.valid(Data(identityText(role: role, k).utf8), sig: boxSig, by: boxKey)
  }
  /// the box key signed secrets' keys, and secrets signed its state
  static func check(_ id: Identity, boxKey: String) throws -> (keys: PublicKeys, state: State) {
    let k = PublicKeys(signingKey: id.signingKey, agreementKey: id.agreementKey)
    guard vouched(role: "secrets", k, boxSig: id.boxSig, boxKey: boxKey) else { throw TrustError.badSignature("the kernel's secrets keys (not the box key's)") }
    let st = try CoreCrypto.decode(id.state, by: k.signingKey, as: State.self, what: "the kernel's secrets state")
    guard st.kind == "secrets-state" else { throw TrustError.mismatch("not the kernel's secrets state") }
    return (k, st)
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
  /// the keys it names, which the box key vouched for in this role
  static func component(_ doc: SignedDoc, role: String, boxKey: String) throws -> PublicKeys {
    struct I: Decodable { let role: String; let signingKey: String; let agreementKey: String; let boxSig: String }
    guard let i = try? JSONDecoder().decode(I.self, from: Data(doc.payload.utf8)) else { throw TrustError.mismatch("not a component's identity") }
    let k = PublicKeys(signingKey: i.signingKey, agreementKey: i.agreementKey)
    guard i.role == role, vouched(role: role, k, boxSig: i.boxSig, boxKey: boxKey),
          CoreCrypto.valid(Data(doc.payload.utf8), sig: doc.sig, by: i.signingKey) else { throw TrustError.badSignature("the kernel's \(role) (not the box key's)") }
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
