// The kernel's routes (router/kernelline.go): its status, the root grant, and secrets' own API relayed as is
// (/api/kernel/secrets/…), and the roster (the kernel's components, signed by the setup key, then by the root key).
// Every document of secrets is checked here against the keys this iPhone pinned (KernelTrust), the root key's roster,
// or, before a claim, the setup session's pending roster.
import Foundation

extension RouterClient {
  struct KernelStatus: Decodable {
    struct Roster: Decodable { var state: String? = nil; var rootKey: Bool? = nil; var pending: Bool? = nil; var stale: [String]? = nil }
    let configured: Bool; let serves: Bool; let root: Bool; var roster: Roster? = nil
    /// whether this box also runs the old core (Jarvis 2's routers report it; Jarvis 4's has none)
    var core: Bool { coreField ?? true }
    var coreField: Bool? = nil
    enum CodingKeys: String, CodingKey { case configured, serves, root, roster, coreField = "core" }
  }
  func kernelStatus() async throws -> KernelStatus { try await json("GET", "api/kernel") }

  /// `next`: the next secrets (blue/green, router/kernel.go): Recover alongside
  private static func q(_ next: Bool) -> String { next ? "?secrets=next" : "" }
  /// secrets' identity, checked against the anchors (KernelSetup.check)
  func kernelIdentity(_ anchors: KernelSetup.Anchors, next: Bool = false) async throws -> (keys: PublicKeys, state: KernelSetup.State) {
    try KernelSetup.check(try await json("GET", "api/kernel/secrets/identity" + Self.q(next), as: KernelSetup.Identity.self), anchors)
  }

  // ---- the roster ----
  /// the root key's public half, for the setup session to commit as keys/root.pub (no Face ID)
  func kernelRegisterRootKey(_ rootKey: String) async throws { try await call("POST", "api/kernel/root-key", ["rootKey": rootKey]) }
  /// what the setup session filed: the components' keys it read, signed with the setup key (nil: nothing pending)
  func kernelPendingRoster() async throws -> KernelRoster.Pending? {
    let (status, data) = try await raw("GET", "api/kernel/roster/pending", nil)
    if status == 404 { return nil }
    guard status == 200 else { throw Self.failure("GET", "api/kernel/roster/pending", status, data) }
    guard let p = try? JSONDecoder().decode(KernelRoster.Pending.self, from: data) else { throw TrustError.mismatch("not a pending roster") }
    return p
  }
  /// the roster the components hold (the root key's signature), checked against this iPhone's root key; nil: none yet
  func kernelRoster(rootKey: String) async throws -> KernelRoster.Roster? {
    let (status, data) = try await raw("GET", "api/kernel/roster", nil)
    if status == 404 { return nil }
    guard status == 200 else { throw Self.failure("GET", "api/kernel/roster", status, data) }
    struct Wrapped: Decodable { let roster: SignedDoc }
    let d = JSONDecoder()
    guard let doc = (try? d.decode(SignedDoc.self, from: data)) ?? (try? d.decode(Wrapped.self, from: data))?.roster else { return nil }
    return try KernelRoster.signed(doc, rootKey: rootKey)
  }
  /// the root key's signature over exactly the roster's payload: the router hands it to every component
  func kernelPostRoster(_ payload: String, rootSig: Data) async throws {
    try await call("POST", "api/kernel/roster", ["payload": payload, "rootSig": rootSig.base64EncodedString()])
  }
  /// secrets' store key C = P + K for this phone, with `secrets` (a Recover's derived K), checked against `signedBy`
  func kernelStoreKey(signedBy: String, secrets: String, next: Bool = false) async throws -> String {
    struct SK: Decodable { let kind: String; let phone: String; let storeKey: String; let secrets: String? }
    let phone = try PhoneKeys.shared.publicKeys().agreementKey
    let d = try await json("POST", "api/kernel/secrets/store-key" + Self.q(next), ["phone": phone, "secrets": secrets], as: SignedDoc.self)
    let sk = try CoreCrypto.decode(d, by: signedBy, as: SK.self, what: "secrets' store key")
    guard sk.kind == "store-key", sk.phone == phone, sk.secrets == secrets else { throw TrustError.stale("store key") }
    return sk.storeKey
  }
  /// the kernel secrets' line state the router kept (its deploy-key stores, which have no backup); nil when it has none
  /// (the caller checks it: CoreSetup.checkLineState against the derived key)
  func kernelLineState() async throws -> CoreSetup.LineStateDoc? {
    let (status, data) = try await raw("GET", "api/kernel/line-state", nil)
    if status == 404 { return nil }
    guard status == 200 else { throw Self.failure("GET", "api/kernel/line-state", status, data) }
    return try? JSONDecoder().decode(CoreSetup.LineStateDoc.self, from: data)
  }
  /// the claim (KernelSetup.claim's body); its answer is checked against the keys the kit derives
  func kernelClaim(_ body: [String: Any], derived: PublicKeys, next: Bool = false) async throws {
    struct C: Decodable { let kind: String }
    let d = try await json("POST", "api/kernel/secrets/claim" + Self.q(next), body, as: SignedDoc.self)
    guard (try CoreCrypto.decode(d, by: derived.signingKey, as: C.self, what: "secrets' claim answer")).kind == "claimed" else { throw TrustError.stale("claim") }
  }

  /// the spawner's Fly token (from the recovered core store), sealed to the keys the root key's roster names
  func kernelSpawnerToken(_ token: String, roster: KernelRoster.Roster) async throws {
    let doc = try await json("GET", "api/kernel/spawner/identity", as: SignedDoc.self)
    let k = try KernelSetup.component(doc, role: "spawner", roster: roster)
    try await call("POST", "api/kernel/spawner/fly-token", try KernelSetup.flyToken(token, to: k))
  }
  /// what the root key signs once: ⊤ on the sink (the router fills in the sink's keys, hashed from its name)
  func rootGrantDraft() async throws -> String {
    struct D: Decodable { let payload: String }
    let d: D = try await json("GET", "api/kernel/root-grant/draft")
    struct G: Decodable {
      struct P: Decodable { struct A: Decodable { let except: [String]? ; let only: [String]? }; let allowed: A; let conditions: [String] }
      let kind: String; let machine: String; let pair: P; let from: [String]
    }
    let g = try JSONDecoder().decode(G.self, from: Data(d.payload.utf8))
    guard g.kind == "grant", g.machine == "sink", g.pair.allowed.only == nil, g.pair.allowed.except == [], g.pair.conditions.isEmpty, g.from.isEmpty else {
      throw TrustError.mismatch("the root grant's draft isn't ⊤ on the sink")
    }
    return d.payload
  }
  func postRootGrant(_ payload: String, signature: Data) async throws {
    try await call("POST", "api/kernel/root-grant", ["grant": ["payload": payload, "sig": signature.base64EncodedString()]])
  }

  /// secrets' signed store list, checked against the pinned keys
  func kernelStores() async throws -> StoresDoc {
    let n = CoreCrypto.nonce()
    let d = try CoreCrypto.decode(try await json("POST", "api/kernel/secrets/stores", ["nonce": n], as: SignedDoc.self), by: try KernelTrust.key(),
                                  as: StoresDoc.self, what: "the kernel's store list")
    guard d.kind == "stores", d.nonce == n else { throw TrustError.stale("store list") }
    return d
  }
  /// an unlock of one store in the kernel's secrets (it stays open until locked: D2): begin, the phone's shares under
  /// the given Face ID, finish
  func kernelUnlock(_ store: String, reason: String, auth: PhoneAuth?) async throws {
    let begin = try await json("POST", "api/kernel/secrets/unlock/begin", ["store": store], as: SignedDoc.self)
    let ub = try CoreCrypto.decode(begin, by: try KernelTrust.key(), as: UnlockBegin.self, what: "the kernel's unlock")
    guard ub.kind == "unlock-begin", ub.store == store else { throw TrustError.stale("unlock of \(store)") }
    let es = ub.es
    let (_, xs) = try await offMain { try PhoneKeys.shared.signAndShares(nil, es: es, reason: reason, auth: auth) }
    var shares: [String: Any] = [:]
    for (k, x) in zip(ub.keys, xs) { shares[k.key] = try CoreCrypto.sealShare(x, to: ub.t) }
    struct U: Decodable { let kind: String; let store: String }
    let d = try await json("POST", "api/kernel/secrets/unlock/finish", ["pending": ub.pending, "shares": shares], as: SignedDoc.self)
    let u = try CoreCrypto.decode(d, by: try KernelTrust.key(), as: U.self, what: "the kernel's unlock answer")
    guard u.kind == "unlocked", u.store == store else { throw TrustError.stale("unlock of \(store)") }
  }
  /// an approval answered with the phone's signatures, one per line (an add-store on a kernel line signs two certs)
  func respond(_ id: String, signatures: [Data]) async throws -> RespondDTO {
    try await json("POST", "api/approvals/\(id)/respond", ["signature": signatures.map { $0.base64EncodedString() }.joined(separator: "\n")])
  }
}
