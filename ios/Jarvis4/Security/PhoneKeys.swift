// The phone's two keys and the app's Keychain items (this app's own Keychain access group; nothing else reads them).
//   - signing key: Secure Enclave P-256, Face ID on every use, bound to the faces enrolled when it was made
//     (.biometryCurrentSet) — signs challenges;
//   - agreement key: Secure Enclave P-256, Face ID on every use — computes this phone's share p·E of an unlock.
// The simulator has no Secure Enclave, so its builds use software keys (the pages say so); when the simulator has
// Face ID enrolled (the phone replica enrols it and drives matches and failures with simctl), every use asks for
// Face ID first, as the iPhone does.
import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum Keychain {
  private static let service = "dev.de0ch.jarvis4.shell"
  static func get(_ account: String) -> Data? {
    let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account, kSecReturnData as String: true]
    var out: CFTypeRef?
    return SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess ? out as? Data : nil
  }
  static func set(_ account: String, _ data: Data?) {
    let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
    SecItemDelete(q as CFDictionary)
    guard let data else { return }
    var add = q
    add[kSecValueData as String] = data
    add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    SecItemAdd(add as CFDictionary, nil)
  }
  static func string(_ account: String) -> String? { get(account).flatMap { String(data: $0, encoding: .utf8) } }
  static func setString(_ account: String, _ s: String?) { set(account, s.map { Data($0.utf8) }) }
}

enum KeyError: LocalizedError {
  case noAccessControl
  /// the Enclave refused a key: Face ID's enrolled faces changed since this iPhone was paired (.biometryCurrentSet)
  case invalidated(String)
  var errorDescription: String? {
    switch self {
    case .noAccessControl: "Could not create the Secure Enclave key's access control."
    case .invalidated(let why): "The key didn't sign (\(why)). If Face ID was cancelled, try again. If it keeps failing, Face ID changed since this iPhone was paired and its keys no longer work: pair it again with Settings → Reset or recover → Recover."
    }
  }
}

/// One Face ID for several uses (a batch from the Inbox: every item signed under one Face ID). On an iPhone it is an
/// LAContext that has evaluated Face ID once; every Enclave key use given it runs on that context, so the Secure
/// Enclave asks for no second Face ID (the keys stay .biometryCurrentSet: a context evaluated for a face enrolled after
/// pairing doesn't open them). On the simulator it records that the stand-in check passed. Each item is still signed
/// exactly as alone; only the Face ID is shared. Dropped (invalidated) when the batch is done.
final class PhoneAuth: @unchecked Sendable {
  let context: LAContext?
  init(context: LAContext?) { self.context = context }
  func invalidate() { context?.invalidate() }
}

final class PhoneKeys: @unchecked Sendable {
  static let shared = PhoneKeys()
  var usesEnclave: Bool {
    #if targetEnvironment(simulator)
    return false
    #else
    return SecureEnclave.isAvailable
    #endif
  }
  var how: String { usesEnclave ? "Face ID" : "a software key (simulator)" }
  private var account: String { usesEnclave ? "se" : "sw" }

  private func accessControl() throws -> SecAccessControl {
    var err: Unmanaged<CFError>?
    guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &err) else { throw KeyError.noAccessControl }
    return ac
  }

  /// New key pairs (a Reset pairs the phone again, so its keys are made fresh there; a Recover keeps them unless the
  /// enrolled faces changed: core/continuity.go): the Enclave keys are bound to the faces enrolled NOW
  /// (.biometryCurrentSet, audit finding 6): enrolling another face or an alternate appearance (which needs only the
  /// passcode) makes them unusable, and the phone is paired again with a Recover.
  func renew() {
    for k in ["signing-se", "agreement-se", "signing-sw", "agreement-sw"] { Keychain.set(k, nil) }
    _ = try? publicKeys()
    Keychain.set("biometry-state", Self.biometryState())
  }
  /// the faces enrolled now, as LocalAuthentication names them (nil: no biometry)
  private static func biometryState() -> Data? {
    let c = LAContext()
    var e: NSError?
    guard c.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &e) else { return nil }
    return c.evaluatedPolicyDomainState
  }
  /// the keys a Recover keeps: renewed only when they can't be read or the enrolled faces changed since they were made
  /// (then the Enclave refuses them)
  func keepOrRenew() {
    let saved = Keychain.get("biometry-state")
    if (try? publicKeys()) == nil || (saved != nil && saved != Self.biometryState()) { renew() }
  }

  // ---- the public halves (no Face ID needed); made on first use ----
  func publicKeys() throws -> PublicKeys {
    PublicKeys(signingKey: try signingPublic().base64EncodedString(), agreementKey: try agreementPublic().base64EncodedString())
  }
  private func signingPublic() throws -> Data {
    if usesEnclave {
      if let b = Keychain.get("signing-" + account) { return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: b).publicKey.x963Representation }
      let k = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl())
      Keychain.set("signing-" + account, k.dataRepresentation)
      return k.publicKey.x963Representation
    }
    return softSigning().publicKey.x963Representation
  }
  private func agreementPublic() throws -> Data {
    if usesEnclave {
      if let b = Keychain.get("agreement-" + account) { return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: b).publicKey.x963Representation }
      let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl())
      Keychain.set("agreement-" + account, k.dataRepresentation)
      return k.publicKey.x963Representation
    }
    return softAgreement().publicKey.x963Representation
  }
  private func softSigning() -> P256.Signing.PrivateKey {
    if let b = Keychain.get("signing-sw"), let k = try? P256.Signing.PrivateKey(rawRepresentation: b) { return k }
    let k = P256.Signing.PrivateKey(); Keychain.set("signing-sw", k.rawRepresentation); return k
  }
  private func softAgreement() -> P256.KeyAgreement.PrivateKey {
    if let b = Keychain.get("agreement-sw"), let k = try? P256.KeyAgreement.PrivateKey(rawRepresentation: b) { return k }
    let k = P256.KeyAgreement.PrivateKey(); Keychain.set("agreement-sw", k.rawRepresentation); return k
  }

  /// the simulator's stand-in for the Secure Enclave's Face ID check: with Face ID enrolled, a use needs a match
  private func simulatorFaceID(_ reason: String) throws {
    #if targetEnvironment(simulator)
    let ctx = LAContext()
    var e: NSError?
    guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &e) else { return } // not enrolled
    // a busy simulator can fail to bring the Face ID sheet up ("UI activation timed out after 5 seconds", code -1000,
    // seen on the iOS 27 replica): that is no answer from the person, so the sheet is asked for again (3 tries)
    for attempt in 1...3 {
      let c = attempt == 1 ? ctx : LAContext()
      let sem = DispatchSemaphore(value: 0)
      nonisolated(unsafe) var err: Error?
      c.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { ok, error in
        if !ok { err = error ?? LAError(.authenticationFailed) }
        sem.signal()
      }
      sem.wait()
      guard let err else { return }
      let ns = err as NSError
      if ns.domain == LAErrorDomain, ns.code == -1000, attempt < 3 { Thread.sleep(forTimeInterval: 2); continue }
      throw err
    }
    #endif
  }

  // ---- the device key: this install's long-lived identity (claims and wipes only) ----
  // Made once per install and kept across Reset/Recover, so the setup session can tell a claim from this iPhone from
  // one the router makes with fresh keys of its own (infra/setup.py pins it from the first claim under a master it
  // trusts). Face ID or the passcode (.userPresence): a re-enrolled face doesn't end it.
  func devicePublic() throws -> String {
    if usesEnclave {
      if let b = Keychain.get("device-se") { return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: b).publicKey.x963Representation.base64EncodedString() }
      var err: Unmanaged<CFError>?
      guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], &err) else { throw KeyError.noAccessControl }
      let k = try SecureEnclave.P256.Signing.PrivateKey(accessControl: ac)
      Keychain.set("device-se", k.dataRepresentation)
      return k.publicKey.x963Representation.base64EncodedString()
    }
    return softDevice().publicKey.x963Representation.base64EncodedString()
  }
  private func softDevice() -> P256.Signing.PrivateKey {
    if let b = Keychain.get("device-sw"), let k = try? P256.Signing.PrivateKey(rawRepresentation: b) { return k }
    let k = P256.Signing.PrivateKey(); Keychain.set("device-sw", k.rawRepresentation); return k
  }
  /// the device key's DER signature over exactly `text`
  func deviceSign(_ text: String, reason: String) throws -> Data {
    _ = try devicePublic()
    if usesEnclave, let b = Keychain.get("device-se") {
      let ctx = LAContext(); ctx.localizedReason = reason
      return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: b, authenticationContext: ctx).signature(for: Data(text.utf8)).derRepresentation
    }
    try simulatorFaceID(reason)
    return try softDevice().signature(for: Data(text.utf8)).derRepresentation
  }

  /// ONE Face ID for a batch of uses (blocking: call it off the main thread). The returned PhoneAuth goes to every
  /// sign/share call of the batch. Apple's LAContext reuse: once evaluated, the context opens the Enclave keys given
  /// it until invalidated. Seen on Deyao's iPhone (2026-10-15, batch b986f9a3177e8d687): two deploy keys, each a
  /// signature and a share, both signed 1.3 s apart under this one evaluatePolicy. Items after the first that failed
  /// were add-stores for one session, a router/core cause (flows.go rebaseAddStores), not this context.
  func authorize(reason: String) throws -> PhoneAuth {
    if usesEnclave {
      let ctx = LAContext()
      ctx.localizedReason = reason
      let sem = DispatchSemaphore(value: 0)
      nonisolated(unsafe) var err: Error?
      ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { ok, error in
        if !ok { err = error ?? LAError(.authenticationFailed) }
        sem.signal()
      }
      sem.wait()
      if let err { throw err }
      return PhoneAuth(context: ctx)
    }
    try simulatorFaceID(reason)
    return PhoneAuth(context: nil)
  }
  /// the context a key use runs on: the batch's (already authenticated) or a fresh one that asks for Face ID
  private func context(_ auth: PhoneAuth?, _ reason: String) -> LAContext {
    if let c = auth?.context { return c }
    let ctx = LAContext(); ctx.localizedReason = reason
    return ctx
  }
  /// the simulator's stand-in check, unless the batch's Face ID already passed
  private func simulatorCheck(_ auth: PhoneAuth?, _ reason: String) throws {
    if auth == nil { try simulatorFaceID(reason) }
  }

  // ---- uses (one Face ID each on a real iPhone, unless a batch's PhoneAuth is given) ----
  /// a key use that fails for any reason but Face ID itself (a cancel, a mismatch) means the Enclave key is gone
  private func guarded<T>(_ body: () throws -> T) throws -> T {
    do { return try body() }
    catch let e as LAError { throw e }
    catch let e as TrustError { throw e }
    catch { if usesEnclave { throw KeyError.invalidated(errText(error)) } else { throw error } }
  }
  /// DER signature over exactly `payload`'s bytes
  func sign(_ payload: String, reason: String, auth: PhoneAuth? = nil) throws -> Data { try guarded { try signRaw(payload, reason: reason, auth: auth) } }
  private func signRaw(_ payload: String, reason: String, auth: PhoneAuth?) throws -> Data {
    _ = try signingPublic()
    if usesEnclave {
      let ctx = context(auth, reason)
      let k = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Keychain.get("signing-se")!, authenticationContext: ctx)
      return try k.signature(for: Data(payload.utf8)).derRepresentation
    }
    try simulatorCheck(auth, reason)
    return try softSigning().signature(for: Data(payload.utf8)).derRepresentation
  }
  /// a signature over `payload` and this phone's share x(p·E), under ONE Face ID: both Enclave keys use the same
  /// LAContext, which the first use authenticates (a deploy key: the phone approves the request and opens the
  /// token store for it)
  func signAndShare(_ payload: String, e: String, reason: String, auth: PhoneAuth? = nil) throws -> (signature: Data, share: Data) { try guarded { try signAndShareRaw(payload, e: e, reason: reason, auth: auth) } }
  private func signAndShareRaw(_ payload: String, e: String, reason: String, auth: PhoneAuth?) throws -> (signature: Data, share: Data) {
    _ = try signingPublic(); _ = try agreementPublic()
    guard let eb = Data(base64Encoded: e) else { throw TrustError.badSignature("the store's key") }
    let pub = try P256.KeyAgreement.PublicKey(x963Representation: eb)
    if usesEnclave {
      let ctx = context(auth, reason)
      let s = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Keychain.get("signing-se")!, authenticationContext: ctx)
      let sig = try s.signature(for: Data(payload.utf8)).derRepresentation
      let a = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: Keychain.get("agreement-se")!, authenticationContext: ctx)
      let secret = try a.sharedSecretFromKeyAgreement(with: pub)
      return (sig, secret.withUnsafeBytes { Data($0) })
    }
    try simulatorCheck(auth, reason)
    let sig = try softSigning().signature(for: Data(payload.utf8)).derRepresentation
    let secret = try softAgreement().sharedSecretFromKeyAgreement(with: pub)
    return (sig, secret.withUnsafeBytes { Data($0) })
  }
  /// an optional signature over `payload` and this phone's share x(p·E) for each store key in `es`, under ONE Face
  /// ID (one LAContext for every Enclave use): New session's Start signs the approval and opens the session's locked
  /// stores at once; the unlock review page opens several stores at once
  func signAndShares(_ payload: String?, es: [String], reason: String, auth: PhoneAuth? = nil) throws -> (signature: Data?, shares: [Data]) { try guarded { try signAndSharesRaw(payload, es: es, reason: reason, auth: auth) } }
  private func signAndSharesRaw(_ payload: String?, es: [String], reason: String, auth: PhoneAuth?) throws -> (signature: Data?, shares: [Data]) {
    _ = try signingPublic(); _ = try agreementPublic()
    let pubs = try es.map { e -> P256.KeyAgreement.PublicKey in
      guard let eb = Data(base64Encoded: e) else { throw TrustError.badSignature("the store's key") }
      return try P256.KeyAgreement.PublicKey(x963Representation: eb)
    }
    if usesEnclave {
      let ctx = context(auth, reason)
      var sig: Data?
      if let payload {
        let k = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Keychain.get("signing-se")!, authenticationContext: ctx)
        sig = try k.signature(for: Data(payload.utf8)).derRepresentation
      }
      var shares: [Data] = []
      if !pubs.isEmpty {
        let a = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: Keychain.get("agreement-se")!, authenticationContext: ctx)
        for pub in pubs { shares.append(try a.sharedSecretFromKeyAgreement(with: pub).withUnsafeBytes { Data($0) }) }
      }
      return (sig, shares)
    }
    try simulatorCheck(auth, reason)
    let sig = try payload.map { try softSigning().signature(for: Data($0.utf8)).derRepresentation }
    let shares = try pubs.map { try softAgreement().sharedSecretFromKeyAgreement(with: $0).withUnsafeBytes { Data($0) } }
    return (sig, shares)
  }
  /// this phone's share of an unlock: x(p·E), 32 bytes
  func share(with e: String, reason: String) throws -> Data { try guarded { try shareRaw(with: e, reason: reason) } }
  private func shareRaw(with e: String, reason: String) throws -> Data {
    _ = try agreementPublic()
    guard let eb = Data(base64Encoded: e) else { throw TrustError.badSignature("the store's key") }
    let pub = try P256.KeyAgreement.PublicKey(x963Representation: eb)
    let secret: SharedSecret
    if usesEnclave {
      let ctx = LAContext(); ctx.localizedReason = reason
      let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: Keychain.get("agreement-se")!, authenticationContext: ctx)
      secret = try k.sharedSecretFromKeyAgreement(with: pub)
    } else {
      try simulatorFaceID(reason)
      secret = try softAgreement().sharedSecretFromKeyAgreement(with: pub)
    }
    return secret.withUnsafeBytes { Data($0) }
  }
}

/// The core this iPhone set up (Reset or Recover): its keys and the master public key it was set up with, pinned
/// in the Keychain when the core accepted the master-signed claim naming them. Every core document is
/// verified against the pinned core key — never learned from the network — and a core set up with another master
/// key is refused (the setup page says so).
enum CoreTrust {
  static var pinned: PublicKeys? { Keychain.get("core-keys").flatMap { try? JSONDecoder().decode(PublicKeys.self, from: $0) } }
  /// this iPhone's master public key (the private half is only in Deyao's recovery kit)
  static var master: String? { Keychain.string("master-public") }
  static func pin(_ k: PublicKeys, master: String) {
    Keychain.set("core-keys", try? JSONEncoder().encode(k))
    Keychain.setString("master-public", master)
  }
  static func key() throws -> String { guard let p = pinned else { throw TrustError.notSetUp }; return p.signingKey }
  /// a next core Recovered alongside with keys other than the pinned core's (the running core wasn't seeded): its keys
  /// (derived from the kit, so trusted as the kit is) are pinned once it is the core that serves (AppModel.adoptNext)
  static var pendingNext: (keys: PublicKeys, master: String)? {
    guard let k = Keychain.get("next-core-keys").flatMap({ try? JSONDecoder().decode(PublicKeys.self, from: $0) }), let m = Keychain.string("next-core-master") else { return nil }
    return (k, m)
  }
  static func setPendingNext(_ k: PublicKeys?, master: String?) {
    Keychain.set("next-core-keys", k.flatMap { try? JSONEncoder().encode($0) })
    Keychain.setString("next-core-master", master)
  }
}

/// The highest record of the sessions (the core's lineSeq, core/continuity.go) this iPhone has seen from each core,
/// by the core's signing key: a Recover refuses an older one from the router (CoreSetup.checkLineState).
enum LineWitness {
  private static func account(_ core: String) -> String { "line-seq-" + String(CoreCrypto.sha256hex(Data(core.utf8)).prefix(32)) }
  static func seen(_ core: String) -> Int { Keychain.string(account(core)).flatMap(Int.init) ?? 0 }
  static func saw(_ core: String, _ seq: Int?) {
    guard let seq, seq > seen(core) else { return }
    Keychain.setString(account(core), String(seq))
  }
}
