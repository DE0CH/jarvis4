// The root key (DESIGN "Target design"): a second Secure Enclave key, apart from the phone's own, that may sign
// anything in the kernel's table: above all the one grant everything else narrows from, ⊤ on the sink. It is never
// part of a batch (each use asks for its own Face ID) and is used only behind its own warning screen
// (KernelSetupView). It signs the kernel's roster (the components' keys), which every component checks against its
// public half in keys/root.pub (registered with the router, committed by a setup session); the kernel's secrets also
// learns it from the claim the master key signs. Its own Keychain items (root-se / root-sw) in this app's own Keychain.
// KernelTrust: secrets' keys this iPhone set up, pinned like the old core's (CoreTrust): every document of secrets is
// checked against them, never against keys learned from the network.
import CryptoKit
import Foundation
import LocalAuthentication
import Security

final class RootKey: @unchecked Sendable {
  static let shared = RootKey()
  private var usesEnclave: Bool { PhoneKeys.shared.usesEnclave }

  /// its public half (made on first use; no Face ID)
  func publicKey() throws -> String {
    if usesEnclave {
      if let b = Keychain.get("root-se") { return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: b).publicKey.x963Representation.base64EncodedString() }
      var err: Unmanaged<CFError>?
      guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &err) else { throw KeyError.noAccessControl }
      let k = try SecureEnclave.P256.Signing.PrivateKey(accessControl: ac)
      Keychain.set("root-se", k.dataRepresentation)
      return k.publicKey.x963Representation.base64EncodedString()
    }
    return soft().publicKey.x963Representation.base64EncodedString()
  }
  private func soft() -> P256.Signing.PrivateKey {
    if let b = Keychain.get("root-sw"), let k = try? P256.Signing.PrivateKey(rawRepresentation: b) { return k }
    let k = P256.Signing.PrivateKey(); Keychain.set("root-sw", k.rawRepresentation); return k
  }
  /// DER signature over exactly `payload`, with a Face ID of its own (blocking: call it off the main thread)
  func sign(_ payload: String, reason: String) throws -> Data {
    _ = try publicKey()
    if usesEnclave, let b = Keychain.get("root-se") {
      let ctx = LAContext(); ctx.localizedReason = reason
      return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: b, authenticationContext: ctx).signature(for: Data(payload.utf8)).derRepresentation
    }
    let ctx = LAContext()
    var e: NSError?
    if ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &e) {
      let sem = DispatchSemaphore(value: 0)
      nonisolated(unsafe) var fail: Error?
      ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { ok, error in
        if !ok { fail = error ?? LAError(.authenticationFailed) }
        sem.signal()
      }
      sem.wait()
      if let fail { throw fail }
    }
    return try soft().signature(for: Data(payload.utf8)).derRepresentation
  }
}

enum KernelTrust {
  /// secrets' keys and the master key it was claimed with
  static var pinned: PublicKeys? { Keychain.get("kernel-secrets-keys").flatMap { try? JSONDecoder().decode(PublicKeys.self, from: $0) } }
  static func pin(_ k: PublicKeys) { Keychain.set("kernel-secrets-keys", try? JSONEncoder().encode(k)) }
  static func key() throws -> String { guard let p = pinned else { throw TrustError.notSetUp }; return p.signingKey }
}
