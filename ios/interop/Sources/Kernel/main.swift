// The app's kernel code (Security/KernelSetup.swift, with CoreCrypto and CoreSetup) against the REAL kernel secrets and
// spawner binaries (kernel/cmd/secrets and spawner, started with KERNEL_ROOT = the public half of the root key this
// test plays) and the documents as the Go side makes them (kernel/cmd/vectors, ios/interop/rostervec over kernel/sig):
// the roster (the setup key's pending one checked, its payload byte for byte Go's RosterPayload, the root key's
// signature taken by the real components, secrets' boot keys replaced by the kit-derived ones), secrets' identity
// checked against it (and refused when only the setup key vouches for a claimed secrets), the claim with the
// kit-derived keys and the root key, the split-key unlock, the keys statement; then the cert checks the approval
// pages make before Face ID, and their refusals.
// Configuration (env): KERNEL_SECRETS, KERNEL_SPAWNER (their URLs), KERNEL_ROOT_PEM (the root key the components were
// started with, PEM), KERNEL_ROSTERVEC (the rostervec binary), KERNEL_VECTORS (kernel/cmd/vectors' output).
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

let env = ProcessInfo.processInfo.environment
func need(_ k: String) -> String { guard let v = env[k], !v.isEmpty else { print("missing \(k)"); exit(2) }; return v }
let secrets = need("KERNEL_SECRETS"), spawner = need("KERNEL_SPAWNER")
let root = try! P256.Signing.PrivateKey(pemRepresentation: try! String(contentsOfFile: need("KERNEL_ROOT_PEM"), encoding: .utf8))
let rootPub = root.publicKey.x963Representation.base64EncodedString()
let rostervec = need("KERNEL_ROSTERVEC")
let vectors = try! JSONDecoder().decode([String: String].self, from: try! Data(contentsOf: URL(fileURLWithPath: need("KERNEL_VECTORS"))))
var failures = 0
setvbuf(stdout, nil, _IOLBF, 0)
func check(_ ok: Bool, _ what: String) { print((ok ? "ok   " : "FAIL ") + what); if !ok { failures += 1 } }
func throwsErr(_ fn: () throws -> Void) -> Bool { do { try fn(); return false } catch { return true } }
func call(_ base: String, _ path: String, _ body: Any? = nil) -> (Int, Data) {
  var r = URLRequest(url: URL(string: base + path)!)
  if let body { r.httpBody = try! JSONSerialization.data(withJSONObject: body); r.httpMethod = "POST"; r.setValue("application/json", forHTTPHeaderField: "Content-Type") }
  let sem = DispatchSemaphore(value: 0)
  nonisolated(unsafe) var out: (Int, Data) = (0, Data())
  URLSession.shared.dataTask(with: r) { d, resp, _ in out = ((resp as? HTTPURLResponse)?.statusCode ?? 0, d ?? Data()); sem.signal() }.resume()
  sem.wait()
  return out
}
func call(_ path: String, _ body: Any? = nil) -> (Int, Data) { call(secrets, path, body) }
func doc(_ d: Data) -> SignedDoc { try! JSONDecoder().decode(SignedDoc.self, from: d) }
/// rostervec (kernel/sig on the Go side): stdin in, stdout out, exit status
func goSide(_ args: [String], _ input: Data) -> (Int32, String) {
  let p = Process(); p.executableURL = URL(fileURLWithPath: rostervec); p.arguments = args
  let i = Pipe(), o = Pipe(); p.standardInput = i; p.standardOutput = o; p.standardError = FileHandle.nullDevice
  try! p.run(); i.fileHandleForWriting.write(input); try! i.fileHandleForWriting.close()
  let out = o.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
  return (p.terminationStatus, String(decoding: out, as: UTF8.self))
}
func json(_ v: some Encodable) -> Data { try! JSONEncoder().encode(v) }
func rootSigned(_ payload: String, by k: P256.Signing.PrivateKey = root) -> SignedDoc {
  SignedDoc(payload: payload, sig: try! k.signature(for: Data(payload.utf8)).derRepresentation.base64EncodedString())
}
let other = P256.Signing.PrivateKey()
let otherPub = other.publicKey.x963Representation.base64EncodedString()

// ---- the setup session's pending roster: secrets' and the spawner's boot keys, signed with the setup key ----
func identity() -> KernelSetup.Identity { try! JSONDecoder().decode(KernelSetup.Identity.self, from: call("/identity").1) }
let id0 = identity()
let spDoc = doc(call(spawner, "/identity").1)
struct CI: Decodable { let role: String; let signingKey: String; let agreementKey: String }
let sp = try! JSONDecoder().decode(CI.self, from: Data(spDoc.payload.utf8))
let members = [KernelRoster.Member(role: "spawner", signingKey: sp.signingKey, agreementKey: sp.agreementKey),
               KernelRoster.Member(role: "secrets", signingKey: id0.signingKey, agreementKey: id0.agreementKey)]
let bootPayload = KernelRoster.payload(copy: "blue", members: members)
struct In: Encodable { let copy: String; let members: [KernelRoster.Member] }
let goPayload = goSide([], json(In(copy: "blue", members: members)))
check(goPayload.0 == 0 && goPayload.1 == bootPayload, "the roster's payload is byte for byte Go's RosterPayload (members sorted by role)")
let setup = P256.Signing.PrivateKey()
let setupPub = setup.publicKey.x963Representation.base64EncodedString()
let filed = KernelRoster.Pending(copy: "blue", payload: bootPayload, setupSig: try! setup.signature(for: Data(bootPayload.utf8)).derRepresentation.base64EncodedString())
let pending = try? KernelRoster.pending(filed, setupKey: setupPub)
check(pending?.members.map(\.role) == ["secrets", "spawner"] && pending?.copy == "blue", "the pending roster checks against the setup key and lists its members")
check(throwsErr { _ = try KernelRoster.pending(filed, setupKey: otherPub) }, "…not against another setup key")
check(throwsErr { _ = try KernelRoster.pending(KernelRoster.Pending(copy: "green", payload: filed.payload, setupSig: filed.setupSig), setupKey: setupPub) }, "…not for another kernel copy")
let spaced = bootPayload.replacingOccurrences(of: ",\"members\"", with: ", \"members\"")
check(throwsErr { _ = try KernelRoster.pending(KernelRoster.Pending(copy: "blue", payload: spaced, setupSig: try! setup.signature(for: Data(spaced.utf8)).derRepresentation.base64EncodedString()), setupKey: setupPub) },
      "…not a payload other than the canonical one, even signed")
let unsorted = { () -> String in
  let ms = members.sorted { $0.role > $1.role }.map { "{\"role\":\"\($0.role)\",\"signingKey\":\"\($0.signingKey)\",\"agreementKey\":\"\($0.agreementKey)\"}" }
  return "{\"kind\":\"kernel-roster\",\"copy\":\"blue\",\"members\":[\(ms.joined(separator: ","))]}"
}()
check(throwsErr { _ = try KernelRoster.parse(unsorted) }, "…nor members out of order")

// ---- secrets' identity, before the claim: only the pending roster vouches for it ----
let c0 = try? KernelSetup.check(id0, KernelSetup.Anchors(pending: pending))
check(c0 != nil && c0?.state.master == "", "secrets' boot keys are the pending roster's and it is empty")
check(throwsErr { _ = try KernelSetup.check(id0, KernelSetup.Anchors()) }, "…nothing vouches without a roster")
check(throwsErr { _ = try KernelSetup.check(KernelSetup.Identity(signingKey: id0.agreementKey, agreementKey: id0.signingKey, state: id0.state), KernelSetup.Anchors(pending: pending)) }, "…not for other keys")
check(KernelSetup.unclaimed(id0) == c0?.keys, "an empty secrets reads as unclaimed")
let spk0 = try? KernelSetup.component(spDoc, role: "spawner", roster: pending!)
check(spk0 != nil, "the spawner's identity is its roster member's")
check(throwsErr { _ = try KernelSetup.component(spDoc, role: "secrets", roster: pending!) }, "…not as another role")

// ---- the claim: a Recover with one store, the kit's derived keys, the root key ----
let master = MasterKey.generate()
let phoneSig = P256.Signing.PrivateKey(), phoneAgree = P256.KeyAgreement.PrivateKey()
let phone = PublicKeys(signingKey: phoneSig.publicKey.x963Representation.base64EncodedString(), agreementKey: phoneAgree.publicKey.x963Representation.base64EncodedString())
let seed = KernelContinuity.seed(master)
let derived = try! KernelContinuity.keys(seed: seed)
let skDoc = doc(call("/store-key", ["phone": phone.agreementKey, "secrets": derived.agreementKey]).1)
struct SK: Decodable { let storeKey: String }
let sk = try! CoreCrypto.decode(skDoc, by: c0!.keys.signingKey, as: SK.self, what: "store key")
let stores = [RecoveredStore(name: "default", values: ["A": "1", "B": "2"], sensitive: false)]
let bundle = try! KernelSetup.bundle(stores, storeKey: sk.storeKey, seed: seed)
let k0 = c0!.keys
// refused: signed by another key, for another secrets, a phone key as the root key
var bad = try! KernelSetup.claim(secrets: k0, phone: phone, root: rootPub, master: master, bundle: bundle, identity: derived)
bad["masterSig"] = try! MasterKey.generate().sign(bad["statement"] as! String)
check(call("/claim", bad).0 == 403, "a claim not signed by its master key is refused")
check(call("/claim", try! KernelSetup.claim(secrets: k0, phone: phone, root: phone.signingKey, master: master, bundle: bundle, identity: derived)).0 == 400, "…the phone's key as the root key too")
check(call("/claim", try! KernelSetup.claim(secrets: PublicKeys(signingKey: derived.signingKey, agreementKey: k0.agreementKey), phone: phone, root: rootPub, master: master, bundle: bundle, identity: derived)).0 == 403, "…and a claim for another secrets")
let (code, _) = call("/claim", try! KernelSetup.claim(secrets: k0, phone: phone, root: rootPub, master: master, bundle: bundle, identity: derived))
check(code == 200, "the claim goes through")
let id1 = identity()
let c1 = try? KernelSetup.check(id1, KernelSetup.Anchors(pinned: derived))
check(c1?.keys == derived, "secrets now answers with the keys the kit derives (Swift and Go derive the same)")
check(throwsErr { _ = try KernelSetup.check(id1, KernelSetup.Anchors(pending: KernelRoster.replacing(pending!, role: "secrets", with: derived))) },
      "…which the setup key alone can't vouch for once claimed")
check(KernelSetup.unclaimed(id1) == nil, "a claimed secrets doesn't read as unclaimed")

// ---- the root key's roster: the pending one with secrets' derived keys, taken by the real components ----
let signedR = try! KernelRoster.replacing(pending!, role: "secrets", with: derived)
check(signedR.member("spawner") == pending!.member("spawner") && signedR.member("secrets") == derived, "the replaced roster keeps every other member")
check(throwsErr { try KernelSetup.signable(pending!, pinned: derived, unclaimed: []) }, "the root key won't sign a roster naming secrets' old boot keys")
check(!throwsErr { try KernelSetup.signable(signedR, pinned: derived, unclaimed: []) }, "…and signs the one with the keys it pinned")
check(!throwsErr { try KernelSetup.signable(pending!, pinned: nil, unclaimed: [c0!.keys]) }, "…or one naming an empty secrets")
let rDoc = rootSigned(signedR.payload)
let goOpen = goSide(["-open", rootPub], json(rDoc))
check(goOpen.0 == 0, "Go's OpenRoster takes the app's payload and the root key's DER signature")
check(goSide(["-open", otherPub], json(rDoc)).0 != 0, "…not checked against another root key")
check(call("/roster", ["roster": ["payload": rDoc.payload, "sig": rDoc.sig]]).0 == 200, "secrets takes the root key's roster naming its derived keys")
check(call("/roster", ["roster": ["payload": bootPayload, "sig": rootSigned(bootPayload).sig]]).0 == 403, "…not one naming its boot keys")
let byOther = rootSigned(signedR.payload, by: other)
check(call("/roster", ["roster": ["payload": byOther.payload, "sig": byOther.sig]]).0 == 403, "…nor one another key signed")
check(call(spawner, "/roster", ["roster": ["payload": rDoc.payload, "sig": rDoc.sig]]).0 == 200, "the spawner takes it too")
let held = try? KernelRoster.signed(doc(call("/roster").1), rootKey: rootPub)
check(held == signedR, "the roster secrets holds checks against the root key and reads as signed")
check(throwsErr { _ = try KernelRoster.signed(rDoc, rootKey: otherPub) }, "…not against another root key")
check((try? KernelSetup.check(id1, KernelSetup.Anchors(roster: held)))?.keys == derived, "secrets' identity checks against the root key's roster")
check(c1.map { MasterKey.same($0.state.master, master.publicKey) && $0.state.phone == phone && $0.state.root == rootPub } ?? false, "its state names the master, the phone and the root key")
check(call("/claim", try! KernelSetup.claim(secrets: derived, phone: phone, root: rootPub, master: master, bundle: bundle, identity: derived)).0 == 409, "a second claim is refused")

// ---- the keys statement and the split-key unlock ----
struct KS: Decodable { let kind: String; let phone: String; let root: String }
let ks = try? CoreCrypto.decode(doc(call("/keys", [String: String]()).1), by: derived.signingKey, as: KS.self, what: "keys")
check(ks?.phone == phone.signingKey && ks?.root == rootPub, "the keys statement names the phone's and the root key")
let begin = doc(call("/unlock/begin", ["store": "default"]).1)
struct UB: Decodable { let pending: String; let t: String; let keys: [K] ; struct K: Decodable { let key: String; let e: String } }
let ub = try! CoreCrypto.decode(begin, by: derived.signingKey, as: UB.self, what: "unlock begin")
var shares: [String: [String: String]] = [:]
for k in ub.keys {
  let pub = try! P256.KeyAgreement.PublicKey(x963Representation: Data(base64Encoded: k.e)!)
  let x = try! phoneAgree.sharedSecretFromKeyAgreement(with: pub).withUnsafeBytes { Data($0) }
  shares[k.key] = try! CoreCrypto.sealShare(x, to: ub.t)
}
check(call("/unlock/finish", ["pending": ub.pending, "shares": shares]).0 == 200, "the phone's shares unlock a store wrapped by the app")

// ---- the certs the phone signs ----
let s = try? KernelChecks.source(payload: vectors["source"]!, session: "s1")
check(s?.stores == ["default", "tunnel"] && s?.harness == "claude" && s?.permissionMode == "auto" && s?.config["label"]?.string == "x" && s?.snapshot == nil,
      "a new source as Go makes it reads as its stores, harness, mode and settings")
check((try? KernelChecks.source(payload: vectors["restore"]!, session: "s1"))?.snapshot?.count == 64, "a restore's source names the snapshot hash")
check(throwsErr { _ = try KernelChecks.source(payload: vectors["source"]!, session: "s2") }, "…not for another session")
check(throwsErr { _ = try KernelChecks.source(payload: vectors["shell"]!, session: "s1") }, "…not a source that allows a shell")
check(throwsErr { _ = try KernelChecks.source(payload: vectors["otherSession"]!, session: "s1") }, "…not one whose conditions name another session")
check(throwsErr { _ = try KernelChecks.source(payload: vectors["otherImage"]!, session: "s1") }, "…not another repo's image")
check(throwsErr { _ = try KernelChecks.source(payload: vectors["addSecond"]!, session: "s1") }, "…not a cert onto a machine")
let a = try? KernelChecks.add(first: vectors["addFirst"]!, second: vectors["addSecond"]!, session: "s1", store: "extra")
check(a?.machine == "0123456789abcd", "an add-store's two certs read as the store onto the running machine")
check(throwsErr { _ = try KernelChecks.add(first: vectors["addFirst"]!, second: vectors["addSecond"]!, session: "s1", store: "other") }, "…not for another store")
check(throwsErr { _ = try KernelChecks.add(first: vectors["source"]!, second: vectors["addSecond"]!, session: "s1", store: "extra") }, "…not when the second cert leaves another source")

// ---- the spawner's Fly token, sealed to the keys the root key's roster names ----
let spk = try? KernelSetup.component(spDoc, role: "spawner", roster: signedR)
check(spk != nil, "the spawner's identity is the root key's roster's")
let foreign = KernelRoster.Roster(copy: "blue", members: [KernelRoster.Member(role: "spawner", signingKey: derived.signingKey, agreementKey: derived.agreementKey)])
check(throwsErr { _ = try KernelSetup.component(spDoc, role: "spawner", roster: foreign) }, "…not against a roster naming other keys")
if let spk {
  let (code, body) = call(spawner, "/fly-token", try! KernelSetup.flyToken("fly-test-token", to: spk))
  check(code == 200 && String(decoding: body, as: UTF8.self).contains("fly-token-set"), "the spawner opens the Fly token the app sealed to it")
}

print(failures == 0 ? "all kernel checks passed" : "\(failures) kernel check(s) FAILED")
exit(failures == 0 ? 0 : 1)
