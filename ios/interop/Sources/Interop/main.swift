// The shell's CoreCrypto + CoreSetup against the REAL core binary (fakefly build, a throwaway box key) and the
// backups as the router serves them (a router on the runner reading a local S3 stand-in that infra/setup.py's own
// code seeded, ios/ci/standin.py): the core's identity and signed state (empty, then set up), the recovery kit
// string (round trip, the old version refused), reading + checking + decrypting the backups with the kit's master
// key, Recover itself (the claim), the signed store list (sensitivity), create / mark sensitive, split-key unlock,
// key backups laid over the whole-store backups (setup- and session-written, deleted, older), per-key writers on
// unlock (a setup-signed key written through the router unlocks; a key sealed under another name doesn't; a session's
// write is shown or refused), approvals (new session, add a store, resume on the latest image), grants (the session
// cert, the draft checks),
// the Fly token sealed to the core, and Reset's wipe at the end — and the refusals: a box signature by another key,
// a state not signed by the core, a tampered backup, a wrong master key, a claim for another core or bundle or
// signed by another key, a second claim, a forged phone signature, a wrong share, a wipe by another key.
// Configuration (env): INTEROP_CORE, INTEROP_ROUTER (its /api/backups reads the stand-in bucket jarvis2-backup-ci),
// INTEROP_KEYS (the dir with box.pub + setup.pub), INTEROP_BACKUPS (standin.py's dump: {bucket: [{key, body}]}),
// INTEROP_MASTER_PEM (e2e/testdata/master-test.pem), INTEROP_EXPORT_OUT (optional: where the offline copy's file goes).
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
let core = need("INTEROP_CORE")
let keysDir = need("INTEROP_KEYS")
let boxKey = try! String(contentsOfFile: keysDir + "/box.pub", encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
let setupKey = try! String(contentsOfFile: keysDir + "/setup.pub", encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
/// the setup session's private key (standin.py writes it next to keys/): signs the keys written as the setup session
let setupSigner = try! P256.Signing.PrivateKey(pemRepresentation: try! String(contentsOfFile: keysDir + "/../setup-key.pem", encoding: .utf8))
let phoneSigningForTests = P256.Signing.PrivateKey().publicKey.x963Representation.base64EncodedString()
var failures = 0
setvbuf(stdout, nil, _IOLBF, 0)
func check(_ ok: Bool, _ what: String) { print((ok ? "ok   " : "FAIL ") + what); if !ok { failures += 1 } }
func throwsErr(_ fn: () throws -> Void) -> Bool { do { try fn(); return false } catch { return true } }

func call(_ path: String, _ body: Any? = nil, base: String = core, method: String = "POST") -> (Int, Data) {
  var r = URLRequest(url: URL(string: base + path)!)
  if let body { r.httpBody = try! JSONSerialization.data(withJSONObject: body); r.httpMethod = method; r.setValue("application/json", forHTTPHeaderField: "Content-Type") }
  let sem = DispatchSemaphore(value: 0)
  nonisolated(unsafe) var out: (Int, Data) = (0, Data())
  URLSession.shared.dataTask(with: r) { d, resp, _ in out = ((resp as? HTTPURLResponse)?.statusCode ?? 0, d ?? Data()); sem.signal() }.resume()
  sem.wait()
  return out
}
func doc(_ d: Data) -> SignedDoc { try! JSONDecoder().decode(SignedDoc.self, from: d) }
func docJSON(_ d: SignedDoc) -> [String: String] { ["payload": d.payload, "sig": d.sig] }

// ---- the core's identity: box-signed keys, its own signed state ----
func identity() -> CoreSetup.Identity { try! JSONDecoder().decode(CoreSetup.Identity.self, from: call("/identity").1) }
let id0 = identity()
let checked = try? CoreSetup.check(id0, boxKey: boxKey)
check(checked != nil, "the core's keys are signed by the box key and its state by the core")
let coreKeys = checked?.keys ?? PublicKeys(signingKey: "", agreementKey: "")
check(checked?.state.master == "" && checked?.state.phone == nil, "a new core is empty")
check(throwsErr { _ = try CoreSetup.check(id0, boxKey: setupKey) }, "…not with another box key")
check(throwsErr { _ = try CoreSetup.check(CoreSetup.Identity(signingKey: id0.agreementKey, agreementKey: id0.signingKey, boxSig: id0.boxSig, state: id0.state), boxKey: boxKey) }, "…not for other keys")
let otherSigner = P256.Signing.PrivateKey()
let forgedState = SignedDoc(payload: id0.state.payload, sig: try! otherSigner.signature(for: Data(id0.state.payload.utf8)).derRepresentation.base64EncodedString())
check(throwsErr { _ = try CoreSetup.check(CoreSetup.Identity(signingKey: id0.signingKey, agreementKey: id0.agreementKey, boxSig: id0.boxSig, state: forgedState), boxKey: boxKey) }, "…not with a state the core didn't sign")

// ---- the master key and the recovery kit (the ONE string) ----
let pem = try! String(contentsOfFile: need("INTEROP_MASTER_PEM"), encoding: .utf8)
let master = MasterKey(signing: try! P256.Signing.PrivateKey(pemRepresentation: pem))
check((try? MasterKey(pkcs8: master.pkcs8))?.publicKey == master.publicKey, "the master key's PKCS#8 part round-trips (\(master.pkcs8.prefix(8))…)")
let fresh = MasterKey.generate()
check((try? MasterKey(pkcs8: fresh.pkcs8))?.publicKey == fresh.publicKey && fresh.pkcs8.hasPrefix("MIG"), "a generated master key is PKCS#8 DER and parses back")
check(throwsErr { _ = try MasterKey(pkcs8: "AAAA") }, "a broken master key is refused")
check(MasterKey.same(master.publicKey, master.publicKey) && !MasterKey.same(fresh.publicKey, master.publicKey) && !MasterKey.same("", ""), "public keys compare by their bytes")
let kitString = RecoveryKit(master: master).string
check(kitString.hasPrefix("jarvis2-kit:2:MIG") && !kitString.dropFirst(14).contains(":"), "the kit string is the version and the master key only (\(kitString.prefix(20))…)")
let kit = try? RecoveryKit.parse(kitString)
check(kit?.master.publicKey == master.publicKey, "the kit round-trips")
let wrapped = String(kitString.enumerated().map { $0.offset > 0 && $0.offset % 64 == 0 ? "\n\($0.element)" : "\($0.element)" }.joined()) + "\n"
check((try? RecoveryKit.parse("  " + wrapped))?.master.publicKey == master.publicKey, "a kit pasted with line breaks and spaces still parses")
func kitError(_ s: String) -> String { do { _ = try RecoveryKit.parse(s); return "" } catch { return (error as? LocalizedError)?.errorDescription ?? "?" } }
check(kitError("jarvis2-kit:1:\(master.pkcs8):AK:SK").contains("older Jarvis 4"), "a version-1 kit is refused with a plain message (\(kitError("jarvis2-kit:1:x")))")
check(kitError(master.pkcs8) == "That isn't a recovery kit.", "a bare master key is not a kit")
check(!kitError("jarvis2-kit:2:AAAA").isEmpty, "a kit with a broken master key is refused")
check(!kitError("jarvis2-kit:3:" + master.pkcs8).isEmpty, "another kit version is refused")
let kitMaster = kit?.master ?? fresh

// ---- the backups, as the router serves them ----
let dumps = try! JSONDecoder().decode([String: [CoreSetup.BackupObject]].self, from: Data(contentsOf: URL(fileURLWithPath: need("INTEROP_BACKUPS"))))
struct Served: Decodable { let objects: [CoreSetup.BackupObject] }
let (bs, bd) = call("/api/backups", base: need("INTEROP_ROUTER"))
let served = (try? JSONDecoder().decode(Served.self, from: bd))?.objects ?? []
check(bs == 200 && Set(served.map { $0.key + $0.body }) == Set((dumps["jarvis2-backup-ci"] ?? []).map { $0.key + $0.body }), "the router serves the bucket's objects unchanged (HTTP \(bs), \(served.count) objects)")
let stores: [RecoveredStore]
do { stores = try CoreSetup.readBackups(served, master: kitMaster, setupKey: setupKey) } catch { print("FAIL reading the backups: \(error)"); exit(1) }
check(stores.map(\.name) == ["claude-login", "core", "default", "github-deploy-keys", "gmail", "marked"], "every store comes back (\(stores.map(\.name)))")
let sens = Dictionary(uniqueKeysWithValues: stores.map { ($0.name, $0.sensitive) })
check(sens["default"] == false && sens["claude-login"] == false && sens["gmail"] == true && sens["core"] == true, "sensitivity from the backups")
check(sens["marked"] == true, "a sensitive/ marker makes a store sensitive whatever its backup says")
check(stores.first { $0.name == "default" }?.values == ["GITHUB_TOKEN": "ci-dummy", "OTHER": "x"], "values decrypt with the master key")
check(throwsErr { _ = try CoreSetup.readBackups(dumps["jarvis2-backup-tampered"] ?? [], master: master, setupKey: setupKey) }, "a backup signed by another key is refused")
check(throwsErr { _ = try CoreSetup.readBackups(served, master: fresh, setupKey: setupKey) }, "another master key doesn't open the backups")
check(throwsErr { _ = try CoreSetup.readBackups(served + [served[0]], master: master, setupKey: setupKey) }, "a backup served twice is refused")
let nocore = try? CoreSetup.readBackups(dumps["jarvis2-backup-nocore"] ?? [], master: master, setupKey: setupKey)
check(nocore?.map(\.name) == ["default"] && (try? CoreSetup.keysBundle(nocore ?? [], storeKey: master.publicKey)) != nil, "backups without the core store still make a bundle (the token comes later)")

// ---- key backups (keys/<store>/<key>.json, router/storedocs.go) laid over the whole-store ones ----
let keyObjs = dumps["jarvis2-backup-keys"] ?? []
check(keyObjs.count == 6, "the stand-in key backups (\(keyObjs.map(\.key)))")
let merged: [RecoveredStore]
do { merged = try CoreSetup.readBackups(served + keyObjs, master: kitMaster, setupKey: setupKey, boxKey: boxKey) } catch { print("FAIL reading the key backups: \(error)"); exit(1) }
let mDefault = merged.first { $0.name == "default" }
check(mDefault?.values == ["OTHER": "y", "RESTORED": "r1", "SESSION_KEY": "from-a-session"], "a later key backup replaces its key, a deleted one removes it, an older one is ignored (\(mDefault?.values.keys.sorted() ?? []))")
check(mDefault?.sensitive == false, "…and the store keeps its whole-store backup's sensitivity")
check(merged.first { $0.name == "keyed-only" }.map { $0.values == ["API_KEY": "k1"] && $0.sensitive } == true, "a store only key backups name comes back, sensitive")
check(throwsErr { _ = try CoreSetup.readBackups(served + keyObjs, master: kitMaster, setupKey: setupKey) }, "a session-written key backup isn't taken without the box key to check its core")
check(throwsErr { _ = try CoreSetup.readBackups(served + keyObjs, master: kitMaster, setupKey: setupKey, boxKey: setupKey) }, "…nor with a core another key vouched for")
check(throwsErr { _ = try CoreSetup.readBackups(served + keyObjs, master: fresh, setupKey: setupKey, boxKey: boxKey) }, "another master key doesn't open the key backups")
check(throwsErr { _ = try CoreSetup.readBackups(served + keyObjs + [keyObjs[0]], master: kitMaster, setupKey: setupKey, boxKey: boxKey) }, "a key backup served twice is refused")
/// one key backup's JSON, changed
func alter(_ o: CoreSetup.BackupObject, key: String? = nil, _ fn: (inout [String: Any]) -> Void) -> CoreSetup.BackupObject {
  var j = (try? JSONSerialization.jsonObject(with: Data(o.body.utf8))) as? [String: Any] ?? [:]
  fn(&j)
  return CoreSetup.BackupObject(key: key ?? o.key, body: String(decoding: try! JSONSerialization.data(withJSONObject: j), as: UTF8.self))
}
let setupObj = keyObjs.first { $0.key == "keys/default/OTHER.json" }!, machineObj = keyObjs.first { $0.key == "keys/default/SESSION_KEY.json" }!
let restoreObj = keyObjs.first { $0.key == "keys/default/RESTORED.json" }!
check(!throwsErr { _ = try CoreSetup.checkKeyBackup(setupObj, setupKey: setupKey, boxKey: boxKey) } && !throwsErr { _ = try CoreSetup.checkKeyBackup(machineObj, setupKey: setupKey, boxKey: boxKey) },
      "a setup-written and a session-written key backup check")
check(!throwsErr { _ = try CoreSetup.checkKeyBackup(restoreObj, setupKey: setupKey, boxKey: boxKey) }, "…and one a phone-approved restore put back (the core's receipt)")
let refusals: [(String, CoreSetup.BackupObject)] = [
  ("moved to another key", CoreSetup.BackupObject(key: "keys/default/ELSEWHERE.json", body: setupObj.body)),
  ("moved to another store", CoreSetup.BackupObject(key: "keys/gmail/OTHER.json", body: setupObj.body)),
  ("naming another key", alter(setupObj) { $0["key"] = "ELSEWHERE" }),
  ("another sealed value", alter(setupObj) { $0["sealed"] = (try? JSONSerialization.jsonObject(with: Data(machineObj.body.utf8)) as? [String: Any])?["sealed"] }),
  ("its hash changed", alter(setupObj) { $0["backupSha256"] = String(repeating: "0", count: 64) }),
  ("signed by another key", alter(setupObj) { $0["writer"] = ["by": "setup", "sig": (try! P256.Signing.PrivateKey().signature(for: Data("x".utf8))).derRepresentation.base64EncodedString()] }),
  ("a setup writer passed off as a machine", alter(setupObj) { var w = $0["writer"] as! [String: Any]; w["by"] = "machine"; w["cert"] = ((try? JSONSerialization.jsonObject(with: Data(machineObj.body.utf8)) as? [String: Any])?["writer"] as? [String: Any])?["cert"]; $0["writer"] = w }),
  ("a machine cert another core signed", alter(machineObj) { var c = $0["core"] as! [String: Any]; c["signingKey"] = phoneSigningForTests; $0["core"] = c }),
  ("a restore receipt naming another value", alter(restoreObj) { $0["e"] = (try? JSONSerialization.jsonObject(with: Data(setupObj.body.utf8)) as? [String: Any])?["e"] }),
  ("a restore receipt passed off as a delete", alter(restoreObj) { $0["deleted"] = true; $0["sealed"] = NSNull(); $0["e"] = ""; $0["dataSha256"] = ""; $0["backupSha256"] = "" }),
  ("an unknown writer", alter(setupObj) { var w = $0["writer"] as! [String: Any]; w["by"] = "core"; $0["writer"] = w }),
  ("a delete that carries a value", alter(setupObj) { $0["deleted"] = true }),
]
for (what, o) in refusals {
  check(throwsErr { _ = try CoreSetup.checkKeyBackup(o, setupKey: setupKey, boxKey: boxKey) }, "a key backup \(what) is refused")
}
let movedOpen: Bool = {
  // the sealed value of OTHER under SESSION_KEY's name (re-signed would still fail: the associated data is the name)
  do { _ = try CoreCrypto.open((try JSONSerialization.jsonObject(with: Data(setupObj.body.utf8)) as! [String: Any])["sealed"] as! [String: String], with: kitMaster.agreement, info: CoreCrypto.backupInfo, aad: CoreCrypto.keyAAD(store: "default", key: "SESSION_KEY")); return true } catch { return false }
}()
check(!movedOpen, "a key's sealed value doesn't open under another key's name")
let keyChecks = CoreSetup.checkSignatures(served + keyObjs, setupKey: setupKey, boxKey: boxKey)
check(keyChecks.allSatisfy { $0.problem == nil }, "the offline copy checks key backups too (\(keyChecks.filter { $0.problem != nil }.map { "\($0.key): \($0.problem!)" }))")

// ---- the offline copy (Settings → Encrypted backup): checked, never opened; tools/decrypt-backup.py opens the file (ios.yml)
let exportChecks = CoreSetup.checkSignatures(served, setupKey: setupKey)
check(exportChecks.count == served.count && exportChecks.allSatisfy { $0.problem == nil }, "the offline copy: every served object is signed by the setup key")
let tamperedChecks = CoreSetup.checkSignatures(dumps["jarvis2-backup-tampered"] ?? [], setupKey: setupKey)
check(tamperedChecks.filter { $0.problem != nil }.map(\.key) == ["stores/default.json"], "…and names the one that isn't (\(tamperedChecks.filter { $0.problem != nil }.map(\.key)))")
if let s0 = served.first(where: { $0.key.hasPrefix("stores/") }) {
  check(CoreSetup.checkSignatures(served + [s0], setupKey: setupKey).last?.problem == "Comes twice", "…a store served twice")
  let moved = CoreSetup.BackupObject(key: "stores/elsewhere.json", body: s0.body)
  check(CoreSetup.checkSignatures([moved], setupKey: setupKey).first?.problem == "Names another store", "…a backup under another store's key")
}
let exportAt = Date()
let exported = try! CoreSetup.exportFile(bucket: "jarvis2-backup-ci", objects: served, setupKey: setupKey, setupKeySource: "interop", fetchedAt: exportAt)
struct ExportBack: Decodable { let format: String; let version: Int; let bucket: String; let fetchedAt: String; let setupKey: String; let objects: [CoreSetup.BackupObject] }
let back = try? JSONDecoder().decode(ExportBack.self, from: exported)
check(back?.format == "jarvis2-backup-export" && back?.version == 1 && back?.setupKey == setupKey && back?.objects.map { $0.key + $0.body } == served.map { $0.key + $0.body },
      "the file holds the objects exactly as served, with the setup key")
check(CoreSetup.exportName(exportAt).hasPrefix("jarvis2-backup-") && CoreSetup.exportName(exportAt).hasSuffix(".json"), "the file's name (\(CoreSetup.exportName(exportAt)))")
if let out = env["INTEROP_EXPORT_OUT"] { try! exported.write(to: URL(fileURLWithPath: out)) }

// ---- Recover: the claim, signed with the kit's master key ----
let phoneSigning = P256.Signing.PrivateKey(), phoneAgreement = P256.KeyAgreement.PrivateKey()
let phone = PublicKeys(signingKey: phoneSigning.publicKey.x963Representation.base64EncodedString(), agreementKey: phoneAgreement.publicKey.x963Representation.base64EncodedString())
// continuity (core/continuity.go): the core's keys come from the kit's master key — the app derives them, the claim
// names them, and the core becomes that core
let seed = CoreContinuity.seed(kitMaster)
let derived = try! CoreContinuity.keys(seed: seed)
let idJSON = (try? JSONSerialization.jsonObject(with: call("/identity").1)) as? [String: Any]
check(idJSON?["continuity"] as? Int == 1, "the core's identity says it takes a seed (continuity \(idJSON?["continuity"] ?? "none"))")
check(derived != coreKeys && PublicKeys.valid(derived), "the kit derives valid core keys, not the empty core's boot keys")
check((try? CoreContinuity.keys(seed: CoreContinuity.seed(kitMaster))) == derived && (try? CoreContinuity.keys(seed: CoreContinuity.seed(fresh))) != derived,
      "the same kit derives the same keys, another kit others")
// R2: the app wraps every store itself to the core's signed store key (P + K), so the core never sees their plaintext;
// with a seed, K is the derived core's (the empty core adds the point the app names)
let (sks, skd) = call("/store-key", ["phone": phone.agreementKey, "core": derived.agreementKey])
let recoverStoreKey = (try? CoreCrypto.storeKey(doc(skd), coreKey: coreKeys.signingKey, phone: phone.agreementKey, core: derived.agreementKey)) ?? ""
check(sks == 200 && !recoverStoreKey.isEmpty, "an empty core signs the store key for this phone and the derived core (HTTP \(sks))")
check(throwsErr { _ = try CoreCrypto.storeKey(doc(skd), coreKey: coreKeys.signingKey, phone: coreKeys.agreementKey) }, "…and the app refuses one for another phone")
check(throwsErr { _ = try CoreCrypto.storeKey(doc(call("/store-key", ["phone": phone.agreementKey]).1), coreKey: coreKeys.signingKey, phone: phone.agreementKey, core: derived.agreementKey) },
      "…and one for the boot core's K when it asked for the derived one")
check(idJSON?["bundle"] as? String == "keys", "the core's identity says it takes stores of keys (bundle \(idJSON?["bundle"] ?? "none"))")
let bundle = try! CoreSetup.keysBundle(merged, storeKey: recoverStoreKey, coreSeed: seed)
let bundleText = String(decoding: bundle, as: UTF8.self)
check(!bundleText.contains("FLY_API_TOKEN") && !bundleText.contains("from-a-session") && bundleText.contains(#""format":"keys""#), "the keys bundle carries no value in the clear (the Fly token goes as flyToken)")
func claim(_ body: [String: Any]) -> (Int, Data) { call("/claim", body) }
var bad = try! CoreSetup.claim(core: coreKeys, phone: phone, master: kitMaster, bundle: bundle, identity: derived)
bad["masterSig"] = try! fresh.sign(bad["statement"] as! String)
check(claim(bad).0 == 403, "a claim signed by another key than the master key it names is refused")
bad = try! CoreSetup.claim(core: phone, phone: phone, master: kitMaster, bundle: bundle, identity: derived)
bad["bundle"] = try! CoreCrypto.seal(bundle, to: coreKeys.agreementKey, info: CoreCrypto.claimInfo)
check(claim(bad).0 == 403, "a claim naming another core is refused")
bad = try! CoreSetup.claim(core: coreKeys, phone: phone, master: kitMaster, bundle: bundle, identity: derived)
bad["bundle"] = try! CoreCrypto.seal(bundle + Data(" ".utf8), to: coreKeys.agreementKey, info: CoreCrypto.claimInfo)
check(claim(bad).0 == 403, "a bundle other than the signed one is refused")
check(claim(try! CoreSetup.claim(core: coreKeys, phone: phone, master: kitMaster, bundle: bundle, identity: PublicKeys(signingKey: derived.signingKey, agreementKey: phone.agreementKey))).0 == 403,
      "a claim whose identity isn't what its seed derives is refused")
check(claim(try! CoreSetup.claim(core: coreKeys, phone: phone, master: kitMaster, bundle: bundle)).0 == 403, "…and a seed with no identity")
check(call("/wipe", try! CoreSetup.wipe(core: coreKeys, master: kitMaster)).0 == 200, "an empty core's wipe is answered (it already is empty; nothing ends)")
let (rs, rb) = claim(try! CoreSetup.claim(core: coreKeys, phone: phone, master: kitMaster, bundle: bundle, identity: derived))
check(rs == 200, "the core is set up (HTTP \(rs) \(String(decoding: rb.prefix(200), as: UTF8.self)))")
// the answer comes from the core the seed made (signed with the derived key)
let rec = try? CoreCrypto.decode(doc(rb), by: derived.signingKey, as: KindDoc.self, what: "claimed")
check(rec?.kind == "claimed" && rec?.stores == 6, "the answer is the core's signed 'claimed' (6 stores, the core's own excluded)")
check(claim(try! CoreSetup.claim(core: coreKeys, phone: phone, master: kitMaster, bundle: bundle, identity: derived)).0 == 409, "a second claim is refused")
check(claim(try! CoreSetup.claim(core: coreKeys, phone: phone, master: fresh, bundle: try! CoreSetup.keysBundle([], storeKey: recoverStoreKey))).0 == 409, "…and a Reset's claim with a new key too")
let after1 = try? CoreSetup.check(identity(), boxKey: boxKey), after2 = try? CoreSetup.check(identity(), boxKey: boxKey)
check(after1?.keys == derived && after2?.keys == derived, "the core now answers with the derived keys, vouched for by the box key (twice: \(after1?.keys.signingKey.prefix(12) ?? "none")…)")
check(after1?.state.derived == true && (after1?.state.lineSeq ?? 0) >= 1, "…its state says its keys are derived and names its record of the sessions (\(after1?.state.lineSeq ?? 0))")
let st1 = after1?.state
check(st1 != nil && CoreSetup.status(st1!, myMaster: kitMaster.publicKey, myPhone: phone) == .mine, "the core's state now names this master key and this phone (mine)")
check(st1 != nil && CoreSetup.status(st1!, myMaster: fresh.publicKey, myPhone: phone) == .foreign, "…a phone with another master key sees it as foreign")
check(st1 != nil && CoreSetup.status(st1!, myMaster: kitMaster.publicKey, myPhone: PublicKeys(signingKey: phone.agreementKey, agreementKey: phone.signingKey)) == .otherPhone, "…and another phone with the same kit as set up for another iPhone")
check(st1 != nil && CoreSetup.status(st1!, myMaster: nil, myPhone: phone) == .foreign, "…and a phone with no master key as foreign")

let coreKey = derived.signingKey

// ---- stores (signed, with the caller's nonce) ----
func list() -> [StoreView] {
  let n = CoreCrypto.nonce()
  let d = try! CoreCrypto.decode(doc(call("/stores", ["nonce": n]).1), by: coreKey, as: StoresDoc.self, what: "stores")
  check(d.kind == "stores" && d.nonce == n, "store list is signed and carries my nonce")
  return d.stores
}
var l = list()
check(l.map(\.name) == ["claude-login", "default", "github-deploy-keys", "gmail", "keyed-only", "marked"], "the core lists every store but its own")
check(l.filter(\.sensitive).map(\.name) == ["github-deploy-keys", "gmail", "keyed-only", "marked"], "sensitivity in the core's list")
check(throwsErr { _ = try CoreCrypto.verified(SignedDoc(payload: "{}", sig: doc(call("/stores", ["nonce": "x"]).1).sig), by: coreKey, what: "x") }, "an altered payload is refused")
check(call("/stores/create", ["name": "notes"]).0 == 200, "create a store")
check(call("/stores/create", ["name": "notes"]).0 == 409, "…once")
l = list()
check(l.first { $0.name == "notes" }.map { !$0.sensitive && $0.empty } == true, "a created store is empty and not sensitive")
let mk = try? CoreCrypto.decode(doc(call("/stores/mark-sensitive", ["name": "notes"]).1), by: coreKey, as: KindDoc.self, what: "mark")
check(mk?.kind == "marked-sensitive" && mk?.name == "notes", "mark sensitive")
let mk2 = try? CoreCrypto.decode(doc(call("/stores/mark-sensitive", ["name": "notes"]).1), by: coreKey, as: KindDoc.self, what: "mark again")
check(mk2?.kind == "marked-sensitive" && list().first { $0.name == "notes" }?.sensitive == true, "…a second mark is answered, still sensitive (one way)")

// ---- split-key unlock: one share per key, each key's writer checked ----
func begin(_ store: String, for f: String? = nil) -> (Int, UnlockBegin?) {
  var body: [String: Any] = ["store": store]
  if let f { body["for"] = f }
  let (s, d) = call("/unlock/begin", body)
  return (s, s == 200 ? try? CoreCrypto.decode(doc(d), by: coreKey, as: UnlockBegin.self, what: "unlock-begin") : nil)
}
func shareOf(_ e: String) -> Data {
  try! phoneAgreement.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: Data(base64Encoded: e)!)).withUnsafeBytes { Data($0) }
}
/// unlock_finish as RouterClient.unlockFinish sends it: {pending, shares: {KEY: share sealed to T}}
func finish(_ b: UnlockBegin, share: (String) -> Data = shareOf) -> (Int, Data) {
  var m: [String: Any] = [:]
  for k in b.keys { m[k.key] = try! CoreCrypto.sealShare(share(k.e), to: b.t) }
  return call("/unlock/finish", ["pending": b.pending, "shares": m])
}
func unlock(_ store: String, share: @escaping (String) -> Data = shareOf) -> (Int, Data) {
  let (s, b) = begin(store)
  guard let b else { return (s, Data()) }
  check(b.kind == "unlock-begin" && b.store == store && !b.keys.isEmpty, "unlock-begin for \(store) is signed and names its keys (\(b.keys.map(\.key)))")
  return finish(b, share: share)
}
let (dbs, db) = begin("default")
check(dbs == 200 && db?.keys.map(\.key) == ["OTHER", "RESTORED", "SESSION_KEY"] && db?.keys.allSatisfy { $0.writer.by == "core" } == true && db?.version?.isEmpty == false,
      "a recovered store's keys are the core's to vouch for (\(db?.keys.map { "\($0.key):\($0.writer.by)" } ?? []))")
check(db.map { x in !throwsErr { try Checks.unlockKeys(x, setupKey: setupKey) } } == true, "…and the app takes them")
let (us, ub) = db.map { finish($0) } ?? (0, Data())
check(us == 200, "the core opens every key of the recovered store with the phone's sealed shares (HTTP \(us) \(String(decoding: ub.prefix(160), as: UTF8.self)))")
let u = try? CoreCrypto.decode(doc(ub), by: coreKey, as: KindDoc.self, what: "unlocked")
check(u?.kind == "unlocked" && u?.store == "default", "unlocked answer is signed")
check(unlock("gmail") { _ in Data((0..<32).map { _ in UInt8.random(in: 0...255) }) }.0 != 200, "a wrong share doesn't open a store")
check(begin("notes").0 == 404, "an empty store can't be unlocked")
if let gb = begin("gmail").1 {
  check(call("/unlock/finish", ["pending": gb.pending, "shares": [String: Any]()]).0 == 400, "an unlock without a share for each key is refused")
}

// a key written as the setup session through the router (infra/setup.py write): the backup first, then the core; the
// phone checks the setup key's signature over the writer text before it gives its share
let sk0 = recoverStoreKey
func setupWrite(_ store: String, _ key: String, _ value: String, signer: P256.Signing.PrivateKey = setupSigner) -> [String: Any] {
  let x = try! CoreCrypto.wrapKey(store: store, key: key, value: Data(value.utf8), storeKey: sk0)
  let bk = try! CoreCrypto.seal(Data(value.utf8), to: kitMaster.publicKey, info: CoreCrypto.backupInfo, aad: CoreCrypto.keyAAD(store: store, key: key))
  let bsha = CoreCrypto.sha256hex(Data("\(bk["e"]!)\n\(bk["data"]!)".utf8))
  let text = Checks.writerText(store: store, key: key, e: x.wrapped.e, dataSha256: CoreCrypto.sha256hex(Data(x.data.utf8)), backupSha256: bsha)
  return ["wrapped": ["e": x.wrapped.e, "wrapped": x.wrapped.wrapped], "data": x.data, "backup": bk, "backupSha256": bsha,
          "sig": try! signer.signature(for: Data(text.utf8)).derRepresentation.base64EncodedString(), "explanation": "what \(key) is for"]
}
let rbaseW = need("INTEROP_ROUTER")
let (ws0, wd0) = call("/setup/stores/default/keys/WRITTEN", setupWrite("default", "WRITTEN", "w1"), base: rbaseW)
check(ws0 == 200, "the setup session writes one key through the router (HTTP \(ws0) \(String(decoding: wd0.prefix(200), as: UTF8.self)))")
let (wbs, wb) = begin("default")
let wk = wb?.keys.first { $0.key == "WRITTEN" }
check(wbs == 200 && wk?.writer.by == "setup" && wk?.writer.sig != nil && wk?.backupSha256.count == 64 && wb?.keys.count == 4,
      "unlock-begin names the written key, its setup writer with the signature and its backup hash")
check(wb.map { x in !throwsErr { try Checks.unlockKeys(x, setupKey: setupKey) } } == true, "…the app checks the setup key's signature over it")
check(wb.map { x in throwsErr { try Checks.unlockKeys(x, setupKey: phoneSigningForTests) } } == true, "…and refuses it against another key")
check(wb.map { finish($0).0 } == 200, "…and the store opens with it")
struct ServedRows: Decodable { struct R: Decodable { let name: String; let about: String?; let keyInfo: [K]?; let keysFrom: String? }; struct K: Decodable { let name: String; let explanation: String?; let writer: W? }; struct W: Decodable { let by: String }; let stores: [R] }
let rows = try? JSONDecoder().decode(ServedRows.self, from: call("/api/stores", base: rbaseW).1)
let rdef = rows?.stores.first { $0.name == "default" }
check(rdef?.keysFrom == "core" && rdef?.keyInfo?.first { $0.name == "WRITTEN" }.map { $0.explanation == "what WRITTEN is for" && $0.writer?.by == "setup" } == true,
      "GET /api/stores lists the key with its explanation and writer")
let docsStatus = call("/api/stores/default/docs", ["about": "everyday keys", "keys": ["WRITTEN": "", "OTHER": "the other one"]], base: rbaseW, method: "PUT").0
let rdef2 = (try? JSONDecoder().decode(ServedRows.self, from: call("/api/stores", base: rbaseW).1))?.stores.first { $0.name == "default" }
check(docsStatus == 200 && rdef2?.about == "everyday keys" && rdef2?.keyInfo?.first { $0.name == "OTHER" }?.explanation == "the other one"
      && (rdef2?.keyInfo?.first { $0.name == "WRITTEN" }?.explanation ?? "") == "", "PUT /api/stores/{store}/docs sets the about text and an explanation; \"\" removes one")
// its backup is in the bucket, and a Recover would lay it over the store
struct ServedAgain: Decodable { let objects: [CoreSetup.BackupObject] }
let servedNow = (try? JSONDecoder().decode(ServedAgain.self, from: call("/api/backups", base: rbaseW).1))?.objects ?? []
let wObj = servedNow.first { $0.key == "keys/default/WRITTEN.json" }
check(wObj.map { x in !throwsErr { _ = try CoreSetup.checkKeyBackup(x, setupKey: setupKey, boxKey: boxKey) } } == true, "the router wrote the key's backup first (keys/default/WRITTEN.json) and it checks")
check((try? CoreSetup.readBackups(servedNow, master: kitMaster, setupKey: setupKey, boxKey: boxKey))?.first { $0.name == "default" }?.values["WRITTEN"] == "w1",
      "…and opens with the kit, laid over the store's whole-store backup")
// the record of the sessions (core/continuity.go): the router keeps the newest (fetched when the write above came back with a higher X-Line-Seq); the app checks it before a Recover
let (lss, lsd) = call("/api/core/line-state", base: need("INTEROP_ROUTER"))
let lsDoc: CoreSetup.LineStateDoc? = lss == 200 ? (try? JSONDecoder().decode(CoreSetup.LineStateDoc.self, from: lsd)) : nil
check(lsDoc.map { d in (try? CoreSetup.checkLineState(d, coreKey: coreKey, atLeast: 1)) != nil } == true, "the router serves the core's record of the sessions, signed by the derived key (HTTP \(lss))")
check(lsDoc.map { d in throwsErr { _ = try CoreSetup.checkLineState(d, coreKey: coreKey, atLeast: 1_000_000) } } == true, "…and the app refuses one older than it saw")
check(lsDoc.map { d in throwsErr { _ = try CoreSetup.checkLineState(CoreSetup.LineStateDoc(head: d.head, sealed: Data("x".utf8).base64EncodedString()), coreKey: coreKey, atLeast: 0) } } == true, "…or one that isn't what its head names")
check(lsDoc.map { d in throwsErr { _ = try CoreSetup.checkLineState(d, coreKey: coreKeys.signingKey, atLeast: 0) } } == true, "…or one another core signed")
check(lsDoc.map { d in !CoreSetup.lineStateSigned(d, coreKey: coreKeys.signingKey) && CoreSetup.lineStateSigned(d, coreKey: coreKey) } == true, "…and the Recover takes one another core signed as none")

// ---- restore: a store put back to an earlier version (core/history.go, router/storerestore.go): the phone signs the
// core's begin document and shares the keys put back; no kit. The core's backups (writer "restore") check at Recover.
func setupDelete(_ store: String, _ key: String) -> [String: Any] {
  let text = Checks.writerText(store: store, key: key, e: "", dataSha256: "", backupSha256: "")
  return ["delete": true, "sig": try! setupSigner.signature(for: Data(text.utf8)).derRepresentation.base64EncodedString()]
}
func versionsOf(_ store: String) -> StoreVersionsDoc? {
  try? CoreCrypto.decode(doc(call("/api/core/stores/versions", ["store": store, "nonce": "n-v"], base: rbaseW).1), by: coreKey, as: StoreVersionsDoc.self, what: "versions")
}
func restoreBeginDoc(_ store: String, _ seq: Int) -> (SignedDoc, RestoreBegin?) {
  let (s, d) = call("/api/core/stores/restore/begin", ["store": store, "seq": seq], base: rbaseW)
  guard s == 200 else { return (SignedDoc(payload: "", sig: ""), nil) }
  let sd = doc(d)
  return (sd, try? CoreCrypto.decode(sd, by: coreKey, as: RestoreBegin.self, what: "restore begin"))
}
func restoreFinish(_ b: RestoreBegin, _ d: SignedDoc, signer: P256.Signing.PrivateKey) -> (Int, Data) {
  var m: [String: Any] = [:]
  for p in b.put { m[p.key] = try! CoreCrypto.sealShare(shareOf(p.e), to: b.t) }
  return call("/api/stores/restore/finish", ["pending": b.pending, "signature": try! signer.signature(for: Data(d.payload.utf8)).derRepresentation.base64EncodedString(),
                                             "shares": m], base: rbaseW)
}
let v0 = versionsOf("default"), withWritten = v0?.versions.first
check(withWritten?.cause.kind == "write" && withWritten?.cause.key == "WRITTEN" && withWritten?.version == v0?.current && (v0?.versions.count ?? 0) >= 2,
      "the core's signed versions of a store, newest first (the write of WRITTEN is current)")
let wseq = withWritten?.seq ?? 0
check(call("/setup/stores/default/keys/WRITTEN", setupDelete("default", "WRITTEN"), base: rbaseW).0 == 200, "WRITTEN deleted as the setup session")
var (rsdoc, rsb) = restoreBeginDoc("default", wseq)
check(rsb?.put.map(\.key) == ["WRITTEN"] && rsb?.remove == [] && rsb?.put.first?.writer.by == "setup"
      && rsb.map { x in !throwsErr { try Checks.restoreBegin(x, store: "default", seq: wseq, setupKey: setupKey) } } == true,
      "restore-begin names exactly the key put back; the app checks its setup writer")
check(rsb.map { x in throwsErr { try Checks.restoreBegin(x, store: "default", seq: wseq, setupKey: phoneSigningForTests) } } == true, "…and refuses it against another setup key")
check(rsb.map { x in throwsErr { try Checks.restoreBegin(x, store: "default", seq: wseq + 1, setupKey: setupKey) } } == true, "…and a begin for another version")
check(rsb.map { restoreFinish($0, rsdoc, signer: P256.Signing.PrivateKey()).0 } != 200, "a restore signed by another key is refused")
check(rsb.map { restoreFinish($0, rsdoc, signer: phoneSigning).0 } != 200, "…and its begin is spent")
check(begin("default").1?.keys.contains { $0.key == "WRITTEN" } == false, "…so nothing was restored")
(rsdoc, rsb) = restoreBeginDoc("default", wseq)
let (rfs, rfd) = rsb.map { restoreFinish($0, rsdoc, signer: phoneSigning) } ?? (0, Data())
struct RestoredOut: Decodable { let restored: SignedDoc }
let rdone = (try? JSONDecoder().decode(RestoredOut.self, from: rfd)).flatMap { try? CoreCrypto.decode($0.restored, by: coreKey, as: RestoreDone.self, what: "restored") }
check(rfs == 200 && rdone != nil && rsb.map { x in !throwsErr { try Checks.restoreDone(rdone!, begin: x) } } == true,
      "the phone's signature and shares put the version back; the committed answer is this restore's (HTTP \(rfs) \(String(decoding: rfd.prefix(160), as: UTF8.self)))")
check(versionsOf("default")?.current == withWritten?.version && versionsOf("default")?.versions.first?.cause.kind == "restore", "…the store is that version again, as a new version")
let (rws, rwb) = begin("default")
check(rws == 200 && rwb?.keys.first { $0.key == "WRITTEN" }?.writer.by == "setup" && rwb.map { finish($0).0 } == 200, "…WRITTEN is back with its own writer, and the store opens")
let servedRestored = (try? JSONDecoder().decode(ServedAgain.self, from: call("/api/backups", base: rbaseW).1))?.objects ?? []
let rsObj = servedRestored.first { $0.key == "keys/default/WRITTEN.json" }
check(rsObj.map { x in !throwsErr { _ = try CoreSetup.checkKeyBackup(x, setupKey: setupKey, boxKey: boxKey) } } == true && rsObj?.body.contains("\"restore\"") == true,
      "the router wrote the core's backup of WRITTEN (writer restore) and the app checks it")
check((try? CoreSetup.readBackups(servedRestored, master: kitMaster, setupKey: setupKey, boxKey: boxKey))?.first { $0.name == "default" }?.values["WRITTEN"] == "w1",
      "…and a Recover brings WRITTEN back with the kit")
if let rsObj {
  check(throwsErr { _ = try CoreSetup.checkKeyBackup(rsObj, setupKey: setupKey, boxKey: setupKey) }, "…not with a core another key vouched for")
  check(throwsErr { _ = try CoreSetup.checkKeyBackup(alter(rsObj) { $0["backupSha256"] = String(repeating: "0", count: 64) }, setupKey: setupKey, boxKey: boxKey) },
        "…nor with another value than its receipt names")
  check(throwsErr { _ = try CoreSetup.checkKeyBackup(alter(rsObj, key: "keys/default/OTHER.json") { $0["key"] = "OTHER" }, setupKey: setupKey, boxKey: boxKey) },
        "…nor moved to a key its receipt doesn't put back")
}

// a key sealed under another name (store or key) doesn't decrypt: the core refuses the whole unlock
func coreWrite(_ store: String, _ key: String, sealedAs: (String, String), signer: P256.Signing.PrivateKey = setupSigner) -> Int {
  let x = try! CoreCrypto.wrapKey(store: sealedAs.0, key: sealedAs.1, value: Data("v".utf8), storeKey: sk0)
  let text = Checks.writerText(store: store, key: key, e: x.wrapped.e, dataSha256: CoreCrypto.sha256hex(Data(x.data.utf8)), backupSha256: "")
  return call("/stores/write-key", ["store": store, "key": key, "wrapped": ["e": x.wrapped.e, "wrapped": x.wrapped.wrapped], "data": x.data,
                                    "writer": "setup", "sig": try! signer.signature(for: Data(text.utf8)).derRepresentation.base64EncodedString()]).0
}
check(coreWrite("moved", "A", sealedAs: ("moved", "B")) == 200 && unlock("moved").0 == 403, "a key sealed under another key's name doesn't decrypt")
check(coreWrite("moved2", "A", sealedAs: ("default", "A")) == 200 && unlock("moved2").0 == 403, "…nor one sealed under another store's name")
check(coreWrite("forged", "A", sealedAs: ("forged", "A"), signer: P256.Signing.PrivateKey()) == 200, "the core passes on a setup writer's signature unchecked")
check(begin("forged").1.map { x in throwsErr { try Checks.unlockKeys(x, setupKey: setupKey) } } == true, "…and the app refuses a key the setup key didn't sign")

// the router writes a Claude account's store (unsigned, named "router"), and nothing else (DECISIONS 190)
func routerWrite(_ store: String) -> Int {
  let x = try! CoreCrypto.wrapKey(store: store, key: "CLAUDE_CREDENTIALS", value: Data("{}".utf8), storeKey: sk0)
  return call("/stores/write-key", ["store": store, "key": "CLAUDE_CREDENTIALS", "wrapped": ["e": x.wrapped.e, "wrapped": x.wrapped.wrapped], "data": x.data, "writer": "router"]).0
}
check(routerWrite("claude-interop") == 200, "the router writes a Claude account store")
let (routerBeginStatus, routerBegin) = begin("claude-interop")
check(routerBeginStatus == 200 && routerBegin?.keys.first?.writer.by == "router" && routerBegin.map { x in !throwsErr { try Checks.unlockKeys(x, setupKey: setupKey) } } == true,
      "…the unlock names the router as its writer, and the app takes it")
check(routerWrite("default") == 403, "…and the core refuses the router any other store")
check(throwsErr { try Checks.keyWriter(StoreWriter(by: "router"), store: "default", key: "K", e: "", dataSha256: "", backupSha256: "", setupKey: nil) },
      "…as does the app")

// a key a session's machine wrote: shown on the page or refused before Face ID (the core checked the machine itself)
func synthetic(_ w: StoreWriter, key: String = "S") -> UnlockBegin {
  UnlockBegin(kind: "unlock-begin", pending: "p", store: "default", t: "", forNonce: nil,
              keys: [KeyBegin(key: key, e: "E", writer: w, dataSha256: "d")])
}
let mb = synthetic(StoreWriter(by: "machine", machine: "fake000042", line: "fake000042"))
check(!throwsErr { try Checks.unlockKeys(mb, setupKey: nil) }, "a key a session's machine wrote is taken (the core checked its signature)…")
check(Checks.unseen([mb], shown: []) == [SessionWrite(store: "default", key: "S", line: "fake000042")], "…but one the page didn't show is refused")
check(Checks.unseen([mb], shown: [SessionWrite(store: "default", key: "S", line: "fake000042", label: "T")]).isEmpty, "…and one it showed goes through")
check(!Checks.unseen([mb], shown: [SessionWrite(store: "default", key: "S", line: "other-line")]).isEmpty, "…not when the page named another session")
check(throwsErr { try Checks.unlockKeys(synthetic(StoreWriter(by: "machine")), setupKey: nil) }, "a machine writer the core doesn't name is refused")
check(throwsErr { try Checks.unlockKeys(synthetic(StoreWriter(by: "router")), setupKey: nil) }, "an unknown writer is refused")
check(throwsErr { try Checks.unlockKeys(UnlockBegin(kind: "unlock-begin", pending: "p", store: "x", t: "", forNonce: nil, keys: []), setupKey: nil) }, "an unlock of no keys is refused")

let n2 = CoreCrypto.nonce()
let ul = try? CoreCrypto.decode(doc(call("/unlocked", ["nonce": n2]).1), by: coreKey, as: UnlockedDoc.self, what: "unlocked list")
check(ul?.nonce == n2 && ul?.unlocked.allSatisfy({ $0.store == "default" }) == true && ul?.unlocked.contains { $0.id == u?.id } == true, "unlocked list is signed, fresh and complete")

// ---- an unlock for one session (a Start's challenge, a waiting session's cert): signed with what it is for, read
// only by that cert's pull, never shown as open to every session ----
let sdoc = try! CoreCrypto.decode(doc(call("/stores", ["nonce": CoreCrypto.nonce()]).1), by: coreKey, as: StoresDoc.self, what: "stores")
check(sdoc.kind == "stores", "the core's signed store list")
let forN = String(repeating: "ab", count: 32)
let sb = begin("gmail", for: forN).1!
check(sb.kind == "unlock-begin" && sb.forNonce == forN, "unlock-begin names the one session it is for (signed)")
let (ss, sd) = finish(sb)
let su = try? CoreCrypto.decode(doc(sd), by: coreKey, as: KindDoc.self, what: "unlocked")
check(ss == 200 && su?.kind == "unlocked", "the core opens it for that session")
check(list().first { $0.name == "gmail" }?.unlocked == false, "…and the store list doesn't show it as open to every session")
let ul2 = try? CoreCrypto.decode(doc(call("/unlocked", ["nonce": CoreCrypto.nonce()]).1), by: coreKey, as: UnlockedDoc.self, what: "unlocked list")
check(ul2?.unlocked.first { $0.id == su?.id }?.forNonce == forN && ul2?.unlocked.first { $0.id == u?.id }.map { ($0.forNonce ?? "").isEmpty } == true, "the unlocked list says which unlock is for one session and which is standing")
let slk = try? CoreCrypto.decode(doc(call("/lock", ["id": su?.id ?? ""]).1), by: coreKey, as: KindDoc.self, what: "locked")
check(slk?.kind == "locked", "an unlock for one session can be locked by hand too")
check(SignedAction.value(SignedAction.unlock(stores: ["gmail"], session: nil, scoped: true), "unlock-scope") == "This session only", "the review page says the unlock is for this session only")

// ---- approvals: the challenge before any machine ----
/// as the router asks: a new line carries its random salt (the core takes exact values, no defaults)
func challenge(_ body: [String: Any]) -> SignedDoc {
  var body = body
  if body["predecessor"] is NSNull { body["salt"] = CoreCrypto.nonce() }
  let (s, d) = call("/succession", body)
  if s != 200 { print("succession HTTP \(s): \(String(decoding: d, as: UTF8.self))") }
  return doc(d)
}
/// current: an add-store's answer continues the machine's newest cert, which the caller (the router) sends beside it
func approve(_ ch: SignedDoc, current: SignedDoc? = nil) -> (Int, SignedDoc?) {
  let sig = try! phoneSigning.signature(for: Data(ch.payload.utf8)).derRepresentation.base64EncodedString()
  var body: [String: Any] = ["challenge": docJSON(ch), "signature": sig]
  if let current { body["current"] = docJSON(current) }
  let (s, d) = call("/approve/by-phone", body)
  return (s, s == 200 ? doc(d) : nil)
}
struct StartedDoc: Codable { let kind: String; let machine: StartedMachine }
struct CreatedDoc: Codable { let kind: String; let id: String }
/// start = one Fly create, then init reads the machine's keys (the router retries init; the fake Fly is up at once)
func start(_ image: String) -> (machine: StartedMachine, started: SignedDoc) {
  let created = try! CoreCrypto.decode(doc(call("/start", ["image": image, "region": "lhr", "size": "small"]).1), by: coreKey, as: CreatedDoc.self, what: "start")
  let d = doc(call("/init", ["machine": created.id]).1)
  return (try! CoreCrypto.decode(d, by: coreKey, as: StartedDoc.self, what: "init").machine, d)
}

// the core starts only the session image pinned by digest (core/vouch.go)
let img = "ghcr.io/de0ch/jarvis4-session:1@sha256:" + String(repeating: "1", count: 64)
let img2 = "ghcr.io/de0ch/jarvis4-session:2@sha256:" + String(repeating: "2", count: 64)

// a core that vouches for inputs carries the session's settings in the challenge; the page checks them and refuses
// a key it can't show
let conf = #"{"v":1,"label":"T","prompt":"do it","repos":["https://github.com/DE0CH/claude-env.git"],"oneShot":true}"#
let chC = challenge(["predecessor": NSNull(), "stores": ["default"], "options": ["harness": "claude", "permissionMode": "auto", "config": conf], "image": img])
let rC = try! Checks.review(challenge: chC, coreKey: coreKey)
check((rC.config?["prompt"] as? String) == "do it", "the signed settings are read from the challenge")
let picked = Checks.Settings(label: "T", prompt: "do it", model: "", repos: ["https://github.com/DE0CH/claude-env.git"], oneShot: true, apiProxy: false)
check(!throwsErr { try Checks.matchesSettings(rC, picked) }, "the settings match what the page chose")
var other = picked; other.prompt = "exfiltrate"
check(throwsErr { try Checks.matchesSettings(rC, other) }, "refused when the signed prompt isn't the page's")
other = picked; other.repos = []
check(throwsErr { try Checks.matchesSettings(rC, other) }, "refused when the signed repos aren't the page's")
check(SignedAction.value(SignedAction.approval(rC), "prompt") == "do it" && SignedAction.value(SignedAction.approval(rC), "title") == "T", "what you sign shows the settings word for word")
// attachments: exactly the files this phone uploaded, by the hash and size of its own bytes, in order
let hA = String(repeating: "a", count: 64), hB = String(repeating: "b", count: 64)
let confA = #"{"v":1,"prompt":"look","attachments":[{"name":"photo.jpg","sha256":"\#(hA)","size":3},{"name":"b.png","sha256":"\#(hB)","size":5}]}"#
let rA = try! Checks.review(challenge: challenge(["predecessor": NSNull(), "stores": ["default"], "options": ["harness": "claude", "permissionMode": "auto", "config": confA], "image": img]), coreKey: coreKey)
var pickedA = Checks.Settings(label: "", prompt: "look", model: "", repos: [], oneShot: false, apiProxy: false,
                              attachments: [.init(name: "photo.jpg", sha256: hA, size: 3), .init(name: "b.png", sha256: hB, size: 5)])
check(!throwsErr { try Checks.matchesSettings(rA, pickedA) }, "the signed attachments are the ones this phone uploaded")
check(Checks.attachments(rA.config ?? [:]) == pickedA.attachments, "the approval page reads the signed attachments")
pickedA.attachments[0].sha256 = hB
check(throwsErr { try Checks.matchesSettings(rA, pickedA) }, "refused when a signed hash isn't of this phone's bytes")
pickedA.attachments = [pickedA.attachments[1]]
check(throwsErr { try Checks.matchesSettings(rA, pickedA) }, "refused when the router added an attachment")
check(throwsErr { try Checks.matchesSettings(rC, Checks.Settings(label: "T", prompt: "do it", model: "", repos: ["https://github.com/DE0CH/claude-env.git"], oneShot: true, apiProxy: false, attachments: [.init(name: "x.png", sha256: hA, size: 1)])) },
      "refused when the router dropped the attachments")
let chBadA = challenge(["predecessor": NSNull(), "stores": ["default"], "options": ["harness": "claude", "permissionMode": "auto", "config": #"{"v":1,"attachments":[{"name":"x.png","sha256":"\#(hA)","size":1,"path":"/etc"}]}"#], "image": img])
check(throwsErr { _ = try Checks.review(challenge: chBadA, coreKey: coreKey) }, "an attachment with a field the app can't show is refused")
// content stores (router/content.go): exactly the ones the page picked, shown as signed
let confK = #"{"v":1,"prompt":"p","content":["notes","proton-email"]}"#
let rK = try! Checks.review(challenge: challenge(["predecessor": NSNull(), "stores": ["default"], "options": ["harness": "claude", "permissionMode": "auto", "config": confK], "image": img]), coreKey: coreKey)
let pickedK = Checks.Settings(label: "", prompt: "p", model: "", repos: [], oneShot: false, apiProxy: false, content: ["proton-email", "notes"])
check(!throwsErr { try Checks.matchesSettings(rK, pickedK) }, "the signed content stores are the ones the page picked")
check(SignedAction.value(SignedAction.approval(rK), "content") == "notes\nproton-email", "what you sign lists the content stores")
var otherK = pickedK; otherK.content = ["notes"]
check(throwsErr { try Checks.matchesSettings(rK, otherK) }, "refused when the router added a content store")
check(throwsErr { try Checks.matchesSettings(rC, pickedK) }, "refused when the router dropped the content stores")
let chBadK = challenge(["predecessor": NSNull(), "stores": ["default"], "options": ["harness": "claude", "permissionMode": "auto", "config": #"{"v":1,"content":["../etc"]}"#], "image": img])
check(throwsErr { _ = try Checks.review(challenge: chBadK, coreKey: coreKey) }, "a content store name the app can't show is refused")
let chX = challenge(["predecessor": NSNull(), "stores": ["default"], "options": ["harness": "claude", "permissionMode": "auto", "config": #"{"v":1,"evil":"x"}"#], "image": img])
check(throwsErr { _ = try Checks.review(challenge: chX, coreKey: coreKey) }, "a setting the app can't show is refused")

// new session
let ch1 = challenge(["predecessor": NSNull(), "stores": ["claude-login", "default"], "options": ["harness": "claude", "permissionMode": "bypass"], "image": img])
let r1 = try! Checks.review(challenge: ch1, coreKey: coreKey)
check(r1.kind == .newSession && r1.stores == ["claude-login", "default"] && r1.harness == "claude" && r1.image == img, "new-session challenge read from its own fields")
check(r1.permissionMode == "bypass", "the permission mode is read from the signed challenge (\(r1.permissionMode))")
check(!throwsErr { try Checks.matchesPicked(r1, stores: ["default"], harnessStores: ["claude-login"], harness: "claude", permissionMode: "bypass") }, "matches what was picked plus the harness's store")
check(throwsErr { try Checks.matchesPicked(r1, stores: ["default", "gmail"], harnessStores: ["claude-login"], harness: "claude", permissionMode: "bypass") }, "refused when the stores differ")
check(throwsErr { try Checks.matchesPicked(r1, stores: ["default"], harnessStores: ["claude-login"], harness: "opencode", permissionMode: "bypass") }, "refused when the harness differs")
check(throwsErr { try Checks.matchesPicked(r1, stores: ["default"], harnessStores: ["claude-login"], harness: "claude", permissionMode: "auto") }, "refused when the permission mode differs")
check(call("/succession", ["predecessor": NSNull(), "stores": ["default"], "options": ["harness": "claude"], "image": img, "salt": CoreCrypto.nonce()]).0 == 400, "the core refuses a request without a mode (the router fills it in)")
check(throwsErr { _ = try Checks.review(challenge: SignedDoc(payload: ch1.payload, sig: try! P256.Signing.PrivateKey().signature(for: Data(ch1.payload.utf8)).derRepresentation.base64EncodedString()), coreKey: coreKey) }, "a challenge not signed by the core is refused")
let forged = try! P256.Signing.PrivateKey().signature(for: Data(ch1.payload.utf8)).derRepresentation.base64EncodedString()
check(call("/approve/by-phone", ["challenge": docJSON(ch1), "signature": forged]).0 == 403, "the core refuses a signature by another key")
let (a1s, a1) = approve(ch1)
check(a1s == 200 && !throwsErr { try Checks.answerFor(r1, answer: a1!, coreKey: coreKey) }, "the phone's signature → the core's approval")
let m1run = start(img)
let m1 = m1run.machine
let (c1s, c1d) = call("/certify", ["approval": docJSON(a1!), "started": docJSON(m1run.started)])
check(c1s == 200, "the approval certifies the started machine")
let cert1 = doc(c1d)

// ---- grants: the session's cert, then the router's draft checked against what the grant page chose ----
let sc = try? Checks.cert(cert1, coreKey: coreKey)
check(sc != nil && sc!.line == m1.id && sc!.phone == phone.signingKey && sc!.sensitive == false && Set(sc!.stores ?? []) == ["claude-login", "default"],
      "the session cert names its line, this phone and its stores (\(sc?.line ?? "?"))")
check(throwsErr { _ = try Checks.cert(SignedDoc(payload: cert1.payload, sig: ch1.sig), coreKey: coreKey) }, "a cert with another signature is refused")
let holderKey = P256.KeyAgreement.PrivateKey().publicKey.x963Representation.base64EncodedString()
func iso(_ d: Date) -> String { let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime]; return f.string(from: d) }
func grantText(_ f: [String: Any]) -> String { String(decoding: try! JSONSerialization.data(withJSONObject: f, options: [.sortedKeys]), as: UTF8.self) }
let now = Date()
let good: [String: Any] = ["kind": "grant", "holder": holderKey, "session": m1.id, "scope": "shell", "issued": iso(now), "expires": iso(now.addingTimeInterval(600))]
func review(_ f: [String: Any], kind: String = "grant", minutes: Int = 10, until: Date? = nil, cert: SessionCert? = nil, phoneKey: String? = nil) -> Bool {
  guard let c = cert ?? sc else { return false }
  let pk = phoneKey ?? phone.signingKey
  return !throwsErr { _ = try Checks.reviewGrant(text: grantText(f), cert: c, phoneKey: pk, holderKey: holderKey, kind: kind, minutes: minutes, until: until, now: now) }
}
check(review(good), "a 10-minute grant for this line and holder passes")
var g2 = good; g2["session"] = "other-line"
check(!review(g2), "…refused for another line")
g2 = good; g2["holder"] = phone.signingKey
check(!review(g2), "…refused for another holder")
g2 = good; g2["expires"] = iso(now.addingTimeInterval(1200))
check(!review(g2), "…refused when longer than chosen")
check(!review(good, minutes: 11), "…refused beyond 10 minutes")
g2 = good; g2["scope"] = "root"
check(!review(g2), "…refused with another scope")
g2 = good; g2["extra"] = "x"
check(!review(g2), "…refused with an extra field")
g2 = good; g2["issued"] = iso(now.addingTimeInterval(-3600)); g2["expires"] = iso(now.addingTimeInterval(-3000))
check(!review(g2), "…refused when not issued now")
check(!review(good, phoneKey: P256.Signing.PrivateKey().publicKey.x963Representation.base64EncodedString()), "…refused when the cert names another phone")
let end = now.addingTimeInterval(30 * 86400)
let rule: [String: Any] = ["kind": "rule", "holder": holderKey, "session": m1.id, "scope": "shell", "issued": iso(now), "until": iso(end)]
check(review(rule, kind: "rule", until: end), "a standing rule until the chosen date passes")
check(!review(rule, kind: "rule", until: end.addingTimeInterval(86400)), "…refused for another date")
check(!review(rule, kind: "grant"), "…refused as a grant")
let sig = try! phoneSigning.signature(for: Data(grantText(good).utf8)).derRepresentation.base64EncodedString()
check(CoreCrypto.valid(Data(grantText(good).utf8), sig: sig, by: sc?.phone ?? ""), "the phone's signature checks against the key in the cert (what the machine does)")

// a task's line: an ordinary new-session challenge whose signed harness is task:<template>
let chT = challenge(["predecessor": NSNull(), "stores": ["default"], "options": ["harness": "task:hello", "permissionMode": "auto"], "image": img])
let rT = try? Checks.review(challenge: chT, coreKey: coreKey)
check(rT?.kind == .newSession && rT?.harness == "task:hello" && rT?.permissionMode == "auto", "a task's challenge is a new session on harness task:hello (\(rT?.harness ?? "?"))")
if let rt = rT {
  check(!throwsErr { try Checks.matchesPicked(rt, stores: ["default"], harnessStores: [], harness: "task:hello", permissionMode: "auto") }, "…and matches its template's harness and stores")
} else { check(false, "…and matches its template's harness and stores") }
let (aTs, aT) = approve(chT)
check(aTs == 200 && rT != nil && !throwsErr { try Checks.answerFor(rT!, answer: aT!, coreKey: coreKey) }, "the phone approves a task's line once")

// add a store (the machine exists)
let ch2 = challenge(["predecessor": docJSON(cert1), "machine": m1.id, "stores": ["claude-login", "default", "gmail"], "options": ["harness": "claude", "permissionMode": "bypass"]])
let r2 = try! Checks.review(challenge: ch2, coreKey: coreKey)
check(r2.kind == .addStore && r2.addedStore == "gmail" && list().first { $0.name == "gmail" }?.sensitive == true, "add-store challenge: one more store, marked sensitive in the core's store list")
// a second add-store for the same machine (a store with a key: an empty one is refused), read on a batch page before the first went in (2026-10-15)
let chN = challenge(["predecessor": docJSON(cert1), "machine": m1.id, "stores": ["claude-login", "default", "moved"], "options": ["harness": "claude", "permissionMode": "bypass"]])
let (a2s, a2) = approve(ch2, current: cert1)
check(a2s == 200 && !throwsErr { try Checks.answerFor(r2, answer: a2!, coreKey: coreKey) }, "adding a store answers with the machine's new succession cert")
// …then made again from the machine's new cert (router rebaseAddStores): the batch page signs it only as the same ask
if let a2, let rN = try? Checks.review(challenge: chN, coreKey: coreKey), let idN = try? Checks.continues(rN, coreKey: coreKey) {
  func fresh(_ stores: [String], mode: String = "bypass") -> (Checks.Reviewed, LineIdentity?)? {
    guard let r = try? Checks.review(challenge: challenge(["predecessor": docJSON(a2), "machine": m1.id, "stores": stores, "options": ["harness": "claude", "permissionMode": mode]]), coreKey: coreKey) else { return nil }
    return (r, try? Checks.continues(r, coreKey: coreKey))
  }
  func same(_ f: (Checks.Reviewed, LineIdentity?)?, _ here: Set<String>) -> Bool {
    guard let f else { return false }
    return !throwsErr { try Checks.sameAddStore(read: rN, of: idN, fresh: f.0, of: f.1, addedHere: here) }
  }
  let fN = fresh(["claude-login", "default", "gmail", "moved"])
  check(fN?.0.kind == .addStore && fN?.0.addedStore == "moved" && fN?.1?.stores.contains("gmail") == true, "an add-store made again continues the machine's new cert")
  check(same(fN, ["gmail"]), "…and is the same ask as the one reviewed when the batch itself added the other store")
  check(!same(fN, []), "…refused when it names a store neither the page nor the batch added")
  check(same((rN, idN), []), "the challenge reviewed is the same ask as itself")
  check(!same(fresh(["claude-login", "default", "gmail", "moved"], mode: "auto"), ["gmail"]), "…refused with another permission mode")
  let rG = try? Checks.review(challenge: ch2, coreKey: coreKey)
  check(rG != nil && throwsErr { try Checks.sameAddStore(read: rN, of: idN, fresh: rG!, of: try? Checks.continues(rG!, coreKey: coreKey), addedHere: ["gmail"]) }, "…refused when it adds another store")
} else { check(false, "a second add-store challenge read before the first went in") }
check(throwsErr { try Checks.answerFor(r2, answer: a1!, coreKey: coreKey) }, "another answer is refused")

// resume on the latest image: approval first, then the machine
check(call("/kill", ["machine": m1.id]).0 == 200, "kill the machine (pause)")
let ch3 = challenge(["predecessor": docJSON(a2!), "stores": ["claude-login", "default", "gmail"], "options": ["harness": "claude", "permissionMode": "auto"], "image": img2])
let r3 = try! Checks.review(challenge: ch3, coreKey: coreKey)
check(r3.kind == .resumeUpgrade && r3.image == img2 && r3.permissionMode == "auto", "resume-upgrade challenge read from its own fields (mode \(r3.permissionMode))")
let (a3s, a3) = approve(ch3)
check(a3s == 200 && !throwsErr { try Checks.answerFor(r3, answer: a3!, coreKey: coreKey) }, "the phone approves the resume")
let m2 = start(img2)
check(call("/certify", ["approval": docJSON(a3!), "started": docJSON(m2.started)]).0 == 200, "…and the new machine is certified")

// a sensitive line: no standing rule
let ch4 = challenge(["predecessor": NSNull(), "stores": ["gmail"], "options": ["harness": "claude", "permissionMode": "auto"], "image": img])
let (a4s, a4) = approve(ch4)
let (c4s, c4d) = a4 == nil ? (0, Data()) : call("/certify", ["approval": docJSON(a4!), "started": docJSON(start(img).started)])
if a4s == 200, c4s == 200, let sc4 = try? Checks.cert(doc(c4d), coreKey: coreKey) {
  check(sc4.sensitive == true, "a session with a sensitive store has a sensitive cert")
  var r4 = rule; r4["session"] = sc4.line
  check(!review(r4, kind: "rule", until: end, cert: sc4), "…and the grant page refuses a standing rule for it")
} else { check(false, "a sensitive session certifies") }

// ---- deploy keys: a repo added and removed, each approved by the phone (the core's fake GitHub in CI) ----
/// the begin body the app sends (RouterClient.deployKeyBegin): the store and title it names, and for an add the key
/// pair it made, the private half's store wrapped to the store key
func keyBegin(_ action: String, _ repo: String, sensitive: Bool) -> ([String: Any], DeployKeySent?) {
  let store = Checks.repoStore(repo), title = Checks.deployKeyTitle(store)
  var body: [String: Any] = ["action": action, "repo": repo, "sensitive": sensitive, "store": store, "title": title]
  guard action == "add" else { return (body, nil) }
  let kp = try! OpenSSH.ed25519(comment: title)
  let keys = try! CoreCrypto.wrapKeys(store: store, values: OpenSSH.storeValues(repo: repo, privateKeyFile: kp.privateKeyFile), storeKey: recoverStoreKey)
  body["publicKey"] = kp.publicKey
  body["keys"] = keys.map(\.json)
  return (body, DeployKeySent(publicKey: kp.publicKey, keys: keys))
}
/// the token key's writer, as RouterClient checks it
func tokenWriterOK(_ b: DeployKeyBegin) -> Bool {
  guard let w = b.tokenWriter, w.by != "machine" else { return false }
  return !throwsErr { try Checks.keyWriter(w, store: b.tokenStore, key: b.tokenKey, e: b.e, dataSha256: b.tokenDataSha256, backupSha256: b.tokenBackupSha256, setupKey: setupKey) }
}
func deployKey(_ action: String, _ repo: String, sensitive: Bool = false, signer: P256.Signing.PrivateKey? = nil, base: String = core, prefix: String = "/deploy-keys") -> (Int, DeployKeyBegin?, Data) {
  let (body, sent) = keyBegin(action, repo, sensitive: sensitive)
  let (bs, bd) = call(prefix + "/begin", body, base: base)
  guard bs == 200, let d = try? JSONDecoder().decode(SignedDoc.self, from: bd) else { return (bs, nil, bd) }
  guard let b = try? Checks.deployKeyBegin(d, coreKey: coreKey, action: action, repo: repo, sensitive: sensitive, sent: sent), tokenWriterOK(b) else { return (0, nil, bd) }
  let sig = try! (signer ?? phoneSigning).signature(for: Data(d.payload.utf8)).derRepresentation.base64EncodedString()
  let x = try! phoneAgreement.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: Data(base64Encoded: b.e)!)).withUnsafeBytes { Data($0) }
  let (fs, fd) = call(prefix + "/finish", ["pending": b.pending, "signature": sig, "share": try! CoreCrypto.sealShare(x, to: b.t)], base: base)
  return (fs, b, fd)
}
check(Checks.repoStore("DE0CH/china_train") == "github-china-train" && Checks.repoStore("someone/Thing.js") == "github-someone-thing-js" && Checks.repoStore("de0ch/Jarvis2") == "github-jarvis2", "the app's store names are the core's")
let (dk1s, dk1b, dk1d) = deployKey("add", "DE0CH/china-train")
let dk1 = dk1b.flatMap { try? Checks.deployKeyAnswer(doc(dk1d), coreKey: coreKey, begin: $0) }
check(dk1s == 200 && dk1?.kind == "deploy-key-added" && dk1?.store == "github-china-train" && dk1?.sensitive == false && dk1?.publicKey != nil && dk1?.publicKey == dk1b?.publicKey, "add a repo: the core adds the app's key, the store github-china-train (HTTP \(dk1s))")
check(list().first { $0.name == "github-china-train" }.map { !$0.sensitive && !$0.empty && !$0.unlocked } == true, "…the repo's store: not sensitive, with contents, locked")
check(list().first { $0.name == "github-deploy-keys" }?.unlocked == false, "…and the token store was opened for that call only")
// Jarvis 4's own repo: the app always asks for it sensitive (RepoKeyView) and refuses a begin that isn't (the core
// takes what is asked)
let (bjBody, bjSent) = keyBegin("add", "DE0CH/jarvis2", sensitive: true)
let (bjs, bjd) = call("/deploy-keys/begin", bjBody)
let bj = bjs == 200 ? try? Checks.deployKeyBegin(doc(bjd), coreKey: coreKey, action: "add", repo: "DE0CH/jarvis2", sensitive: true, sent: bjSent) : nil
check(bj?.sensitive == true && bj?.store == "github-jarvis2", "Jarvis 4's own repo asked for sensitive: the begin document says so before Face ID")
let (bnBody, bnSent) = keyBegin("add", "DE0CH/jarvis2", sensitive: false)
let (bns, bnd) = call("/deploy-keys/begin", bnBody)
check(bns == 200 && throwsErr { _ = try Checks.deployKeyBegin(doc(bnd), coreKey: coreKey, action: "add", repo: "DE0CH/jarvis2", sensitive: false, sent: bnSent) }, "…and the app refuses a begin for it that isn't sensitive")
check(bjs == 200 && throwsErr { _ = try Checks.deployKeyBegin(doc(bjd), coreKey: coreKey, action: "remove", repo: "DE0CH/jarvis2", sensitive: false) }, "the page refuses a begin for another action")
// the Inbox review's "What you sign (exact)" is rendered from this signed document
let bjFacts = bj.map(SignedAction.deployKey) ?? []
check(SignedAction.value(bjFacts, "repo") == "DE0CH/jarvis2" && SignedAction.value(bjFacts, "store") == "github-jarvis2" && SignedAction.value(bjFacts, "sensitive") == "Yes"
      && SignedAction.value(bjFacts, "token-store") == "github-deploy-keys", "the signed action renders from the core's begin document: \(bjFacts.map { "\($0.id)=\($0.value)" })")
check(bjs == 200 && throwsErr { _ = try Checks.deployKeyBegin(doc(bjd), coreKey: coreKey, action: "add", repo: "DE0CH/claude-env", sensitive: false) }, "…or another repo")
check(deployKey("add", "DE0CH/x", signer: P256.Signing.PrivateKey()).0 == 403, "a signature by another key is refused")
let (nas, _, nad) = deployKey("add", "DE0CH/no-admin")
check(nas == 502 && String(decoding: nad, as: UTF8.self).contains("github: HTTP 403"), "a token GitHub refuses: the core says what GitHub said (HTTP \(nas))")
let (nrs, _, nrd) = deployKey("add", "DE0CH/no-admin", base: need("INTEROP_ROUTER"), prefix: "/api/repos/key")
check(nrs == 502 && String(decoding: nrd, as: UTF8.self).contains("Administration: read and write"), "…and the router names the permission it needs (HTTP \(nrs))")
let (rms, rmb, rmd) = deployKey("remove", "DE0CH/china-train")
check(rms == 200 && rmb.flatMap { try? Checks.deployKeyAnswer(doc(rmd), coreKey: coreKey, begin: $0) }?.kind == "deploy-key-removed", "remove: the key and the store go")
check(!list().contains { $0.name == "github-china-train" }, "…the store is gone from the core's list")
// through the router (Settings → Repos): the list follows the core's answer
// ---- R2: the app makes the key pair and wraps its store; the core adds that key and keeps those keys ----
struct SSHVector: Decodable { let seedHex: String; let checkint: String; let comment: String; let publicKey: String; let privateKeyFile: String; let storeValue: String }
if let vb = FileManager.default.contents(atPath: "testdata/openssh-ed25519.json"), let v = try? JSONDecoder().decode(SSHVector.self, from: vb) {
  let seed = Data(stride(from: 0, to: v.seedHex.count, by: 2).map { i in UInt8(v.seedHex[v.seedHex.index(v.seedHex.startIndex, offsetBy: i)..<v.seedHex.index(v.seedHex.startIndex, offsetBy: i + 2)], radix: 16)! })
  let kv = try? OpenSSH.ed25519(comment: v.comment, seed: seed, checkint: UInt32(v.checkint, radix: 16))
  check(kv?.publicKey == v.publicKey && kv?.privateKeyFile == v.privateKeyFile, "the app's OpenSSH key matches the core's vector")
  check(OpenSSH.storeValues(repo: "DE0CH/china-train", privateKeyFile: v.privateKeyFile)["GITHUB_DEPLOY_KEY_DE0CH_CHINA_TRAIN"] == v.storeValue, "…and its store value")
} else {
  check(false, "the OpenSSH vector (testdata/openssh-ed25519.json) is readable")
}
let kp = try! OpenSSH.ed25519(comment: "jarvis4 github-r2-app")
let skNow = try! CoreCrypto.storeKey(doc(call("/store-key", ["phone": phone.agreementKey]).1), coreKey: coreKey, phone: phone.agreementKey)
let appKeys = try! CoreCrypto.wrapKeys(store: "github-r2-app", values: OpenSSH.storeValues(repo: "DE0CH/r2-app", privateKeyFile: kp.privateKeyFile), storeKey: skNow)
check(appKeys.map(\.key) == ["GITHUB_DEPLOY_KEY_DE0CH_R2_APP", "GITHUB_DEPLOY_REPO_DE0CH_R2_APP"], "a repo's store is two keys, each sealed on its own")
let (abStatus, abd) = call("/deploy-keys/begin", ["action": "add", "repo": "DE0CH/r2-app", "sensitive": false, "store": "github-r2-app",
                                             "title": "jarvis4 github-r2-app", "publicKey": kp.publicKey, "keys": appKeys.map(\.json)])
let abeg = abStatus == 200 ? try? Checks.deployKeyBegin(doc(abd), coreKey: coreKey, action: "add", repo: "DE0CH/r2-app", sensitive: false, sent: DeployKeySent(publicKey: kp.publicKey, keys: appKeys)) : nil
check(abeg != nil && abeg?.keys?.count == 2 && abeg?.tokenKey == "GITHUB_DEPLOY_KEYS_TOKEN", "the core's begin names the app's public key and each key it sent (HTTP \(abStatus))")
check(abeg.map(tokenWriterOK) == true && abeg?.tokenWriter?.by == "core", "…and who wrote the GitHub token (the core: a Recover's key)")
let otherKeys = try! CoreCrypto.wrapKeys(store: "github-r2-app", values: ["X": "y"], storeKey: skNow)
check(abStatus == 200 && throwsErr { _ = try Checks.deployKeyBegin(doc(abd), coreKey: coreKey, action: "add", repo: "DE0CH/r2-app", sensitive: false, sent: DeployKeySent(publicKey: kp.publicKey, keys: otherKeys)) }, "…the page refuses a begin naming other keys")
let movedKeys = [appKeys[0], KeyEntry(store: "github-r2-app", key: "GITHUB_DEPLOY_REPO_DE0CH_R2_APP", wrapped: appKeys[0].wrapped, data: appKeys[0].data)]
check(abStatus == 200 && throwsErr { _ = try Checks.deployKeyBegin(doc(abd), coreKey: coreKey, action: "add", repo: "DE0CH/r2-app", sensitive: false, sent: DeployKeySent(publicKey: kp.publicKey, keys: movedKeys)) }, "…or a key under another name")
if let b = abeg {
  let sig = try! phoneSigning.signature(for: Data(doc(abd).payload.utf8)).derRepresentation.base64EncodedString()
  let (afs, afd) = call("/deploy-keys/finish", ["pending": b.pending, "signature": sig, "share": try! CoreCrypto.sealShare(shareOf(b.e), to: b.t)])
  let a = try? Checks.deployKeyAnswer(doc(afd), coreKey: coreKey, begin: b)
  check(afs == 200 && a?.kind == "deploy-key-added" && a?.publicKey == kp.publicKey && a?.store == "github-r2-app", "the core added the app's key (HTTP \(afs))")
  check(unlock("github-r2-app").0 == 200, "…and the app-wrapped keys open with the phone's shares")
}
// the store's keys sealed under another key's name: the core keeps them as sent, and they don't open
let swapped = [KeyEntry(store: "github-r2-swap", key: "GITHUB_DEPLOY_KEY_DE0CH_R2_SWAP", wrapped: appKeys[1].wrapped, data: appKeys[1].data),
               KeyEntry(store: "github-r2-swap", key: "GITHUB_DEPLOY_REPO_DE0CH_R2_SWAP", wrapped: appKeys[0].wrapped, data: appKeys[0].data)]
let kp2 = try! OpenSSH.ed25519(comment: "jarvis4 github-r2-swap")
let (sws, swd) = call("/deploy-keys/begin", ["action": "add", "repo": "DE0CH/r2-swap", "sensitive": false, "store": "github-r2-swap",
                                       "title": "jarvis4 github-r2-swap", "publicKey": kp2.publicKey, "keys": swapped.map(\.json)])
if sws == 200, let b = try? Checks.deployKeyBegin(doc(swd), coreKey: coreKey, action: "add", repo: "DE0CH/r2-swap", sensitive: false, sent: DeployKeySent(publicKey: kp2.publicKey, keys: swapped)) {
  let sig = try! phoneSigning.signature(for: Data(doc(swd).payload.utf8)).derRepresentation.base64EncodedString()
  _ = call("/deploy-keys/finish", ["pending": b.pending, "signature": sig, "share": try! CoreCrypto.sealShare(shareOf(b.e), to: b.t)])
  check(unlock("github-r2-swap").0 == 403, "a deploy key's values moved to another store or key don't decrypt")
} else { check(false, "a deploy key's values moved to another store or key don't decrypt (begin HTTP \(sws))") }

let rbase = need("INTEROP_ROUTER")
struct ReposDTO: Decodable { struct R: Decodable { let name: String; let repo: String; let store: String; let sensitive: Bool? }; let repos: [R] }
let (ras, _, _) = deployKey("add", "DE0CH/claude-env", base: rbase, prefix: "/api/repos/key")
let rl = try? JSONDecoder().decode(ReposDTO.self, from: call("/api/repos", base: rbase).1)
check(ras == 200 && rl?.repos.map(\.repo) == ["DE0CH/claude-env"] && rl?.repos.first?.store == "github-claude-env", "through the router: the repo is on the list with its store")
_ = deployKey("remove", "DE0CH/claude-env", base: rbase, prefix: "/api/repos/key")
check((try? JSONDecoder().decode(ReposDTO.self, from: call("/api/repos", base: rbase).1))?.repos.isEmpty == true, "…and off it after remove")

// ---- the Inbox (router/inbox.go): a request filed through an intent endpoint opens the same review page ----
let (qs, qd) = call("/api/requests/repo/add", ["repo": "https://github.com/DE0CH/claude-env", "explanation": "for the skill"], base: rbase)
let qid = ((try? JSONSerialization.jsonObject(with: qd)) as? [String: Any])?["id"] as? String ?? ""
let (gs, gd) = call("/api/requests/" + qid, base: rbase)
let qi = (try? JSONSerialization.jsonObject(with: gd)) as? [String: Any] ?? [:]
let qopen = qi["open"] as? [String: Any] ?? [:], qopts = qopen["options"] as? [String: Any] ?? [:]
let qcall = qi["call"] as? [String: Any] ?? [:]
check(qs == 200 && gs == 200 && qopen["kind"] as? String == "repo-key" && qopts["repo"] as? String == "DE0CH/claude-env" && qopts["inboxId"] as? String == qid, "a filed request opens the repo-key page for that repo (HTTP \(qs) \(gs))")
check(SignedAction.mismatch(page: qopts.merging(["kind": "repo-key", "requestId": "x"]) { a, _ in a }, request: qopts) == "", "…its options match the page's")
check(SignedAction.mismatch(page: qopts.merging(["repo": "DE0CH/other"]) { _, b in b }, request: qopts) == "repo", "…a page for another repo shows the mismatch")
check(SignedAction.call(method: qcall["method"] as? String ?? "", path: qcall["path"] as? String ?? "", args: qcall["args"] as? [String: Any]) == #"POST /api/requests/repo/add {"repo":"DE0CH/claude-env"}"#, "…the API call as the review shows it")
check(qi["explanation"] as? String == "for the skill" && (qi["callerText"] as? String ?? "") != "", "…with the caller's words and who called")
check(call("/api/requests/" + qid + "/done", [String: Any](), base: rbase).0 == 200 && call("/api/requests/" + qid, base: rbase).0 == 404, "…and done takes it out of the Inbox")

// ---- lock ----
let lk = try? CoreCrypto.decode(doc(call("/lock", ["id": u?.id ?? ""]).1), by: coreKey, as: KindDoc.self, what: "locked")
check(lk?.kind == "locked", "lock releases the unlock id")

// ---- the Fly token, sealed to the core (infra/setup.py backup-core) ----
let tok = try! CoreCrypto.seal(Data(#"{"FLY_API_TOKEN":"ci-token"}"#.utf8), to: derived.agreementKey, info: "jarvis2/fly-token")
let ft = try? CoreCrypto.decode(doc(call("/fly-token", ["sealed": tok]).1), by: coreKey, as: KindDoc.self, what: "fly token")
check(ft?.kind == "fly-token-set", "the core takes a Fly token sealed to it")
check(call("/fly-token", ["sealed": try! CoreCrypto.seal(Data(#"{"FLY_API_TOKEN":"x"}"#.utf8), to: derived.agreementKey, info: CoreCrypto.shareInfo)]).0 == 400, "…not one sealed for something else")

// ---- Reset on a set-up core: only the master key it was set up with ends it ----
check(call("/wipe", try! CoreSetup.wipe(core: derived, master: fresh)).0 == 403, "a wipe signed by another key is refused")
var w2 = try! CoreSetup.wipe(core: phone, master: kitMaster)
check(call("/wipe", w2).0 == 403, "a wipe naming another core is refused")
w2 = try! CoreSetup.wipe(core: derived, master: kitMaster)
let (ws, wd) = call("/wipe", w2)
let wiping = try? CoreCrypto.decode(doc(wd), by: coreKey, as: KindDoc.self, what: "wiping")
check(ws == 200 && wiping?.kind == "wiping" && wiping?.core == coreKey, "the master key ends the core (a signed 'wiping')")
sleep(3)
check(call("/identity").0 == 0, "…and the core process is gone (Kubernetes starts a new, empty one)")
print(failures == 0 ? "ALL OK" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
