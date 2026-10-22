// Setting the core up — Reset and Recover — with no UI, network or Keychain in it (compiled into the interop test
// too, which runs it against the real core). A new core is empty: it takes a master public key once, from a
// claim statement the master key signs (naming the core and this iPhone), with a bundle of stores sealed to it.
//   Reset:   a new master key, an empty bundle; the stores are filled later by the setup session.
//   Recover: the master key from the kit; the bundle = every store from the backups.
// The backups come from the router, which holds the bucket's read key and passes the objects on as they are:
//   stores/<name>.json    {doc, sig}: doc = {"kind":"store-backup","name","sensitive","sealed":{e,data},"at"},
//                         sig = the setup key's ECDSA over the doc text; sealed to the master key
//                         (info "jarvis2/backup", the store's name as associated data) → JSON values
//   sensitive/<name>.json {doc, sig}: doc = {"kind":"store-sensitive","name","at"} — the store is sensitive
//                         whatever its backup says
//   keys/<store>/<key>.json {kind "key-backup", store, key, deleted, sealed {e,data} | null, backupSha256, e,
//                         dataSha256, writer {by "setup"|"machine"|"restore", sig, cert?, receipt?}, core (the core's
//                         identity), explanation, at (RFC 3339)}: one key, written after the whole-store backups
//                         (router/storedocs.go, storerestore.go). Its writer signed Checks.writerText (backupSha256 =
//                         sha256(sealed.e + "\n" + sealed.data)): the setup key, or a machine whose cert a core signed whose
//                         identity the box key signed; or a phone-approved restore, whose receipt that core signed. Sealed to the master
//                         key (info "jarvis2/backup", "<store>\n<key>" as associated data) → the value's raw bytes.
// (infra/setup.py writes the first two; the router the key backups.) So the router can't read, change or forge a
// backup; it can only withhold one or serve an older signed version. A store is its whole-store backup with every
// later key backup of that store laid over it (a deleted one removes the key).
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

/// one store as the backups give it back
struct RecoveredStore { let name: String; let values: [String: String]; let sensitive: Bool }

enum CoreSetup {
  // ---- the core: its keys (vouched for by the box key) and its own signed state ----
  struct Identity: Decodable {
    let signingKey: String; let agreementKey: String; let boxSig: String; let state: SignedDoc
  }
  /// lineSeq: the newest record of the sessions the core keeps (this iPhone remembers the highest it saw: LineWitness);
  /// derived: the core's keys come from the master key, so a Recover with the same kit brings this core back
  /// serving: "serving" | "standby" (Recovered alongside a core that still serves, waiting for its handoff) | "handed-off"
  struct State: Decodable {
    let kind: String; let master: String; let phone: PublicKeys?; var lineSeq: Int? = nil; var derived: Bool? = nil; var serving: String? = nil
  }
  /// the core as this iPhone sees it
  enum Status: Equatable {
    case empty                // waiting for Reset or Recover
    case mine                 // set up with this iPhone's master key and this iPhone
    case otherPhone           // set up with this master key, but for another iPhone (or this one before a reinstall)
    case foreign              // set up with a master key that isn't this iPhone's
  }

  /// the box key (keys/box.pub) signed the core's keys, and the core signed its state: or nothing goes on
  static func check(_ id: Identity, boxKey: String) throws -> (keys: PublicKeys, state: State) {
    let k = PublicKeys(signingKey: id.signingKey, agreementKey: id.agreementKey)
    guard CoreCrypto.identityVouched(k, boxSig: id.boxSig, boxKey: boxKey) else { throw TrustError.badSignature("the core's keys (not the box key's)") }
    let st = try CoreCrypto.decode(id.state, by: k.signingKey, as: State.self, what: "the core's state")
    guard st.kind == "core-state" else { throw TrustError.mismatch("not the core's state") }
    return (k, st)
  }
  static func status(_ st: State, myMaster: String?, myPhone: PublicKeys) -> Status {
    if st.master.isEmpty { return .empty }
    guard let m = myMaster, MasterKey.same(m, st.master) else { return .foreign }
    return st.phone == myPhone ? .mine : .otherPhone
  }

  // ---- the backups, as the router serves them ----
  struct BackupObject: Decodable { let key: String; let body: String }
  struct Signed: Decodable { let doc: String; let sig: String }
  struct BackupDoc: Decodable { let kind: String; let name: String; let sensitive: Bool; let sealed: [String: String]; var at: Double? = nil }
  /// keys/<store>/<key>.json (router/storedocs.go)
  struct KeyBackup: Decodable {
    /// setup: sig; machine: sig + cert; restore: the core's signed receipt (a phone-approved restore, core/history.go)
    struct Writer: Decodable { let by: String; var sig: String? = nil; var cert: SignedDoc? = nil; var receipt: SignedDoc? = nil }
    let kind: String; let store: String; let key: String; let deleted: Bool
    var sealed: [String: String]? = nil
    let backupSha256: String; let e: String; let dataSha256: String
    let writer: Writer
    var core: Identity? = nil
    let at: String
  }
  /// a restore's receipt (core/history.go "store-restore-approved"): each key put back with its hashes, each removed
  struct RestoreReceipt: Decodable {
    struct Put: Decodable { let key: String; let e: String; let dataSha256: String; let backupSha256: String }
    let kind: String; let store: String; var put: [Put]? = nil; var remove: [String]? = nil
  }
  /// a machine's cert, as far as a key backup needs it: the machine's signing key
  struct CertMachine: Decodable {
    struct M: Decodable { let id: String; let signingKey: String }
    let kind: String; let machine: M?; var line: String? = nil
  }
  struct MarkerDoc: Decodable { let kind: String; let name: String }

  static func name(of key: String, prefix: String) -> String? {
    guard key.hasPrefix(prefix), key.hasSuffix(".json") else { return nil }
    return String(key.dropFirst(prefix.count).dropLast(5))
  }
  private static func signed(_ body: String, key: String, setupKey: String) throws -> Data {
    guard let o = try? JSONDecoder().decode(Signed.self, from: Data(body.utf8)) else { throw TrustError.backup("\(key) isn't a signed document.") }
    let doc = Data(o.doc.utf8)
    guard CoreCrypto.valid(doc, sig: o.sig, by: setupKey) else { throw TrustError.backup("\(key) isn't signed by the setup key.") }
    return doc
  }

  /// every store in the backups, checked (setup key; a session-written key: its machine's cert from a core the box key
  /// vouched for) and decrypted (master key): each store's whole-store backup, then its later key backups
  static func readBackups(_ objects: [BackupObject], master: MasterKey, setupKey: String, boxKey: String? = nil) throws -> [RecoveredStore] {
    var marked = Set<String>()
    for o in objects {
      guard let n = name(of: o.key, prefix: "sensitive/") else { continue }
      let m = try JSONDecoder().decode(MarkerDoc.self, from: try signed(o.body, key: o.key, setupKey: setupKey))
      guard m.kind == "store-sensitive", m.name == n else { throw TrustError.backup("\(o.key) names another store.") }
      marked.insert(n)
    }
    var whole: [String: (values: [String: String], sensitive: Bool, at: Date)] = [:]
    for o in objects {
      guard let n = name(of: o.key, prefix: "stores/") else { continue }
      guard whole[n] == nil else { throw TrustError.backup("\(o.key) comes twice.") }
      let d = try JSONDecoder().decode(BackupDoc.self, from: try signed(o.body, key: o.key, setupKey: setupKey))
      guard d.kind == "store-backup", d.name == n else { throw TrustError.backup("\(o.key) names another store.") }
      let plain: Data
      do { plain = try CoreCrypto.open(d.sealed, with: master.agreement, info: CoreCrypto.backupInfo, aad: Data(n.utf8)) }
      catch { throw TrustError.backup("\(o.key) doesn't open with this recovery kit.") }
      guard let values = try? JSONDecoder().decode([String: String].self, from: plain) else { throw TrustError.backup("\(o.key) holds something that isn't a store.") }
      whole[n] = (values, d.sensitive || marked.contains(n), Date(timeIntervalSince1970: d.at ?? 0))
    }
    // key backups, each checked and opened, laid over their store's whole-store backup in the order they were written
    var keyed: [(store: String, key: String, value: String?, at: Date)] = []
    var seen = Set<String>()
    for o in objects where o.key.hasPrefix("keys/") {
      guard seen.insert(o.key).inserted else { throw TrustError.backup("\(o.key) comes twice.") }
      let (b, value) = try openKeyBackup(o, master: master, setupKey: setupKey, boxKey: boxKey)
      guard let at = Checks.isoDate(b.at) else { throw TrustError.backup("\(o.key) has no time it was written.") }
      keyed.append((b.store, b.key, value, at))
    }
    var out: [String: RecoveredStore] = [:]
    for (n, w) in whole { out[n] = RecoveredStore(name: n, values: w.values, sensitive: w.sensitive) }
    for k in keyed.sorted(by: { $0.at < $1.at }) {
      if let w = whole[k.store], k.at <= w.at { continue } // the whole-store backup is newer: it holds the key as it was then
      // a store only key backups name: sensitive (only create_store makes a store that isn't, and its backup says so)
      var s = out[k.store] ?? RecoveredStore(name: k.store, values: [:], sensitive: true)
      var v = s.values
      v[k.key] = k.value
      s = RecoveredStore(name: s.name, values: v, sensitive: s.sensitive || marked.contains(k.store))
      out[k.store] = s
    }
    return out.values.sorted { $0.name < $1.name }
  }

  /// "keys/<store>/<key>.json" → (store, key)
  static func keyName(_ key: String) -> (store: String, key: String)? {
    guard let rest = name(of: key, prefix: "keys/") else { return nil }
    let parts = rest.split(separator: "/", omittingEmptySubsequences: false)
    guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else { return nil }
    return (String(parts[0]), String(parts[1]))
  }

  /// one key backup: it names its own store and key, its hash is of its sealed value, its writer signed it (the setup
  /// key, or a machine certified by a core the box key vouched for). Problems as one plain sentence.
  static func checkKeyBackup(_ o: BackupObject, setupKey: String, boxKey: String?) throws -> KeyBackup {
    guard let (store, key) = keyName(o.key) else { throw TrustError.backup("\(o.key) isn't a key backup.") }
    guard let b = try? JSONDecoder().decode(KeyBackup.self, from: Data(o.body.utf8)), b.kind == "key-backup" else { throw TrustError.backup("\(o.key) isn't a key backup.") }
    guard b.store == store, b.key == key else { throw TrustError.backup("\(o.key) names another key.") }
    if b.deleted {
      guard b.sealed == nil, b.e.isEmpty, b.dataSha256.isEmpty, b.backupSha256.isEmpty else { throw TrustError.backup("\(o.key) is a delete that carries a value.") }
    } else {
      guard let s = b.sealed, let se = s["e"], let sd = s["data"],
            CoreCrypto.sha256hex(Data("\(se)\n\(sd)".utf8)) == b.backupSha256 else { throw TrustError.backup("\(o.key)'s hash isn't of its sealed value.") }
    }
    let text = Data(Checks.writerText(store: store, key: key, e: b.e, dataSha256: b.dataSha256, backupSha256: b.backupSha256).utf8)
    /// the core the object names, vouched for by the box key
    func vouchedCore(_ what: String) throws -> PublicKeys {
      guard let boxKey, let id = b.core else { throw TrustError.backup("\(o.key)'s \(what) can't be checked.") }
      let k = PublicKeys(signingKey: id.signingKey, agreementKey: id.agreementKey)
      guard CoreCrypto.identityVouched(k, boxSig: id.boxSig, boxKey: boxKey) else { throw TrustError.backup("\(o.key) names a core the box key didn't vouch for.") }
      return k
    }
    let sig = b.writer.sig ?? ""
    switch b.writer.by {
    case "setup":
      guard CoreCrypto.valid(text, sig: sig, by: setupKey) else { throw TrustError.backup("\(o.key) isn't signed by the setup key.") }
    case "restore":
      // a phone-approved restore: the core's signed receipt names this key put back (its hashes) or removed
      let k = try vouchedCore("restore")
      guard let rd = b.writer.receipt, let r = try? CoreCrypto.decode(rd, by: k.signingKey, as: RestoreReceipt.self, what: "the restore receipt"),
            r.kind == "store-restore-approved", r.store == store else { throw TrustError.backup("\(o.key)'s restore receipt isn't that core's.") }
      if b.deleted {
        guard (r.remove ?? []).contains(key) else { throw TrustError.backup("\(o.key)'s restore receipt doesn't remove it.") }
      } else {
        guard (r.put ?? []).contains(where: { $0.key == key && $0.e == b.e && $0.dataSha256 == b.dataSha256 && $0.backupSha256 == b.backupSha256 })
        else { throw TrustError.backup("\(o.key)'s restore receipt doesn't name this value.") }
      }
    case "machine":
      guard let cert = b.writer.cert else { throw TrustError.backup("\(o.key)'s session writer can't be checked.") }
      let k = try vouchedCore("session writer")
      guard let c = try? CoreCrypto.decode(cert, by: k.signingKey, as: CertMachine.self, what: "the writer's cert"),
            c.kind == "succession-cert", let m = c.machine else { throw TrustError.backup("\(o.key)'s machine cert isn't that core's.") }
      guard CoreCrypto.valid(text, sig: sig, by: m.signingKey) else { throw TrustError.backup("\(o.key) isn't signed by the machine its cert names.") }
    default:
      throw TrustError.backup("\(o.key) was written by \(b.writer.by).")
    }
    return b
  }

  /// a key backup checked and opened: its value (nil for a delete)
  static func openKeyBackup(_ o: BackupObject, master: MasterKey, setupKey: String, boxKey: String?) throws -> (KeyBackup, String?) {
    let b = try checkKeyBackup(o, setupKey: setupKey, boxKey: boxKey)
    guard !b.deleted, let sealed = b.sealed else { return (b, nil) }
    let plain: Data
    do { plain = try CoreCrypto.open(sealed, with: master.agreement, info: CoreCrypto.backupInfo, aad: CoreCrypto.keyAAD(store: b.store, key: b.key)) }
    catch { throw TrustError.backup("\(o.key) doesn't open with this recovery kit.") }
    guard let v = String(data: plain, encoding: .utf8) else { throw TrustError.backup("\(o.key) holds something that isn't text.") }
    return (b, v)
  }

  /// the claim statement: this master key sets up this core for this iPhone, with this bundle
  /// `device`: this install's long-lived device key (PhoneKeys.devicePublic), inside the master-signed text so the setup
  /// session takes it only from there (a router can't attach its own); the core ignores the field
  /// `identity`: the keys the bundle's seed derives (CoreContinuity), which the core takes on from the claim (nil = no seed)
  /// `standby`: Recovered alongside the core that still serves; it serves nothing until that core hands over (only with a
  /// seed; encoded only when true)
  static func statement(master: String, core: PublicKeys, phone: PublicKeys, bundle: Data, device: String? = nil, identity: PublicKeys? = nil,
                        standby: Bool = false) throws -> String {
    struct St: Encodable {
      let kind = "claim"; let master: String; let core: PublicKeys; let phone: PublicKeys; let bundleSha256: String; let device: String?; let identity: PublicKeys?
      let standby: Bool?
    }
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return String(decoding: try e.encode(St(master: master, core: core, phone: phone, bundleSha256: CoreCrypto.sha256hex(bundle), device: device, identity: identity,
                                            standby: standby ? true : nil)), as: UTF8.self)
  }

  /// the body of POST /api/core/claim
  static func claim(core: PublicKeys, phone: PublicKeys, master: MasterKey, bundle: Data, device: String? = nil, identity: PublicKeys? = nil,
                    standby: Bool = false) throws -> [String: Any] {
    let st = try statement(master: master.publicKey, core: core, phone: phone, bundle: bundle, device: device, identity: identity, standby: standby)
    return ["statement": st, "masterSig": try master.sign(st), "bundle": try CoreCrypto.seal(bundle, to: core.agreementKey, info: CoreCrypto.claimInfo)]
  }

  /// the body of POST /api/core/wipe: the core's own master key ends it (a new, empty core takes its place)
  static func wipe(core: PublicKeys, master: MasterKey, device: String? = nil) throws -> [String: Any] {
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    struct W: Encodable { let kind = "wipe"; let core: String; let device: String? }
    let st = String(decoding: try e.encode(W(core: core.signingKey, device: device)), as: UTF8.self)
    return ["statement": st, "masterSig": try master.sign(st)]
  }
}

// ---- Recover with keys (core/keys.go): every key wrapped on its own to the core's store key ----------------------
extension CoreSetup {
  /// the claim bundle (core/keys.go): every store's name but `core`, every key of them
  /// wrapped to the store key (its value's raw bytes, "<store>\n<key>" as associated data), the core store's Fly token
  /// on its own, which stores are not sensitive, which repo owns each deploy-key store
  /// coreSeed / lineState: the seed the core's keys come from (core/continuity.go), and the record
  /// of the sessions an earlier core from the same kit left (checked first: checkLineState)
  static func keysBundle(_ stores: [RecoveredStore], storeKey: String, coreSeed: Data? = nil, lineState: LineStateDoc? = nil) throws -> Data {
    struct B: Encodable {
      let coreSeed: String?; let flyToken: String?; let format = "keys"; let keys: [KeyEntry]; let lineState: LineStateDoc?
      let notSensitive: [String]; let owners: [String: String]; let stores: [String]
    }
    let rest = stores.filter { $0.name != StoreView.coreStore }
    let keys = try rest.flatMap { try CoreCrypto.wrapKeys(store: $0.name, values: $0.values, storeKey: storeKey) }
    let fly = stores.first { $0.name == StoreView.coreStore }?.values["FLY_API_TOKEN"]
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try e.encode(B(coreSeed: coreSeed?.base64EncodedString(), flyToken: fly, keys: keys, lineState: lineState,
                          notSensitive: rest.filter { !$0.sensitive }.map(\.name), owners: owners(rest), stores: rest.map(\.name)))
  }
  /// a deploy-key store → its repo (from its GITHUB_DEPLOY_REPO_ key)
  static func owners(_ stores: [RecoveredStore]) -> [String: String] {
    var owners: [String: String] = [:]
    for s in stores where s.name.hasPrefix("github-") {
      if let repo = s.values.first(where: { $0.key.hasPrefix("GITHUB_DEPLOY_REPO_") })?.value { owners[s.name] = repo }
    }
    return owners
  }
}

// ---- the offline copy (Settings → Encrypted backup) ---------------------------------------------------------------
// The objects exactly as the router served them, each signature checked against keys/setup.pub like Recover does, and
// saved as ONE file: {format "jarvis2-backup-export", version 1, bucket, fetchedAt, setupKey, setupKeySource, objects}.
// Nothing is opened here and no kit is needed: tools/decrypt-backup.py opens the file offline with the kit (it checks
// the signatures again, against the file's setup key and keys/setup.pub).
extension CoreSetup {
  /// one object's check: nil problem = signed by the setup key and naming its own store
  struct BackupCheck: Equatable, Identifiable { let key: String; let problem: String?; var id: String { key } }
  static let exportFormat = "jarvis2-backup-export", exportVersion = 1

  /// the same per-object checks as readBackups, minus opening: signed, the setup key's, the doc names its own key
  static func checkSignatures(_ objects: [BackupObject], setupKey: String, boxKey: String? = nil) -> [BackupCheck] {
    var seen = Set<String>()
    return objects.map { o in
      if o.key.hasPrefix("keys/") {
        guard seen.insert(o.key).inserted else { return BackupCheck(key: o.key, problem: "Comes twice") }
        do { _ = try checkKeyBackup(o, setupKey: setupKey, boxKey: boxKey); return BackupCheck(key: o.key, problem: nil) }
        catch { return BackupCheck(key: o.key, problem: (error as? LocalizedError)?.errorDescription ?? "Not a key backup") }
      }
      guard let s = try? JSONDecoder().decode(Signed.self, from: Data(o.body.utf8)) else { return BackupCheck(key: o.key, problem: "Not a signed document") }
      guard CoreCrypto.valid(Data(s.doc.utf8), sig: s.sig, by: setupKey) else { return BackupCheck(key: o.key, problem: "Not signed by the setup key") }
      let doc = (try? JSONDecoder().decode(MarkerDoc.self, from: Data(s.doc.utf8)))
      if let n = name(of: o.key, prefix: "stores/") {
        guard doc?.kind == "store-backup", doc?.name == n else { return BackupCheck(key: o.key, problem: "Names another store") }
        guard seen.insert(n).inserted else { return BackupCheck(key: o.key, problem: "Comes twice") }
      } else if let n = name(of: o.key, prefix: "sensitive/") {
        guard doc?.kind == "store-sensitive", doc?.name == n else { return BackupCheck(key: o.key, problem: "Names another store") }
      } else {
        return BackupCheck(key: o.key, problem: "Not a store backup")
      }
      return BackupCheck(key: o.key, problem: nil)
    }
  }

  /// the file's bytes (sorted keys, slashes as they are; each body unchanged)
  static func exportFile(bucket: String, objects: [BackupObject], setupKey: String, setupKeySource: String, fetchedAt: Date) throws -> Data {
    struct O: Encodable { let key: String; let body: String }
    struct F: Encodable {
      let format = CoreSetup.exportFormat; let version = CoreSetup.exportVersion
      let bucket: String; let fetchedAt: String; let setupKey: String; let setupKeySource: String; let objects: [O]
    }
    let iso = ISO8601DateFormatter()
    iso.formatOptions = [.withInternetDateTime]
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes, .prettyPrinted]
    return try e.encode(F(bucket: bucket, fetchedAt: iso.string(from: fetchedAt), setupKey: setupKey, setupKeySource: setupKeySource,
                          objects: objects.map { O(key: $0.key, body: $0.body) }))
  }

  /// jarvis2-backup-2026-10-13-1015.json (UTC)
  static func exportName(_ at: Date) -> String {
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX"); f.timeZone = TimeZone(identifier: "UTC"); f.dateFormat = "yyyy-MM-dd-HHmm"
    return "jarvis2-backup-\(f.string(from: at)).json"
  }
}

// ---- the record of the sessions (core/continuity.go): what a Recover hands back to the core ------------------------
// The core seals its line state (each machine's newest cert, the killed and used sets, the input log's head, the
// deploy-key stores) under a key only a core from the same kit has, and signs a head over it; the router keeps the
// newest. The app checks the head with the derived core key and that it isn't older than the newest this iPhone saw,
// so the router can't hand back an earlier record (which could revive a line that has since ended or dropped a store).
extension CoreSetup {
  struct LineStateDoc: Codable, Equatable { let head: SignedDoc; let sealed: String }
  struct LineHead: Decodable { let kind: String; let seq: Int; let sha256: String }

  /// the record's head is signed by this core key (one another core signed is not this core's record: none)
  static func lineStateSigned(_ d: LineStateDoc, coreKey: String) -> Bool {
    (try? CoreCrypto.decode(d.head, by: coreKey, as: LineHead.self, what: "the record of the sessions")) != nil
  }
  /// the record's number, once checked: signed by the derived core key, its hash, at least `atLeast`
  static func checkLineState(_ d: LineStateDoc, coreKey: String, atLeast: Int) throws -> Int {
    let h = try CoreCrypto.decode(d.head, by: coreKey, as: LineHead.self, what: "the record of the sessions")
    guard h.kind == "line-state-head" else { throw TrustError.mismatch("not a record of the sessions") }
    guard let raw = Data(base64Encoded: d.sealed), CoreCrypto.sha256hex(raw) == h.sha256 else { throw TrustError.mismatch("the record of the sessions isn't the one its head names") }
    guard h.seq >= atLeast else { throw TrustError.stale("record of the sessions \(h.seq), this iPhone saw \(atLeast)") }
    return h.seq
  }
}
