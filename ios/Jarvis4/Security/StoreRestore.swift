// Restoring a store to an earlier version (core/history.go; docs/DESIGN.md "Restoring a store"): the core keeps each
// store's last versions; putting one back is this phone's signature over the core's signed begin document — exactly
// which keys come back (each with who wrote it), which go and which stay — plus its share of every key put back, under
// one Face ID. No recovery kit and no plaintext outside the core: the core opens the keys put back and seals their
// backups to the master public key itself. Foundation only (the interop test runs it against the real core).
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

/// the core's signed list of a store's kept versions, newest first (never a value)
struct StoreVersionsDoc: Decodable {
  struct Cause: Decodable { let kind: String; var key: String? = nil; var from: Int? = nil; var writer: StoreWriter? = nil }
  struct KeyRow: Decodable { let name: String; let e: String; let dataSha256: String; var at: String? = nil; var writer: StoreWriter? = nil }
  struct Version: Decodable, Identifiable {
    let seq: Int; let at: String; let version: String; let cause: Cause; let keys: [KeyRow]
    var id: Int { seq }
  }
  let kind: String; let nonce: String; let store: String; let current: String; let sensitive: Bool; let versions: [Version]
}

/// restore_begin: what putting a version back changes, signed by the core
struct RestoreBegin: Decodable {
  struct Side: Decodable { let seq: Int; let version: String; var at: String? = nil }
  struct Put: Decodable { let key: String; let e: String; let dataSha256: String; var backupSha256: String = ""; var at: String? = nil; let writer: StoreWriter }
  let kind: String; let pending: String; let store: String; let sensitive: Bool
  let from: Side; let to: Side
  let put: [Put]; let remove: [String]; let keep: [String]
  let t: String
  /// the E of every share this restore needs, in order
  var es: [String] { put.map(\.e) }
}

/// restore_commit's answer, relayed by the router after it wrote the backups
struct RestoreDone: Decodable { let kind: String; let pending: String; let store: String; let from: Int; let seq: Int; let version: String }

extension Checks {
  /// the begin document answers what this page asked for, names each key once, and every key put back has a writer
  /// the phone accepts (Checks.keyWriter: the setup key's signature, a session's machine, or the core)
  static func restoreBegin(_ b: RestoreBegin, store: String, seq: Int, setupKey: String?) throws {
    guard b.kind == "store-restore-begin", b.store == store, b.to.seq == seq else { throw TrustError.stale("restore of \(store) to version \(seq)") }
    guard !b.put.isEmpty || !b.remove.isEmpty else { throw TrustError.mismatch("restore of \(store) changes nothing") }
    let names = b.put.map(\.key) + b.remove + b.keep
    guard Set(names).count == names.count else { throw TrustError.mismatch("a key of \(store) named twice") }
    for p in b.put {
      try keyWriter(p.writer, store: store, key: p.key, e: p.e, dataSha256: p.dataSha256, backupSha256: p.backupSha256, setupKey: setupKey)
    }
  }
  /// the committed answer is this restore's
  static func restoreDone(_ d: RestoreDone, begin b: RestoreBegin) throws {
    guard d.kind == "store-restored", d.pending == b.pending, d.store == b.store, d.from == b.to.seq, d.version == b.to.version else {
      throw TrustError.stale("the restore of \(b.store)")
    }
  }
}

extension SignedAction {
  /// a restore, from the core's signed begin document
  static func restore(_ b: RestoreBegin) -> [SignedFact] {
    var f: [SignedFact] = [
      .init(id: "kind", label: "Kind", value: "Core request"),
      .init(id: "action", label: "Action", value: "Restore store"),
      .init(id: "store", label: "Store", value: b.store, style: .code),
      .init(id: "sensitive", label: "Sensitive", value: yes(b.sensitive), style: b.sensitive ? .warning : .plain),
      .init(id: "version", label: "Puts back version", value: "\(b.to.seq)"),
      .init(id: "replaces", label: "Replaces version", value: "\(b.from.seq)"),
      .init(id: "put", label: "Keys put back", value: list(b.put.map(\.key)), style: .code),
    ]
    let bySession = b.put.filter { $0.writer.by == "machine" }
    if !bySession.isEmpty {
      f.append(.init(id: "session-written", label: "Written by a session", value: list(bySession.map { "\($0.key) · \($0.writer.line ?? "")" }), style: .warning))
    }
    f.append(.init(id: "remove", label: "Keys removed", value: list(b.remove), style: b.remove.isEmpty ? .code : .warning))
    f.append(.init(id: "keep", label: "Keys unchanged", value: "\(b.keep.count)"))
    f.append(.init(id: "backup", label: "Backups", value: "Sealed by the core to the master key"))
    return f
  }
}
