// Settings → Encrypted backup: an offline copy of the store backups. "Download encrypted backup" reads them through
// the router (GET api/backups), checks every signature against keys/setup.pub from GitHub like Recover does (a key a
// session wrote: its machine's cert from a core keys/box.pub vouched for; and shows which fail), and keeps ONE file, jarvis2-backup-<date>.json: the objects exactly as served plus the bucket, the fetch
// time and the setup public key. Save file… hands it to the share sheet (Save to Files, AirDrop…). The page never asks
// for the recovery kit and never opens a backup: tools/decrypt-backup.py does that offline on the Mac
// (docs/RUNBOOK.md "Offline copy of the stores").
import SwiftUI

struct BackupView: View {
  struct Copy: Equatable {
    let file: URL, name: String, bucket: String, fetched: Date, size: Int
    let stores: Int, keys: Int, markers: Int, checks: [CoreSetup.BackupCheck]
    var failed: [CoreSetup.BackupCheck] { checks.filter { $0.problem != nil } }
  }
  @State private var busy = false
  @State private var error: String?
  @State private var copy: Copy?

  var body: some View {
    List {
      Section {
        if busy {
          HStack(spacing: 8) { ProgressView(); Text("Reading the backups…") }.accessibilityIdentifier("backup-busy")
        } else {
          Button("Download encrypted backup", systemImage: "arrow.down.doc") { Task { await download() } }
            .accessibilityIdentifier("backup-download")
        }
        if let error { ErrorRow(text: error, id: "backup-error") }
      } footer: {
        Text("Sealed to the master key. Open it offline with tools/decrypt-backup.py and the recovery kit.")
      }
      if let c = copy {
        checks(c)
        Section {
          LabeledContent("Name") { Text(c.name).font(.footnote.monospaced()) }
          LabeledContent("Size", value: Fmt.bytes(c.size))
          ShareLink(item: c.file) { Label("Save file…", systemImage: "square.and.arrow.up") }
            .accessibilityIdentifier("backup-share")
        } header: { Text("File") }
      }
    }
    .navigationTitle("Encrypted backup")
  }

  @ViewBuilder private func checks(_ c: Copy) -> some View {
    Section {
      LabeledContent("Bucket") { Text(c.bucket).font(.footnote.monospaced()) }
      LabeledContent("Fetched", value: c.fetched.formatted(date: .abbreviated, time: .shortened))
      LabeledContent("Stores", value: "\(c.stores)").accessibilityIdentifier("backup-stores")
      if c.keys > 0 { LabeledContent("Key backups", value: "\(c.keys)").accessibilityIdentifier("backup-keys") }
      LabeledContent("Sensitive markers", value: "\(c.markers)")
      LabeledContent("Checked against", value: "keys/setup.pub")
      if c.failed.isEmpty {
        LabeledContent { Text("\(c.checks.count) of \(c.checks.count)") } label: { Label("Valid", systemImage: "checkmark.seal.fill") }
          .foregroundStyle(.green)
          .accessibilityElement(children: .combine).accessibilityIdentifier("backup-valid")
      } else {
        LabeledContent { StatusPill(text: "\(c.failed.count) of \(c.checks.count)", color: .red) } label: { Text("Not valid").foregroundStyle(.red) }
          .accessibilityElement(children: .combine).accessibilityIdentifier("backup-invalid")
        ForEach(c.failed) { f in
          LabeledContent { Text(f.problem ?? "").foregroundStyle(.red) } label: { Text(f.key).font(.footnote.monospaced()) }
            .accessibilityElement(children: .combine).accessibilityIdentifier("backup-bad-\(f.key)")
        }
      }
    } header: { Text("Signatures") }
  }

  private func download() async {
    busy = true
    error = nil
    defer { busy = false }
    do {
      let setupKey = try await KeySource.key("setup.pub"), boxKey = try await KeySource.key("box.pub")
      let (bucket, objects) = try await RouterClient.shared.backupDump()
      guard !objects.isEmpty else { throw RouterError(message: "The bucket has no backups.") }
      let at = Date.now
      let data = try CoreSetup.exportFile(bucket: bucket, objects: objects, setupKey: setupKey,
                                          setupKeySource: KeySource.keysBase + "setup.pub", fetchedAt: at)
      let name = CoreSetup.exportName(at)
      let dir = FileManager.default.temporaryDirectory.appending(path: "backups", directoryHint: .isDirectory)
      try? FileManager.default.removeItem(at: dir)  // one copy at a time on the phone
      try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
      let file = dir.appending(path: name)
      try data.write(to: file, options: [.atomic, .completeFileProtection])
      copy = Copy(file: file, name: name, bucket: bucket, fetched: at, size: data.count,
                  stores: objects.count { CoreSetup.name(of: $0.key, prefix: "stores/") != nil },
                  keys: objects.count { CoreSetup.keyName($0.key) != nil },
                  markers: objects.count { CoreSetup.name(of: $0.key, prefix: "sensitive/") != nil },
                  checks: CoreSetup.checkSignatures(objects, setupKey: setupKey, boxKey: boxKey))
    } catch {
      copy = nil
      self.error = "Could not download the backup: " + errText(error)
    }
  }
}
