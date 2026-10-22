// New session's images (docs/DECISIONS.md 94, 95, 97): from Photos, the camera, Files or the clipboard, each shown with its
// thumbnail, name and size. Start uploads them and signs their sha256 + size with the session.
import PhotosUI
import SwiftUI
import UniformTypeIdentifiers

struct AttachmentsSection: View {
  @Binding var images: [PickedImage]
  let disabled: Bool
  @State private var photoItems: [PhotosPickerItem] = []
  @State private var camera = false
  @State private var files = false
  @State private var adding = 0
  @State private var problem: String?

  private var room: Int { max(0, ImagePrep.maxFiles - images.count) }

  var body: some View {
    Section {
      ForEach(images) { img in
        HStack(spacing: 12) {
          thumb(img)
          VStack(alignment: .leading) {
            Text(img.name).lineLimit(1).truncationMode(.middle)
            Text(Int64(img.size).formatted(.byteCount(style: .file))).font(.footnote).foregroundStyle(.secondary)
          }
          Spacer()
          Button("Remove \(img.name)", systemImage: "xmark.circle.fill") { images.removeAll { $0.id == img.id } }
            .labelStyle(.iconOnly)
            .buttonStyle(.borderless)
            .foregroundStyle(.secondary)
            .disabled(disabled)
            .accessibilityIdentifier("ns-attachment-remove-\(img.name)")
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("ns-attachment-\(img.name)")
      }
      if adding > 0 { HStack { ProgressView(); Text("Preparing…").foregroundStyle(.secondary) } }
      if let problem { Text(problem).font(.footnote).foregroundStyle(.orange).accessibilityIdentifier("ns-attach-problem") }
      if room > 0 && !disabled {
        PhotosPicker(selection: $photoItems, maxSelectionCount: room, matching: .images) {
          Label("Add from Photos", systemImage: "photo.on.rectangle")
        }
        .accessibilityIdentifier("ns-attach-photos")
        if CameraPicker.available {
          Button("Take a photo", systemImage: "camera") { camera = true }.accessibilityIdentifier("ns-attach-camera")
        }
        Button("Add from Files", systemImage: "folder") { files = true }.accessibilityIdentifier("ns-attach-files")
        PasteButton(supportedContentTypes: [.image]) { providers in Task { await addPasted(providers) } }
          .accessibilityIdentifier("ns-attach-paste")
      }
    } header: { Text("Images") } footer: {
      Text("Sent with the first prompt. Start signs each image's hash.")
    }
    .onChange(of: photoItems) { _, items in
      guard !items.isEmpty else { return }
      photoItems = []
      Task { await addPhotos(items) }
    }
    .fullScreenCover(isPresented: $camera) {
      CameraPicker { shot in
        camera = false
        if let shot { Task { await add(1, "camera") { ImagePrep.jpeg(shot) } } }
      }
      .ignoresSafeArea()
    }
    .fileImporter(isPresented: $files, allowedContentTypes: [.image], allowsMultipleSelection: true) { result in
      guard case .success(let urls) = result else { return }
      Task { await addFiles(urls) }
    }
  }

  @ViewBuilder private func thumb(_ img: PickedImage) -> some View {
    Group {
      if let t = img.thumbnail { Image(uiImage: t).resizable().scaledToFill() }
      else { Image(systemName: "photo").foregroundStyle(.secondary) }
    }
    .frame(width: 48, height: 48)
    .clipShape(.rect(cornerRadius: 6))
    .accessibilityHidden(true)
  }

  /// prepares off the main thread, then appends under a name of its own
  private func add(_ count: Int, _ stem: String, _ prep: @escaping @Sendable () -> ImagePrep.Prepared?) async {
    adding += count
    defer { adding -= count }
    let p = try? await offMain(prep)
    guard let p else { problem = "That image couldn't be read."; return }
    append(p, stem: stem)
  }

  private func append(_ p: ImagePrep.Prepared, stem: String) {
    guard images.count < ImagePrep.maxFiles else { problem = "At most \(ImagePrep.maxFiles) images."; return }
    guard p.data.count <= ImagePrep.maxBytes else { problem = "An image is larger than 25 MB even as a JPEG."; return }
    let name = ImagePrep.name(stem, ext: p.ext, taken: Set(images.map(\.name)))
    images.append(PickedImage(name: name, data: p.data, sha256: p.sha256, thumbnail: p.thumbnail))
    problem = nil
  }

  private func addPhotos(_ items: [PhotosPickerItem]) async {
    for item in items {
      adding += 1
      let data = try? await item.loadTransferable(type: Data.self)
      adding -= 1
      guard let data else { problem = "A photo couldn't be loaded."; continue }
      await add(1, "photo") { ImagePrep.photo(data) }
    }
  }

  private func addFiles(_ urls: [URL]) async {
    for url in urls {
      let scoped = url.startAccessingSecurityScopedResource()
      let data = try? Data(contentsOf: url)
      if scoped { url.stopAccessingSecurityScopedResource() }
      guard let data else { problem = "\(url.lastPathComponent) couldn't be read."; continue }
      let type = UTType(filenameExtension: url.pathExtension)
      let stem = url.deletingPathExtension().lastPathComponent
      await add(1, stem.isEmpty ? "file" : stem) { ImagePrep.file(data, type: type) }
    }
  }

  private func addPasted(_ providers: [NSItemProvider]) async {
    for p in providers {
      let type = ImagePrep.kept.map(\.0).first { p.hasItemConformingToTypeIdentifier($0.identifier) } ?? .image
      let data: Data? = await withCheckedContinuation { k in
        _ = p.loadDataRepresentation(for: type) { d, _ in k.resume(returning: d) }
      }
      guard let data else { problem = "The clipboard's image couldn't be read."; continue }
      await add(1, "pasted") { ImagePrep.file(data, type: type == .image ? nil : type) }
    }
  }
}
