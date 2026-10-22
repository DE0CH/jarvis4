// An image attached on New session (docs/DECISIONS.md 94, 95, 97): its bytes as they will be uploaded, their sha256 and size
// (Start checks the signed config names exactly these), and a thumbnail for the page.
import CryptoKit
import ImageIO
import UIKit
import UniformTypeIdentifiers

struct PickedImage: Identifiable, Equatable {
  let id = UUID()
  /// the name it goes up under: already what the router's safeName makes of it, and unique on the page
  let name: String
  let data: Data
  let sha256: String
  let thumbnail: UIImage?
  var size: Int { data.count }
  var signed: Checks.Attachment { .init(name: name, sha256: sha256, size: size) }

  static func == (a: PickedImage, b: PickedImage) -> Bool { a.id == b.id }
}

/// Making a picked image ready to upload, off the main thread. Photos and camera shots go as JPEG (quality 0.85, longest
/// side at most 4096 px: HEIC never leaves the phone); a PNG, JPEG, GIF or WebP from Files or the clipboard goes as it
/// is; any other image (or one over the router's 25 MB) is made a JPEG.
enum ImagePrep {
  static let maxSide: CGFloat = 4096
  static let maxBytes = 25 << 20
  static let maxFiles = 20
  /// what Claude Code attaches inline, kept as they are
  static let kept: [(UTType, String)] = [(.png, "png"), (.jpeg, "jpg"), (.gif, "gif"), (.webP, "webp")]

  struct Prepared: Sendable { let data: Data; let ext: String; let sha256: String; let thumbnail: UIImage? }

  /// a photo or a camera shot (any format UIKit decodes): a JPEG
  static func photo(_ data: Data) -> Prepared? {
    guard let img = UIImage(data: data) else { return nil }
    return jpeg(img)
  }

  static func jpeg(_ img: UIImage) -> Prepared? {
    let w = img.size.width * img.scale, h = img.size.height * img.scale
    guard w > 0, h > 0 else { return nil }
    let k = min(1, maxSide / max(w, h))
    let target = CGSize(width: (w * k).rounded(), height: (h * k).rounded())
    let fmt = UIGraphicsImageRendererFormat()
    fmt.scale = 1
    fmt.opaque = true
    // drawing applies the photo's orientation, so the JPEG is upright without EXIF
    let out = UIGraphicsImageRenderer(size: target, format: fmt).image { _ in img.draw(in: CGRect(origin: .zero, size: target)) }
    guard let d = out.jpegData(compressionQuality: 0.85) else { return nil }
    return finish(d, ext: "jpg")
  }

  /// from Files or the clipboard: `type` when known, else read from the bytes
  static func file(_ data: Data, type: UTType?) -> Prepared? {
    let t = type ?? sniff(data)
    if data.count <= maxBytes, let t, let ext = kept.first(where: { t.conforms(to: $0.0) })?.1 {
      return finish(data, ext: ext)
    }
    return photo(data)
  }

  static func sniff(_ data: Data) -> UTType? {
    guard let src = CGImageSourceCreateWithData(data as CFData, nil), let id = CGImageSourceGetType(src) as String? else { return nil }
    return UTType(id)
  }

  static func finish(_ data: Data, ext: String) -> Prepared {
    Prepared(data: data, ext: ext, sha256: sha256(data), thumbnail: thumbnail(data))
  }

  static func sha256(_ d: Data) -> String { SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined() }

  static func thumbnail(_ d: Data, side: Int = 240) -> UIImage? {
    guard let src = CGImageSourceCreateWithData(d as CFData, nil) else { return nil }
    let opts: [CFString: Any] = [kCGImageSourceCreateThumbnailFromImageAlways: true, kCGImageSourceCreateThumbnailWithTransform: true,
                                 kCGImageSourceThumbnailMaxPixelSize: side]
    return CGImageSourceCreateThumbnailAtIndex(src, 0, opts as CFDictionary).map { UIImage(cgImage: $0) }
  }

  /// the router's safeName (router/uploads.go): a basename, no control characters, whitespace → "_", ≤ 200 bytes
  static func safeName(_ raw: String) -> String {
    let base = raw.split(whereSeparator: { $0 == "/" || $0 == "\\" }).last.map(String.init) ?? ""
    var s = base.unicodeScalars.filter { $0.value >= 0x20 }.map { String($0) }.joined()
    s = s.split(whereSeparator: \.isWhitespace).joined(separator: "_")
    while s.utf8.count > 200 { s.removeLast() }
    return s.isEmpty || s == "." || s == ".." ? "file" : s
  }

  /// `stem.ext`, made safe, with -2, -3… until no other image on the page has it
  static func name(_ stem: String, ext: String, taken: Set<String>) -> String {
    var st = safeName(stem)
    while st.utf8.count > 180 { st.removeLast() }
    var n = "\(st).\(ext)", i = 2
    while taken.contains(n) { n = "\(st)-\(i).\(ext)"; i += 1 }
    return n
  }
}
