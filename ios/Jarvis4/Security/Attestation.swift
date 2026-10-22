// Which session image CI built (agreed with the R1 server fixes, 2026-10-11): CI on main signs each session image with
// a key whose public half is keys/ci.pub in git; the router passes that signature with every approval that names an
// image (`imageSig`). Until keys/ci.pub exists in git, an image can't be attested and the page says so; once it does,
// an approval whose image isn't attested is refused.
import Foundation

enum ImageAttestation: Equatable {
  /// CI signed this image
  case attested
  /// git has no keys/ci.pub yet: nothing can be attested (shown, not refused)
  case noKeyYet

  static func check(image: String, sig: String?) async throws -> ImageAttestation {
    guard let ci = try await KeySource.optionalKey("ci.pub") else { return .noKeyYet }
    guard Checks.imageAttested(image, sig: sig, ciKey: ci) else { throw TrustError.badSignature("the session image (not a CI build: keys/ci.pub)") }
    return .attested
  }

  /// a short badge for the approval page
  var badge: String {
    switch self {
    case .attested: "CI signed"
    case .noKeyYet: "Not attested"
    }
  }
}
