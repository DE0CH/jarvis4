// The camera for New session's attachments. SwiftUI has no camera view, so this wraps UIImagePickerController; offered
// only where a camera exists (not on the simulator).
import SwiftUI
import UIKit

struct CameraPicker: UIViewControllerRepresentable {
  /// the shot, or nil when cancelled
  let done: (UIImage?) -> Void

  static var available: Bool { UIImagePickerController.isSourceTypeAvailable(.camera) }

  func makeUIViewController(context: Context) -> UIImagePickerController {
    let c = UIImagePickerController()
    c.sourceType = .camera
    c.delegate = context.coordinator
    return c
  }
  func updateUIViewController(_ c: UIImagePickerController, context: Context) {}
  func makeCoordinator() -> Coordinator { Coordinator(done: done) }

  @MainActor final class Coordinator: NSObject, UIImagePickerControllerDelegate, UINavigationControllerDelegate {
    let done: (UIImage?) -> Void
    init(done: @escaping (UIImage?) -> Void) { self.done = done }
    func imagePickerController(_ picker: UIImagePickerController, didFinishPickingMediaWithInfo info: [UIImagePickerController.InfoKey: Any]) {
      done(info[.originalImage] as? UIImage)
    }
    func imagePickerControllerDidCancel(_ picker: UIImagePickerController) { done(nil) }
  }
}
