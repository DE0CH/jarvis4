// What the Sessions page warns about for the box's trusted base. A box with the old core: "Core not answering" while
// the core doesn't answer. A Jarvis 4 box runs no core (the router's NO_CORE=1): GET /api/state carries the kernel's
// health instead (router/kernelhealth.go), and the warning names what is wrong with the kernel, if anything.
// Plain Foundation (no SwiftUI, no app JSON type), so `swift run Units` checks it on its own.
import Foundation

/// the router's last check of the kernel (api/state "kernel"; only on a router that runs no core)
struct KernelHealth: Equatable {
  /// false until the router's first check after it started: no warning yet
  var checked: Bool
  var healthy: Bool
  /// each a short plain sentence ("notary not answering", "No signed kernel roster")
  var problems: [String]

  /// the banner's text: nil when there is nothing to warn about
  static func warning(loaded: Bool, coreUp: Bool, kernel: KernelHealth?) -> String? {
    guard loaded else { return nil }
    guard let kernel else { return coreUp ? nil : "Core not answering" }
    guard kernel.checked, !kernel.healthy else { return nil }
    return kernel.problems.isEmpty ? "Kernel not healthy" : kernel.problems.joined(separator: "\n")
  }
}
