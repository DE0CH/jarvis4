// A continuation that takes the FIRST answer and ignores the rest. A CheckedContinuation resumed twice traps the app,
// and some Apple callbacks can answer twice: on iOS 27 an ASWebAuthenticationSession that can't present calls its
// completion handler (with an error) AND returns false from start() (TestFlight crash, build 1039, 2026-10-13:
// RouterClient.signIn resumed from both). Foundation only: the units check (ios/interop, Units) runs it on its own.
import Foundation

final class ResumeOnce<T: Sendable>: @unchecked Sendable {
  private let lock = NSLock()
  private var k: CheckedContinuation<T, Never>?
  init(_ k: CheckedContinuation<T, Never>) { self.k = k }
  /// hands `value` to the waiter; false (and nothing happens) when it already had an answer
  @discardableResult
  func resume(_ value: T) -> Bool {
    lock.lock()
    let c = k
    k = nil
    lock.unlock()
    c?.resume(returning: value)
    return c != nil
  }

  /// runs `start`, which hands `done` to a callback and says whether it started; the first of the callback's answers
  /// and `failed` (when `start` says false) is the result. On the main actor: `start` presents UI.
  @MainActor
  static func run(failed: T, _ start: (_ done: @escaping @Sendable (T) -> Void) -> Bool) async -> T {
    await withCheckedContinuation { k in
      let once = ResumeOnce(k)
      if !start({ once.resume($0) }) { once.resume(failed) }
    }
  }
}
