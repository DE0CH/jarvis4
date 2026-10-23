// Units: app code that needs no simulator, checked on its own (`swift run Units`; CI's interop job). A failure exits 1;
// a CheckedContinuation resumed twice traps the process, which fails the step too.
import Foundation

var failed = 0
func check(_ ok: Bool, _ what: String) {
  print(ok ? "ok   \(what)" : "FAIL \(what)")
  if !ok { failed += 1 }
}

@MainActor
func checks() async {
  // the crash of build 1039 (2026-10-13): an ASWebAuthenticationSession that can't present calls its completion
  // handler and also returns false from start(); signIn resumed its continuation from both and the app trapped
  let a = await ResumeOnce<String?>.run(failed: nil) { done in done("callback"); return false }
  check(a == "callback", "callback, then start() false: one answer, the callback's (no double resume)")

  let b = await ResumeOnce<String?>.run(failed: nil) { _ in false }
  check(b == nil, "start() false with no callback: the failed value")

  let c = await ResumeOnce<String?>.run(failed: nil) { done in
    DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) { done("first"); done("second") }
    return true
  }
  check(c == "first", "a callback that answers twice: the first answer")

  let d = await ResumeOnce<Int>.run(failed: -1) { done in
    DispatchQueue.concurrentPerform(iterations: 64) { done($0) }
    return false
  }
  check((0..<64).contains(d), "64 racing answers and start() false: exactly one is taken")

  let e: Bool = await withCheckedContinuation { k in
    let once = ResumeOnce(k)
    let first = once.resume(true)
    let second = once.resume(false)
    check(first && !second, "resume says whether it delivered")
  }
  check(e, "the first resume's value arrives")

  // the Sessions page's warning about the trusted base (Model/KernelHealth.swift)
  check(KernelHealth.warning(loaded: true, coreUp: false, kernel: nil) == "Core not answering", "a box with a core that doesn't answer: Core not answering")
  check(KernelHealth.warning(loaded: true, coreUp: true, kernel: nil) == nil, "a box with a core that answers: nothing")
  check(KernelHealth.warning(loaded: false, coreUp: false, kernel: nil) == nil, "before api/state: nothing")
  let healthy = KernelHealth(checked: true, healthy: true, problems: [])
  check(KernelHealth.warning(loaded: true, coreUp: false, kernel: healthy) == nil, "no core, a healthy kernel: nothing (core.up false doesn't matter)")
  let unchecked = KernelHealth(checked: false, healthy: false, problems: [])
  check(KernelHealth.warning(loaded: true, coreUp: false, kernel: unchecked) == nil, "no core, the router hasn't checked the kernel yet: nothing")
  let sick = KernelHealth(checked: true, healthy: false, problems: ["notary not answering", "mover holding no roster"])
  check(KernelHealth.warning(loaded: true, coreUp: false, kernel: sick) == "notary not answering\nmover holding no roster", "no core, an unhealthy kernel: what is wrong")
}

await checks()
if failed > 0 { print("\(failed) failed"); exit(1) }
print("all units passed")
