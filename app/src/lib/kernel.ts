// What the Sessions banner warns about for the box's trusted base (ios/Jarvis4/Model/KernelHealth.swift, the same rule).
// A box with the old core: "Core not answering" while the core doesn't answer. A Jarvis 4 box runs no core (the
// router's NO_CORE=1): GET /api/state carries the kernel's health instead (router/kernelhealth.go), and the warning
// names what is wrong with the kernel, if anything.
import type { State } from "./api";

/** the banner's text: null when there is nothing to warn about */
export function trustWarning(st: State): string | null {
  if (!st.loaded) return null;
  const k = st.kernel;
  if (!k) return st.core.none || st.core.up ? null : "Core not answering: no create, resume or approve.";
  if (!k.checked || k.healthy) return null;
  return k.problems?.length ? k.problems.join("\n") : "Kernel not healthy";
}
