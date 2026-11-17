// New session's model. The router owns the default (GET api/models `defaults`, router/harness.go): the form shows it
// until Deyao picks a model by hand, and a new default reaches a form that is already open. A form that kept the model
// it had put there itself showed the old default after the router's changed (Fable 5.2 after Opus 5.5 became it,
// Deyao 2026-11-17).

/** The model New session shows: the one picked by hand while the harness offers it, else the router's default for
 *  the harness, else the harness's first. */
export function formModel(current: string, picked: boolean, offered: string[], def: string | undefined): string {
  if (picked && offered.includes(current)) return current;
  if (def && offered.includes(def)) return def;
  return offered[0] || "";
}
