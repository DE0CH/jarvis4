// New session's model. The router owns the default (GET api/models `defaults`, rust/router/src/harness.rs): the form shows it
// until Deyao picks a model by hand, and a new default reaches a form that is already open (app/src/lib/newsession.ts,
// the web page's same rule). The app read the list once per launch and the form kept the model it had put there
// itself: Fable 5.2 after Opus 5.5 became the default (Deyao, 2026-11-17).
enum FormModel {
  /// the model picked by hand while the harness offers it, else the router's default for the harness, else its first
  static func pick(current: String, picked: Bool, offered: [String], default def: String?) -> String {
    if picked && offered.contains(current) { return current }
    if let def, offered.contains(def) { return def }
    return offered.first ?? ""
  }
}
