// Switch a session's Claude account (router/accountswap.go, POST api/sessions/{id}/account): a sheet from the session's
// More menu. It lists the other accounts (one not signed in or with an expired login can't be picked) and
// whether to type "continue" into its chat once Claude is back. A running session switches now (the
// router installs the new account's login under the running Claude, in the same conversation: its `wake` job, kind "account",
// shown as the busy label); a paused or failed one takes the account at its next start.
import SwiftUI

/// the sheet's subject: one session
struct AccountSwitchAsk: Identifiable, Hashable { let id: String }

struct SwitchAccountView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
  let sessionId: String
  @State private var accounts: [JSON]?
  @State private var loadError: String?
  @State private var account = ""
  @State private var cont = true
  @State private var busy = false
  @State private var error: String?

  var body: some View {
    let m = model.session(sessionId)
    let running = m?.state == "started" || m?.state == "initialising"
    let others = (accounts ?? []).filter { $0["store"].string != m?.claudeAccount }
    let chosen = others.first { $0["store"].string == account }
    NavigationStack {
      List {
        Section {
          LabeledContent("Session", value: m?.title ?? sessionId)
          LabeledContent("Now", value: m?.claudeAccount ?? "—").accessibilityIdentifier("account-current")
          LabeledContent("Applies", value: running ? "Now, under the running Claude (Remote Control gets a new entry in that account’s app)" : "At its next start")
        }
        Section {
          if let accounts {
            if others.isEmpty { Text(accounts.isEmpty ? "No Claude account yet (Settings)." : "No other Claude account (Settings).").foregroundStyle(.secondary) }
            ForEach(others, id: \.self) { a in
              let store = a["store"].string ?? ""
              let why = Self.unusable(a)
              CheckRow(on: account == store, id: "account-pick-\(store)", action: { account = store }) {
                VStack(alignment: .leading) {
                  Text(store + (a["default"].bool == true ? " (default)" : ""))
                  Text(why ?? a["email"].text ?? a["name"].text ?? "")
                    .font(.footnote).foregroundStyle(why == nil ? Color.secondary : Color.red)
                }
              }
              .disabled(why != nil)
            }
          } else if let loadError { ErrorRow(text: loadError) } else { ProgressView() }
        } header: { Text("Switch to") }
        Section {
          Toggle("Type “continue” after the switch", isOn: $cont).accessibilityIdentifier("account-continue")
        } footer: { Text(cont ? (running ? "Claude picks up where it stopped." : "Claude picks up where it stopped once it starts.") : "Claude waits for your next message.") }
        if let error { Section { ErrorRow(text: error, id: "account-error") } }
      }
      .navigationTitle("Claude account")
      .navigationBarTitleDisplayMode(.inline)
      .toolbar {
        ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy).accessibilityIdentifier("account-cancel") }
        ToolbarItem(placement: .confirmationAction) {
          Button(busy ? "Switching…" : "Switch") { Task { await run() } }
            .disabled(busy || m == nil || chosen == nil || chosen.flatMap(Self.unusable) != nil)
            .accessibilityIdentifier("account-switch")
        }
      }
      .interactiveDismissDisabled(busy)
    }
    .task { await load() }
  }

  /// why an account can't be picked (nil when it can)
  static func unusable(_ a: JSON) -> String? {
    if a["hasLogin"].bool != true { return "Not signed in (Settings → Claude accounts)" }
    if a["expired"].bool == true { return "Login expired (Settings → Claude accounts: Re-login)" }
    return nil
  }

  private func load() async {
    do { accounts = try await RouterClient.shared.get("api/claude-accounts")["accounts"].array; loadError = nil } catch { loadError = errText(error) }
  }

  private func run() async {
    busy = true; error = nil
    // nil: the router took it (the sheet closes; the model follows the job); otherwise its error, shown here
    if let e = await model.switchAccount(sessionId, to: account, continue: cont) { error = e; busy = false }
  }
}
