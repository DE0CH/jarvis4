// A session's wakeups and crons (router/schedule.go): at the due time the router delivers the prompt into the session
// as a message, resuming it first when it is paused. Into a session holding a sensitive store, each delivery waits in
// the Inbox as a pending message until Deyao delivers it (Face ID) or denies it, unless a per-kind message rule says
// to deliver it (MessageReviewView). Only the session arms them (scripts/schedule-wakeup.sh, schedule-cron.sh: its own
// signed request is what vouches for the delivery; the router refuses arming from the app), so this page lists and
// cancels them (app DECISIONS 76).
import SwiftUI

struct SchedulesView: View {
  @Environment(AppModel.self) private var model
  let sessionId: String
  @State private var wakeups: [Wakeup]?
  @State private var crons: [Cron]?
  @State private var error: String?


  var body: some View {
    Form {
      Section {
        Text("The session arms its own wakeups and crons: ask it in its chat. The prompt arrives as a message; a paused session resumes first.")
          .font(.footnote).foregroundStyle(.secondary)
      }
      Section("Armed") {
        if let error { ErrorRow(text: error) }
        else if let wakeups, let crons {
          if wakeups.isEmpty && crons.isEmpty { Text("Nothing armed").foregroundStyle(.secondary).accessibilityIdentifier("sch-none") }
          ForEach(wakeups) { w in
            HStack {
              WakeRow(symbol: "alarm", when: w.at.map(Fmt.when) ?? "", name: w.name == "default" ? nil : w.name, prompt: w.prompt)
              Spacer()
              PendingButton(key: "sch:wakeup:" + w.name, title: "Cancel", role: .destructive) { await cancel("wakeup", w.name) }
                .buttonStyle(.borderless).accessibilityIdentifier("sch-cancel-w-\(w.name)")
            }
          }
          ForEach(crons) { c in
            HStack {
              WakeRow(symbol: "repeat", when: Fmt.every(c.everySeconds), name: c.name, prompt: c.prompt, next: c.nextAt.map(Fmt.when),
                          tags: [c.tz.flatMap { $0 == "UTC" ? nil : $0 }, c.runs > 0 ? Fmt.plural(c.runs, "run") : nil].compactMap { $0 })
              Spacer()
              PendingButton(key: "sch:cron:" + c.name, title: "Cancel", role: .destructive) { await cancel("cron", c.name) }
                .buttonStyle(.borderless).accessibilityIdentifier("sch-cancel-c-\(c.name)")
            }
          }
        } else { ProgressView() }
      }
    }
    .navigationTitle("Schedules")
    .navigationBarTitleDisplayMode(.inline)
    .task { await load() }
  }

  private func load() async {
    do {
      async let w = RouterClient.shared.get("api/sessions/\(sessionId)/wakeups")
      async let c = RouterClient.shared.get("api/sessions/\(sessionId)/crons")
      wakeups = try await w["wakeups"].array.map(Wakeup.init)
      crons = try await c["crons"].array.map(Cron.init)
      error = nil
    } catch { self.error = errText(error) }
  }

  private func cancel(_ what: String, _ n: String) async {
    await model.exclusive("sch:\(what):\(n)") {
      guard await model.confirm("Cancel the \(what)\(n == "default" ? "" : " “\(n)”")?", action: "Cancel \(what)", destructive: true) else { return }
      model.pend("sch:\(what):\(n)", "Cancelling…")
      defer { model.pend("sch:\(what):\(n)", nil) }
      let enc = n.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? n
      do {
        try await RouterClient.shared.call("DELETE", "api/sessions/\(sessionId)/\(what == "wakeup" ? "wakeups" : "crons")/\(enc)")
        await load(); await model.refresh()
      } catch { model.fail(error) }
    }
  }
}
