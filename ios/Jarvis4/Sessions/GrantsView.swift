// A session's grants (docs/DESIGN.md "Grants"): which router features may run commands in it, and for how long. A new
// one is chosen here (feature, minutes or a standing rule's end) and the Face ID review only shows that request;
// here they are listed and forgotten (the router stops using one; the signed text stays valid on the machine until
// it ends).
import SwiftUI

struct GrantsView: View {
  @Environment(AppModel.self) private var model
  let sessionId: String
  @State private var grants: [Grant]?
  @State private var error: String?
  @State private var holder = "terminal"
  @State private var length = "10"
  @State private var days = 30

  private var title: String { model.session(sessionId)?.title ?? sessionId }

  var body: some View {
    Form {
      if let h = model.session(sessionId)?.needsGrant {
        Section {
          LabeledContent("Feature", value: Holder.title(h))
          LabeledContent("Why", value: "The session holds a sensitive store, so Jarvis can't do this without your approval.")
          Button("Allow for 10 minutes") { make(h, rule: false) }.accessibilityIdentifier("grant-quick")
          Button("Make a standing rule") { make(h, rule: true) }.accessibilityIdentifier("grant-rule")
        } header: { Label("Needs your approval", systemImage: "hand.raised") }
      }
      Section("In force") {
        if let error { ErrorRow(text: error) }
        else if let grants {
          if grants.isEmpty { Text("None").foregroundStyle(.secondary).accessibilityIdentifier("grants-none") }
          ForEach(grants) { g in
            HStack {
              VStack(alignment: .leading, spacing: 2) {
                HStack {
                  Label(Holder.title(g.holder), systemImage: Holder.all.first { $0.id == g.holder }?.symbol ?? "checkmark.shield").font(.headline)
                  StatusPill(text: g.isRule ? "standing rule" : "grant", color: g.isRule ? .blue : .green)
                }
                if let e = g.ends { LabeledContent("Ends", value: Fmt.when(e)).font(.footnote).foregroundStyle(.secondary) }
              }
              .accessibilityElement(children: .combine)
              .accessibilityIdentifier("grant-row-\(g.holder)")
              Spacer()
              PendingButton(key: "g:" + g.id, title: "Forget", role: .destructive) { await forget(g) }
                .buttonStyle(.borderless)
                .accessibilityIdentifier("grant-forget-\(g.holder)")
            }
          }
        } else { ProgressView() }
      }
      Section {
        Picker("Feature", selection: $holder) {
          ForEach(Holder.all) { h in Text(h.title).tag(h.id) }
        }
        .accessibilityIdentifier("grant-holder")
        Text(Holder.sub(holder)).font(.footnote).foregroundStyle(.secondary)
        Picker("How long", selection: $length) {
          Text("1 min").tag("1"); Text("2 min").tag("2"); Text("5 min").tag("5"); Text("10 min").tag("10"); Text("Standing rule").tag("rule")
        }
        .accessibilityIdentifier("grant-len")
        if length == "rule" {
          Picker("Until", selection: $days) {
            Text("7 days").tag(7); Text("30 days").tag(30); Text("90 days").tag(90); Text("1 year").tag(365)
          }
          .accessibilityIdentifier("grant-days")
        }
        Button("Review and allow…", systemImage: "faceid", action: review).accessibilityIdentifier("grant-review")
      } header: { Text("New") } footer: {
        Text("A grant lasts up to 10 minutes; a standing rule until a date.")
      }
    }
    .navigationTitle("Grants")
    .navigationBarTitleDisplayMode(.inline)
    .task {
      if let h = model.session(sessionId)?.needsGrant { holder = h }
      while !Task.isCancelled { await load(); try? await Task.sleep(for: .seconds(15)) }
    }
  }

  private func load() async {
    do { grants = try await RouterClient.shared.get("api/sessions/\(sessionId)/grants")["grants"].array.map(Grant.init); error = nil }
    catch { self.error = errText(error) }
  }
  private func make(_ h: String, rule: Bool) {
    model.requestGrant(sessionId, title, holder: h, rule: rule) { _ in Task { await load() } }
  }
  private func review() {
    if length == "rule" {
      model.requestGrant(sessionId, title, holder: holder, rule: true, until: .now.addingTimeInterval(Double(days) * 86400)) { _ in Task { await load() } }
    } else {
      model.requestGrant(sessionId, title, holder: holder, minutes: Int(length) ?? 10) { _ in Task { await load() } }
    }
  }
  private func forget(_ g: Grant) async {
    await model.exclusive("g:" + g.id) {
      guard await model.confirm("Forget the \(Holder.title(g.holder)) \(g.isRule ? "standing rule" : "grant")?",
                                "The router stops using it at once. The signed text itself stays valid on the machine until it ends\(g.ends.map { " (\($0.formatted()))" } ?? "").",
                                action: "Forget", destructive: true) else { return }
      model.pend("g:" + g.id, "Forgetting…")
      defer { model.pend("g:" + g.id, nil) }
      do {
        try await RouterClient.shared.call("DELETE", "api/grants/\(g.id)")
        for _ in 0..<10 { await load(); if !(grants ?? []).contains(where: { $0.id == g.id }) { break } }
      } catch { model.fail(error) }
    }
  }
}
