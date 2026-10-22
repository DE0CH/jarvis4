// New / edit a task: a name plus the template's fields (task.json: text, textarea, number, select, multiselect,
// checkbox). A (multi)select of stores is filled from the core's signed store list; the picked stores join the task's
// session line, which the iPhone approves when the task is made (they can't change afterwards: make a new task).
// Values are not secret (they reach the machine unsigned): secrets belong in a store.
import SwiftUI

struct TaskEditView: View {
  @Environment(AppModel.self) private var model
  let template: String?
  let instanceId: String?
  @Binding var path: [TaskRoute]
  @State private var name = ""
  @State private var text: [String: String] = [:]
  @State private var flags: [String: Bool] = [:]
  @State private var multi: [String: Set<String>] = [:]
  @State private var started = false
  @State private var busy = false
  @State private var error: String?
  /// a prompt template runs claude -p on a Claude account (router/claudeaccounts.go): the default pre-picked, fixed
  @State private var accounts: [JSON] = []
  @State private var account = ""

  private var inst: TaskInstance? { instanceId.flatMap { id in model.tasks.instances.first { $0.id == id } } }
  private var t: TaskTemplate? { model.tasks.templates.first { $0.name == (inst?.template ?? template) } }

  var body: some View {
    if let t {
      Form {
        Section {
          LabeledContent("Template", value: t.title)
          if let d = t.description { Text(d).font(.subheadline).foregroundStyle(.secondary) }
        }
        Section("Name") { TextField("What this task is for", text: $name).accessibilityIdentifier("te-name") }
        ForEach(t.fields) { f in
          Section {
            field(f)
          } header: { Text(f.label + (f.required ? " *" : "")) } footer: {
            VStack(alignment: .leading) {
              if f.optionsFrom == "stores" { Text(inst != nil ? "Fixed for this task." : "Approved with the task.") }
              if let h = f.help { Text(h) }
            }
          }
        }
        if t.hasPrompt && inst == nil && !accounts.isEmpty {
          Section {
            ForEach(accounts, id: \.self) { a in
              let store = a["store"].string ?? ""
              CheckRow(on: account == store, id: "te-account-\(store)", action: { account = store }) {
                VStack(alignment: .leading) {
                  Text(store + (a["default"].bool == true ? " (default)" : ""))
                  Text(a["email"].text ?? "not signed in").font(.footnote).foregroundStyle(Color.secondary)
                }
              }
            }
          } header: { Text("Claude account") } footer: { Text("Fixed once approved.") }
        }
        Section {
          LabeledContent("Template stores") { Text(t.stores.isEmpty ? "None" : t.stores.joined(separator: "\n")).font(.footnote.monospaced()).multilineTextAlignment(.trailing) }
          if let error { ErrorRow(text: error, id: "te-err") }
        } footer: {
          Text("Values are not secret; secrets come from stores.")
        }
      }
      .navigationTitle(inst == nil ? "New task" : "Edit task")
      .navigationBarTitleDisplayMode(.inline)
      .toolbar {
        ToolbarItem(placement: .confirmationAction) {
          Button(busy ? "Saving…" : (inst == nil ? "Make task" : "Save")) { Task { await save(t) } }.disabled(busy).accessibilityIdentifier("te-save")
        }
      }
      .task { start(t); await loadAccounts(t) }
    } else {
      ContentUnavailableView(instanceId != nil && inst == nil ? "This task no longer exists" : "Template “\(template ?? "")” is not in tasks/", systemImage: "checklist")
    }
  }

  @ViewBuilder private func field(_ f: TaskField) -> some View {
    let opts = options(f)
    switch f.type {
    case "textarea":
      TextField(f.placeholder ?? "", text: binding(f.name), axis: .vertical).lineLimit(4...10).accessibilityIdentifier("tf-\(f.name)")
    case "number":
      TextField(f.placeholder ?? "", text: binding(f.name)).keyboardType(.decimalPad).accessibilityIdentifier("tf-\(f.name)")
    case "select":
      if opts.isEmpty { Text("No options available.").foregroundStyle(.secondary) }
      ForEach(opts) { o in
        CheckRow(on: text[f.name] == o.value, id: "tf-\(f.name)-\(o.value)", action: { text[f.name] = o.value }) { OptionLabel(o: o) }
      }
    case "multiselect":
      if opts.isEmpty { Text("No options available.").foregroundStyle(.secondary) }
      ForEach(opts) { o in
        CheckRow(on: multi[f.name, default: []].contains(o.value), id: "tf-\(f.name)-\(o.value)", action: { toggle(f.name, o.value) }) { OptionLabel(o: o) }
      }
    case "checkbox":
      Toggle(f.label, isOn: Binding(get: { flags[f.name] ?? false }, set: { flags[f.name] = $0 })).accessibilityIdentifier("tf-\(f.name)")
    default:
      TextField(f.placeholder ?? "", text: binding(f.name)).textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityIdentifier("tf-\(f.name)")
    }
  }

  private func binding(_ n: String) -> Binding<String> { Binding(get: { text[n] ?? "" }, set: { text[n] = $0 }) }
  private func toggle(_ n: String, _ v: String) { var s = multi[n, default: []]; if s.contains(v) { s.remove(v) } else { s.insert(v) }; multi[n] = s }
  /// the template's own options, or the core's stores / the sizes / the models
  private func options(_ f: TaskField) -> [TaskOption] {
    switch f.optionsFrom ?? "" {
    case "stores":
      model.stores.items.filter { !$0.isCore && !model.harnessHidden.contains($0.name) && $0.name != "claude" }.map { s in
        TaskOption(value: s.name, label: s.name, sub: [s.sensitive ? "sensitive" : nil, s.empty ? "empty" : nil, s.unlocked ? nil : "locked"].compactMap { $0 }.joined(separator: " · "))
      }
    case "sizes": model.sizes.map { TaskOption(value: $0.id, label: $0.id, sub: $0.label) }
    case "models": model.models.map { TaskOption(value: $0.id, label: $0.label ?? $0.id, sub: nil) }
    default: f.options
    }
  }
  private func start(_ t: TaskTemplate) {
    guard !started else { return }
    started = true
    name = inst?.name ?? t.title
    for f in t.fields {
      let v = inst.map { $0.params[f.name] } ?? .null
      let x = v.isNull ? f.defaultValue : v
      switch f.type {
      case "checkbox": flags[f.name] = x.bool ?? false
      case "multiselect": multi[f.name] = Set(x.strings)
      default: text[f.name] = x.string ?? ""
      }
    }
  }
  private func loadAccounts(_ t: TaskTemplate) async {
    guard t.hasPrompt, inst == nil, let l = try? await RouterClient.shared.get("api/claude-accounts") else { return }
    accounts = l["accounts"].array
    if account.isEmpty { account = l["default"].string ?? "" }
  }
  private func save(_ t: TaskTemplate) async {
    error = nil
    let n = name.trimmingCharacters(in: .whitespaces)
    guard !n.isEmpty else { error = "A name is required."; return }
    var params: [String: Any] = [:]
    for f in t.fields {
      switch f.type {
      case "checkbox": params[f.name] = flags[f.name] ?? false
      case "multiselect": params[f.name] = Array(multi[f.name] ?? []).sorted()
      default: params[f.name] = text[f.name] ?? ""
      }
    }
    busy = true
    defer { busy = false }
    do {
      if let inst {
        try await RouterClient.shared.call("PUT", "api/tasks/instances/\(inst.id)", ["name": n, "params": params])
        await model.loadTasks()
        if !path.isEmpty { path.removeLast() }
      } else {
        var body: [String: Any] = ["template": t.name, "name": n, "params": params]
        if t.hasPrompt && !account.isEmpty { body["account"] = account }
        let r = try await RouterClient.shared.call("POST", "api/tasks/instances", body)
        await model.loadTasks()
        model.say("Made “\(n)”: the iPhone approves it once.")
        if !path.isEmpty { path.removeLast() }
        if let id = r["id"].text { path.append(.task(id)) }
        await model.openApproval(for: r["session"].text, kind: "new-session")
      }
    } catch { self.error = errText(error) }
  }
}

private struct OptionLabel: View {
  let o: TaskOption
  var body: some View {
    VStack(alignment: .leading) {
      Text(o.label)
      if let s = o.sub, !s.isEmpty { Text(s).font(.footnote).foregroundStyle(Color.secondary) }
    }
  }
}
