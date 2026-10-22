// Tasks: the instances (a template filled in, each its own session line the phone approved once; Run resumes the line,
// runs the template's script and pauses it again), the templates (tasks/<name>/ in the repo) and the daily schedules.
import SwiftUI

enum TaskRoute: Hashable { case task(String), edit(template: String?, instance: String?), run(name: String, title: String), schedule(id: String?, instance: String?) }

struct TasksView: View {
  @Environment(AppModel.self) private var model
  @State private var path: [TaskRoute] = []

  var body: some View {
    NavigationStack(path: $path) {
      List {
        if let e = model.tasksError { ErrorRow(text: "Could not load tasks: \(e)") }
        Section {
          if model.tasksLoaded && model.tasks.instances.isEmpty { Text("No tasks").foregroundStyle(.secondary) }
          ForEach(model.tasks.instances) { i in
            NavigationLink(value: TaskRoute.task(i.id)) { InstanceRow(inst: i, t: model.tasks.templates.first { $0.name == i.template }) }
              .accessibilityIdentifier("open-\(i.id)")
              .swipeActions(edge: .leading) {
                if i.state == "ready" { Button("Run", systemImage: "play") { Task { await model.runTask(i.id) } }.tint(.green) }
              }
          }
        } header: { Text("Tasks") }
        Section {
          ForEach(model.tasks.schedules) { s in
            let inst = model.tasks.instances.first { $0.id == s.instance }
            NavigationLink(value: TaskRoute.schedule(id: s.id, instance: nil)) { ScheduleRow(s: s, name: inst?.name ?? "(deleted task)") }
              .accessibilityIdentifier("schedule-\(s.id)")
          }
          if model.tasksLoaded && model.tasks.schedules.isEmpty { Text(model.tasks.instances.isEmpty ? "No schedules yet. Make a task first." : "No schedules yet.").foregroundStyle(.secondary) }
        } header: { Text("Daily schedules") }
        Section {
          if model.tasksLoaded && model.tasks.templates.isEmpty { Text("No templates in tasks/ yet. Ask Claude to write one.").foregroundStyle(.secondary) }
          ForEach(model.tasks.templates) { t in
            NavigationLink(value: TaskRoute.edit(template: t.name, instance: nil)) { TemplateRow(t: t) }
              .disabled(t.error != nil)
              .accessibilityIdentifier("new-\(t.name)")
          }
        } header: { Text("Templates") } footer: { Text("Pick a template to make a task from it.") }
      }
      .overlay { if !model.tasksLoaded && model.tasksError == nil { ProgressView("Loading tasks…") } }
      .navigationTitle("Tasks")
      .toolbar {
        ToolbarItem(placement: .primaryAction) {
          Button("New schedule", systemImage: "calendar.badge.plus") { path.append(.schedule(id: nil, instance: nil)) }
            .disabled(model.tasks.instances.isEmpty).accessibilityIdentifier("newScheduleBtn")
        }
      }
      .refreshable { await model.loadTasks() }
      .task { await model.loadTasks() }
      .navigationDestination(for: TaskRoute.self) { r in
        switch r {
        case .task(let id): TaskDetailView(id: id, path: $path)
        case .edit(let t, let i): TaskEditView(template: t, instanceId: i, path: $path)
        case .run(let n, let title): TaskRunView(name: n, title: title)
        case .schedule(let id, let inst): TaskScheduleEditView(scheduleId: id, instanceId: inst)
        }
      }
    }
  }
}

extension TaskRun {
  var pill: (String, Color) {
    switch phase {
    case "queued", "starting": (phase, .orange)
    case "running": ("running", .blue)
    case "succeeded": ("succeeded", .green)
    case "failed", "lost": (phase, .red)
    case "timedout": ("timed out", .red)
    default: (phase, .secondary)
    }
  }
}
extension TaskInstance {
  var pill: (String, Color) {
    switch state {
    case "approval": ("needs approval", .blue)
    case "ready": ("ready", .green)
    case "running": ("running", .blue)
    case "busy": ("busy", .orange)
    case "failed": ("failed", .red)
    case "gone": ("no line", .red)
    default: (state, .secondary)
    }
  }
}

private struct InstanceRow: View {
  @Environment(AppModel.self) private var model
  let inst: TaskInstance
  let t: TaskTemplate?
  var body: some View {
    let r = inst.activeRun ?? inst.lastRun
    VStack(alignment: .leading, spacing: 3) {
      HStack {
        Text(inst.name).font(.headline)
        StatusPill(text: inst.pill.0, color: inst.pill.1, spinning: inst.state == "running" || inst.state == "busy")
        if let r { StatusPill(text: r.pill.0, color: r.pill.1, spinning: r.active) }
        if let p = model.pending["task:" + inst.id] { StatusPill(text: p, color: .orange, spinning: true) }
      }
      HStack(spacing: 6) {
        Text(t?.title ?? inst.template).font(.subheadline).foregroundStyle(.secondary)
        if t == nil { StatusPill(text: "Template missing", color: .orange) }
        if inst.schedules > 0 { StatusPill(text: Fmt.plural(inst.schedules, "schedule"), color: .blue) }
      }
      if !inst.stores.isEmpty { Text(inst.stores.joined(separator: ", ")).font(.footnote.monospaced()).foregroundStyle(.secondary) }
      ForEach(Array(inst.summary(t).prefix(2)), id: \.label) { row in LabeledContent(row.label, value: row.value).font(.subheadline).lineLimit(1) }
      HStack(spacing: 6) {
        if let w = r?.when { LabeledContent(w.label, value: w.value) } else { Text("Never run") }
        if r?.scheduled == true { StatusPill(text: "Scheduled") }
      }
      .font(.footnote).foregroundStyle(.secondary)
    }
  }
}

private struct TemplateRow: View {
  let t: TaskTemplate
  var body: some View {
    VStack(alignment: .leading, spacing: 3) {
      Text(t.title).font(.headline)
      HStack(spacing: 6) {
        Text(t.name).font(.footnote.monospaced()).foregroundStyle(.secondary)
        if t.hasPrompt { StatusPill(text: "Claude prompt", color: .blue) }
      }
      if !t.stores.isEmpty { Text(t.stores.joined(separator: ", ")).font(.footnote.monospaced()).foregroundStyle(.secondary) }
      if let e = t.error { LabeledContent("Broken task.json", value: e).font(.footnote).foregroundStyle(.red) }
      else if let d = t.description { Text(d).font(.subheadline) }
    }
  }
}

private struct ScheduleRow: View {
  @Environment(AppModel.self) private var model
  let s: TaskSchedule
  let name: String
  var body: some View {
    HStack {
      VStack(alignment: .leading, spacing: 3) {
        Text(name).font(.headline)
        Text(s.text).font(.subheadline)
        if s.enabled, let n = s.nextAt { LabeledContent("Next run", value: Fmt.fromNow(n)).font(.footnote).foregroundStyle(.secondary) }
      }
      Spacer()
      if let p = model.pending["sched:" + s.id] { HStack { ProgressView(); Text(p).font(.footnote) } }
      else {
        Toggle("On", isOn: Binding(get: { s.enabled }, set: { v in Task { await model.setSchedule(s, enabled: v) } })).labelsHidden()
          .accessibilityIdentifier("sw-\(s.id)")
      }
    }
  }
}
