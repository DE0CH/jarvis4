// New / edit a task's daily schedule: which task, daily at a time in a time zone. Saving never fires a slot that has
// already passed today.
import SwiftUI

struct TaskScheduleEditView: View {
  @Environment(AppModel.self) private var model
  @Environment(\.dismiss) private var dismiss
  let scheduleId: String?
  let instanceId: String?
  @State private var instance = ""
  @State private var time = Calendar.current.date(from: DateComponents(hour: 9, minute: 0)) ?? .now
  @State private var tz = "Europe/London"
  @State private var enabled = true
  @State private var started = false
  @State private var busy = false
  @State private var error: String?

  static let zones = ["Europe/London", "Asia/Shanghai", "Asia/Hong_Kong", "UTC"]
  private var cur: TaskSchedule? { scheduleId.flatMap { id in model.tasks.schedules.first { $0.id == id } } }

  var body: some View {
    if scheduleId != nil && cur == nil {
      ContentUnavailableView("This schedule no longer exists", systemImage: "calendar")
    } else {
      Form {
        Section("Task") {
          if cur != nil || instanceId != nil {
            Text(model.tasks.instances.first { $0.id == instance }?.name ?? "(deleted task)")
          } else if model.tasks.instances.isEmpty {
            Text("No tasks yet: make one first.").foregroundStyle(.secondary)
          } else {
            Picker("Task", selection: $instance) {
              Text("Pick one").tag("")
              ForEach(model.tasks.instances) { i in Text(i.name).tag(i.id) }
            }
            .accessibilityIdentifier("se-task")
          }
        }
        Section {
          DatePicker("Daily at", selection: $time, displayedComponents: .hourAndMinute).accessibilityIdentifier("se-time")
          Picker("Time zone", selection: $tz) {
            ForEach(Array(Set(Self.zones + [TimeZone.current.identifier, tz])).sorted(), id: \.self) { z in Text(z.replacing("_", with: " ")).tag(z) }
          }
          .accessibilityIdentifier("se-tz")
          Toggle(enabled ? "Runs every day" : "Paused", isOn: $enabled).accessibilityIdentifier("se-enabled")
        } footer: { Text("Daylight saving is followed. A slot missed by more than 2 h (router down) is skipped.") }
        if let error { Section { ErrorRow(text: error, id: "se-err") } }
        if let cur {
          Section {
            Button("Delete schedule", role: .destructive) {
              Task { if await model.deleteSchedule(cur, name: model.tasks.instances.first { $0.id == cur.instance }?.name ?? "task") { dismiss() } }
            }
            .accessibilityIdentifier("se-delete")
          }
        }
      }
      .navigationTitle(cur == nil ? "New schedule" : "Edit schedule")
      .navigationBarTitleDisplayMode(.inline)
      .toolbar {
        ToolbarItem(placement: .confirmationAction) { Button(busy ? "Saving…" : "Save") { Task { await save() } }.disabled(busy).accessibilityIdentifier("se-save") }
      }
      .task { start() }
    }
  }

  private func start() {
    guard !started else { return }
    started = true
    if let cur {
      instance = cur.instance; tz = cur.tz; enabled = cur.enabled
      let p = cur.time.split(separator: ":").compactMap { Int($0) }
      if p.count == 2, let d = Calendar.current.date(from: DateComponents(hour: p[0], minute: p[1])) { time = d }
    } else {
      instance = instanceId ?? (model.tasks.instances.count == 1 ? model.tasks.instances[0].id : "")
    }
  }
  private func save() async {
    error = nil
    guard !instance.isEmpty else { error = "Pick a task."; return }
    let c = Calendar.current.dateComponents([.hour, .minute], from: time)
    let hhmm = String(format: "%02d:%02d", c.hour ?? 9, c.minute ?? 0)
    busy = true
    defer { busy = false }
    do {
      if let cur {
        try await RouterClient.shared.call("PUT", "api/tasks/schedules/\(cur.id)", ["time": hhmm, "tz": tz, "enabled": enabled])
      } else {
        try await RouterClient.shared.call("POST", "api/tasks/schedules", ["instance": instance, "time": hhmm, "tz": tz, "enabled": enabled])
      }
      await model.loadTasks()
      dismiss()
    } catch { self.error = errText(error) }
  }
}
