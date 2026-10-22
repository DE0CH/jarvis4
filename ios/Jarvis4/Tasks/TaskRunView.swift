// One run: its phase, why it failed or waits, its output and log (store values masked by the machine), refreshed every
// 2 s while it is queued or running. Stop drops a queued run or stops a running one and pauses the line.
import SwiftUI

struct TaskRunView: View {
  @Environment(AppModel.self) private var model
  let name: String
  let title: String
  @State private var run: TaskRun?
  @State private var log = ""
  @State private var output = ""
  @State private var error: String?
  @State private var stopping = false

  var body: some View {
    List {
      if let run {
        Section {
          HStack {
            StatusPill(text: run.pill.0, color: run.pill.1, spinning: run.active)
            Text(run.scheduled ? "Scheduled" : "Manual").font(.subheadline)
            if run.upgrade { StatusPill(text: "Latest image", color: .blue) }
          }
          if let d = run.createdAt { LabeledContent("Queued", value: Fmt.ago(d)) }
          if let d = run.ranAt { LabeledContent("Script started", value: Fmt.ago(d)) }
          if let d = run.finishedAt { LabeledContent("Finished", value: Fmt.ago(d)) }
          if let x = run.exitCode { LabeledContent("Exit code", value: "\(x)") }
          Text(run.runId).font(.footnote.monospaced()).foregroundStyle(.secondary)
          if let r = run.reason { ErrorRow(text: r) }
          if let w = run.waiting { LabeledContent { Text(w) } label: { Label("Waiting", systemImage: "hourglass") }.foregroundStyle(.orange) }
          if let error { ErrorRow(text: error) }
        }
        Section("Output") { MonoText(text: output.isEmpty ? (run.active ? "No output yet…" : "No output.") : output, id: "tr-output") }
        Section("Log") { MonoText(text: log.isEmpty ? (run.active ? "No log yet…" : "No log.") : log, id: "tr-log") }
      } else if let error { ErrorRow(text: error) }
    }
    .overlay { if run == nil && error == nil { ProgressView("Loading the run…") } }
    .navigationTitle(title)
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      if run?.active == true {
        ToolbarItem(placement: .primaryAction) {
          Button(stopping ? "Stopping…" : "Stop", role: .destructive) { Task { await stop() } }.disabled(stopping).accessibilityIdentifier("tr-stop")
        }
      }
    }
    .task {
      while !Task.isCancelled {
        do { let r = try await get(); error = nil; if !r.active { await model.loadTasks(); break } }
        catch { self.error = errText(error) }
        try? await Task.sleep(for: .seconds(2))
      }
    }
  }

  @discardableResult private func get() async throws -> TaskRun {
    let j = try await RouterClient.shared.get("api/tasks/runs/\(name.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? name)")
    let r = TaskRun(j: j["run"])
    run = r; log = j["log"].string ?? ""; output = j["output"].string ?? ""
    return r
  }
  private func stop() async {
    guard await model.confirm("Stop this run?", "It stays in the history as stopped.", action: "Stop", destructive: true) else { return }
    stopping = true
    defer { stopping = false }
    do {
      try await RouterClient.shared.call("POST", "api/tasks/runs/\(name.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? name)/stop")
      for _ in 0..<15 { if !(try await get().active) { break }; try? await Task.sleep(for: .seconds(1)) }
    } catch { self.error = errText(error) }
  }
}

struct MonoText: View {
  let text: String
  let id: String
  var body: some View {
    ScrollView(.horizontal) {
      Text(text).font(.caption.monospaced()).textSelection(.enabled).fixedSize(horizontal: true, vertical: false)
    }
    .accessibilityIdentifier(id)
  }
}
