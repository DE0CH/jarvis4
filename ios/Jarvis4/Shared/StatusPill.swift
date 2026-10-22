// A small coloured capsule for a state ("idle", "needs you", "paused"), as Apple's apps tag rows.
import SwiftUI

struct StatusPill: View {
  let text: String
  var color: Color = .secondary
  var spinning = false
  var body: some View {
    HStack(spacing: 4) {
      if spinning { ProgressView().controlSize(.mini) }
      Text(text).font(.caption.weight(.medium)).lineLimit(1)
    }
    .padding(.horizontal, 8).padding(.vertical, 3)
    .foregroundStyle(color)
    .background(color.opacity(0.14), in: .capsule)
    .accessibilityElement(children: .combine)
  }
}

extension Session {
  /// the pill: what the router is doing, the machine's own status (working / needs you / idle), or the state
  var pill: (text: String, color: Color, spin: Bool) {
    // what the router is doing, with what it waits on (e.g. "upgrading: uploading snapshot 1.2/3.4 GB, 40 MB/s, 55 s left")
    if let b = serverBusy, state != "destroying" { return (waiting.map { "\(b.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "…"))): \($0)" } ?? b.lowercased(), .orange, true) }
    switch state {
    case "failed": return ("failed", .red, false)
    case "paused": return hasSchedule ? ("scheduled", .blue, false) : ("paused", .secondary, false)
    case "approval": return ("needs approval", .blue, false)
    case "starting", "initialising", "pausing", "resuming", "destroying":
      let base = ["starting": "starting…", "initialising": "initialising…", "pausing": "pausing…", "resuming": "resuming…", "destroying": "destroying…"][state] ?? state
      return (waiting.map { "\(state): \($0)" } ?? base, state == "destroying" ? .red : .orange, true)
    case "started":
      if oneShotDone { return ("done · archiving…", .orange, true) }
      guard let s = status else { return ("booting…", .orange, true) }
      switch s {
      case "busy": return ("working", .orange, false)
      case "waiting": return ("needs you", .red, false)
      case "idle": return bgTasks > 0 ? ("idle · \(bgTasks) background", .orange, false) : ("idle", .green, false)
      default: return (s, .green, false)
      }
    default: return (state, .secondary, false)
    }
  }
  /// the section a session is listed under: a paused session that will wake on its own is not "just paused"
  var group: String {
    switch state {
    case "paused": hasSchedule ? "Scheduled" : "Paused"
    case "failed": "Failed"
    default: "Running"
    }
  }
}
