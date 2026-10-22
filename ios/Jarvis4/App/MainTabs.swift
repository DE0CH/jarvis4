// The tabs: a tab bar on iPhone, a sidebar on iPad (sidebarAdaptable). Search is the system's search tab. Previous
// sessions sit under Sessions (its toolbar), Stores, Machines and Repos under Settings, task schedules under Tasks.
import SwiftUI

struct MainTabs: View {
  @Environment(AppModel.self) private var model

  var body: some View {
    @Bindable var model = model
    TabView(selection: $model.tab) {
      Tab("Sessions", systemImage: "rectangle.stack", value: AppTab.sessions) { SessionsView() }
      Tab("Inbox", systemImage: "tray", value: AppTab.inbox) { InboxView() }
        .badge(model.inboxCount)
      Tab("Tasks", systemImage: "checklist", value: AppTab.tasks) { TasksView() }
      Tab("Settings", systemImage: "gear", value: AppTab.settings) { SettingsView() }
      Tab(value: AppTab.search, role: .search) { SearchView() }
    }
    .tabViewStyle(.sidebarAdaptable)
    .onChange(of: model.tab) { _, t in
      Task {
        switch t {
        case .tasks: await model.loadTasks(); await model.loadStores()
        case .settings: await model.loadStores()
        default: break
        }
      }
    }
  }
}
