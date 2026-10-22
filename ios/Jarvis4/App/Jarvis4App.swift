// Jarvis 4 on iPhone and iPad: one native SwiftUI app (Deyao, 2026-10-11). The keys stay in the Secure Enclave and the
// Keychain (Security/), what the phone signs is rendered from the signed content and signed under Face ID (Review/),
// and the router is an ordinary network path (Network/RouterClient.swift).
import SwiftUI

@main
struct Jarvis4App: App {
  @State private var model = AppModel()
  @Environment(\.scenePhase) private var phase

  var body: some Scene {
    WindowGroup {
      RootView()
        .environment(model)
        .task { await model.launch() }
    }
    .onChange(of: phase) { _, p in if p == .active { model.foreground() } }
  }
}
