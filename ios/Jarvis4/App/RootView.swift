// The window: the tabs, and above them what the model asks for — Reset or recover, a review sheet, a question, an
// error, a short notice. A signed-out app shows one screen that opens the sign-in sheet again.
import SwiftUI

struct RootView: View {
  @Environment(AppModel.self) private var model

  var body: some View {
    @Bindable var model = model
    Group {
      if model.signedOut && !model.loaded {
        SignedOutView()
      } else {
        MainTabs()
      }
    }
    .fullScreenCover(isPresented: $model.showSetup) { SetupView() }
    .fullScreenCover(isPresented: $model.showNextSetup) { SetupView(next: true) }
    .sheet(item: $model.secure, onDismiss: model.secureDismissed) { req in ReviewSheet(request: req) }
    .sheet(item: $model.accountSwitch) { a in SwitchAccountView(sessionId: a.id) }
    .alert(model.question?.title ?? "", isPresented: Binding(get: { model.question != nil }, set: { if !$0 { model.question = nil } }), presenting: model.question) { q in
      QuestionActions(question: q)
    } message: { q in
      if !q.message.isEmpty { Text(q.message) }
    }
    .alert("Something went wrong", isPresented: Binding(get: { model.failure != nil }, set: { if !$0 { model.failure = nil } })) {
      Button("OK", role: .cancel) {}
    } message: {
      Text(model.failure ?? "")
    }
    .overlay(alignment: .bottom) { NoticeView() }
  }
}

/// the alert's buttons; a text field when the question takes one (a resume prompt, a title typed to confirm)
private struct QuestionActions: View {
  @Environment(AppModel.self) private var model
  let question: Ask
  @State private var text = ""

  var body: some View {
    if let input = question.input {
      TextField(input.placeholder, text: $text)
        .accessibilityIdentifier("ask-text")
    }
    Button(question.action, role: question.destructive ? .destructive : nil, action: answerYes)
      .disabled(question.input?.match.map { text != $0 } ?? false)
      .accessibilityIdentifier("ask-ok")
    Button("Cancel", role: .cancel, action: answerNo)
  }

  private func answerYes() { let q = question; model.question = nil; q.answer(text) }
  private func answerNo() { let q = question; model.question = nil; q.answer(nil) }
}

/// a short note at the bottom, gone after a few seconds
private struct NoticeView: View {
  @Environment(AppModel.self) private var model
  var body: some View {
    if let n = model.notice {
      Text(n.text)
        .font(.subheadline)
        .padding(.horizontal, 16).padding(.vertical, 10)
        .glassEffect(.regular, in: .capsule)
        .padding(.bottom, 64)
        .transition(.opacity)
        .accessibilityIdentifier("notice")
        .task(id: n.id) {
          try? await Task.sleep(for: .seconds(3))
          if model.notice?.id == n.id { model.notice = nil }
        }
    }
  }
}

/// Cloudflare Access refused the login and the sign-in sheet didn't complete
private struct SignedOutView: View {
  @Environment(AppModel.self) private var model
  @State private var busy = false
  var body: some View {
    ContentUnavailableView {
      Label("Signed out", systemImage: "person.crop.circle.badge.exclamationmark")
    } description: {
      Text("Sign in with your Cloudflare login (Google or an email code).")
    } actions: {
      Button(busy ? "Signing in…" : "Sign in", action: signIn)
        .buttonStyle(.borderedProminent)
        .disabled(busy)
        .accessibilityIdentifier("sign-in")
    }
  }
  private func signIn() {
    busy = true
    Task {
      if !(await RouterClient.shared.signIn()).isEmpty { model.signedOut = false; await model.refresh() }
      busy = false
    }
  }
}
