import SwiftUI

/// The one alert, carrying the daemon's own words.
///
/// Applied to every window that can raise one, not only to the browser. It was
/// on the browser alone, and `node.alert` is written by every non-quiet failure
/// anywhere — so every button in every Node pane failed silently when no
/// browser was open, and the message then fired over an unrelated window the
/// next time one appeared.
///
/// Which window shows it is decided once, in an `onChange`, rather than by a
/// continuously-evaluated binding: a macOS alert is a sheet, and once it is up
/// the sheet is key and its host drops to `.active` — so a test on
/// `controlActiveState` inside the `isPresented` getter would tear the alert
/// straight back down.
struct DaemonAlert: ViewModifier {
  @Environment(NodeStore.self) private var node
  @Environment(\.controlActiveState) private var activeState
  @State private var showing: DaemonFailure?

  func body(content: Content) -> some View {
    content
      .onChange(of: node.alert) { _, failure in take(failure) }
      // And when this window *becomes* the key one, in case the failure
      // arrived while the app was in the background and no window took it.
      .onChange(of: activeState) { _, _ in take(node.alert) }
      .alert(
        showing?.title ?? "Synchronicity",
        isPresented: Binding(get: { showing != nil }, set: { if !$0 { showing = nil } }),
        presenting: showing
      ) { _ in
      } message: { failure in
        Text(failure.recoverySuggestion.map { "\(failure.detail)\n\n\($0)" } ?? failure.detail)
      }
  }

  private func take(_ failure: DaemonFailure?) {
    guard let failure, showing == nil, activeState == .key else { return }
    showing = failure
    // Cleared only once a window has actually taken it, so a failure raised
    // while the app is in the background waits rather than vanishing.
    node.alert = nil
  }
}

#if DEBUG
/// A window in miniature: something that fails, and the modifier that says
/// what the daemon answered.
private struct DaemonAlertPreview: View {
  @Environment(NodeStore.self) private var node

  var body: some View {
    VStack(spacing: Theme.Space.m) {
      Text("Every window that can raise a failure carries this modifier, and the key one takes it.")
        .font(.callout)
        .foregroundStyle(Theme.muted)
        .multilineTextAlignment(.center)
        .fixedSize(horizontal: false, vertical: true)
      Button("Fail Something") {
        node.alert = DaemonFailure(
          code: .notFound,
          detail: "no space `notes`: not a local space",
          operation: "upload notes.zip")
      }
    }
    .padding(Theme.Space.section)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .modifier(DaemonAlert())
  }
}

#Preview("Nothing raised") {
  DaemonAlertPreview()
    .environment(NodeStore.preview())
    .frame(width: 520, height: 260)
}

#Preview("A failure already waiting") {
  // Seeded before the view exists, so `onChange(of: node.alert)` never fires
  // for it: what raises this one is the window becoming key, which is the same
  // path a failure that arrived while the app was in the background takes.
  let store = NodeStore.preview()
  store.alert = DaemonFailure(
    code: .unavailable,
    detail: "Nothing is listening on the control socket.",
    operation: "sync now")
  return DaemonAlertPreview()
    .environment(store)
    .frame(width: 520, height: 260)
}
#endif
