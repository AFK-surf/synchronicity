import SwiftUI

/// Opening another of the app's windows, from inside the AppKit-hosted split.
///
/// `@Environment(\.openWindow)` is a *scene* action: SwiftUI hands it down the
/// scene's own view tree, and an `NSHostingController` built by hand is not on
/// that tree. Everything inside ``BrowserSplit`` is behind one, so the sidebar
/// and the first-run screen would have got the empty default and their buttons
/// would have done nothing at all — silently, which is the worst way for it to
/// go wrong.
///
/// So the browser window captures the real action once, where it still has
/// one, and passes it across the boundary as a plain closure.
struct OpenAppWindow: Sendable {
  let run: @MainActor @Sendable (String) -> Void
  @MainActor func callAsFunction(id: String) { run(id) }
}

private struct OpenAppWindowKey: EnvironmentKey {
  static let defaultValue = OpenAppWindow { _ in }
}

extension EnvironmentValues {
  var openAppWindow: OpenAppWindow {
    get { self[OpenAppWindowKey.self] }
    set { self[OpenAppWindowKey.self] = newValue }
  }
}
