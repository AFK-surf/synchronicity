import SwiftUI

/// Which page the Settings window is showing, as something that can be written
/// — and opened — from outside it.
///
/// Three places send someone here at a particular page: the first-run screen's
/// "Use a Different Zone…", the alarm banner's recovery action, and the browser
/// sidebar's connection footer. A fourth, the folder list's context menu, asks
/// from an `@objc` AppKit callback with no SwiftUI environment at all.
///
/// None of them can open the window the ordinary way. `openSettings` is a
/// *scene* action, handed down a scene's own view tree; everything inside
/// ``BrowserSplit`` lives in an `NSHostingController` built by hand, which is
/// not on that tree — the same reason ``OpenAppWindow`` exists — and an `@objc`
/// callback is not in a view at all.
///
/// This class holds the target page, and a closure that a view still on the
/// scene tree installs for everyone else to call. ``SettingsOpener`` is that
/// view.
///
/// The obvious shortcut does not work, and was measured not working:
/// `NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)`
/// opens nothing and makes SwiftUI log "Please use SettingsLink for opening the
/// Settings scene." The probe caught it as
/// `[settings] no window titled "Synchronicity Settings"` — three entry points
/// that looked wired and did nothing when pressed.
@MainActor
@Observable
final class SettingsRoute {
  var pane: SettingsPane

  init(pane: SettingsPane = .initial) {
    self.pane = pane
  }

  /// The one route the app's Settings scene reads.
  static let shared = SettingsRoute()

  /// How to bring the Settings window up, installed by ``SettingsOpener`` from
  /// somewhere that still has the scene's `openSettings` action.
  ///
  /// Not observed: nothing draws from it, and re-installing it on every scene
  /// that appears would otherwise invalidate every view reading this object.
  @ObservationIgnored var present: (@MainActor () -> Void)?

  /// Show the Settings window on `pane`, from anywhere on the main actor.
  ///
  /// The page is set first, so the window opens already showing it rather than
  /// opening on the last page and then moving.
  static func open(_ pane: SettingsPane) {
    shared.pane = pane
    shared.present?()
  }
}

/// Lends ``SettingsRoute`` the scene action it cannot reach on its own.
///
/// Applied to the root of every scene that has one, because any of them may be
/// the only one open: the browser is where three of the four callers live, and
/// the menu bar item is what remains when every window is closed.
struct SettingsOpener: ViewModifier {
  @Environment(\.openSettings) private var openSettings

  func body(content: Content) -> some View {
    content.onAppear {
      // Captured once per scene appearance. Every scene installs the same
      // behaviour, so whichever installed last is as good as any other.
      SettingsRoute.shared.present = { openSettings() }
    }
  }
}

extension View {
  /// See ``SettingsOpener``.
  func lendsSettingsAction() -> some View { modifier(SettingsOpener()) }
}

private struct SettingsRouteKey: EnvironmentKey {
  /// `nil` outside the Settings scene. Everywhere else calls
  /// ``SettingsRoute/open(_:)``, which does not need the window to exist yet;
  /// handing those callers a default instance would give them one nothing
  /// reads.
  static let defaultValue: SettingsRoute? = nil
}

extension EnvironmentValues {
  /// The selected page, for a view already inside the Settings window — a page
  /// that sends the reader to another page.
  var settingsRoute: SettingsRoute? {
    get { self[SettingsRouteKey.self] }
    set { self[SettingsRouteKey.self] = newValue }
  }
}

#if DEBUG
/// The window in miniature: something outside the sidebar writing the page,
/// and the sidebar reading it back.
private struct SettingsRoutePreview: View {
  @State private var route = SettingsRoute(pane: .general)

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.m) {
      Text("Showing \(route.pane.rawValue)").font(.headline)
      Text("The four entries into these pages are outside this scene, so what they write is this object rather than a selection.")
        .font(.callout).foregroundStyle(Theme.muted)
        .fixedSize(horizontal: false, vertical: true)
      HStack(spacing: Theme.Space.s) {
        Button("Members") { route.pane = .members }
        Button("Network") { route.pane = .network }
        Button("Diagnostics") { route.pane = .diagnostics }
      }
    }
    .padding(Theme.Space.xl)
    .frame(width: 460, alignment: .leading)
  }
}

#Preview("Writing the page from outside") {
  SettingsRoutePreview()
}
#endif
