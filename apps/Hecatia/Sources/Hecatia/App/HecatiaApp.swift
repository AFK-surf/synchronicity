import SwiftUI

/// Four scenes, one of which is the app.
@main
struct HecatiaApp: App {
  /// One store per data directory. Every window reads it; only browsing state
  /// is per-window.
  @State private var node = NodeStore()
  /// Which page Settings is showing. Held here because it outlives the
  /// window — the entries into it write a page whether or not it is open.
  @State private var route = SettingsRoute.shared

  init() {
    #if DEBUG
    WindowSnapshot.scheduleIfAsked()
    MainActorWatchdog.startIfAsked()
    FocusTrace.startIfAsked()
    #endif
  }

  var body: some Scene {
    WindowGroup("Files", id: "files") {
      FilesWindow(store: node)
        .environment(node)
        // Hands `SettingsRoute` the scene's `openSettings`, which is the only
        // thing that opens that window — three of the four callers are inside
        // this one's AppKit-hosted split and cannot reach it themselves.
        .lendsSettingsAction()
        .frame(minWidth: 860, minHeight: 520)
    }
    .defaultSize(width: 1080, height: 700)
    .commands { AppCommands() }

    // A singleton: there is one daemon, so there is one log of what has been
    // asked of it. It is also a page of Settings, and both exist because a
    // live log is read beside the browser it explains.
    //
    // It carries no `keyboardShortcut` of its own: the Go menu already gives
    // it one, and a shortcut declared in both places puts the same key
    // equivalent on two different menu items — ⇧⌘A was on Window ▸ Activity
    // and on Go ▸ Activity at the same time.
    Window("Activity", id: "activity") {
      ActivityWindow()
        .environment(node)
        .frame(minWidth: 700, minHeight: 420)
    }
    .defaultSize(width: 900, height: 560)

    // The operator console, as the settings window it always was. ⌘, is the
    // only shortcut it needs; Go ▸ Node ⌘2 went with the scene it opened.
    Settings {
      PreferencesView(route: route).environment(node)
    }

    // Also lends the action, because this is the one scene that is still there
    // when every window has been closed.
    MenuBarExtra("Synchronicity", systemImage: menuBarIcon) {
      NodeGlance().environment(node).lendsSettingsAction()
    }
    .menuBarExtraStyle(.menu)
  }

  private var menuBarIcon: String {
    if !node.connection.isConnected {
      "arrow.triangle.2.circlepath.circle"
    } else if !node.alarms.isEmpty {
      "exclamationmark.triangle.fill"
    } else {
      "arrow.triangle.2.circlepath.circle.fill"
    }
  }
}
