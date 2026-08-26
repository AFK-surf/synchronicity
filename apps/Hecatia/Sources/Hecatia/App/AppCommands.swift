import SwiftUI

/// The menu bar.
///
/// This is where completeness gets to be free: an operation that has a menu
/// item costs no pixels in any window, and every file action finally has a
/// keyboard path — the old app hid all three behind a right-click with no
/// shortcut, no menu and no selection binding at all.
@MainActor
struct AppCommands: Commands {
  @FocusedValue(\.filesModel) private var files
  @Environment(\.openWindow) private var openWindow

  var body: some Commands {
    CommandGroup(replacing: .newItem) {
      Button("New Window") { openWindow(id: "files") }
        .keyboardShortcut("n", modifiers: .command)
      Divider()
      Button("Add Files…") { files?.importRequested = true }
        .keyboardShortcut("o", modifiers: .command)
        .disabled(files?.selectedSpace == nil)
    }

    CommandGroup(after: .saveItem) {
      // Both are disabled while the daemon is unreachable, which is what the
      // same two commands in the table's context menu already did. Enabled,
      // they queued a command against nothing and reported nothing.
      // Disabled while one is running as well as while the daemon is
      // unreachable: both take a while and neither shows anything outside
      // Activity, so pressing again simply queued a second whole run.
      Button(files?.store.houseworkRunning == true ? "Scanning…" : "Scan Now") {
        files?.store.scanNow()
      }
      .keyboardShortcut("r", modifiers: .command)
      .disabled(files?.store.connection.isConnected != true || files?.store.houseworkRunning == true)
      Button(files?.store.houseworkRunning == true ? "Working…" : "Sync Now") {
        files?.store.syncNow()
      }
      .keyboardShortcut("r", modifiers: [.command, .shift])
      .disabled(files?.store.connection.isConnected != true || files?.store.houseworkRunning == true)

      // Was reachable only from an ellipsis menu in the toolbar, which cost a
      // slot the toolbar did not have and hid the command from anyone looking
      // for it where Mac commands live.
      Button("Compare With Another Device…") { files?.compareRequested = true }
        .keyboardShortcut("d", modifiers: [.command, .shift])
        .disabled(files?.selectedSpace == nil)
        .disabled(files == nil)
    }

    CommandMenu("Go") {
      Button("Back") { files?.goBack() }
        .keyboardShortcut("[", modifiers: .command)
        .disabled(files?.canGoBack != true)
      Button("Forward") { files?.goForward() }
        .keyboardShortcut("]", modifiers: .command)
        .disabled(files?.canGoForward != true)
      // The daemon has no change notification, so the window looks on a timer
      // — and this is the way to not wait for it.
      Button("Refresh This Space") { if let files { Task { await files.reload() } } }
        .keyboardShortcut("r", modifiers: [.command, .option])
        .disabled(files?.selectedSpace == nil)
      Divider()
      Button("Enclosing Folder") { files?.goUp() }
        .keyboardShortcut(.upArrow, modifiers: .command)
        .disabled(files?.canGoUp != true)
      Divider()
      // No Node item. Those eight panes are pages of Settings now, which the
      // app menu already opens on ⌘, — and a second menu item for the same
      // window under a different name is how ⌘2 ended up on two of them.
      //
      // Not a window: the transfer list is a popover on the browser's toolbar,
      // so this opens it in whichever browser is focused.
      Button("Find…") { files?.openSearch() }
        .keyboardShortcut("f", modifiers: .command)
        .disabled(files == nil)

      Button("Transfers") { files?.showingTransfers = true }
        .keyboardShortcut("t", modifiers: [.command, .shift])
        .disabled(files == nil)
      Button("Activity") { openWindow(id: "activity") }
        .keyboardShortcut("a", modifiers: [.command, .shift])
    }

    CommandMenu("Version") {
      Button("Newest") { files?.policy = .newest }
        .disabled(files == nil)
      Button("Strict") { files?.policy = .strict }
        .disabled(files == nil)
      Divider()
      // Opens the panel *on the Versions tab*, on a row that has versions —
      // it used to open it on whichever tab was last used, usually Info — and
      // closes it again, like every other panel toggle on this platform.
      Button(files?.inspectorVisible == true ? "Hide Versions" : "Show Versions") {
        files?.toggleVersionsPanel()
      }
      .keyboardShortcut("i", modifiers: [.command, .option])
      .disabled(files == nil)

      // Space is the shortcut people reach for, and it is handled where a
      // table will actually give it up — see `QuickLookKeyMonitor`. This is
      // the menu entry that makes the feature discoverable at all, on the
      // second shortcut Finder offers for it.
      Button("Quick Look") {
        if let entry = files?.previewableSelection { files?.requestPreview(entry) }
      }
      .keyboardShortcut("y", modifiers: .command)
      .disabled(files?.previewableSelection == nil)
    }

    // No `InspectorCommands()` beside it. That group drives SwiftUI's
    // `.inspector`, and the versions panel is an AppKit
    // `NSSplitViewItem(inspectorWithViewController:)` now — so View ▸ Show
    // Inspector was a menu item with nothing behind it. The panel's entry is
    // the Show/Hide Versions item below, which also opens it on the right tab.
    SidebarCommands()
    ToolbarCommands()
  }
}
