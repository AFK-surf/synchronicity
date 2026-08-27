import SwiftUI

/// Connect on launch, follow the folder list, and load versions on selection.
struct BrowserLifecycle: ViewModifier {
  @Environment(NodeStore.self) private var node
  let model: FilesModel

  func body(content: Content) -> some View {
    content
      .task {
        node.connectOnLaunch()
        // And adopt whatever is already known. `onChange(of: node.spaces)`
        // only fires when the list *changes*, so the second browser window —
        // ⌘N, File ▸ New Window, the menu bar's Open Files — opened with no
        // folder selected and drew "Nothing here yet" over a daemon that had
        // folders in it.
        model.adoptFirstSpaceIfNeeded(node.spaces)
      }
      .onChange(of: node.listingGeneration) { _, _ in Task { await model.reload() } }
      .onChange(of: node.spaces) { _, spaces in model.adoptFirstSpaceIfNeeded(spaces) }
      .onChange(of: node.connection) { _, connection in
        if connection.isConnected { Task { await model.reload() } }
      }
      // No `onChange(of: selection)` loading versions here.
      //
      // `model.versions` is read in exactly one place — the inspector's
      // Versions tab — and that tab already loads itself with `.task(id:)`, so
      // this was a second loader for the same data. It also ran when the panel
      // was closed and when the tab was Info or History, and `loadVersions` is
      // two daemon round trips that do not go through `enqueue`: arrow-keying
      // down a folder piled up a resolve and a status per row, concurrently,
      // against the daemon's global store mutex.
  }
}
