import SwiftUI
import UniformTypeIdentifiers

/// The browser once there is a daemon to browse: the banners that graduate out
/// of the Node window, the rows, and the drop target over both.
struct ConnectedBrowser: View {
  @Environment(NodeStore.self) private var node
  let model: FilesModel
  @Binding var addingSpace: Bool
  @State private var isDropTargeted = false

  var body: some View {
    VStack(spacing: 0) {
      // Two alarms graduate out of Settings ▸ Diagnostics: both silently break
      // trust or publishing, and a user who never opens Settings still needs to
      // be told.
      ForEach(node.alarms) { alarm in
        AlarmBanner(
          text: alarm.text,
          tint: alarm.isRecovery ? Theme.danger : Theme.warning,
          actionTitle: alarm.isRecovery ? "Open Node" : nil,
          // ``SettingsRoute``, not `openAppWindow`: a `Settings` scene has no
          // window id, so there is nothing for `openWindow` to name.
          action: alarm.isRecovery ? { SettingsRoute.open(.diagnostics) } : nil
        )
      }
      if !node.transfers.resumable.isEmpty {
        AlarmBanner(
          text: node.transfers.resumable.count == 1
            ? "One upload was interrupted. The daemon still has its parts."
            : "\(node.transfers.resumable.count) uploads were interrupted. The daemon still has their parts.",
          // A state colour, like the two banners around it. The accent belongs
          // to the button inside the banner and to nothing else.
          tint: Theme.warning,
          actionTitle: "Show Transfers",
          action: { model.showingTransfers = true }
        )
      }
      if node.loading.contains(.spaces), node.spaces.isEmpty {
        // Not "Add a space to get started" — the question has not been answered
        // yet. `connect()` publishes `.connected` before it runs the first
        // the space listing, and it has to: `refresh` is gated on the connection. So
        // between those two lines the app is connected with an empty list it
        // has never asked about — which on a first launch, and after the app's
        // own Stop, is every launch — and the whole first-run screen was drawn
        // over a daemon that had folders, then replaced by the file list.
        // The same test ``PinsPane`` and ``PinsSection`` make before
        // asserting an empty state of their own.
        ProgressView()
          .frame(maxWidth: .infinity, maxHeight: .infinity)
      } else if node.spaces.isEmpty {
        // A connected daemon with no folders used to show "Connect to your
        // daemon", which was both wrong and a dead end.
        FirstRunView(state: .noSpaces { addingSpace = true })
      } else {
        EntryTable(model: model)
      }
    }
    .overlay { if isDropTargeted { DropHighlight(canAccept: model.selectedSpace != nil) } }
    .onDrop(of: [UTType.fileURL], isTargeted: $isDropTargeted, perform: accept)
  }

  /// Only accepted where it can actually work. The old target lit up over
  /// the disconnected placeholder, reported the drop as accepted, and then
  /// silently discarded it.
  private func accept(_ providers: [NSItemProvider]) -> Bool {
    guard model.selectedSpace != nil else { return false }
    Task { @MainActor in
      let urls = await FileDropLoader.urls(from: providers)
      if !urls.isEmpty { model.upload(urls: urls) }
    }
    return true
  }
}

#if DEBUG
#Preview("Browsing") {
  let store = NodeStore.preview()
  return ConnectedBrowser(
    model: FilesModel.preview(rows: SampleData.rows, space: "notes", store: store),
    addingSpace: .constant(false))
    .environment(store)
    .frame(width: 850, height: 620)
}

#Preview("No spaces shared") {
  // A daemon that is connected and has nothing to browse. This used to be the
  // same dead-end screen as no daemon at all.
  let store = NodeStore.preview(spaces: [])
  // The real initialiser, not the harness: with no folders there is no folder
  // to have selected, and the harness always selects one.
  return ConnectedBrowser(model: FilesModel(store: store), addingSpace: .constant(false))
    .environment(store)
    .frame(width: 850, height: 620)
}

#Preview("Asking what there is") {
  // Connected, with the first space listing still in flight. The list is empty for
  // the same reason it is empty on every launch — nobody has asked yet — and
  // the screen above is what used to be drawn over it.
  let store = NodeStore.preview(spaces: [], loading: [.spaces])
  return ConnectedBrowser(model: FilesModel(store: store), addingSpace: .constant(false))
    .environment(store)
    .frame(width: 850, height: 620)
}

#Preview("Everything shouting at once") {
  // Three banners stacked over the rows: both node alarms, which are drawn
  // here as well as in Settings ▸ Diagnostics, and the interrupted upload.
  let store = NodeStore.preview(
    status: SampleData.alarmedStatus, resumable: SampleData.resumable)
  return ConnectedBrowser(
    model: FilesModel.preview(rows: SampleData.rows, space: "notes", store: store),
    addingSpace: .constant(false))
    .environment(store)
    .frame(width: 850, height: 620)
}

#Preview("Shouting, squeezed") {
  // At the 560pt floor ``BrowserSplit`` holds the browser to, minus the
  // sidebar's own minimum: the banner text has to wrap rather than clip.
  let store = NodeStore.preview(
    status: SampleData.alarmedStatus, resumable: SampleData.resumable)
  return ConnectedBrowser(
    model: FilesModel.preview(rows: SampleData.rows, space: "notes", store: store),
    addingSpace: .constant(false))
    .environment(store)
    .frame(width: 360, height: 620)
}
#endif
