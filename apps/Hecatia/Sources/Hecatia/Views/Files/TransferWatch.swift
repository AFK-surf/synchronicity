import SwiftUI

/// Opens the transfer popover when a transfer a person asked for begins.
struct TransferWatch: View {
  let queue: TransferQueue
  let model: FilesModel
  /// Only the window being looked at, and only if the preference says so.
  /// Every browser window shares one queue, so without this a download would
  /// pop a popover in each of them at once.
  let enabled: Bool

  var body: some View {
    Color.clear
      .onChange(of: queue.startedCount) { _, _ in
        guard enabled else { return }
        model.showingTransfers = true
      }
  }
}

#if DEBUG
/// A canvas for something that draws nothing.
///
/// ``TransferWatch`` is a behaviour, so on its own it previews as an empty
/// rectangle. The line here reads the flag the watch sets, and the buttons
/// start the two kinds of transfer it has to tell apart.
private struct TransferWatchHarness: View {
  let store: NodeStore
  let model: FilesModel
  let enabled: Bool

  var body: some View {
    VStack(spacing: Theme.Space.m) {
      Text(model.showingTransfers ? "The transfer list was opened" : "The transfer list is closed")
        .font(.headline)
      Text(store.transfers.summary).font(.caption).foregroundStyle(Theme.muted)
      Button("Download a File") { start(asked: true) }
      // Quick Look, a double-click and a drag out to Finder fetch their bytes
      // through this same queue, and none of them is a request to look at a
      // transfer list. A small file also finishes before the popover draws, so
      // this used to pop a panel that said "Nothing is transferring".
      Button("Fetch One for Quick Look") { start(asked: false) }
      Button("Close It Again") { model.showingTransfers = false }
    }
    .padding(Theme.Space.xl)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .background(TransferWatch(queue: store.transfers, model: model, enabled: enabled))
  }

  private func start(asked: Bool) {
    var transfer = Transfer(
      id: UUID(), direction: .download, name: "roadmap.pdf",
      space: "notes", path: "roadmap.pdf", total: 1_482_311)
    transfer.state = .running
    store.transfers.add(transfer, asked: asked) { _ in }
  }
}

#Preview("Watching") {
  let store = NodeStore.preview()
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes", store: store)
  return TransferWatchHarness(store: store, model: model, enabled: true)
    .frame(width: 420, height: 280)
}

#Preview("Not the window in front") {
  // Every browser window shares one queue, so the same start reaches every
  // watch there is and only the enabled one may act on it.
  let store = NodeStore.preview()
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes", store: store)
  return TransferWatchHarness(store: store, model: model, enabled: false)
    .frame(width: 420, height: 280)
}
#endif
