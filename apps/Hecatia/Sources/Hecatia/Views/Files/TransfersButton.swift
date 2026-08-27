import SwiftUI

struct TransfersButton: View {
  @Bindable var model: FilesModel
  /// Observed here, because nothing else observes it. ``TransferQueue`` is a
  /// plain `let` on `NodeStore`, so its own `objectWillChange` reached no view
  /// at all: the glyph, the progress bars and every byte count only redrew
  /// when something unrelated happened to publish on the store.
  let queue: TransferQueue

  var body: some View {
    // Always present, whether or not anything is transferring. It used to
    // exist only while a transfer did, so starting one grew the toolbar and
    // reflowed everything around it.
    Button { model.showingTransfers.toggle() } label: {
      Label(
        "Transfers",
        systemImage: queue.hasActive
          ? "arrow.up.arrow.down.circle.fill" : "arrow.up.arrow.down.circle")
    }
    .help(queue.summary)
    .accessibilityLabel("Transfers: \(queue.summary)")
    .popover(isPresented: $model.showingTransfers, arrowEdge: .bottom) {
      TransfersPopover()
    }
  }
}

#if DEBUG
#Preview("Something transferring") {
  let store = NodeStore.preview(transfers: SampleData.transfers)
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes", store: store)
  return NavigationStack {
    Color.clear.toolbar {
      ToolbarItem(placement: .primaryAction) {
        TransfersButton(model: model, queue: store.transfers)
      }
    }
  }
  .environment(store)
  .frame(width: 560, height: 160)
}

#Preview("Nothing transferring") {
  // The same button, and it is still there. It used to exist only while a
  // transfer did, so starting one grew the toolbar and moved everything else
  // along it.
  let store = NodeStore.preview()
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes", store: store)
  return NavigationStack {
    Color.clear.toolbar {
      ToolbarItem(placement: .primaryAction) {
        TransfersButton(model: model, queue: store.transfers)
      }
    }
  }
  .environment(store)
  .frame(width: 560, height: 160)
}
#endif
