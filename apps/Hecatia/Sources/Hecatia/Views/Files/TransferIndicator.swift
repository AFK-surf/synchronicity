import SwiftUI

/// What is transferring, in the status area beside the item count.
///
/// Its own view, observing the queue, for the reason ``TransfersPopover`` is:
/// `NodeStore.transfers` is a plain `let`, so reading it through the store
/// subscribes to nothing and the bar advanced only when something else
/// published.
struct TransferIndicator: View {
  let model: FilesModel
  let queue: TransferQueue

  var body: some View {
    let active = queue.active
    if let first = active.first {
      Button {
        model.showingTransfers = true
      } label: {
        HStack(spacing: Theme.Space.snug) {
          ProgressView(value: first.progress).controlSize(.small).frame(width: 54)
          Text(active.count == 1 ? first.name : "\(active.count) transfers")
            .font(.caption).lineLimit(1).truncationMode(.middle)
        }
      }
      .buttonStyle(.borderless)
      .help(active.count == 1 ? first.statusLabel : queue.summary)
      .accessibilityLabel("Transfers: \(queue.summary). Open the transfer list")
    }
  }
}

#if DEBUG
#Preview("One transfer") {
  let store = NodeStore.preview(transfers: SampleData.transfers)
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes", store: store)
  return TransferIndicator(model: model, queue: store.transfers)
    .padding()
    .frame(width: 320)
}

#Preview("Two at once") {
  // Two in flight is what makes the label count them instead of naming one,
  // and the sample queue only ever has the one running.
  var second = Transfer(
    id: UUID(), direction: .download, name: "family-2019.tar",
    space: "archive", path: "2019.tar", total: 8_400_000_000)
  second.bytes = 2_100_000_000
  second.state = .running
  let store = NodeStore.preview(transfers: SampleData.transfers + [second])
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes", store: store)
  return TransferIndicator(model: model, queue: store.transfers)
    .padding()
    .frame(width: 320)
}

#Preview("Narrow") {
  // It sits at the trailing end of the status bar, which is as narrow as the
  // window is: the bar keeps its width and the name truncates in the middle.
  let store = NodeStore.preview(transfers: SampleData.transfers)
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes", store: store)
  return TransferIndicator(model: model, queue: store.transfers)
    .padding()
    .frame(width: 150)
}

#Preview("Nothing transferring") {
  // With nothing in flight it draws nothing at all, and the status bar is left
  // with its item count. The rule is the space it would have occupied.
  let store = NodeStore.preview()
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes", store: store)
  return TransferIndicator(model: model, queue: store.transfers)
    .padding()
    .frame(width: 320, height: 44)
    .border(Theme.line)
}
#endif
