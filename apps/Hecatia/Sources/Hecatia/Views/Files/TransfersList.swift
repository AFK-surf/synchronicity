import SwiftUI

struct TransfersList: View {
  let queue: TransferQueue

  private var rowDivider: some View {
    Divider().padding(.leading, TransfersPopover.textInset)
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      HStack {
        Text(queue.summary).font(.headline)
        Spacer()
        if queue.transfers.contains(where: \.isFinished) {
          Button("Clear") { queue.clearFinished() }
            .buttonStyle(.borderless).font(.caption)
        }
      }
      .padding(.horizontal, Theme.Space.l).padding(.vertical, Theme.Space.m)

      Divider()

      if queue.transfers.isEmpty && queue.resumable.isEmpty {
        Text("Nothing is transferring.")
          .foregroundStyle(Theme.muted).font(.callout)
          .padding(Theme.Space.xl)
          .frame(maxWidth: .infinity, minHeight: TransfersPopover.minimumListHeight)
      } else {
        ScrollView {
          LazyVStack(spacing: 0) {
            // The divider goes *above* every row but the first, so the list
            // does not end in a rule with nothing under it.
            ForEach(Array(queue.listed.enumerated()), id: \.element.id) { index, transfer in
              if index > 0 { rowDivider }
              TransferRow(transfer: transfer)
            }
            ForEach(Array(queue.resumable.enumerated()), id: \.element.id) { index, upload in
              if index > 0 || !queue.transfers.isEmpty { rowDivider }
              ResumableRow(upload: upload)
            }
          }
        }
        // Bounded at both ends. Finished rows accumulate for the whole session
        // — `clearFinished` is the only thing that empties the list — so with
        // nothing but `.frame(width:)` the popover grew to the height of the
        // screen and still did not scroll. The floor is the empty state's own
        // height, so the box does not jump when the last row is cleared.
        .frame(
          minHeight: TransfersPopover.minimumListHeight,
          maxHeight: TransfersPopover.maximumListHeight)
      }
    }
    .frame(width: 380)
  }
}

#if DEBUG
#Preview("Transfers") {
  let store = NodeStore.preview(transfers: SampleData.transfers)
  return TransfersList(queue: store.transfers).environment(store)
}

#Preview("Nothing to show") {
  let store = NodeStore.preview()
  return TransfersList(queue: store.transfers).environment(store)
}

#Preview("An interrupted upload") {
  let store = NodeStore.preview(resumable: SampleData.resumable)
  return TransfersList(queue: store.transfers).environment(store)
}

#Preview("Running and interrupted") {
  // The two halves together, which is the only arrangement in which the first
  // resumable row needs a divider of its own.
  let store = NodeStore.preview(
    transfers: SampleData.transfers, resumable: SampleData.resumable)
  return TransfersList(queue: store.transfers).environment(store)
}

#Preview("A long history") {
  // Finished rows stay for the whole session, so the list has to stop growing
  // somewhere: with nothing but `.frame(width:)` this reached the height of
  // the screen and still did not scroll.
  let history = (1...14).map { index -> Transfer in
    var transfer = Transfer(
      id: UUID(), direction: .download, name: "chapter-\(index).mov",
      space: "archive", path: "video/chapter-\(index).mov", total: 412_000_000)
    transfer.bytes = 412_000_000
    transfer.state = .completed(detail: nil)
    transfer.finishedAt = SampleData.day(0)
    return transfer
  }
  let store = NodeStore.preview(transfers: history)
  return TransfersList(queue: store.transfers).environment(store)
}
#endif
