import SwiftUI

/// Uploads and downloads, in flight and finished.
///
/// Finished rows stay for the session: this is a history, and the Clear button
/// is the only thing that empties it.
///
/// A popover on a toolbar button, which is where a transfer list belongs: it is
/// glanced at, not worked in. The button is *always* there, which is the part
/// that used to be wrong — it appeared only while a transfer existed, so
/// starting one grew the toolbar and pushed everything else around it.
struct TransfersPopover: View {
  @Environment(NodeStore.self) private var node

  /// Where a row's text begins: the row's own inset, past the icon, past the
  /// gap after it. The dividers start there rather than at the window edge, so
  /// they read as separating rows instead of cutting the popover in half.
  static let textInset = Theme.Space.l + Theme.glyphTarget + Theme.Space.m

  /// The list's floor and ceiling. The floor is roughly one row, which is also
  /// what the empty state occupies, so the two do not step over each other.
  static let minimumListHeight: Double = 88
  static let maximumListHeight: Double = 320

  var body: some View {
    // The queue, observed. It is a plain `let` on `NodeStore`, so its own
    // `objectWillChange` reached no view: every byte written by a running
    // transfer invalidated nothing, and the rows below only redrew when the
    // five-second status poll happened to publish something unrelated. A
    // progress bar that advances in five-second steps looks like a hang.
    TransfersList(queue: node.transfers)
  }
}

#if DEBUG
#Preview("Transfers") {
  TransfersPopover()
    .environment(NodeStore.preview(transfers: SampleData.transfers))
}

#Preview("Nothing to show") {
  TransfersPopover()
    .environment(NodeStore.preview())
}

#Preview("An interrupted upload") {
  // The daemon still holds parts for it, so it is resumable rather than lost —
  // which is a row of its own and not a failed transfer.
  TransfersPopover()
    .environment(NodeStore.preview(resumable: SampleData.resumable))
}

#Preview("Both") {
  TransfersPopover()
    .environment(NodeStore.preview(
      transfers: SampleData.transfers, resumable: SampleData.resumable))
}
#endif
