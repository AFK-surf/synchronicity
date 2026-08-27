import SwiftUI

/// The bar under the rows: what this window is doing, or how much is in it.
struct EntryStatusBar: View {
  @Environment(NodeStore.self) private var node
  let model: FilesModel
  /// Whether a delete plan is being worked out. Owned by ``EntryTable``,
  /// because it is that view's press that starts one.
  let isPlanning: Bool

  var body: some View {
    HStack(spacing: Theme.Space.m) {
      // Ahead of `isLoading`, and it has to be. A delete publishes a tombstone
      // per path, so the five-second status poll sees the head move mid-run,
      // bumps the listing generation and reloads — and that reload's `List` is
      // queued behind the delete on the daemon's global store mutex, so
      // `isLoading` stays true for long stretches of it. Below `isLoading` in
      // this chain the Stop button left the view hierarchy on the poll tick of
      // the very operation it exists to interrupt. The delete is what the
      // person is watching; "Loading…" can wait its turn.
      if let progress = model.deleteProgress {
        ProgressView().controlSize(.mini)
        Text("Deleting \(progress.done) of \(progress.total)…")
          .font(.caption).foregroundStyle(Theme.muted).monospacedDigit()
        // The transfer rows have had a cancel since they were written. A
        // multi-path delete had none, and closing the window did not stop it
        // either — the loop runs on the store's command chain, not on this
        // view.
        //
        // "Stopping…" rather than a greyed-out "Stop": the request lands
        // between paths, so there is a wait after the press, and a button that
        // only dims does not say whether it was heard.
        Button(model.stopDeleteRequested ? "Stopping…" : "Stop") {
          model.stopDeleteRequested = true
        }
        .buttonStyle(.borderless)
        .font(.caption)
        .disabled(model.stopDeleteRequested)
        .accessibilityLabel(model.stopDeleteRequested ? "Stopping the delete" : "Stop deleting")
        .help("Stop after the item being deleted now. What has already been deleted stays deleted.")
      } else if model.isLoading {
        ProgressView().controlSize(.mini)
        Text("Loading…").font(.caption).foregroundStyle(Theme.muted)
      } else if node.houseworkRunning {
        ProgressView().controlSize(.mini)
        Text("Checking your spaces and your devices…")
          .font(.caption).foregroundStyle(Theme.muted)
      } else if isPlanning {
        // Working out what a folder holds is up to fifty round trips, and
        // nothing in the window said it was happening.
        ProgressView().controlSize(.mini)
        Text("Working out what that holds…").font(.caption).foregroundStyle(Theme.muted)
      } else {
        Text(countLabel).font(.caption).foregroundStyle(Theme.muted)
      }
      if model.divergentCount > 0 {
        Button(action: reviewDivergent) {
          // The state is on the glyph; the label is left to the accent, like
          // every other button. A whole control painted in a state colour was
          // the loudest thing in the window claiming to be a second "click me".
          Label {
            Text(model.divergentCount == 1
              ? "1 needs a decision" : "\(model.divergentCount) need a decision")
              .font(.caption)
          } icon: {
            Image(systemName: "arrow.triangle.branch").foregroundStyle(Theme.warning)
          }
        }
        .buttonStyle(.borderless)
      }
      Spacer()
      TransferIndicator(model: model, queue: node.transfers)
      ParseWarningChip(lines: node.parseWarnings[.spaces] ?? [])
    }
    .padding(.horizontal, Theme.Space.l)
    .padding(.vertical, Theme.Space.snug)
    .overlay(alignment: .top) { Divider() }
  }

  /// The filter is cleared first: `showVersions` picks its row out of
  /// `visibleRows`, so a divergent row the filter had hidden could not be
  /// found and the panel would open on nothing.
  private func reviewDivergent() {
    model.clearSearch()
    model.showVersions()
  }

  private var countLabel: String {
    let shown = model.visibleRows.count
    let total = model.rows.count
    if shown != total { return "\(shown) of \(total) items" }
    return total == 1 ? "1 item" : "\(total) items"
  }
}

#if DEBUG
#Preview("The count") {
  let store = NodeStore.preview(transfers: SampleData.transfers)
  return EntryStatusBar(
    model: FilesModel.preview(rows: SampleData.rows, space: "notes", store: store),
    isPlanning: false)
    .environment(store)
    .frame(width: 850)
}

#Preview("Filtered") {
  let store = NodeStore.preview()
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes", store: store)
  model.search = "journal"
  return EntryStatusBar(model: model, isPlanning: false)
    .environment(store)
    .frame(width: 850)
}

#Preview("Deleting") {
  let store = NodeStore.preview()
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes", store: store)
  model.deleteProgress = DeleteProgress(done: 3, total: 12)
  return EntryStatusBar(model: model, isPlanning: false)
    .environment(store)
    .frame(width: 850)
}

#Preview("Stopping a delete") {
  // The gap between the press and the next path landing, which is the only
  // state in this bar a person sees and cannot act on.
  let store = NodeStore.preview()
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes", store: store)
  model.deleteProgress = DeleteProgress(done: 3, total: 12)
  model.stopDeleteRequested = true
  return EntryStatusBar(model: model, isPlanning: false)
    .environment(store)
    .frame(width: 850)
}

#Preview("Working out what that holds") {
  let store = NodeStore.preview()
  return EntryStatusBar(
    model: FilesModel.preview(rows: SampleData.rows, space: "notes", store: store),
    isPlanning: true)
    .environment(store)
    .frame(width: 850)
}

#Preview("Squeezed") {
  // Everything this bar can hold at once, at the narrowest the file list is
  // ever asked to be: a count, a decision to make, and a transfer running.
  let store = NodeStore.preview(transfers: SampleData.transfers)
  return EntryStatusBar(
    model: FilesModel.preview(rows: SampleData.rows, space: "notes", store: store),
    isPlanning: false)
    .environment(store)
    .frame(width: 360)
}
#endif
