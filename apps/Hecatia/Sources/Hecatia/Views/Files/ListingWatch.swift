import SwiftUI

/// Re-reads the folder every so often, and redraws it only if it changed.
struct ListingWatch: View {
  let model: FilesModel
  let enabled: Bool

  /// Slow on purpose. This is the fallback for changes nothing tells the app
  /// about; everything the app does itself refreshes immediately.
  private static let interval = Duration.seconds(12)

  var body: some View {
    Color.clear.task(id: enabled) {
      guard enabled else { return }
      // Once on becoming the window being looked at, so coming back to the app
      // does not show a folder as it was twelve seconds ago, and then on the
      // slow cadence.
      await model.refreshIfChanged()
      while !Task.isCancelled {
        try? await Task.sleep(for: Self.interval)
        guard !Task.isCancelled else { return }
        await model.refreshIfChanged()
      }
    }
  }
}

#if DEBUG
#Preview("Nothing to draw") {
  // It renders `Color.clear` and does its work in a `.task`, so a canvas of it
  // alone is an empty canvas — this is how the browser window attaches it, as
  // a background behind something that does draw.
  //
  // `enabled: false`, because a preview has no daemon: an enabled watch would
  // spend the canvas's life reaching for a control socket that is not there.
  Text("The folder is re-read behind this, every 12 seconds.")
    .font(.caption)
    .foregroundStyle(Theme.muted)
    .padding(Theme.Space.xl)
    .background(ListingWatch(
      model: FilesModel.preview(rows: SampleData.rows, space: "notes"),
      enabled: false))
    .frame(width: 360)
}
#endif
