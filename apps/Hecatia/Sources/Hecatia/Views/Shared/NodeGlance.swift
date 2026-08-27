import SwiftUI

/// The menu bar item.
///
/// Five things, no browsing and nothing destructive. A sync product that cannot
/// answer "is it working right now" without being launched is missing the one
/// thing a menu bar item is for.
struct NodeGlance: View {
  @Environment(NodeStore.self) private var node
  @Environment(\.openWindow) private var openWindow

  /// What quitting would interrupt, if anything.
  private var queueSummary: String? {
    let active = node.transfers.active.count
    guard active > 0 else { return nil }
    return active == 1
      ? "Quitting stops 1 transfer in progress."
      : "Quitting stops \(active) transfers in progress."
  }

  var body: some View {
    Text(node.nodeSummary)
    if let alarm = node.alarms.first {
      Text(alarm.text).foregroundStyle(Theme.danger)
    }
    TransferGlance(queue: node.transfers)
    Divider()
    // The store already assembles both of these, and a second copy of the
    // `Operations.require(...)` lookup is a second place to get a deadline or a
    // force-unwrap wrong.
    Button(node.houseworkRunning ? "Working…" : "Sync Now", action: node.syncNow)
      .disabled(!node.connection.isConnected || node.houseworkRunning)
    Button(node.houseworkRunning ? "Working…" : "Scan Now", action: node.scanNow)
      .disabled(!node.connection.isConnected || node.houseworkRunning)
    Divider()
    Button("Open Files") { openWindow(id: "files") }
    Button("Activity…") { openWindow(id: "activity") }
    Divider()
    // Named for what it quits. The daemon keeps running — it is a separate
    // process and this app has never started or stopped it — and saying
    // "Quit Synchronicity" over a menu whose other items describe the daemon
    // read as stopping the sync itself.
    if let queueSummary { Text(queueSummary).foregroundStyle(Theme.ink(Theme.warning)) }
    Button("Quit This App") { NSApplication.shared.terminate(nil) }
      .keyboardShortcut("q")
  }
}

/// Observed, because `NodeStore.transfers` is a plain `let` and reading it
/// through the store subscribes to nothing.
private struct TransferGlance: View {
  let queue: TransferQueue

  var body: some View {
    if queue.hasActive { Text(queue.summary) }
  }
}

#if DEBUG
#Preview("Glance") {
  NodeGlance()
    .environment(NodeStore.preview())
    .frame(width: 320)
}

#Preview("Glance, transferring") {
  // The queue line only exists while something is in flight, and it is what
  // makes quitting a decision rather than a reflex.
  NodeGlance()
    .environment(NodeStore.preview(transfers: SampleData.transfers))
    .frame(width: 320)
}

#Preview("Glance, no daemon") {
  NodeGlance()
    .environment(NodeStore.preview(
      connection: .failed(DaemonFailure(
        code: .unavailable, detail: "Nothing is listening on control.sock.")),
      status: nil))
    .frame(width: 320)
}
#endif
