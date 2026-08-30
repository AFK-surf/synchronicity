import SwiftUI

/// Devices this node has seen — `peer ls`.
struct NetworkPane: View {
  @Environment(NodeStore.self) private var node
  @State private var sortOrder: [KeyPathComparator<PeerInfo>] = [
    .init(\.lastSeenSort, order: .forward)
  ]

  var body: some View {
    ScrollView {
      // One table and the sentence that explains it, so the section takes no
      // name of its own: the sidebar already says Network, and a heading here
      // would be that word a second time.
      SettingsSection(
        footer: "Devices this Mac has exchanged with. Times are the daemon\u{2019}s own wording; the column sorts on the interval each one bounds.",
        warnings: node.parseWarnings[.peers] ?? []
      ) {
        BorderedTable {
          table
            // The window is 980 × 660 and never anything else, so the table is
            // given the height that leaves room for the bar, the footer and
            // the padding rather than a share of a size it will never be
            // asked for.
            .frame(height: 440)
            .overlay { placeholder }
        } actions: {
          Button("Sync Now") {
            node.enqueue {
              await node.run(Operations.require("peer.sync"), Cmd.peerSync)
            }
          }
          Button("Refresh") { Task { await node.refresh([.peers]) } }
        }
      }
      .padding(Theme.Space.xl)
    }
  }

  private var table: some View {
    Table(node.peers.sorted(using: sortOrder), sortOrder: $sortOrder) {
      // The one column with no maximum. A device key is 52 characters, so
      // whatever the other three leave over belongs here.
      TableColumn("Device") { peer in
        HStack(spacing: Theme.Space.snug) {
          if peer.isStale {
            Image(systemName: "exclamationmark.circle.fill")
              .foregroundStyle(Theme.warning).imageScale(.small)
              .help("Not heard from in over an hour")
              .accessibilityLabel("Not heard from in over an hour")
          }
          Text(peer.key)
            .font(Theme.Font.mono(.subheadline)).lineLimit(1).truncationMode(.middle)
            .help(peer.key).textSelection(.enabled)
        }
      }
      .width(min: 140, ideal: 200)

      TableColumn("Known as") { peer in
        // An origin can be a name, several names, or `key:` and 52 characters
        // for a device nothing has named yet — long enough to truncate, so the
        // whole of it has to be reachable from the tooltip and the selection.
        let known = peer.origins.isEmpty ? "—" : peer.origins
        Text(known)
          .font(.caption).foregroundStyle(Theme.muted)
          .lineLimit(1).truncationMode(.middle)
          .help(known).textSelection(.enabled)
      }
      .width(min: 90, ideal: 140, max: 260)

      // Sorted on a *recovered* interval, displayed as the daemon's own
      // words. `render::ago` destroys the instant, but "3m ago" still
      // bounds it to [180s, 240s) — enough to order the table correctly
      // between buckets, which a string comparison cannot do at all.
      TableColumn("Last seen", value: \.lastSeenSort) { peer in
        Text(peer.lastSeenText).font(.caption)
          .foregroundStyle(peer.isStale ? Theme.warning : Theme.muted)
      }
      .width(min: 80, ideal: 100, max: 140)

      TableColumn("Last sync", value: \.lastSyncSort) { peer in
        Text(peer.lastSyncText).font(.caption).foregroundStyle(Theme.muted)
      }
      .width(min: 80, ideal: 100, max: 140)
    }
    .contextMenu(forSelectionType: PeerInfo.ID.self) { ids in
      if let peer = node.peers.first(where: { ids.contains($0.id) }) {
        Button("Copy Device Key") {
          NSPasteboard.general.clearContents()
          NSPasteboard.general.setString(peer.key, forType: .string)
        }
      }
    }
  }

  /// What stands in the empty table's rectangle.
  ///
  /// Over the table rather than instead of it: the column headers and the
  /// action bar stay where they are, so the row of buttons does not move under
  /// the pointer when the first peer arrives.
  @ViewBuilder private var placeholder: some View {
    if node.loading.contains(.peers), node.peers.isEmpty {
      ProgressView().controlSize(.small)
    } else if node.peers.isEmpty {
      ContentUnavailableView(
        "No devices yet", systemImage: "network.slash",
        description: Text("Trust a device in Members, and it will appear here once the two have talked."))
    }
  }
}

#if DEBUG
#Preview("Network") {
  NetworkPane()
    .environment(NodeStore.preview())
    .frame(width: 760, height: 560)
}

#Preview("No devices yet") {
  NetworkPane()
    .environment(NodeStore.preview(peers: []))
    .frame(width: 760, height: 560)
}

#Preview("Larger text") {
  // The footer is what grows; the table keeps its height, so this is where a
  // page that has outgrown the fixed window starts to scroll.
  NetworkPane()
    .environment(NodeStore.preview())
    .dynamicTypeSize(.accessibility1)
    .frame(width: 760, height: 560)
}
#endif
