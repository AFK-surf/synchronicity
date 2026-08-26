import SwiftUI

/// The mirrors half of the Mirrors & Pins page.
///
/// One table in a box with what can be done to a mirror on the box's bottom
/// edge. "Sync Mirrored Spaces Now" sits on that bar rather than in a window
/// toolbar because it acts on these rows and on nothing else — the settings
/// window has no toolbar of its own to put it in.
struct MirrorsSection: View {
  @Environment(NodeStore.self) private var node
  @Binding var confirmation: ConfirmationRequest?
  @State private var selection: MirrorEntry.ID?
  @State private var addingMirror = false

  /// How much of the table is shown before it scrolls inside its own box.
  ///
  /// A `Table` has no height of its own, and the page it is on is now a fixed
  /// 660-point window: something has to name a number, and it may as well be
  /// the number of rows that fit — about six here.
  private let tableHeight: CGFloat = 180

  var body: some View {
    SettingsSection(
      "Mirrors",
      footer: "A mirror writes the shared view of a space into a normal directory on this Mac, so other apps can open it. The directory is written to, not read from.",
      warnings: node.parseWarnings[.mirrors] ?? []
    ) {
      if let outcome = node.lastMirrorSync, !outcome.isClean {
        MirrorSyncBanner(outcome: outcome) { sync() }
      }
      BorderedTable {
        table
      } actions: {
        TableActionButton(symbol: "plus", name: "Mirror a Space…") { addingMirror = true }
        TableActionButton(symbol: "minus", name: "Stop Mirroring…") {
          if let mirror = selected { requestRemove(mirror) }
        }
        .disabled(selected == nil)
        Spacer()
        if node.mirrorSyncRunning { ProgressView().controlSize(.small) }
      Button("Sync Mirrored Spaces Now") { sync() }
          .disabled(node.mirrorSyncRunning || node.mirrors.isEmpty)
      }
    }
    .sheet(isPresented: $addingMirror) { MirrorSheet() }
  }

  @ViewBuilder private var table: some View {
    if node.loading.contains(.mirrors), node.mirrors.isEmpty {
      // Not "No mirrors" — the question has not been answered yet. Asserting
      // an empty state before the first fetch returns states something the app
      // does not know, and then pops a table in over it.
      ProgressView().controlSize(.small)
        .frame(maxWidth: .infinity).frame(height: tableHeight)
    } else if node.mirrors.isEmpty {
      ContentUnavailableView(
        "No mirrors", systemImage: "arrow.down.doc",
        description: Text("A mirror writes the shared view of a space into a normal directory, so other apps can open it."))
        // `minHeight`, not `height`. A fixed height centres the view *and*
        // clips it when it wants more, which is what took the glyph off the
        // top of this one and left the title sitting against the box's edge.
        // A floor lets the empty state be as tall as it is and centres it in
        // whatever is left over.
        .frame(maxWidth: .infinity, minHeight: tableHeight)
    } else {
      Table(node.mirrors, selection: $selection) {
      TableColumn("Space") { Text($0.space) }.width(min: 80, ideal: 120, max: 220)
        TableColumn("Version") {
          StatusChip(text: VersionPolicy(wire: $0.policy)?.label ?? $0.policy, tint: Theme.muted)
        }
        .width(min: 80, ideal: 110, max: 160)
        // The one column with no ceiling, because it is the one that can need
        // the width: an absolute path, truncated in the middle, with the whole
        // of it in the tooltip and selectable for whoever wants to paste it.
        TableColumn("Written to") { mirror in
          HStack(spacing: Theme.Space.snug) {
            Text(mirror.localPath).font(Theme.Font.mono(.subheadline))
              .lineLimit(1).truncationMode(.middle)
              .textSelection(.enabled).help(mirror.localPath)
            Button {
              reveal(mirror.localPath)
            } label: { Image(systemName: "arrow.up.forward.app").imageScale(.small).glyphButton() }
            .accessibilityLabel("Reveal \(mirror.localPath) in Finder")
            .buttonStyle(.plain).foregroundStyle(Theme.muted).help("Reveal in Finder")
          }
        }
      }
      .frame(height: tableHeight)
      .contextMenu(forSelectionType: MirrorEntry.ID.self) { ids in
        if let mirror = node.mirrors.first(where: { ids.contains($0.id) }) {
          Button("Stop Mirroring…", role: .destructive) { requestRemove(mirror) }
        }
      }
    }
  }

  private var selected: MirrorEntry? {
    selection.flatMap { id in node.mirrors.first { $0.id == id } }
  }

  private func sync() {
    node.enqueue { await node.syncMirrors() }
  }

  private func reveal(_ path: String) {
    NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: path)
  }

  private func requestRemove(_ mirror: MirrorEntry) {
    confirmation = ConfirmationRequest(
      title: "Stop mirroring into this directory?",
      consequence: "The files already in \(mirror.localPath) stay exactly where they are. Only the updating stops.",
      verb: "Stop Mirroring",
      gate: .confirm,
      commandLine: "synch mirror rm \(Shell.quote(mirror.localPath))",
      perform: {
        node.enqueue {
          await node.run(
            Operations.require("mirror.rm"), Cmd.mirrorRm(path: mirror.localPath),
            commandLine: "synch mirror rm \(Shell.quote(mirror.localPath))")
        }
      }
    )
  }
}

/// What one `mirror sync` run did, when it did not do all of it.
///
/// The daemon stops at the first failing mirror and says nothing about the
/// rest. Naming them is the whole of what the client can do, and it is the
/// difference between a silent partial run and a precise one.
private struct MirrorSyncBanner: View {
  let outcome: MirrorSyncOutcome
  let retry: () -> Void

  var body: some View {
    AlarmBanner(text: text, tint: Theme.warning, actionTitle: "Try Again", action: retry)
      // Contained rather than full-bleed: on this page the banner belongs to
      // the section it is inside, not to the window.
      .clipShape(RoundedRectangle(cornerRadius: Theme.Radius.s))
  }

  private var text: String {
    var text = ""
    if let failed = outcome.failed {
      text += "\((failed as NSString).lastPathComponent) failed to sync."
    }
    if !outcome.notAttempted.isEmpty {
      let names = outcome.notAttempted.map { ($0 as NSString).lastPathComponent }
      text += " The run stopped there, so \(names.joined(separator: ", ")) "
      text += outcome.notAttempted.count == 1 ? "was never attempted." : "were never attempted."
    }
    if !outcome.succeeded.isEmpty {
      text += " \(outcome.succeeded.count) finished before it."
    }
    return text.trimmingCharacters(in: .whitespaces)
  }
}

#if DEBUG
#Preview("Mirrors") {
  MirrorsSection(confirmation: .constant(nil))
    .environment(NodeStore.preview())
    .padding(Theme.Space.xl)
    .frame(width: 760)
}

#Preview("No mirrors") {
  // A store built by hand rather than by the harness: `NodeStore.preview`
  // always installs one mirror and takes no argument that removes it.
  MirrorsSection(confirmation: .constant(nil))
    .environment(NodeStore())
    .padding(Theme.Space.xl)
    .frame(width: 760)
}

#Preview("A sync stopped part way") {
  // The banner on its own: `lastMirrorSync` is `private(set)` on the store, so
  // no preview store can be put into this state from here.
  MirrorSyncBanner(
    outcome: MirrorSyncOutcome(
      succeeded: ["/Users/me/Mirrors/archive"],
      failed: "/Users/me/Mirrors/notes",
      notAttempted: ["/Users/me/Mirrors/photos"]),
    retry: {})
    .padding(Theme.Space.xl)
    .frame(width: 760)
}
#endif
