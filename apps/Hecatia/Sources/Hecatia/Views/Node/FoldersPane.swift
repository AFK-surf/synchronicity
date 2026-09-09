import SwiftUI

/// Independent source and replica roles for each known namespace.
struct SpacesPane: View {
  @Environment(NodeStore.self) private var node
  @Binding var confirmation: ConfirmationRequest?
  @State private var adding = false
  @State private var configuring: Space?
  @State private var adopting: Space?
  @State private var selection: Space.ID?

  /// The window opens with nothing selected and no report under the table. A
  /// preview names a row, which is the only way to draw the second state.
  init(confirmation: Binding<ConfirmationRequest?>, selection: Space.ID? = nil) {
    _confirmation = confirmation
    _selection = State(initialValue: selection)
  }

  private var selected: Space? {
    selection.flatMap { id in node.spaces.first { $0.id == id } }
  }

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: Theme.Space.section) {
        SettingsSection(
          footer: "Filesystem and API sources this Mac publishes. The space name is shared across every device.",
          warnings: (node.parseWarnings[.spaces] ?? []) + (node.parseWarnings[.replication] ?? [])
        ) {
          BorderedTable {
            table
          } actions: {
            TableActionButton(symbol: "plus", name: "Add a Space…") { adding = true }
            // The gate is the one this pane always had: the checkbox below,
            // and then a confirmation that has to be typed out. Only the
            // button's place on the page changed.
            TableActionButton(symbol: "minus", name: "Stop Sharing…") { requestRemove() }
              .disabled(selected?.isSource != true || !node.advancedUnlocked)
            Spacer()
            Button("Adopt From the Cluster…") { adopting = selected }
              .disabled(
                selected?.hasFilesystemSource != true || selected?.isSourceUnavailable == true)
          }
          // Directly under the bar it unlocks, rather than at the foot of the
          // page: － is the control it governs.
          AdvancedToggle()
        }

        if let selected, selected.isSourceUnavailable {
          SettingsSection {
            HStack(alignment: .top, spacing: Theme.Space.m) {
              Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(Theme.warning)
              VStack(alignment: .leading, spacing: Theme.Space.tiny) {
                Text("Local folder unavailable").font(.headline)
                Text("The original location \(selected.localPath ?? "—") cannot be found. Scanning and local writes are paused; the cloud space and existing published files are unchanged.")
                  .font(.callout).foregroundStyle(Theme.muted)
                  .textSelection(.enabled)
                if let error = selected.sourceError {
                  Text(error).font(Theme.Font.mono(.caption)).foregroundStyle(Theme.muted)
                    .textSelection(.enabled)
                }
              }
              Spacer()
              Button("Locate…") { locate(selected) }
              Button("Disconnect Folder…") { requestDetach(selected) }
            }
          }
        }

        if let selected {
          // No title of its own: the report's first line is the folder's name,
          // and a heading above it would be a word for the same block twice.
          SettingsSection {
            ReplicationInspector(
              space: selected,
              status: node.replicaStatus[selected.id],
              onConfigure: { configuring = selected },
              onSyncNow: { node.syncReplica(id: selected.id) })
          }
        }
      }
      .padding(Theme.Space.xl)
    }
    .sheet(isPresented: $adding) { AddSourceSheet() }
    .sheet(item: $configuring) { space in
      ReplicationSheet(
        space: space, heldBytes: node.replicaStatus[space.id]?.heldBytes ?? 0)
    }
    .sheet(item: $adopting) { space in AdoptTreeSheet(space: space) }
  }

  /// Name, path, replication — and only the path grows.
  ///
  /// The window is 760 points wide and does not resize, so the width left over
  /// goes somewhere by decision rather than by luck. A name and a policy label
  /// are both short and have a maximum; a path is the one column whose content
  /// has no bound, so it takes the slack and truncates in the middle.
  private var table: some View {
    Table(node.spaces, selection: $selection) {
      TableColumn("Name") { space in Text(space.id) }
        .width(min: 100, ideal: 160, max: 220)
      TableColumn("On this Mac") { space in path(space) }
      TableColumn("Replication") { space in replication(space) }
        .width(min: 90, ideal: 130, max: 160)
    }
    .frame(height: 220)
    .overlay {
      if node.spaces.isEmpty {
        Text("No spaces shared yet.").font(.callout).foregroundStyle(Theme.muted)
      }
    }
  }

  private func path(_ space: Space) -> some View {
    HStack(spacing: Theme.Space.snug) {
      if space.isSourceUnavailable {
        Image(systemName: "exclamationmark.triangle.fill")
          .foregroundStyle(Theme.warning)
          .accessibilityLabel("Local folder unavailable")
      }
      Text(space.pathLabel)
        .font(Theme.Font.mono(.subheadline))
        .foregroundStyle(space.isRemoteOnly ? Theme.muted : Color.primary)
        .lineLimit(1).truncationMode(.middle)
        // Truncated in the middle by design, so the whole path has to be
        // readable and copyable some other way.
        .help(space.pathLabel)
        .textSelection(.enabled)
      // A API source has no directory, so there is nothing to reveal and
      // the button is not drawn rather than drawn dead.
      if space.isSourceUnavailable {
        Button("Locate…") { locate(space) }
          .buttonStyle(.borderless)
          .help("Locate the renamed or moved folder")
      } else if space.localPath != nil {
        Button {
          node.revealSource(space)
        } label: { Image(systemName: "arrow.up.forward.app").imageScale(.small).glyphButton() }
        .accessibilityLabel("Reveal \(space.id) in Finder")
        .buttonStyle(.plain).foregroundStyle(Theme.muted)
        .help("Reveal in Finder")
      }
    }
  }

  @ViewBuilder
  private func replication(_ space: Space) -> some View {
    if let policy = space.replicate {
      StatusChip(
        text: policy.label,
        tint: node.replicaStatus[space.id]?.isAlarming == true ? Theme.warning : Theme.accent,
        systemImage: node.replicaStatus[space.id]?.isAlarming == true
          ? "exclamationmark.triangle" : "arrow.trianglehead.2.clockwise")
    } else {
      Text("—").foregroundStyle(Theme.muted)
    }
  }

  private func requestRemove() {
    guard let space = selected else { return }
    let id = space.id
    var consequence = "Every device in your cluster sees this Mac’s entries for “\(id)” disappear."
    if !space.hasFilesystemSource {
      consequence += " This source has no filesystem directory, so there are no files to keep."
    } else {
      consequence += " Your files stay on this Mac exactly where they are — only the publishing stops."
    }
    if space.isReplicating { consequence += " The independent replica is unchanged." }
    confirmation = ConfirmationRequest(
      title: "Stop sharing “\(id)”?",
      consequence: consequence,
      verb: "Stop Sharing",
      gate: .typed,
      typedPhrase: id,
      commandLine: "synch source rm \(Shell.quote(id))",
      perform: {
        node.enqueue {
          await node.run(
            Operations.require("source.rm"), Cmd.sourceRm(id: id),
            commandLine: "synch source rm \(Shell.quote(id))")
        }
      }
    )
  }

  private func locate(_ space: Space) {
    let panel = NSOpenPanel()
    panel.title = "Locate “\(space.id)”"
    panel.message = "Choose the renamed or moved folder that belongs to this space."
    panel.prompt = "Reconnect"
    panel.canChooseFiles = false
    panel.canChooseDirectories = true
    panel.allowsMultipleSelection = false
    if panel.runModal() == .OK, let url = panel.url {
      node.enqueue { await node.relinkSource(id: space.id, path: url.path) }
    }
  }

  private func requestDetach(_ space: Space) {
    let id = space.id
    confirmation = ConfirmationRequest(
      title: "Disconnect the local folder from “\(id)”?",
      consequence: "This Mac stops scanning and writing the missing folder. The cloud space and every entry already published in it stay unchanged; this source remains available through APIs.",
      verb: "Disconnect Folder",
      gate: Operations.require("source.detach").gate,
      commandLine: "synch source detach \(Shell.quote(id))",
      isDestructive: false,
      perform: {
        node.enqueue { await node.detachSource(id: id) }
      }
    )
  }
}

#if DEBUG
#Preview("Spaces") {
  SpacesPane(confirmation: .constant(nil))
    .environment(NodeStore.preview())
    .frame(width: 760, height: 560)
}

#Preview("A space selected") {
  // The report opens as a second section under the table rather than as a
  // panel inside it, so the page grows downwards and scrolls.
  SpacesPane(confirmation: .constant(nil), selection: "archive")
    .environment(NodeStore.preview())
    .frame(width: 760, height: 560)
}

#Preview("No spaces shared") {
  SpacesPane(confirmation: .constant(nil))
    .environment(NodeStore.preview(spaces: []))
    .frame(width: 760, height: 560)
}

#Preview("Stop Sharing unlocked") {
  // － is dead until the checkbox is ticked and a row is chosen. This is the
  // only state in which it can be looked at alive.
  let store = NodeStore.preview()
  store.advancedUnlocked = true
  return SpacesPane(confirmation: .constant(nil), selection: "notes")
    .environment(store)
    .frame(width: 760, height: 560)
}

#Preview("Local folder unavailable") {
  SpacesPane(confirmation: .constant(nil), selection: "renamed folder")
    .environment(NodeStore.preview())
    .frame(width: 760, height: 620)
}
#endif
