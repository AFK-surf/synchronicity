import SwiftUI

/// Folders on this Mac, and the directories it materializes.
///
/// A real `.listStyle(.sidebar)` list, so it gets the system's vibrant
/// material, its selection behaviour and its keyboard navigation instead of a
/// stack of plain buttons painted over the material.
struct FilesSidebar: View {
  @Environment(NodeStore.self) private var node
  let model: FilesModel
  @Binding var addingSpace: Bool
  @State private var confirmation: ConfirmationRequest?
  @State private var filling: Space?

  var body: some View {
    // An `NSOutlineView`, not a SwiftUI `List`. See ``FolderListView`` for
    // what decided it: a SwiftUI list in this window could be clicked and not
    // take the keyboard.
    FolderListView(
      spaces: node.spaces,
      mirrors: node.mirrors,
      selected: model.selectedSpace,
      policyLabel: policyLabel,
      onSelect: { model.select(space: $0) },
      onAddFolder: { addingSpace = true },
      onRevealMirror: { mirror in
        // A mirror is a materialization of the tree, so browsing one *inside*
        // the app would be a second, subtly different view of the same data.
        // It reveals in Finder instead.
        NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: mirror.localPath)
      },
      onStopSharing: requestStopSharing,
      onFill: { filling = $0 })
    .confirmedAction($confirmation)
    .sheet(item: $filling) { space in FillSheet(space: space) }
    .safeAreaInset(edge: .bottom) { SidebarConnectionFooter() }
    .task(id: node.connection) {
      guard node.connection.isConnected else { return }
      // `.pins` as well as `.mirrors`: the browser's "Keep Offline" toggle has
      // to know which way it points, and nothing in this window had ever asked
      // for the pin list.
      await node.refresh([.mirrors, .pins])
    }
  }

  /// The mirror's read policy, with a device key rendered as a name.
  private func policyLabel(_ wire: String) -> String {
    guard let policy = VersionPolicy(wire: wire) else { return wire }
    if case .origin(let id) = policy { return "From \(node.label(forOrigin: id))" }
    return policy.label
  }

  /// What `space rm` does to *this* folder.
  ///
  /// It used to say "the files stay on disk" and stop there, which is only the
  /// whole story for a plain published folder. On a replicating one the daemon
  /// stops the replication too, and what that replication holds stays held
  /// unless `--release` is sent — so the sentence promised less than happens
  /// and more than is freed. On a detached one there are no files to reassure
  /// anybody about.
  private func stopSharingConsequence(_ space: Space) -> String {
    var text = space.isDetached
      ? "This Mac stops holding \u{201c}\(space.id)\u{201d} for the cluster and publishes that its entries are gone."
      : "This Mac stops indexing \(space.localPath ?? space.id) and publishes that its entries are gone. The files themselves stay on disk; other devices keep whatever they published."
    if space.isReplicating {
      text += " Replication stops as well, and what it holds stays on this Mac \u{2014} turn replication off first if you want that space back."
    }
    return text
  }

  /// The same gate Settings ▸ Folders puts on it: unpublishing a folder's
  /// entries is not undone by adding it back.
  private func requestStopSharing(_ space: Space) {
    confirmation = ConfirmationRequest(
      title: "Stop sharing \u{201c}\(space.id)\u{201d}?",
      consequence: stopSharingConsequence(space),
      verb: "Stop Sharing",
      gate: .typed,
      typedPhrase: space.id,
      commandLine: "synch space rm \(Shell.quote(space.id))",
      perform: {
        node.enqueue {
          await node.run(
            Operations.require("space.rm"), Cmd.spaceRm(id: space.id),
            commandLine: "synch space rm \(Shell.quote(space.id))")
        }
      }
    )
  }

  private var selectionBinding: Binding<String?> {
    Binding(
      get: { model.selectedSpace },
      set: { if let id = $0 { model.select(space: id) } }
    )
  }
}

#if DEBUG
#Preview("Spaces") {
  let store = NodeStore.preview()
  return FilesSidebar(
    model: FilesModel.preview(rows: SampleData.rows, space: "notes", store: store),
    addingSpace: .constant(false))
    .environment(store)
    .frame(width: 240, height: 420)
}

#Preview("No spaces shared") {
  let store = NodeStore.preview(spaces: [])
  return FilesSidebar(
    model: FilesModel.preview(rows: [], space: "", store: store),
    addingSpace: .constant(false))
    .environment(store)
    .frame(width: 240, height: 420)
}
#endif
