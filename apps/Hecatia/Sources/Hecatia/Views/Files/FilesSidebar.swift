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
  @State private var adopting: Space?

  var body: some View {
    // An `NSOutlineView`, not a SwiftUI `List`. See ``FolderListView`` for
    // what decided it: a SwiftUI list in this window could be clicked and not
    // take the keyboard.
    FolderListView(
      spaces: node.spaces,
      checkouts: node.checkouts,
      selected: model.selectedSpace,
      policyLabel: policyLabel,
      onSelect: { model.select(space: $0) },
      onAddFolder: { addingSpace = true },
      onRevealCheckout: { checkout in
        // A checkout is a materialization of the tree, so browsing one *inside*
        // the app would be a second, subtly different view of the same data.
        // It reveals in Finder instead.
        NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: checkout.localPath)
      },
      onStopSharing: requestStopSharing,
      onAdopt: { adopting = $0 })
    .confirmedAction($confirmation)
    .sheet(item: $adopting) { space in AdoptTreeSheet(space: space) }
    .safeAreaInset(edge: .bottom) { SidebarConnectionFooter() }
    .task(id: node.connection) {
      guard node.connection.isConnected else { return }
      // `.pins` as well as `.checkouts`: the browser's "Keep Offline" toggle has
      // to know which way it points, and nothing in this window had ever asked
      // for the pin list.
      await node.refresh([.spaces, .pins])
    }
  }

  /// The checkout's read policy, with a device key rendered as a name.
  private func policyLabel(_ wire: String) -> String {
    guard let policy = VersionPolicy(wire: wire) else { return wire }
    if case .origin(let id) = policy { return "From \(node.label(forOrigin: id))" }
    return policy.label
  }

  /// What `source rm` does to *this* folder.
  ///
  /// Removing a source does not alter an independent replica role. A filesystem
  /// source also leaves its directory untouched.
  private func stopSharingConsequence(_ space: Space) -> String {
    "This Mac stops publishing \(space.localPath ?? space.id). Its replica role, if any, is unchanged. The source files stay on disk."
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
      commandLine: "synch source rm \(Shell.quote(space.id))",
      perform: {
        node.enqueue {
          await node.run(
            Operations.require("source.rm"), Cmd.sourceRm(id: space.id),
            commandLine: "synch source rm \(Shell.quote(space.id))")
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
