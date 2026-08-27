import SwiftUI

/// The browser window — the product.
///
/// Nothing that does not name a file or a folder is allowed in here. Identity,
/// keys, trust, zones, mirrors and pins live in the Node window, which has
/// never been opened when a user first launches the app.
struct FilesWindow: View {
  @Environment(NodeStore.self) private var node
  @State private var model: FilesModel
  @Environment(\.openWindow) private var openWindow

  @State private var confirmation: ConfirmationRequest?
  @State private var addingSpace = false
  @State private var quickLookURL: URL?
  @State private var exporting: RemoteEntry?
  @AppStorage("showTransfersAutomatically") private var showTransfersAutomatically = true
  /// Only the window a person is looking at opens the popover. Every browser
  /// window shares one queue, so without this a download would pop a popover
  /// in each of them at once.
  @Environment(\.controlActiveState) private var activeState

  init(store: NodeStore) {
    _model = State(initialValue: FilesModel(store: store))
  }

  var body: some View {
    split
      .modifier(BrowserDialogs(
        model: model, confirmation: $confirmation,
        addingSpace: $addingSpace, exporting: $exporting, quickLookURL: $quickLookURL,
        space: model.selectedSpace, prefix: model.prefix))
      .modifier(DaemonAlert())
      .modifier(BrowserLifecycle(model: model))
      // Inert unless HECATIA_WINDOW_SNAPSHOT_DIR is set, and DEBUG only. Here
      // rather than on the scene because it needs this window's model.
      .modifier(SnapshotDriverIfDebug(node: node, model: model))
  }

  private var split: some View {
    BrowserSplit(panelVisible: model.inspectorVisible) {
      NavigationSplitView {
        FilesSidebar(model: model, addingSpace: $addingSpace)
          .navigationSplitViewColumnWidth(min: 200, ideal: 230, max: 300)
          .toolbar(removing: .sidebarToggle)
      } detail: {
        detail
          .toolbar { FilesToolbar(model: model) }
      }
      .searchable(
        text: $model.search, isPresented: $model.searchPresented,
        placement: .toolbar, prompt: "Filter")
      .background(FilterFocus(request: model.searchFocusRequest) {
        // An empty field folds back to the magnifier when it is left, the way
        // Finder's does — and, more to the point, the way this app's own field
        // did before `.searchable` replaced it.
        if model.search.isEmpty { model.searchPresented = false }
      })
      .background(FileListCaret(request: model.listFocusRequest))
      // Everything the scene environment would have carried, carried by hand.
      // An `NSHostingController` is not on the scene's view tree, so none of
      // these reach the other side on their own — and the way they fail is by
      // quietly resolving to their default, not by refusing to compile.
      .environment(node)
      .environment(\.exportEntry, ExportAction { entry in exporting = entry })
      .environment(\.openAppWindow, OpenAppWindow { openWindow(id: $0) })
    } panel: {
      FileInspector(model: model, confirmation: $confirmation)
        .environment(node)
    }
    // Fills the window. A representable has no opinion about its own size, so
    // without this it is given whatever its content last reported — which for
    // an `NSHostingController` is its intrinsic size, and that is not a window.
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    // And fills it past the title bar, which is what "full height" means: the
    // sidebar and the panel run the whole height of the window with the
    // toolbar drawn over them, the way Finder's and Xcode's do. Their
    // `NSSplitViewItem`s carry `allowsFullHeightLayout`, so AppKit insets each
    // pane's *content* below the toolbar itself — the panes are full height,
    // what is in them is not underneath anything.
    .ignoresSafeArea()
    // On a view that observes the queue, not on this one. `node.transfers` is
    // a plain `let`, so `onChange` here compared a value nothing had told
    // SwiftUI to re-read: it fired only when some *other* publish on the store
    // happened to bring the window's body round again.
    // The daemon changes the tree behind the app's back — a watcher publishes
    // what Finder drops into the folder, and anti-entropy pulls in what peers
    // publish — and its control service has no call to subscribe to. So the
    // window looks, quietly, and only while it is the one being looked at.
    .background(ListingWatch(
      model: model,
      enabled: activeState == .key && node.connection.isConnected))
    .background(TransferWatch(
      queue: node.transfers, model: model,
      enabled: showTransfersAutomatically && activeState == .key))
    // Every route to Quick Look funnels through the model, so there is one
    // place that fetches the bytes and one that knows which version was asked
    // for. The space bar is not one of SwiftUI's to give — see below.
    .onChange(of: model.previewRequest) { _, request in
      guard let request else { return }
      model.previewRequest = nil
      Task { quickLookURL = await model.materialize(request.entry, version: request.version) }
    }
    // The titlebar names the folder, and the path bar along the bottom of the
    // window spells the whole location — which is how Finder splits the two,
    // and why neither repeats the other.
    //
    // Set here rather than with `.navigationTitle` so the whole location can
    // still be the *window's* name, for the Window menu and Mission Control,
    // while the titlebar shows only the folder.
    // The title no longer has to stand aside for anything. It used to be
    // hidden whenever the filter was open, to free the middle of the title
    // bar for a field this app was placing itself — and hiding it was what
    // made the whole trailing group stop being right-aligned and pack against
    // the leading items. `.searchable` is placed by macOS, which needs no
    // help.
    .background(TitleBar(title: model.folderTitle, windowName: model.locationTitle))
    .focusedSceneValue(\.filesModel, model)
  }

  @ViewBuilder private var detail: some View {
    switch node.connection {
    case .idle:
      FirstRunView(state: .notConnected)
    case .connecting:
      FirstRunView(state: .connecting)
    case .failed(let failure):
      FirstRunView(state: .cannotConnect(failure))
    case .needsUpdate(let failure):
      FirstRunView(state: .versionMismatch(failure))
    case .connected:
      if node.isWaitingToBeNamed {
        FirstRunView(state: .waitingToBeNamed)
      } else {
        ConnectedBrowser(model: model, addingSpace: $addingSpace)
      }
    }
  }
}

#if DEBUG
#Preview("Browser") {
  // The lifecycle modifier is inert against a preview store — see
  // `NodeStore.isPreview` — so this draws the fixture rather than a window
  // spending its deadline failing to reach a daemon.
  FilesWindow(store: NodeStore.preview())
    .environment(NodeStore.preview())
    .frame(width: 900, height: 560)
}
#endif
