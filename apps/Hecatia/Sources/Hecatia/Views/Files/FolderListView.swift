import SwiftUI

/// The folder list, as a real `NSOutlineView`.
///
/// It was a SwiftUI `List(selection:)`, and clicking it did not give it the
/// keyboard: the caret would not move between the two lists, and getting it
/// back took a second click. Reported by hand, against the app as it ships —
/// built against the current SDK, not the compatibility build `swift build`
/// produces, which is a different app for this purpose. There is no cheaper
/// fix than owning the view, and owning it fixed it.
///
/// What it must keep from the SwiftUI version, all of it load-bearing:
/// the source-list material and selection, a "Spaces" section over the
/// shared spaces and an "Add a Space…" row, an "On This Mac" section over
/// the checkouts, a context menu per row, the local path as a tooltip, and a
/// spoken label that names the path as well as the folder.
struct FolderListView: NSViewRepresentable {
  /// The folder list's own type.
  ///
  /// It adds nothing. It exists so the two places that have to find this view
  /// in a window can ask for it by identity — see
  /// ``EntryNSTableView/inWindow(_:)`` for what asking any other way cost.
  final class FolderNSOutlineView: NSOutlineView {}

  let spaces: [Space]
  let checkouts: [CheckoutEntry]
  let selected: String?
  /// A device key rendered as a name, for the checkout rows.
  let policyLabel: (String) -> String
  let onSelect: (String) -> Void
  let onAddFolder: () -> Void
  let onRevealCheckout: (CheckoutEntry) -> Void
  let onStopSharing: (Space) -> Void
  /// `synch adopt tree` — pull the cluster's content into this folder's own
  /// directory. Offered here because this is where someone is when they have
  /// just added a folder that other devices already have files in.
  let onAdopt: (Space) -> Void

  func makeNSView(context: Context) -> NSScrollView {
    let outline = FolderNSOutlineView()
    outline.headerView = nil
    outline.rowSizeStyle = .default
    outline.floatsGroupRows = false
    outline.indentationPerLevel = 0
    // `style` alone. Setting `selectionHighlightStyle = .sourceList` beside it
    // drew the selected row as a flat black bar with the name invisible on it:
    // the row was painting a selection AppKit did not then report to the cell,
    // so `backgroundStyle` never became `.emphasized` and the label kept its
    // ordinary colour — dark text on a dark bar.
    outline.style = .sourceList
    outline.selectionHighlightStyle = .regular
    outline.allowsEmptySelection = true
    outline.allowsMultipleSelection = false
    outline.backgroundColor = .clear
    let column = NSTableColumn(identifier: .init("folder"))
    column.resizingMask = .autoresizingMask
    outline.addTableColumn(column)
    outline.outlineTableColumn = column
    outline.dataSource = context.coordinator
    outline.delegate = context.coordinator
    outline.menu = context.coordinator.makeMenu()
    // A single click, for the rows that are actions rather than selections:
    // "Add a Space…" and a checkout, both of which refuse selection above.
    outline.target = context.coordinator
    outline.action = #selector(Coordinator.rowClicked(_:))

    let scroll = NSScrollView()
    scroll.documentView = outline
    // Scrollers only while scrolling, and never a horizontal one: a sidebar
    // with three rows in it was reserving a track down its right edge.
    scroll.hasVerticalScroller = true
    scroll.hasHorizontalScroller = false
    scroll.autohidesScrollers = true
    scroll.scrollerStyle = .overlay
    scroll.drawsBackground = false
    context.coordinator.outline = outline
    return scroll
  }

  func updateNSView(_ scroll: NSScrollView, context: Context) {
    context.coordinator.apply(self)
  }

  func makeCoordinator() -> Coordinator { Coordinator(self) }

  @MainActor
  final class Coordinator: NSObject, NSOutlineViewDataSource, NSOutlineViewDelegate {
    /// One row of the list. A class so `NSOutlineView`'s untyped `item`
    /// pointers stay identical across reloads, which is what keeps the
    /// selection and the disclosure state from resetting under it.
    final class Row: NSObject {
      enum Kind { case header(String), space(Space), addFolder, checkout(CheckoutEntry) }
      let kind: Kind
      init(_ kind: Kind) { self.kind = kind }

      var isHeader: Bool { if case .header = kind { return true } else { return false } }
      var spaceID: String? { if case .space(let space) = kind { return space.id } else { return nil } }
    }

    private var view: FolderListView
    private var rows: [Row] = []
    weak var outline: NSOutlineView?
    /// What the rows were built from, so a redraw that changes nothing does
    /// not reload the table and drop the selection under the person using it.
    private var builtFrom: [String] = []

    init(_ view: FolderListView) {
      self.view = view
      super.init()
    }

    func apply(_ view: FolderListView) {
      self.view = view
      let signature = ["h:Spaces"]
        // Deliberately not the replication summary: it carries live byte and
        // object counts, so folding it in here would make the signature differ
        // on every five-second poll, reload the table, and drop the selection
        // under whoever is using it. What the rows are *built* from is the id,
        // the path, and whether there is a replication badge at all.
        + view.spaces.map { "s:\($0.id):\($0.localPath ?? "—"):\($0.isReplicating)" }
        + ["+"]
        + (view.checkouts.isEmpty ? [] : ["h:On This Mac"])
        + view.checkouts.map { "m:\($0.id):\($0.localPath):\($0.policy)" }
      if signature != builtFrom {
        builtFrom = signature
        rows = [Row(.header("Spaces"))]
          + view.spaces.map { Row(.space($0)) }
          + [Row(.addFolder)]
        if !view.checkouts.isEmpty {
          rows += [Row(.header("On This Mac"))] + view.checkouts.map { Row(.checkout($0)) }
        }
        outline?.reloadData()
      }
      // Only when it disagrees: setting the selection unconditionally fights
      // the click that is setting it.
      let wanted = rows.firstIndex { $0.spaceID == view.selected }
      if let wanted, outline?.selectedRow != wanted {
        outline?.selectRowIndexes([wanted], byExtendingSelection: false)
      }
    }

    // MARK: - Data

    func outlineView(_ outlineView: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
      item == nil ? rows.count : 0
    }

    func outlineView(_ outlineView: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
      rows[index]
    }

    func outlineView(_ outlineView: NSOutlineView, isItemExpandable item: Any) -> Bool { false }

    func outlineView(_ outlineView: NSOutlineView, isGroupItem item: Any) -> Bool {
      (item as? Row)?.isHeader ?? false
    }

    func outlineView(_ outlineView: NSOutlineView, shouldSelectItem item: Any) -> Bool {
      guard let row = item as? Row else { return false }
      switch row.kind {
      case .header, .addFolder, .checkout: return false
      case .space: return true
      }
    }

    // MARK: - Views

    func outlineView(_ outlineView: NSOutlineView, viewFor column: NSTableColumn?, item: Any) -> NSView? {
      guard let row = item as? Row else { return nil }
      switch row.kind {
      case .header(let title):
        return label(title, secondary: true)
      case .space(let space):
        // An API source or replica-only namespace has no source directory, so
        // it gets a symbol that does not imply a folder exists on this Mac.
        let cell = label(
          space.id, symbol: space.hasFilesystemSource ? "folder" : "shippingbox",
          tint: NSColor.controlAccentColor)
        cell.toolTip = space.pathLabel
        cell.setAccessibilityLabel("\(space.id), \(space.hasFilesystemSource ? "at \(space.localPath ?? "")" : space.pathLabel)")
        return cell
      case .addFolder:
        let cell = label("Add a Space…", symbol: "plus", tint: NSColor.controlAccentColor)
        cell.textField?.textColor = .controlAccentColor
        return cell
      case .checkout(let checkout):
        let name = (checkout.localPath as NSString).lastPathComponent
        let cell = label(name, symbol: "arrow.down.doc")
        cell.toolTip = "Reveal \(checkout.localPath) in Finder"
        cell.detail = "\(checkout.space) · \(view.policyLabel(checkout.policy))"
        return cell
      }
    }

    private func label(
      _ text: String, symbol: String? = nil, tint: NSColor? = nil, secondary: Bool = false
    ) -> SidebarCell {
      let cell = SidebarCell()
      cell.configure(text: text, symbol: symbol, tint: tint, secondary: secondary)
      return cell
    }

    func outlineView(_ outlineView: NSOutlineView, rowViewForItem item: Any) -> NSTableRowView? {
      SidebarRowView()
    }

    // MARK: - Acting on a row

    func outlineViewSelectionDidChange(_ notification: Notification) {
      guard let outline, outline.selectedRow >= 0,
            let id = rows[outline.selectedRow].spaceID
      else { return }
      view.onSelect(id)
    }

    /// A single click on the rows that are not selections but actions.
    @objc func rowClicked(_ sender: NSOutlineView) {
      guard sender.clickedRow >= 0 else { return }
      switch rows[sender.clickedRow].kind {
      case .addFolder: view.onAddFolder()
      case .checkout(let checkout): view.onRevealCheckout(checkout)
      case .header, .space: break
      }
    }

    // MARK: - The context menu

    func makeMenu() -> NSMenu {
      let menu = NSMenu()
      menu.delegate = self
      return menu
    }

    private func clickedRow() -> Row? {
      guard let outline, outline.clickedRow >= 0 else { return nil }
      return rows[outline.clickedRow]
    }

    @objc private func openClicked() {
      if let id = clickedRow()?.spaceID { view.onSelect(id) }
    }

    @objc private func revealClicked() {
      switch clickedRow()?.kind {
      case .space(let space):
        guard let path = space.localPath else { return }
        NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: path)
      case .checkout(let checkout): view.onRevealCheckout(checkout)
      default: break
      }
    }

    @objc private func copyPathClicked() {
      let path: String?
      switch clickedRow()?.kind {
      case .space(let space): path = space.localPath
      case .checkout(let checkout): path = checkout.localPath
      default: path = nil
      }
      guard let path else { return }
      NSPasteboard.general.clearContents()
      NSPasteboard.general.setString(path, forType: .string)
    }

    @objc private func adoptClicked() {
      if case .space(let space)? = clickedRow()?.kind { view.onAdopt(space) }
    }

    @objc private func stopSharingClicked() {
      if case .space(let space)? = clickedRow()?.kind { view.onStopSharing(space) }
    }

    /// The checkout list is a Settings page now, and a `Settings` scene has no
    /// window id — so this asks ``SettingsRoute`` rather than taking a closure
    /// down from the sidebar the way it used to.
    @objc private func checkoutsClicked() { SettingsRoute.open(.spaces) }
  }
}

extension FolderListView.Coordinator: NSMenuDelegate {
  /// Built when it is opened, because what a row offers depends on the row —
  /// and a sidebar row with no context menu is the first place a Mac user
  /// looks for what can be done to the thing it names.
  func menuNeedsUpdate(_ menu: NSMenu) {
    menu.removeAllItems()
    guard let row = clickedRowForMenu() else { return }
    switch row.kind {
    case .space(let space):
      menu.addItem(withTitle: "Open", action: #selector(openClicked), keyEquivalent: "")
      // Only a filesystem source has a directory for these actions.
      if space.hasFilesystemSource {
        menu.addItem(withTitle: "Reveal in Finder", action: #selector(revealClicked), keyEquivalent: "")
        menu.addItem(.separator())
        menu.addItem(
          withTitle: "Adopt From the Cluster\u{2026}", action: #selector(adoptClicked),
          keyEquivalent: "")
        menu.addItem(withTitle: "Copy Path", action: #selector(copyPathClicked), keyEquivalent: "")
      }
      if space.isSource {
        menu.addItem(.separator())
        menu.addItem(withTitle: "Stop Sharing…", action: #selector(stopSharingClicked), keyEquivalent: "")
      }
    case .checkout:
      menu.addItem(withTitle: "Reveal in Finder", action: #selector(revealClicked), keyEquivalent: "")
      menu.addItem(withTitle: "Copy Path", action: #selector(copyPathClicked), keyEquivalent: "")
      menu.addItem(.separator())
      menu.addItem(withTitle: "Checkouts…", action: #selector(checkoutsClicked), keyEquivalent: "")
    case .header, .addFolder:
      break
    }
    for item in menu.items { item.target = self }
  }

  private func clickedRowForMenu() -> Row? {
    guard let outline, outline.clickedRow >= 0 else { return nil }
    return outline.item(atRow: outline.clickedRow) as? Row
  }
}

#if DEBUG
/// The list with the sidebar's own rows in it, and a selection that moves.
///
/// The closures are ``FilesSidebar``'s, minus what they open. The selection is
/// state here rather than a constant because a row that cannot be clicked into
/// says nothing about the list this file exists to fix.
private struct FolderListPreview: View {
  let store: NodeStore
  let spaces: [Space]
  let checkouts: [CheckoutEntry]
  @State private var selected: String?

  init(store: NodeStore, checkouts: [CheckoutEntry]? = nil) {
    self.store = store
    self.spaces = store.spaces
    self.checkouts = checkouts ?? store.checkouts
    _selected = State(initialValue: store.spaces.first?.id)
  }

  var body: some View {
    FolderListView(
      spaces: spaces,
      checkouts: checkouts,
      selected: selected,
      policyLabel: { wire in
        guard let policy = VersionPolicy(wire: wire) else { return wire }
        if case .origin(let id) = policy { return "From \(store.label(forOrigin: id))" }
        return policy.label
      },
      onSelect: { selected = $0 },
      onAddFolder: {},
      onRevealCheckout: { _ in },
      onStopSharing: { _ in },
      onAdopt: { _ in })
  }
}

#Preview("Spaces") {
  // Four spaces and a checkout. One is an API source with no directory, so it
  // is the row drawn with a box
  // instead of a folder, and the checkout is the row that carries a second line.
  FolderListPreview(store: NodeStore.preview())
    .frame(width: 230, height: 420)
}

#Preview("No spaces shared") {
  // Nothing to list and nothing to select. The header and "Add a Space…"
  // stay, because that row is the way out of this state; the "On This Mac"
  // header is gone with the checkouts, rather than standing over nothing.
  FolderListPreview(store: NodeStore.preview(spaces: []), checkouts: [])
    .frame(width: 230, height: 420)
}

#Preview("Spaces, squeezed") {
  // 200pt is the least `FilesWindow` lets this column be. The checkout row is
  // what has to survive it: a name, a symbol and a line of detail under both.
  FolderListPreview(store: NodeStore.preview())
    .frame(width: 200, height: 420)
}
#endif
