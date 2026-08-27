import SwiftUI

/// The file list, as a real `NSTableView`.
///
/// It was a SwiftUI `Table`, and clicking it did not give it the keyboard:
/// reported by hand as "the caret leaves the file list and it takes two
/// clicks to get it back", and reproducible with a mouse in a way no amount
/// of coaxing from the SwiftUI side fixed. The folder list went first
/// (``FolderListView``); this is the other half.
///
/// What the probe said at the time is not quoted here, and should not be
/// quoted anywhere: its clicks were delivered by `sendEvent`, which an AppKit
/// table cannot answer — see `UIProbe.send`. The report that decided this was
/// a person's.
///
/// The cells are still SwiftUI, hosted per row. What had to become AppKit is
/// the table: the selection, the sorting, the columns and the keyboard.
struct EntryTableView: NSViewRepresentable {
  let rows: [RemoteEntry]
  let selection: Set<RemoteEntry.ID>
  let sortOrder: [KeyPathComparator<RemoteEntry>]
  /// Built by the caller, so every cell looks exactly as it did in the
  /// `Table` this replaces.
  let cell: (RemoteEntry, Column) -> AnyView
  let onSelect: (Set<RemoteEntry.ID>) -> Void
  let onSort: ([KeyPathComparator<RemoteEntry>]) -> Void
  let onActivate: (Set<RemoteEntry.ID>) -> Void
  let onDelete: () -> Void
  /// What the context menu offers, for a set of rows — empty for the area
  /// below the last one. A ``MenuPlan`` rather than an `NSMenu`, because the
  /// menu AppKit shows is the one it hands the delegate, not one built beside
  /// it.
  let menu: (Set<RemoteEntry.ID>) -> MenuPlan

  /// The five columns, in the order they are added.
  ///
  /// `Device` is hidden until someone asks for it, the way
  /// `.defaultVisibility(.hidden)` had it — and the table's own autosave
  /// remembers that choice from then on.
  enum Column: String, CaseIterable {
    case name, versions, size, modified, device

    var title: String {
      switch self {
      case .name: "Name"
      case .versions: "Versions"
      case .size: "Size"
      case .modified: "Modified"
      case .device: "Device"
      }
    }

    var widths: (min: Double, ideal: Double, max: Double) {
      switch self {
      case .name: (200, 320, 10_000)
      case .versions: (60, 70, 100)
      case .size: (70, 90, 130)
      case .modified: (100, 140, 200)
      case .device: (80, 130, 240)
      }
    }

    var hiddenByDefault: Bool { self == .device }

    /// What a click on the header sorts by. The same key paths the `Table`
    /// sorted on, so a saved sort order still means what it meant.
    var comparator: KeyPathComparator<RemoteEntry> {
      switch self {
      case .name: KeyPathComparator(\.name)
      case .versions: KeyPathComparator(\.versions)
      case .size: KeyPathComparator(\.size)
      case .modified: KeyPathComparator(\.modified)
      case .device: KeyPathComparator(\.origin)
      }
    }
  }

  func makeNSView(context: Context) -> NSScrollView {
    let table = EntryNSTableView()
    table.usesAlternatingRowBackgroundColors = true
    table.allowsMultipleSelection = true
    table.allowsEmptySelection = true
    table.style = .inset
    table.rowSizeStyle = .default
    // The coordinator, named. Writing `context.coordinator` inside a closure
    // captures `context` — the whole `NSViewRepresentableContext`, with its
    // `Transaction` and a snapshot of the environment taken here — and these
    // closures live on the table for as long as the window does, so that
    // snapshot would never be released.
    let coordinator = context.coordinator
    table.dataSource = coordinator
    table.delegate = coordinator
    table.target = coordinator
    table.doubleAction = #selector(Coordinator.doubleClicked)
    table.onDelete = { [weak coordinator] in coordinator?.view.onDelete() }
    table.onActivate = { [weak table, weak coordinator] in
      guard let table, let coordinator else { return }
      coordinator.view.onActivate(coordinator.ids(for: table.selectedRowIndexes))
    }
    // Built when it is opened, by the delegate, so `NSTableView` gets to set
    // `clickedRow` on the way — see ``EntryTableView/Coordinator``.
    let menu = NSMenu()
    menu.delegate = coordinator
    table.menu = menu
    // The column widths and which ones are showing, remembered the way
    // `columnCustomization` used to remember them.
    table.autosaveName = "entryColumns"
    table.autosaveTableColumns = true

    for column in Column.allCases {
      let item = NSTableColumn(identifier: .init(column.rawValue))
      item.title = column.title
      item.minWidth = column.widths.min
      item.maxWidth = column.widths.max
      item.width = column.widths.ideal
      item.isHidden = column.hiddenByDefault
      item.sortDescriptorPrototype = NSSortDescriptor(key: column.rawValue, ascending: true)
      table.addTableColumn(item)
    }
    table.sortDescriptors = context.coordinator.descriptors(from: sortOrder)

    let scroll = NSScrollView()
    scroll.documentView = table
    scroll.hasVerticalScroller = true
    scroll.hasHorizontalScroller = true
    scroll.autohidesScrollers = true
    context.coordinator.table = table
    return scroll
  }

  func updateNSView(_ scroll: NSScrollView, context: Context) {
    context.coordinator.apply(self)
  }

  func makeCoordinator() -> Coordinator { Coordinator(self) }

  @MainActor
  final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate {
    var view: EntryTableView
    weak var table: EntryNSTableView?
    /// The rows as the table currently has them, so a redraw that changes
    /// nothing does not reload the table under the person using it.
    private var shown: [RemoteEntry] = []

    init(_ view: EntryTableView) {
      self.view = view
      super.init()
    }

    func apply(_ view: EntryTableView) {
      self.view = view
      guard let table else { return }
      let changed = shown != view.rows
      shown = view.rows
      if changed { table.reloadData() }
      let wanted = IndexSet(shown.indices.filter { view.selection.contains(shown[$0].id) })
      if table.selectedRowIndexes != wanted {
        table.selectRowIndexes(wanted, byExtendingSelection: false)
      }
      let descriptors = descriptors(from: view.sortOrder)
      if table.sortDescriptors != descriptors { table.sortDescriptors = descriptors }
    }

    func ids(for rows: IndexSet) -> Set<RemoteEntry.ID> {
      Set(rows.compactMap { $0 < shown.count ? shown[$0].id : nil })
    }

    func descriptors(from order: [KeyPathComparator<RemoteEntry>]) -> [NSSortDescriptor] {
      order.compactMap { comparator in
        guard let column = Column.allCases.first(where: {
          $0.comparator.keyPath == comparator.keyPath
        }) else { return nil }
        return NSSortDescriptor(
          key: column.rawValue, ascending: comparator.order == .forward)
      }
    }

    // MARK: - Data

    func numberOfRows(in tableView: NSTableView) -> Int { shown.count }

    func tableView(
      _ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int
    ) -> NSView? {
      guard let tableColumn, let column = Column(rawValue: tableColumn.identifier.rawValue),
            row < shown.count
      else { return nil }
      let identifier = tableColumn.identifier
      let cell = tableView.makeView(withIdentifier: identifier, owner: self)
        as? HostingCell<AnyView> ?? {
          let made = HostingCell<AnyView>()
          made.identifier = identifier
          return made
        }()
      cell.setContent(view.cell(shown[row], column))
      return cell
    }

    // MARK: - Selection and sorting

    func tableViewSelectionDidChange(_ notification: Notification) {
      guard let table else { return }
      view.onSelect(ids(for: table.selectedRowIndexes))
    }

    func tableView(_ tableView: NSTableView, sortDescriptorsDidChange old: [NSSortDescriptor]) {
      let order: [KeyPathComparator<RemoteEntry>] = tableView.sortDescriptors.compactMap {
        guard let key = $0.key, let column = Column(rawValue: key) else { return nil }
        var comparator = column.comparator
        comparator.order = $0.ascending ? .forward : .reverse
        return comparator
      }
      guard !order.isEmpty else { return }
      view.onSort(order)
    }

    @objc func doubleClicked() {
      guard let table, table.clickedRow >= 0 else { return }
      view.onActivate(ids(for: table.selectedRowIndexes))
    }
  }
}

extension EntryTableView.Coordinator: NSMenuDelegate {
  /// Built when it is opened, because what it offers depends on the row — and
  /// through the delegate rather than through a `menu(for:)` override, which
  /// is the same shape ``FolderListView`` uses.
  ///
  /// The override is what `NSTableView` sets ``NSTableView/clickedRow`` in, so
  /// answering from one without calling `super` leaves it at `-1` for the
  /// whole right-click: the menu fell back to whatever was selected, and both
  /// a folder and the empty area below the rows offered a file's menu. Working
  /// the row out from the event instead would have fixed the menu and left
  /// `clickedRow` lying to everything else that reads it — `doubleClicked`
  /// above, for one.
  func menuNeedsUpdate(_ menu: NSMenu) {
    guard let table else { return menu.removeAllItems() }
    let clicked = table.clickedRow
    guard shown.indices.contains(clicked) else {
      // Below the last row: the empty area's menu, which offers to add files
      // rather than to act on whatever happened to be selected.
      return view.menu([]).fill(menu)
    }
    // The clicked row joins the selection the way AppKit's own tables do:
    // right-clicking a row that is not selected acts on *it*.
    if !table.selectedRowIndexes.contains(clicked) {
      table.selectRowIndexes([clicked], byExtendingSelection: false)
    }
    view.menu(ids(for: table.selectedRowIndexes)).fill(menu)
  }
}

/// The table itself, for the two keys a delegate cannot answer.
///
/// Delete is `keyDown` rather than `deleteBackward:` because the second is
/// only sent to a field editor, and ⌘↓ opens what is selected by the same rule
/// a double-click uses — both were `onDeleteCommand` and `onKeyPress` on the
/// SwiftUI table.
final class EntryNSTableView: NSTableView {
  var onDelete: (() -> Void)?
  var onActivate: (() -> Void)?

  /// The file list in a window, by identity.
  ///
  /// One answer to "which of these views is the file list", in the one place
  /// that owns the type. It has been three answers: a walk here that took the
  /// `NSTableView` that was not an `NSOutlineView` — true only while nothing
  /// else in the window is a table — and two spellings that sniffed the class
  /// *name* for "TableView", which was how SwiftUI's two lists told themselves
  /// apart and meant nothing once both became this app's own.
  static func inWindow(_ window: NSWindow) -> EntryNSTableView? {
    func walk(_ view: NSView?) -> EntryNSTableView? {
      guard let view else { return nil }
      if let table = view as? EntryNSTableView { return table }
      for child in view.subviews {
        if let found = walk(child) { return found }
      }
      return nil
    }
    return walk(window.contentView?.superview ?? window.contentView)
  }

  override func keyDown(with event: NSEvent) {
    let deleteKeys: Set<UInt16> = [51, 117]  // delete, forward delete
    if deleteKeys.contains(event.keyCode), !selectedRowIndexes.isEmpty {
      onDelete?()
      return
    }
    if event.keyCode == 125, event.modifierFlags.contains(.command), !selectedRowIndexes.isEmpty {
      onActivate?()
      return
    }
    super.keyDown(with: event)
  }

  /// Declared, and it must be. It does nothing but call `super`, and taking it
  /// away breaks clicking into the file list.
  ///
  /// Measured, both directions, twice each, one variable at a time: with this
  /// override the probe's `focuschain` suite passes; delete it and the same
  /// binary fails five checks — a click into a row leaves the caret wherever it
  /// was, and the trace shows no `becomeFirstResponder` after the click at all,
  /// so `NSTableView.mouseDown` is never reaching the point where it asks. The
  /// body is irrelevant: a bare `super.mouseDown(with: event)` passes exactly
  /// as the instrumented version does.
  ///
  /// I cannot explain it, and it is written down rather than explained away.
  /// What can be said is what was ruled out by experiment: it is not
  /// `HostingCell.hitTest` (the suite passes with that override gone and this
  /// one present, and fails with that one present and this gone), not the
  /// `NSMenuDelegate` conformance on the coordinator, not the coordinator
  /// capture in `makeNSView`, and not the row diffing in `apply`.
  ///
  /// It lived in `#if DEBUG` as instrumentation, which meant release builds did
  /// not have it — so this is a fix, not a preservation.
  override func mouseDown(with event: NSEvent) {
    super.mouseDown(with: event)
    #if DEBUG
    FocusTrace.claim("EntryNSTableView", "mouseDown -> \(String(describing: window?.firstResponder.map { type(of: $0) }))")
    #endif
  }

  #if DEBUG
  // Instrumentation, inert unless `HECATIA_FOCUS_TRACE` is set. It answers the
  // question that took the longest to answer honestly: when a click lands and
  // the caret does not follow, is it the table refusing the caret or the table
  // taking it and something else taking it back? These two settled it — the
  // table was never asked, because the click never finished.
  override func becomeFirstResponder() -> Bool {
    let granted = super.becomeFirstResponder()
    FocusTrace.claim("EntryNSTableView", "becomeFirstResponder -> \(granted)")
    return granted
  }

  override func resignFirstResponder() -> Bool {
    let released = super.resignFirstResponder()
    FocusTrace.claim("EntryNSTableView", "resignFirstResponder -> \(released)")
    return released
  }

  #endif
}

#if DEBUG
/// The table with the browser's own cells in it.
///
/// Not stand-ins: this is an AppKit surface hosting SwiftUI per row, and what
/// a row looks like once it is inside a ``HostingCell`` is the thing a preview
/// of it is for. The closures are ``EntryTable``'s, minus what they open — the
/// selection and the sort still go through the model, so clicking a row and
/// clicking a header both do here what they do in the app.
private struct EntryTablePreview: View {
  let model: FilesModel
  /// Read directly rather than from the environment: a hosted cell is built by
  /// an `NSHostingView` of AppKit's making and inherits nothing from the view
  /// this preview puts the store in.
  let store: NodeStore

  var body: some View {
    EntryTableView(
      rows: model.visibleRows,
      selection: model.selection,
      sortOrder: model.sortOrder,
      cell: { entry, column in
        AnyView(
          cell(entry, column)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Theme.Space.xs))
      },
      onSelect: { model.selection = $0 },
      onSort: { model.sortOrder = $0 },
      onActivate: { _ in },
      onDelete: {},
      menu: { ids in
        // Two menus, because the table has two: the empty area below the last
        // row offers to add files rather than to act on the selection.
        ids.isEmpty
          ? MenuPlan([.item("Add Files\u{2026}") {}, .item("Refresh") {}])
          : MenuPlan([
              .item("Quick Look") {},
              .item("Show Versions") {},
              .separator,
              .item("Delete", destructive: true) {},
            ])
      })
  }

  @ViewBuilder private func cell(
    _ entry: RemoteEntry, _ column: EntryTableView.Column
  ) -> some View {
    switch column {
    case .name:
      EntryNameCell(
        entry: entry, model: model,
        opensUnderPolicy: !model.withheldPaths.contains(entry.path),
        withheldChip: "several versions",
        withheldHelp: "More than one device publishes this, and Strict refuses to choose between them.",
        spokenLabel: "\(entry.name), \(entry.kindLabel)")
    case .versions:
      if entry.hasVersions {
        StatusChip(
          text: "\(entry.versions)", tint: Theme.warning, systemImage: "arrow.triangle.branch")
      } else if !entry.isSynthesizedDirectory {
        Text("\u{2014}").cellForeground(Theme.muted)
      }
    case .size:
      Text(entry.sizeLabel)
        .font(Theme.Font.mono(.subheadline))
        .cellForeground(Theme.muted)
        .monospacedDigit()
    case .modified:
      Text(entry.modifiedLabel).font(.caption).cellForeground(Theme.muted)
    case .device:
      DeviceCell(name: store.label(forOrigin: entry.origin), key: entry.origin)
    }
  }
}

#Preview("Rows") {
  // A conflicted file and two synthesized folders among the rest: the versions
  // chip and the em dashes a folder row leaves behind are half of what this
  // table draws.
  let store = NodeStore.preview()
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes", store: store)
  return EntryTablePreview(model: model, store: store)
    .environment(store)
    .frame(width: 840, height: 420)
}

#Preview("Rows, squeezed") {
  // About what the table is given when the window is at its 860pt minimum and
  // the sidebar is at its ideal 230. The four visible columns' minimum widths
  // add up to 430, so this is still above the point where it scrolls sideways.
  let store = NodeStore.preview()
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes", store: store)
  return EntryTablePreview(model: model, store: store)
    .environment(store)
    .frame(width: 620, height: 320)
}

#Preview("An empty folder") {
  // Headers and nothing under them. The sentences that explain an empty folder
  // are an overlay ``EntryTable`` draws over this, not something the table has.
  let store = NodeStore.preview()
  let model = FilesModel.preview(rows: [], space: "notes", store: store)
  return EntryTablePreview(model: model, store: store)
    .environment(store)
    .frame(width: 840, height: 240)
}
#endif
