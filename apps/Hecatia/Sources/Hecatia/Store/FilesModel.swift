import Foundation
import SwiftUI

/// One browser window's state.
///
/// Per-window on purpose: ⌘N used to open a second window onto the same model,
/// so both navigated together and both raised every alert. The daemon-wide
/// state they genuinely share stays in ``NodeStore``.
@MainActor
@Observable
final class FilesModel {

  private(set) var selectedSpace: String?
  private(set) var prefix = ""
  private(set) var rows: [RemoteEntry] = [] {
    didSet { visibleCache = nil }
  }
  private(set) var isLoading = false
  /// True when a listing stopped before the daemon ran out of paths. Never
  /// silent: the old client capped at 500 rows with no notice, so a large
  /// folder simply looked small.
  private(set) var wasTruncated = false
  /// How far a multi-path delete has got, while one is running.
  ///
  /// Not `private(set)`: `delete` lives in the FileOperations extension, and
  /// `private(set)` is file scope.
  var deleteProgress: DeleteProgress?
  /// Set by the status bar's Stop, read by the delete loop between paths.
  ///
  /// A flag rather than `Task.cancel()`, and the reason is not that
  /// cancellation would fail to arrive — it would. `client.delete` goes
  /// through `makeDeleteCall`, and `GRPCAsyncUnaryCall.response` is wrapped in
  /// a `withTaskCancellationHandler` that cancels the RPC, so a cancelled task
  /// really would abort the request in flight. That is the objection, not the
  /// argument for it: a `Delete` aborted mid-flight leaves that one path in a
  /// state nobody can report, because the daemon may have removed it or may
  /// not. A flag read between paths leaves a boundary the loop can name, which
  /// is the same "N of M" the failure branch below already reports.
  ///
  /// There is also no handle that means *this* delete. `store.enqueue` makes
  /// a task per call but keeps only the newest in `commandChain`, so by the
  /// time a person reaches for Stop that property is as likely to be some
  /// later command's task as this one's — and cancelling the newest would
  /// drop whatever was queued behind the delete rather than the delete.
  ///
  /// Not `private(set)`, for the reason above it.
  var stopDeleteRequested = false
  /// Paths this folder holds that the chosen version policy will not open.
  ///
  /// Empty under Newest. The daemon's `List` applies the policy itself and has
  /// no way to report a per-path refusal, so it simply omits the path — which
  /// meant choosing Strict deleted every divergent row from the folder, took
  /// the "N need a decision" button with it, and could leave an all-divergent
  /// folder reading "Nothing here yet". So the listing is folded under Newest,
  /// which is what the folder *holds*, and the policy marks rather than
  /// removes — which is what the toolbar control has always claimed it did.
  private(set) var withheldPaths: Set<String> = []
  /// Why the last listing did not finish, if it did not.
  ///
  /// A failed listing used to be indistinguishable from an empty folder: the
  /// table drew "Nothing here yet — drop files in", which is a statement the
  /// app could not make, with no trace of what went wrong and no way to try
  /// again.
  private(set) var loadFailure: DaemonFailure?
  /// Which entry ``history`` describes, so a stale panel can be told apart
  /// from a loading one.
  private(set) var historyPath: String?

  var selection: Set<RemoteEntry.ID> = []
  var sortOrder: [KeyPathComparator<RemoteEntry>] = [
    .init(\.name, order: .forward)
  ] {
    didSet { visibleCache = nil }
  }
  var search = "" {
    didSet { if search != oldValue { visibleCache = nil } }
  }
  var policy: VersionPolicy = .newest
  /// Whether the versions panel is showing. Set through ``setPanel(_:)``
  /// rather than directly, so it opens the same way everywhere.
  var inspectorVisible = false
  /// Which of the inspector's three tabs is showing.
  ///
  /// On the model rather than as the panel's own `@State`, for the reason
  /// ``importRequested`` is: four things call themselves "Show Versions" — the
  /// toolbar's own help text, the row menu, the empty-area menu and ⌥⌘I — and
  /// none of them could reach a `@State` inside the panel, so all four opened
  /// it on whichever tab was last used, usually Info.
  var inspectorSection: InspectorSection = .info
  /// Set by the toolbar button and by the File menu, so both open the same panel.
  var importRequested = false
  /// Whether the transfer list is open. On the model rather than the window so
  /// the status bar, the menu bar and the "open it automatically" preference
  /// can all reach the one popover.
  var showingTransfers = false
  /// Whether the toolbar's search field is open.
  ///
  /// Without this binding `.searchable` draws a full-width field whenever there
  /// is room for one, which takes about a fifth of the toolbar whether or not
  /// anyone is searching. Presented explicitly, macOS draws the collapsed
  /// magnifier that expands on click — Finder's behaviour — and Command-F and
  /// the status bar can open it too.
  ///
  /// It watches itself, because the field has more ways out than this app
  /// knows about: Escape, the field's own clear button, ⌘F a second
  /// time. `.searchable` writes `false` here for all of them without passing
  /// through ``clearSearch()``, and the caret — which was in the field — left
  /// with it and landed nowhere. Measured: the first responder became the
  /// window itself, and from there the arrow keys, the space bar and
  /// Command-Delete all did nothing until something was clicked.
  var searchPresented = false {
    didSet {
      // Only on the way down, and only on a change. This is assigned `false`
      // on every navigation by way of `clearSearch()`, and asking for the
      // caret there would drag it into the file list each time a folder
      // changed — which is exactly what arrowing down the sidebar does, so the
      // next press would have gone to the wrong list. The guard is what makes
      // that structural rather than something each caller has to remember.
      guard oldValue, !searchPresented else { return }
      listFocusRequest += 1
    }
  }
  /// Bumped every time something asks for the caret, so the field can tell a
  /// fresh request apart from a redraw.
  ///
  /// A `Bool` cannot express this: ⌘F with the field already open re-assigns
  /// `true` to a value that is already `true`, and the field — which takes the
  /// first responder exactly once — has nothing to distinguish that from any
  /// other update. Typing a filter and pressing Return left the field on
  /// screen, unfocused, and ⌘F could not get back into it.
  private(set) var searchFocusRequest = 0
  /// Bumped every time the file list should have the caret. Same shape as
  /// ``searchFocusRequest`` and for the same reason: a `Bool` cannot tell a
  /// fresh request from a redraw.
  private(set) var listFocusRequest = 0
  /// A preview the window should open.
  ///
  /// Every route to Quick Look — the space bar, Command-Y, a double-click, the
  /// context menu, the inspector's per-version button — sets this, so there is
  /// one path to the file being fetched and one place that knows which version
  /// was asked for.
  var previewRequest: PreviewRequest?
  /// Beside ``importRequested`` and for the same reason: the menu bar drives
  /// the window, and a menu command reaches the focused window through its
  /// model rather than through a `@State` the menu cannot see.
  var compareRequested = false

  /// The selected path's versions, for the inspector.
  private(set) var versions: PathVersions?
  private(set) var versionsLoading = false
  private(set) var history: [String] = []
  /// Attestors `status` truncated and nothing known could restore.
  private(set) var unresolvedAttestors: [String] = []
  /// A file the daemon wrote into the folder and then refused to publish.
  private(set) var historyLoading = false

  private var back: [(space: String, prefix: String)] = []
  private var forward: [(space: String, prefix: String)] = []

  /// Discards a listing that a newer navigation has superseded. Without it a
  /// slow folder's rows land under a different folder's heading, and a delete
  /// from those rows targets a path the confirmation never named.
  private var generation = 0
  private var versionGeneration = 0
  private var historyGeneration = 0
  /// Which folder ``rows`` describes, so a refresh of the folder you are in
  /// can be told apart from a move to a different one.
  private var rowsTarget: (space: String, prefix: String)?
  private var pendingReload: Task<Void, Never>?
  /// Which schedule owns ``pendingReload``. `cancel()` does not stop a task
  /// already inside `reload()`, so a superseded one must not clear a newer
  /// one's handle on its way out.
  private var reloadToken = 0

  let store: NodeStore

  init(store: NodeStore) { self.store = store }

  // MARK: - Derived

  var canGoUp: Bool { !prefix.isEmpty }
  var canGoBack: Bool { !back.isEmpty }
  var canGoForward: Bool { !forward.isEmpty }

  /// The window's title: the whole location, since the titlebar no longer
  /// draws it beside the path control that says the same thing. The Window
  /// menu, Mission Control and the app switcher still use it.
  var locationTitle: String {
    guard let space = selectedSpace else { return "Synchronicity" }
    return prefix.isEmpty ? space : "\(space)/\(prefix)"
  }

  /// The folder itself, which is what the titlebar shows.
  var folderTitle: String {
    breadcrumbs.last?.name ?? selectedSpace ?? "Synchronicity"
  }

  var breadcrumbs: [(name: String, prefix: String)] {
    guard let space = selectedSpace else { return [] }
    var crumbs: [(String, String)] = [(space, "")]
    var accumulated = ""
    for component in prefix.split(separator: "/") {
      accumulated = accumulated.isEmpty ? String(component) : "\(accumulated)/\(component)"
      crumbs.append((String(component), accumulated))
    }
    return crumbs
  }

  /// The rows the table draws, filtered and sorted.
  ///
  /// Cached, because it is read three times per pass of `EntryTable.body` —
  /// as the table's data, as the empty-state test and as the item count — and
  /// that body re-runs on every arrow key, since `selection` is published.
  /// Measured at 10,000 rows the sort alone was 43ms, so a keypress cost about
  /// 130ms of it. The cache is dropped by the `didSet` on each of the three
  /// inputs, so there is no way to read a stale one.
  var visibleRows: [RemoteEntry] {
    if let visibleCache { return visibleCache }
    let computed = computeVisibleRows()
    visibleCache = computed
    return computed
  }

  private var visibleCache: [RemoteEntry]?

  private func computeVisibleRows() -> [RemoteEntry] {
    Self.arrange(rows, matching: search, by: sortOrder)
  }

  /// Filter and order, in one pass, with folders first.
  ///
  /// It used to be two passes: `sorted(using:)` and then
  /// `sorted { lhs.isDirectory && !rhs.isDirectory }`. That is twice the work,
  /// and the second sort is only correct if the first one's order survives it
  /// — which Swift's sort does not promise, because it is not stable. A folder
  /// could come back with its files in an order no column header asked for.
  ///
  /// Static, pure and `nonisolated` so the ordering can be tested without a
  /// daemon and without a main actor.
  nonisolated static func arrange(
    _ rows: [RemoteEntry], matching search: String,
    by comparators: [KeyPathComparator<RemoteEntry>]
  ) -> [RemoteEntry] {
    let filtered = search.isEmpty
      ? rows
      : rows.filter { $0.name.localizedStandardContains(search) }
    return filtered.sorted { lhs, rhs in
      // Folders first, whatever the sort — the same rule Finder uses.
      if lhs.isDirectory != rhs.isDirectory { return lhs.isDirectory }
      for comparator in comparators {
        switch comparator.compare(lhs, rhs) {
        case .orderedAscending: return true
        case .orderedDescending: return false
        case .orderedSame: continue
        }
      }
      return false
    }
  }

  var selectedEntries: [RemoteEntry] {
    rows.filter { selection.contains($0.id) }
  }

  /// The selection in the order it is on screen.
  ///
  /// ``selectedEntries`` filters `rows`, and `rows` comes off the listing fold
  /// as folders followed by a dictionary's values — so `.first` of it is a
  /// folder if one is selected, and otherwise an arbitrary file that differs
  /// between launches. Everything that acts on "the selected thing" reads this
  /// instead. Costs nothing: `visibleRows` is cached.
  var visibleSelectedEntries: [RemoteEntry] {
    visibleRows.filter { selection.contains($0.id) }
  }

  /// The file a Quick Look would open: one row does what it says, and a mixed
  /// selection previews the first *file* in screen order rather than refusing
  /// because a folder happened to sort first.
  var previewableSelection: RemoteEntry? {
    visibleSelectedEntries.first(where: \.isFile)
  }

  var selectedEntry: RemoteEntry? {
    selectedEntries.count == 1 ? selectedEntries.first : nil
  }

  var divergentCount: Int { rows.count(where: \.hasVersions) }

  /// The first row that has something to decide, for the status bar's button.
  var firstDivergentEntry: RemoteEntry? { visibleRows.first(where: \.hasVersions) }

  /// Opens the versions panel on a row that actually has versions.
  ///
  /// The status bar's "N need a decision" used to open the panel and change
  /// nothing else, so it landed on "Nothing selected" — a button that named a
  /// number and then showed none of it.
  /// Puts the folder back to the policy that opens everything.
  func showNewest() {
    policy = .newest
  }

  func showVersions(of entry: RemoteEntry? = nil) {
    if let entry {
      selection = [entry.id]
    } else if selection.isEmpty || selectedEntry?.hasVersions != true,
              let first = firstDivergentEntry {
      selection = [first.id]
    }
    inspectorSection = .versions
    setPanel(true)
  }

  /// Shows or hides the versions panel.
  func setPanel(_ visible: Bool) {
    inspectorVisible = visible
  }

  func togglePanel() { setPanel(!inspectorVisible) }

  /// Closes the panel, or opens it *on the Versions tab* on a row that has
  /// versions. Not the same as ``togglePanel()``, which leaves the tab alone:
  /// this is what the menu item and the table's own menu both mean by
  /// "Show Versions".
  func toggleVersionsPanel() {
    if inspectorVisible { setPanel(false) } else { showVersions() }
  }

  // MARK: - The filter

  /// Opens the filter field and asks for the caret.
  func openSearch() {
    searchPresented = true
    searchFocusRequest += 1
  }

  /// Clears the filter and puts the magnifier back.
  ///
  /// Every route out of a filter *this app* offers goes through here. Clearing
  /// it from the empty state's button or from the status bar used to leave an
  /// expanded, empty field in the toolbar, because collapsing was only ever a
  /// reaction to that field losing the focus.
  ///
  /// The caret is not this function's business: ``searchPresented`` asks for it
  /// whenever a field that was up goes away, which covers the routes macOS
  /// offers too.
  func clearSearch() {
    search = ""
    searchPresented = false
  }

  // MARK: - Navigation

  func select(space id: String) {
    guard selectedSpace != id else {
      // Clicking the folder you are already in used to do nothing at all, so
      // there was no way to refresh it or return to its root.
      if prefix.isEmpty { Task { await reload() } } else { navigate(space: id, prefix: "") }
      return
    }
    navigate(space: id, prefix: "")
  }

  func open(_ entry: RemoteEntry) {
    guard entry.isDirectory, let space = selectedSpace else { return }
    navigate(space: space, prefix: entry.path)
  }

  func goUp() {
    guard let space = selectedSpace, canGoUp else { return }
    navigate(space: space, prefix: prefix.split(separator: "/").dropLast().joined(separator: "/"))
  }

  func goBack() {
    guard let previous = back.popLast(), let space = selectedSpace else { return }
    forward.append((space, prefix))
    apply(space: previous.space, prefix: previous.prefix)
  }

  func goForward() {
    guard let next = forward.popLast(), let space = selectedSpace else { return }
    back.append((space, prefix))
    apply(space: next.space, prefix: next.prefix)
  }

  func jump(to crumb: String) {
    guard let space = selectedSpace else { return }
    // The last crumb is the folder you are in, and it stays clickable — greying
    // it out would dim the most legible label in the toolbar. Clicking it just
    // does nothing, rather than pushing a back step to where you already are
    // and throwing the forward history away on the way.
    guard crumb != prefix else { return }
    navigate(space: space, prefix: crumb)
  }

  private func navigate(space: String, prefix newPrefix: String) {
    if let current = selectedSpace { back.append((current, prefix)) }
    forward.removeAll()
    apply(space: space, prefix: newPrefix)
  }

  private func apply(space: String, prefix newPrefix: String) {
    selectedSpace = space
    prefix = newPrefix
    selection = []
    versions = nil
    history = []
    // The filter belongs to the folder it was typed in. Carrying it across
    // meant arriving somewhere new and being shown a subset of it, with the
    // only explanation sitting in a search field at the other end of the
    // toolbar — a folder that looked empty and was not.
    clearSearch()
    Task { await reload() }
  }

  /// Keeps the selection pointed at a folder that still exists.
  ///
  /// It used to only ever *adopt*: removing the folder you were browsing left
  /// the sidebar with no selected row while the title bar, the path bar and
  /// Add Files… all went on naming it — and the daemon no longer indexes it,
  /// so anything added would have gone nowhere.
  func adoptFirstSpaceIfNeeded(_ spaces: [Space]) {
    // An empty list is "not known yet", not "yours is gone": `disconnect`
    // empties `spaces`, and the app reconnects on its own — so clearing on it
    // would throw away the folder someone was in every time the daemon
    // blinked. A daemon that really has no folders shows the no-folders screen
    // regardless, so a selection left standing behind it is invisible.
    if !spaces.isEmpty, let current = selectedSpace,
       !spaces.contains(where: { $0.id == current }) {
      selectedSpace = nil
      prefix = ""
      selection = []
      rows = []
      rowsTarget = nil
      clearSearch()
    }
    guard selectedSpace == nil, let first = spaces.first else { return }
    selectedSpace = first.id
    Task { await reload() }
  }

  // MARK: - Listing

  #if DEBUG
  /// How many listings this model has run. Read only by the probe, so that
  /// "one listing per burst" can be counted rather than assumed.
  private(set) var reloadCount = 0
  #endif

  func reload() async {
    #if DEBUG
    MainActorWatchdog.doing = "reload the folder"
    defer { MainActorWatchdog.doing = "idle" }
    #endif
    #if DEBUG
    reloadCount += 1
    #endif
    guard store.connection.isConnected, let space = selectedSpace else {
      rows = []
      rowsTarget = nil
      wasTruncated = false
      withheldPaths = []
      return
    }
    generation += 1
    let mine = generation
    isLoading = true
    loadFailure = nil
    // Cleared when the folder changes, and only then. Leaving the *previous
    // folder's* rows on screen while a new one loads left them clickable, and
    // a Delete from one of them targeted a path the dialog never named — but
    // clearing on a refresh of the folder you are already in is what made a
    // multi-file drop tear the listing down and rebuild it once per file,
    // spinner and all, with the selection and the inspector emptied each time.
    if rowsTarget?.space != space || rowsTarget?.prefix != prefix {
      rows = []
      // With the banner it came with. Left standing, it told the reader to
      // open a subfolder of a folder the app had not managed to read at all.
      wasTruncated = false
      withheldPaths = []
      rowsTarget = (space, prefix)
    }
    defer { if mine == generation { isLoading = false } }

    switch await fold(space: space, prefix: prefix, policy: .newest) {
    case .cancelled:
      return
    case .failed(let failure):
      guard mine == generation else { return }
      // `loadFailure` alone, deliberately. The table already reports this where
      // the person is looking: a `ContentUnavailableView` carrying the daemon's
      // message, its recovery suggestion and a Try Again when there are no
      // rows, and the banner over the rows when there are. ``DaemonAlert``
      // builds the very same sentence as a modal on top of that — two reports
      // of one failure — and the Try Again under the first re-raised the
      // second, so a folder that keeps failing put a modal in front of the
      // screen that explains it, once per attempt and once per listing
      // generation. ``markWithheld`` had the same pair thirty lines down and
      // now does the same thing; its `quiet` is a different question — that
      // one is about the background poll not interrupting, not about one
      // failure being reported twice.
      loadFailure = failure
    case .loaded(let level):
      guard mine == generation else { return }
      adopt(level, space: space, prefix: prefix)
      await markWithheld(in: level, space: space, prefix: prefix, generation: mine)
    }
  }

  /// Re-folds the folder on screen and adopts the result only if it changed.
  ///
  /// The daemon has no change notification — its control service has no call
  /// to subscribe to — and it changes the tree behind the app's back all the
  /// time: a watcher publishes files dropped into the folder in Finder, and
  /// anti-entropy pulls in what peers publish with nobody pressing anything.
  /// Until this, the table was a snapshot of whenever it was last navigated,
  /// which for a synchronising product is the wrong thing to be.
  ///
  /// Nothing is assigned unless the fold differs, so an unchanged folder costs
  /// one listing and no redraw at all — the selection, the scroll position and
  /// the versions panel are untouched.
  func refreshIfChanged() async {
    guard store.connection.isConnected, let space = selectedSpace,
          !isLoading, pendingReload == nil,
          // A folder near the cap is expensive to re-fold and holds the
          // daemon's global store mutex while it does. Those get the explicit
          // Refresh instead.
          rows.count <= Self.pollCeiling
    else { return }
    let mine = generation
    guard case .loaded(let level) = await fold(space: space, prefix: prefix, policy: .newest)
    else { return }
    guard mine == generation, selectedSpace == space, self.prefix == prefix else { return }
    guard Set(level.rows) != Set(rows) else { return }
    adopt(level, space: space, prefix: prefix)
    await markWithheld(in: level, space: space, prefix: prefix, generation: mine, quiet: true)
  }

  /// Works out which of the folder's paths the chosen policy would refuse.
  ///
  /// Strict needs no second question — it refuses exactly the paths with more
  /// than one version, and the listing already says which those are. Pinning a
  /// device does need one, because "which paths does that device publish" is
  /// not in the listing, and it is the only case that costs an extra fold.
  private func markWithheld(
    in level: Level, space: String, prefix: String, generation mine: Int,
    quiet: Bool = false
  ) async {
    switch policy {
    case .newest:
      withheldPaths = []
    case .strict:
      withheldPaths = Set(level.rows.lazy.filter(\.hasVersions).map(\.path))
    case .origin:
      let answer = await fold(space: space, prefix: prefix, policy: policy)
      guard case .loaded(let pinned) = answer else {
        // Superseded folds change nothing at all — including the marks, which
        // belong to whichever fold is current.
        guard mine == generation, selectedSpace == space, self.prefix == prefix
        else { return }
        // Otherwise never silently: without knowing what the pinned device
        // publishes the app cannot mark anything, and leaving the previous
        // marks in place would be worse than saying so. Except from the
        // background poll, which is documented as changing nothing the person
        // did not ask for — a modal alert every twelve seconds from a folder
        // nobody touched is not a report, it is an interruption.
        withheldPaths = []
        // `loadFailure` alone here too. This was the other half of the same
        // double report: the banner over the rows and a modal saying the same
        // sentence on top of it, and the banner's own Try Again came straight
        // back through here to raise the modal again. `quiet` still means what
        // it says above — the poll marks nothing and says nothing — and it is
        // a separate question from how many times one failure is reported.
        if case .failed(let failure) = answer, !quiet {
          loadFailure = failure
        }
        return
      }
      guard mine == generation, selectedSpace == space, self.prefix == prefix else { return }
      let published = Set(pinned.rows.map(\.path))
      withheldPaths = Set(
        level.rows.lazy.filter { !$0.isDirectory && !published.contains($0.path) }.map(\.path))
    }
  }

  /// What the chosen policy is keeping closed, in a sentence.
  var withheldSummary: String? {
    guard !withheldPaths.isEmpty else { return nil }
    let count = withheldPaths.count
    let items = count == 1 ? "1 file" : "\(count) files"
    switch policy {
    case .newest: return nil
    case .strict:
      return "Strict will not open \(items) here: more than one device publishes them, and Strict refuses to choose."
    case .origin:
      return "\(items) here \(count == 1 ? "is" : "are") not published by the device you pinned, so \(count == 1 ? "it" : "they") will not open."
    }
  }

  private func adopt(_ level: Level, space: String, prefix: String) {
    // Only when it actually changed. The status poll bumps
    // `NodeStore.listingGeneration` whenever the head sequence moves — which
    // it does whenever *anything* on this node publishes, not only in the
    // folder being looked at — and every browser window turns that into a
    // reload. Assigning unconditionally dropped `visibleCache` through the
    // `rows` didSet, so the next body pass re-filtered and re-sorted the whole
    // listing to arrive at exactly the rows already on screen.
    //
    // `Set` rather than `==` on the arrays, because the fold's order is not
    // stable between calls and only membership decides whether the view has
    // anything new to draw.
    if Set(level.rows) != Set(rows) { rows = level.rows }
    rowsTarget = (space, prefix)
    wasTruncated = level.truncated
  }

  private struct Level {
    var rows: [RemoteEntry]
    var truncated: Bool
  }

  private enum FoldResult {
    case loaded(Level)
    case failed(DaemonFailure)
    /// Superseded or cancelled: say nothing, change nothing.
    case cancelled
  }

  /// Reads a whole directory level, a page at a time.
  private func fold(
    space: String, prefix: String, policy: VersionPolicy
  ) async -> FoldResult {
    let mine = generation
    var builder = LevelBuilder(space: space, prefix: prefix)
    var startAfter: String?
    var total = 0
    var truncated = false

    while true {
      let page: ControlClient.ListPage
      do {
        page = try await store.client.listPage(
          space: space, prefix: prefix, policy: policy,
          startAfter: startAfter, wanted: Self.pageSize)
      } catch let failure as DaemonFailure {
        // `!Task.isCancelled` as well as the generation. `scheduleReload`
        // replaces a pending listing by cancelling its task, and a cancel that
        // lands *inside* `listPage` comes back as a `DaemonFailure` —
        // `classify` maps `CancellationError` to "Cancelled." — while the
        // replacement is still sleeping, so the generation has not moved.
        // A ten-file drop raised a modal alert saying the daemon could not
        // serve the listing yet.
        guard !Task.isCancelled, mine == generation else { return .cancelled }
        return .failed(failure)
      } catch {
        guard !Task.isCancelled, mine == generation else { return .cancelled }
        return .failed(DaemonFailure.classify(error, operation: "list this folder"))
      }
      guard mine == generation else { return .cancelled }

      if page.entries.isEmpty {
        // A page can come back empty while paths remain: the daemon applies the
        // limit to distinct paths and only then drops the ones every publisher
        // has tombstoned, so a whole window can be filtered away and no row
        // count at any limit distinguishes that from the end of the listing.
        //
        // So the question is asked in a form that has no window to empty: one
        // unbounded request from the same cursor. Zero rows to that is the end,
        // definitively. It runs at most once per listing, and only for a folder
        // that actually has a run of fully-deleted paths.
        let remainder: [Synch_Control_V1_Entry]
        do {
          remainder = try await store.client.listRemainder(
            space: space, prefix: prefix, policy: policy, startAfter: startAfter)
        } catch let failure as DaemonFailure {
          guard !Task.isCancelled, mine == generation else { return .cancelled }
          return .failed(failure)
        } catch {
          guard mine == generation else { return .cancelled }
          break
        }
        guard mine == generation else { return .cancelled }
        for entry in remainder { builder.add(RemoteEntry(entry)) }
        total += remainder.count
        if total > Self.maximumRows { truncated = true }
        break
      }

      for entry in page.entries { builder.add(RemoteEntry(entry)) }
      total += page.entries.count
      startAfter = page.entries.last?.path

      if total >= Self.maximumRows {
        truncated = true
        break
      }
    }

    guard mine == generation else { return .cancelled }
    return .loaded(Level(rows: builder.rows(), truncated: truncated))
  }

  /// Reloads once for a burst of reasons rather than once per reason.
  ///
  /// A ten-file drop starts ten concurrent uploads, and each one finishing
  /// asked for its own listing — ten listings of the same folder, each
  /// superseding the last, for one user action.
  func scheduleReload() {
    reloadToken += 1
    let mine = reloadToken
    pendingReload?.cancel()
    pendingReload = Task { [weak self] in
      try? await Task.sleep(for: .milliseconds(250))
      guard !Task.isCancelled, let self, mine == self.reloadToken else { return }
      // Cleared before the work, not after: a finished `Task` is not nil, and
      // `refreshIfChanged` refuses to run while this is set — so leaving the
      // spent handle in place meant one upload silently switched off the
      // window's background listing watch for good. `reload` sets `isLoading`
      // with no suspension before it, and that is a separate arm of the same
      // guard, so clearing here does not open a window for two folds.
      self.pendingReload = nil
      await self.reload()
      await self.store.refresh([.status])
    }
  }

  private static let pageSize = 2_000
  /// Above this many rows the background refresh stands down: re-folding a
  /// folder that size every few seconds is real work for the daemon, which
  /// takes one global mutex for every store read.
  private static let pollCeiling = 5_000
  /// A ceiling so one folder cannot exhaust memory. Reaching it sets
  /// `wasTruncated`, which the browser says out loud.
  private static let maximumRows = 200_000

  // MARK: - Versions

  /// Loads the selected path's versions.
  ///
  /// The lossless source first for a divergent path: a `strict` resolve refuses
  /// it with every version, full origins, untruncated roots and raw seqs.
  /// A successful structured Resolve no longer carries a seq, so the unanimous
  /// case comes from `status`, which is also where attestor lists live.
  func loadVersions(for entry: RemoteEntry) async {
    // A synthesised folder row is not a published path, so it has no versions
    // and no history — and asking anyway is what surfaced somebody else's.
    guard !entry.isSynthesizedDirectory else {
      versions = nil
      unresolvedAttestors = []
      return
    }
    versionGeneration += 1
    let mine = versionGeneration
    versionsLoading = true
    defer { if mine == versionGeneration { versionsLoading = false } }

    var strictVersions: PathVersions?
    do {
      _ = try await store.client.resolve(
        space: entry.space, path: entry.path, policy: .strict)
    } catch let failure as DaemonFailure where failure.code == .divergent {
      strictVersions = Versions.fromStrictRefusal(
        failure.detail, space: entry.space, path: entry.path)
    } catch {
      // Not fatal: the inspector degrades to what the listing already knows.
    }
    guard mine == versionGeneration else { return }

    let reference = Cmd.reference(space: entry.space, path: entry.path)
    let human = await store.run(
      Operations.require("status"),
      Cmd.status(reference),
      commandLine: "synch status \(Shell.quote(reference))",
      deadline: .fast,
      quiet: true
    )
    guard mine == versionGeneration else { return }
    // The row for *this* path, not the first one printed. `status` takes its
    // path as a prefix — `unified_listing(&space, &path, …)`, and that second
    // parameter is used as one — so asking about a folder returns every path
    // under it, and taking `.first` showed an unrelated child file's version
    // set as the folder's own: "Only this Mac has this file" about a folder,
    // or a Use-This-Version card whose reference was the folder's path.
    var attestors = human.flatMap {
      Versions.fromStatus($0.lines).rows.first {
        $0.space == entry.space && $0.path == entry.path
      }
    }

    // `status` renders attestors through `OriginId::short()`, which cuts a
    // key-identified origin to 10 of 52 characters — a form no command accepts.
    // The truncation is a prefix, so it is undone against the origins this node
    // already knows before anything is offered as an action.
    if let human = attestors {
      let restored = Versions.restoreOrigins(human, knownOrigins: knownOrigins(for: entry))
      attestors = restored.set
      unresolvedAttestors = restored.unresolved
    } else {
      unresolvedAttestors = []
    }

    if let strictVersions {
      versions = Versions.merge(lossless: strictVersions, attestorsFrom: attestors)
    } else {
      versions = attestors
    }

    // A prefix that matched nothing known is asked about directly: a per-origin
    // Resolve says whether that device publishes this path, and it answers with
    // the full canonical origin.
    if !unresolvedAttestors.isEmpty, versions?.versions.contains(where: {
      $0.attestors.contains(where: { !Versions.isActionable($0) })
    }) == true {
      await probeOrigins(for: entry, generation: mine)
    }
  }

  /// Every origin this node can name, for undoing a truncated one.
  private func knownOrigins(for entry: RemoteEntry) -> [String] {
    var origins = Set(store.members.compactMap(\.origin))
    origins.formUnion(store.peers.flatMap { $0.origins.split(separator: ",").map {
      $0.trimmingCharacters(in: .whitespaces) } })
    origins.formUnion(rows.map(\.origin))
    if let own = store.origin { origins.insert(own) }
    return origins.filter { !$0.isEmpty && $0 != "(untrusted)" }
  }

  /// Asks each known origin whether it publishes this path, which recovers the
  /// full canonical name that `status` truncated away.
  private func probeOrigins(for entry: RemoteEntry, generation mine: Int) async {
    var found: [String: RemoteEntry] = [:]
    for origin in knownOrigins(for: entry) {
      guard mine == versionGeneration else { return }
      guard let resolved = try? await store.client.resolve(
        space: entry.space, path: entry.path, policy: .origin(origin))
      else { continue }
      found[origin] = RemoteEntry(resolved)
    }
    guard mine == versionGeneration, let current = versions, !found.isEmpty else { return }
    let repaired = current.versions.map { version -> EntryVersion in
      let matches = found.filter { Versions.matches($0.value, version: version) }.keys.sorted()
      guard !matches.isEmpty else { return version }
      return EntryVersion(
        identity: version.identity, kind: version.kind, size: version.size,
        seq: version.seq, attestors: matches)
    }
    versions = PathVersions(space: current.space, path: current.path, versions: repaired)
    unresolvedAttestors = []
  }

  /// The publish history of one path.
  ///
  /// `historyPath` is stamped alongside the lines so the panel can prove they
  /// belong to the file that is selected. It used to be cleared only on folder
  /// navigation, so selecting a different file in the same folder left the
  /// previous file's log on screen under the new file's name.
  func loadHistory(for entry: RemoteEntry) async {
    guard !entry.isSynthesizedDirectory else {
      history = []
      historyPath = entry.id
      return
    }
    historyGeneration += 1
    let mine = historyGeneration
    historyLoading = true
    historyPath = nil
    history = []
    // Guarded, like the versions load beside it. Unguarded, a superseded log
    // cleared the spinner belonging to the newer one, and the panel then said
    // "No history recorded for this path" about a file whose log was still in
    // flight — and contradicted itself a second later.
    defer { if mine == historyGeneration { historyLoading = false } }
    let wanted = entry.id
    let reference = Cmd.reference(space: entry.space, path: entry.path)
    let output = await store.run(
      Operations.require("log"),
      Cmd.log(reference),
      commandLine: "synch log \(Shell.quote(reference))",
      deadline: .standard,
      quiet: true
    )
    // A slow `synch log` must not land on a file the user has since left.
    guard mine == historyGeneration else { return }
    guard selection.contains(wanted) || selection.isEmpty else { return }
    // `log` is prose and stays prose: it is rendered verbatim rather than
    // parsed into a shape it does not reliably have.
    history = output?.lines ?? []
    historyPath = wanted
  }

  /// Adopts one origin's version as this node's own.
  ///
  /// The origin is passed in rather than chosen here, and that is the point:
  /// the user confirmed a sentence naming a device, so choosing one again in
  /// this function is what let the two disagree. The dialog named
  /// `attestors.first` while this took the first *actionable* attestor — a
  /// different device on any list beginning with a key `status` had truncated,
  /// which is a list `restoreOrigins` can plainly leave behind.
  ///
  /// The previous root is pinned first, so the version being replaced stays
  /// fetchable. It is not an undo — the restore would republish at a fresh
  /// mtime as a new assertion — but it is the difference between a reversible
  /// mistake and an unrecoverable one.
  func adopt(_ version: EntryVersion, of entry: RemoteEntry, from attestor: String) async {
    // The pair still has to hold together: an origin that does not assert this
    // version, or one the daemon would refuse as a reference, is not what the
    // confirmation described.
    guard version.attestors.contains(attestor), Versions.isActionable(attestor) else { return }
    if let previousRoot = entry.rootHex {
      await store.run(
        Operations.require("pin.add"), Cmd.pinAdd(previousRoot),
        commandLine: "synch pin add \(previousRoot)", deadline: .long, quiet: true)
    }
    let reference = Cmd.reference(origin: attestor, space: entry.space, path: entry.path)
    // `adopt path` declares `.listing` among its dirties, so `run` refreshes the
    // listing itself and the window reloads from that. Calling `reload()` here
    // as well was a second listing for one click — and the version refresh
    // that followed it looked the new row up in `rows`, which the other reload
    // had just emptied, so it usually found nothing and skipped.
    await store.run(
      Operations.require("adopt.path"), Cmd.adoptPath(reference),
      commandLine: "synch adopt path \(Shell.quote(reference))", deadline: .long)
    await loadVersions(for: entry)
  }
}

// MARK: - Proto bridging

extension RemoteEntry {
  /// Every field the daemon sends is kept. `content` and `symlinkTarget` used
  /// to be dropped here, which is what left the version badge with nothing
  /// behind it.
  init(_ entry: Synch_Control_V1_Entry) {
    let kind: Kind
    switch entry.kind {
    case .file: kind = .file
    case .dir: kind = .directory
    case .symlink: kind = .symlink
    case .tombstone: kind = .tombstone
    // v3's `ENTRY_KIND_SOCKET`. Not the beginning of a socket UI — it only
    // stops a socket entry arriving as `.unknown`, which is this app's word
    // for "the daemon sent a kind this build cannot name" and would have been
    // a lie about a kind it can. `default` stays for `.UNRECOGNIZED`, which is
    // the real one.
    case .socket: kind = .socket
    default: kind = .unknown
    }
    self.init(
      origin: entry.origin,
      space: entry.space,
      path: entry.path,
      kind: kind,
      size: entry.size,
      // A zero or negative mtime is a real value in this system — an entry a
      // peer published with an unusable clock — and must not render as 1970 in
      // a column the user sorts by.
      modified: entry.mtimeNs > 0
        ? Date(timeIntervalSince1970: Double(entry.mtimeNs) / 1_000_000_000)
        : .distantPast,
      versions: entry.versions,
      contentRoot: entry.hasContent ? entry.content : nil,
      symlinkTarget: entry.hasSymlinkTarget ? entry.symlinkTarget : nil
    )
  }
}

/// One request to preview a file, and which version of it.
struct PreviewRequest: Equatable {
  let entry: RemoteEntry
  let version: EntryVersion?
  /// Asking twice for the same file has to re-open it, so identity is the
  /// request rather than its contents.
  private let token = UUID()

  init(entry: RemoteEntry, version: EntryVersion? = nil) {
    self.entry = entry
    self.version = version
  }

  static func == (a: PreviewRequest, b: PreviewRequest) -> Bool { a.token == b.token }
}

/// How far a multi-path delete has got.
struct DeleteProgress: Equatable, Sendable {
  var done: Int
  var total: Int
}

/// Which of the inspector's tabs is showing.
///
/// Declared beside the model rather than inside `FileInspector`, because the
/// menu bar and two context menus choose it and none of them can see a view.
enum InspectorSection: String, CaseIterable, Identifiable, Hashable {
  case info = "Info", versions = "Versions", history = "History"
  var id: String { rawValue }
}

#if DEBUG
extension FilesModel {
  /// A model seeded for previews and tests, with no daemon behind it.
  ///
  /// In this file because the properties it writes are `private(set)`, which
  /// is the same reason `NodeStore.preview` lives beside its own.
  static func preview(
    rows: [RemoteEntry], space: String = "demo", prefix: String = "",
    store: NodeStore? = nil
  ) -> FilesModel {
    // `store` matters wherever the preview also puts one in the environment:
    // two stores means the view's `@EnvironmentObject` and its model disagree
    // about the same daemon, which is a state the app itself cannot reach.
    let model = FilesModel(store: store ?? NodeStore.preview())
    model.selectedSpace = space
    model.prefix = prefix
    model.rows = rows
    return model
  }
}
#endif
