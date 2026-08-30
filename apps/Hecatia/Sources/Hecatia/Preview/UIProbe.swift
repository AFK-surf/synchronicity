#if DEBUG
import AppKit
import SwiftUI

/// Scripted interaction traces, for questions a screenshot cannot answer.
///
/// A still frame says what the window looked like once. "The sidebar shrinks
/// and springs back" and "the search field will not give the focus up" are both
/// claims about a *sequence*, so this drives the sequence and samples the thing
/// in question every frame while it runs.
///
/// DEBUG only, and inert unless `HECATIA_PROBE` names one. It writes its trace
/// to `HECATIA_PROBE_OUT` (default: stdout).
@MainActor
enum UIProbe {
  static var name: String? { ProcessInfo.processInfo.environment["HECATIA_PROBE"] }

  private static var lines: [String] = []

  static func note(_ text: String) { lines.append(text) }

  /// Ends the process when the main actor stops answering.
  ///
  /// A probe that hangs is worse than one that fails: it reports nothing, and
  /// what it reports nothing about is usually the thing being investigated.
  /// Every check here is main-actor isolated, so when the main actor is gone —
  /// inside an AppKit tracking loop, say — nothing in this file can say so. A
  /// plain thread can.
  ///
  /// It asks rather than infers. The first version of this watched a timestamp
  /// the probe stamped as it went, which measures "a stamping helper ran
  /// recently" and not "the main actor is alive": `fetchEveryFile` awaits the
  /// daemon once per file with no stamp in the loop, so a slow folder would
  /// have been killed under a message accusing the main actor of being stuck.
  /// That is the same species of lie this whole commit exists to remove. A ping
  /// that has to come back cannot be desynchronized by a probe stage that
  /// forgets to stamp, and its verdict is true by construction.
  ///
  /// `nonisolated(unsafe)` on purpose: one counter, incremented on the main
  /// queue and compared on one watcher thread, where a torn read costs a
  /// second of patience. The alternative is a lock in a diagnostic.
  nonisolated(unsafe) private static var pong = 0

  nonisolated static func startDeadline(_ limit: Int = 45) {
    Thread.detachNewThread {
      var lastPong = pong
      var unanswered = 0
      while true {
        DispatchQueue.main.async { pong &+= 1 }
        Thread.sleep(forTimeInterval: 1)
        if pong != lastPong {
          lastPong = pong
          unanswered = 0
          continue
        }
        unanswered += 1
        guard unanswered > limit else { continue }
        FileHandle.standardError.write(Data(
          "probe: the main actor has not answered for \(unanswered)s. Giving up.\n".utf8))
        exit(3)
      }
    }
  }

  static func flush() {
    let text = lines.joined(separator: "\n") + "\n"
    if let path = ProcessInfo.processInfo.environment["HECATIA_PROBE_OUT"] {
      try? text.write(toFile: path, atomically: true, encoding: .utf8)
    }
    FileHandle.standardError.write(Data(text.utf8))
  }

  /// The browser window, once it exists.
  static func browser(_ model: FilesModel) -> NSWindow? {
    NSApp.windows.first { $0.title == model.folderTitle && $0.toolbar != nil }
  }

  /// Every `NSSplitView` under a view, outermost first.
  static func splitViews(in view: NSView) -> [NSSplitView] {
    var found: [NSSplitView] = []
    if let split = view as? NSSplitView { found.append(split) }
    for child in view.subviews { found.append(contentsOf: splitViews(in: child)) }
    return found
  }

  static func root(_ window: NSWindow) -> NSView? {
    window.contentView?.superview ?? window.contentView
  }

  /// The split view that holds the sidebar, wherever it sits in the tree.
  ///
  /// By role, never by index: moving the inspector from the split view into
  /// the detail column reverses the order these come back in, and an
  /// index-addressed probe silently starts dragging the other one's divider.
  static func sidebarSplit(_ window: NSWindow) -> NSSplitView? {
    guard let root = root(window) else { return nil }
    // By role. This asked for `SwiftUIOutlineListView` by name, and the folder
    // list stopped being one the day it became an `NSOutlineView` — so this
    // returned nil, `inspectorSplit` below then answered with the *outermost*
    // split view, and every panel measurement in this file was quietly being
    // taken from the wrong one.
    guard let list = folderList(allTables(in: root)) else { return nil }
    return enclosingSplit(of: list)
  }

  static func inspectorSplit(_ window: NSWindow) -> NSSplitView? {
    guard let root = root(window) else { return nil }
    let sidebar = sidebarSplit(window)
    return splitViews(in: root).first { $0 !== sidebar }
  }

  /// The first view of a given class, by type rather than by name — a name is
  /// wrong the moment the app subclasses the control.
  static func firstView<T: NSView>(in view: NSView, ofType type: T.Type) -> T? {
    if let match = view as? T { return match }
    for child in view.subviews {
      if let found = firstView(in: child, ofType: type) { return found }
    }
    return nil
  }

  static func enclosingSplit(of view: NSView) -> NSSplitView? {
    var current: NSView? = view.superview
    while let here = current {
      if let split = here as? NSSplitView { return split }
      current = here.superview
    }
    return nil
  }

  static func responder(_ window: NSWindow) -> String {
    guard let responder = window.firstResponder else { return "nil" }
    var text = String(describing: type(of: responder))
    if let text_ = responder as? NSText, let delegate = text_.delegate {
      text += "(editing \(type(of: delegate)))"
    }
    return text
  }

  static func settle(_ seconds: Double = 0.6) async {
    try? await Task.sleep(for: .seconds(seconds))
  }

  static func run(_ model: FilesModel, _ node: NodeStore) async {
    guard let name else { return }
    guard let window = browser(model) else {
      note("probe \(name): no browser window")
      flush()
      return
    }
    // Frontmost, and with this window key, before anything is measured.
    //
    // Four rounds of checks passed against an app that was never activated,
    // while the person running it saw the fault every time. A window that is
    // not key does not draw a focused selection, does not get the system's
    // current material, and does not route events the way an active app's
    // does — so every focus and appearance measurement taken from one was of a
    // different app from the one being reported on.
    NSApp.activate(ignoringOtherApps: true)
    window.makeKeyAndOrderFront(nil)
    startDeadline()
    await settle(1.0)
    note("probe: \(name)")
    note("  window \(window.frame.size)  key=\(window.isKeyWindow) active=\(NSApp.isActive)")
    switch name {
    case "menus": await menus(model, window)
    case "delete": await deletePlans(model)
    case "connection": await connectionTrace(node)
    case "upload": await uploads(model)
    case "external": await externalChange(model, node)
    case "add": await addingAFullFolder(model, node)
    case "policy": await policyMarking(model, node)
    case "inspector": await inspector(model, window)
    case "sidebar": await sidebarToggle(window)
    case "focuschain": await focusChain(model, window)
    case "fetch": await fetchEveryFile(model)
    case "focus": await focus(model, window)
    case "settings": await settingsWindow()
    case "all":
      // The read-only ones. `upload`, `external` and `connection` each change
      // something outside the app — files in a shared folder, or the daemon
      // itself — so they are asked for by name against a scratch daemon rather
      // than run by default. The Makefile says so.
      await inspector(model, window)
      await sidebarToggle(window)
      await focus(model, window)
      await focusChain(model, window)
      await menus(model, window)
      await deletePlans(model)
      await policyMarking(model, node)
      // Last, and always. It takes the key window away from the browser, so
      // nothing that measures the browser may follow it; and it is in this list
      // rather than only under its own name so that the sidebar checks it says
      // it owes cannot be quietly forgotten.
      await settingsWindow()
    default: note("  unknown probe")
    }
    flush()
  }

  // MARK: - The right panel against the left one

  /// Drags the sidebar divider, the way a person who wants a wider sidebar
  /// does. By role, never by index: moving the inspector from the split view
  /// into the detail column reverses the order the split views come back in,
  /// and an index-addressed probe silently starts dragging the other divider —
  /// which is exactly the mistake that made a closed panel look open.
  static func widenSidebar(_ window: NSWindow, to width: Double) {
    sidebarSplit(window)?.setPosition(width, ofDividerAt: 0)
  }

  /// The panel's `inspectorColumnWidth` ideal, which the divider test has to
  /// put back when it is done.
  static let idealPanelWidth: Double = 330

  /// One frame of the layout, as numbers rather than as a string.
  struct Frame {
    var at: Date
    var window: Double
    var sidebar: Double
    var splitWidth: Double
    var content: Double
    /// The panel's own width. `content` alone cannot tell a panel that slides
    /// in over the list from one that appears at the end of a wait: in both
    /// the list holds its width and then changes once.
    var panel: Double
    /// Where the browser starts, in the window's coordinates.
    ///
    /// The blind spot this probe had. Every check here read widths, so it
    /// could report the sidebar as 290pt throughout while the whole browser
    /// was being pushed off the left edge of the window and pulled back — a
    /// pane keeps its width when it is shifted.
    var browserX: Double
    /// The panel's top and height against the sidebar's, for the strip of
    /// window above it that the sidebar does not have.
    var panelTop: Double
    var panelHeight: Double
    var sidebarTop: Double
    var sidebarHeight: Double
  }

  static func measure(_ window: NSWindow) -> Frame {
    let sidebarSplit = sidebarSplit(window)
    let panelSplit = inspectorSplit(window)
    return Frame(
      at: .now,
      window: window.frame.width,
      // Zero when it is collapsed, for the same reason as the panel below:
      // AppKit hides the subview and leaves its frame at the width it had, so
      // reading the frame alone reports a sidebar that never moved through an
      // animation that collapsed it entirely.
      sidebar: sidebarSplit?.arrangedSubviews.first.map {
        $0.isHidden ? 0 : Double($0.frame.width)
      } ?? 0,
      splitWidth: Double(max(
        sidebarSplit?.frame.width ?? 0,
        sidebarSplit?.arrangedSubviews.map(\.frame.maxX).max() ?? 0)),
      content: Double(panelSplit?.arrangedSubviews.first?.frame.width ?? 0),
      panel: panelSplit?.arrangedSubviews.dropFirst().first.map {
        // Zero once it is collapsed. AppKit hides the subview and leaves its
        // frame at the width it had, so reading the frame alone reports a
        // panel that is fully open at the moment it has just finished closing
        // — which reads as a 330pt jump that never happened.
        $0.isHidden ? 0 : Double($0.frame.width)
      } ?? 0,
      browserX: panelSplit.map { split in
        Double(split.arrangedSubviews.first.map {
          $0.convert($0.bounds, to: nil).minX
        }?.rounded() ?? 0)
      } ?? 0,
      panelTop: panelSplit?.arrangedSubviews.dropFirst().first.map {
        Double($0.convert($0.bounds, to: nil).maxY.rounded())
      } ?? 0,
      panelHeight: panelSplit?.arrangedSubviews.dropFirst().first.map {
        Double($0.frame.height.rounded())
      } ?? 0,
      sidebarTop: sidebarSplit?.arrangedSubviews.first.map {
        Double($0.convert($0.bounds, to: nil).maxY.rounded())
      } ?? 0,
      sidebarHeight: sidebarSplit?.arrangedSubviews.first.map {
        Double($0.frame.height.rounded())
      } ?? 0)
  }

  /// The left sidebar's own collapse and expand, for comparison.
  ///
  /// It is the benchmark: it is an `NSSplitViewItem` collapsed through the
  /// animator, so AppKit re-lays-out every pane on every frame of it. Whatever
  /// the panel does should look like this, and this is where the numbers to
  /// compare against come from.
  /// Materialises every file in the folder, the way Quick Look does.
  ///
  /// For "io: No such file or directory (os error 2)" on a download or a
  /// preview — which is Rust's `io::Error`, so it is the daemon saying it
  /// cannot find something, not this app failing to write. This asks for every
  /// row in turn and reports which ones the daemon refuses and what it says,
  /// so a pattern can be seen rather than one report guessed at.
  static func fetchEveryFile(_ model: FilesModel) async {
    await model.reload()
    await settle(0.6)
    let files = model.visibleRows.filter { !$0.isDirectory }
    note("  [fetch] \(files.count) files under \(model.selectedSpace ?? "?")/\(model.prefix)")
    var refused: [String] = []
    for entry in files {
      let url = await model.materialize(entry)
      let transfer = model.store.transfers.transfers.first { $0.path == entry.path }
      let state: String
      switch transfer?.state {
      case .completed(let detail): state = "ok \(detail ?? "")"
      case .failed(let why): state = "FAILED \(why)"; refused.append("\(entry.name): \(why)")
      case .cancelled: state = "cancelled"
      default: state = url == nil ? "no url, no row" : "ok"
      }
      note("   \(entry.name)  size=\(entry.size) versions=\(entry.versions) origin=\(entry.origin.isEmpty ? "—" : String(entry.origin.prefix(12)))  -> \(state)")
    }
    note(refused.isEmpty
      ? "  FETCH: pass — every file in the folder came back"
      : "  FETCH: \(refused.count) of \(files.count) refused")
    for line in refused { note("    - \(line)") }
  }

  /// Where the caret is, through the things a person actually does with it.
  ///
  /// Three complaints, in order: the filter field takes the caret when nobody
  /// asked, clicking the file list often does not give it the caret, and the
  /// folder list has the same trouble. Each one is a line here.
  static func focusChain(_ model: FilesModel, _ window: NSWindow) async {
    var failures: [String] = []
    var frame = window.frame
    frame.size.width = 1200
    window.setFrame(frame, display: true)
    model.setPanel(false)
    model.clearSearch()
    await settle(1.2)

    note("  [focus] at rest: \(responder(window))")
    if responder(window).contains("Search") {
      failures.append("at rest: the filter has the caret and nobody asked for it")
    }

    guard let root = window.contentView?.superview ?? window.contentView else {
      note("  FOCUS: no content view"); return
    }
    let table = firstView(in: root, ofType: NSTableView.self)
    let lists = allTables(in: root)
    note("   table views in the window: \(lists.map { String(describing: type(of: $0)) }.joined(separator: ", "))")

    // 1. Click the file list. It should take the caret.
    for table in lists {
      note("   rows of \(String(describing: type(of: table))): \(describeRows(table))")
      note("     appearance=\(table.effectiveAppearance.name.rawValue)"
        + " window=\(window.effectiveAppearance.name.rawValue)")
      if let cell = table.view(atColumn: 0, row: table.selectedRow >= 0 ? table.selectedRow : 0, makeIfNecessary: false) as? NSTableCellView {
        note("     selected cell: text=\(cell.textField?.stringValue ?? "—")"
          + " colour=\(cell.textField?.textColor?.description ?? "—")"
          + " backgroundStyle=\(cell.backgroundStyle.rawValue)")
      }
      if let row = table.rowView(atRow: table.selectedRow >= 0 ? table.selectedRow : 0, makeIfNecessary: false) {
        note("     row view: \(String(describing: type(of: row))) selected=\(row.isSelected) emphasized=\(row.isEmphasized)")
      }
    }
    if let fileList = fileList(lists) {
      // Asked directly first. "The click does not move the caret" has two very
      // different causes — a table that refuses the caret, and a table that
      // takes it and has it taken back — and this separates them before any
      // click is sent.
      window.makeFirstResponder(nil)
      await settle(0.3)
      let granted = window.makeFirstResponder(fileList)
      await settle(0.4)
      note("   window.makeFirstResponder(file list) -> \(granted),"
        + " and after settling: \(responder(window))")

      let selectionBefore = model.selection
      clickFirstRow(fileList, in: window)
      await settle(0.6)
      // The selection as well as the responder, so a click that simply missed
      // can be told from one that landed and did not take the caret.
      note("   clicked the file list -> \(responder(window))"
        + "  selection \(selectionBefore.count) -> \(model.selection.count)")
      if !responder(window).contains("Table") {
        failures.append("clicking the file list left the caret on \(responder(window))")
      }
    } else {
      failures.append("no file list to click")
    }

    // 1b. Click the empty area below the last row, which is most of the file
    //     list in a folder of ten files and a window 700pt tall. A person
    //     clicking "in the file list" hits this far more often than a row.
    if let fileList = fileList(lists) {
      window.makeFirstResponder(nil)
      await settle(0.4)
      // What is actually under that point, and whether it would take the
      // caret if asked. "The click does nothing" has two very different
      // causes and this tells them apart.
      let centre = fileList.convert(
        NSPoint(x: fileList.bounds.midX, y: fileList.bounds.midY), to: nil)
      let hit = window.contentView?.hitTest(centre)
      var chain: [String] = []
      var walk: NSView? = hit
      while let view = walk, chain.count < 6 {
        chain.append(String(describing: type(of: view)))
        walk = view.superview
      }
      note("   under the empty area: \(chain.joined(separator: " < "))"
        + "  acceptsFirstResponder=\(hit?.acceptsFirstResponder ?? false)"
        + "  gestures=\(hit?.gestureRecognizers.count ?? -1)")
      note("   the table's own subviews: "
        + fileList.subviews.map { String(describing: type(of: $0)) }.joined(separator: ", "))
      click(fileList, in: window)
      await settle(0.6)
      note("   clicked the empty area below the rows -> \(responder(window))")
      if !responder(window).contains("Table") {
        failures.append("clicking the empty area of the file list left the caret on \(responder(window))")
      }
    }

    // 1c. Two clicks in a row, from a responder that is neither list. The
    //     report is that the caret comes back only on the second — so the
    //     first one has to be judged on its own.
    let both: [(String, NSTableView?, String)] = [
      ("file list", fileList(lists), "Table"),
      ("folder list", folderList(lists), "Outline"),
    ]
    for (name, target, wanted) in both {
      guard let target else { note("   no \(name) to click"); continue }
      // Park the caret somewhere else first, the way leaving for the filter or
      // another app does.
      model.openSearch()
      await settle(0.8)
      let parked = responder(window)
      clickFirstRow(target, in: window)
      await settle(0.5)
      let afterFirst = responder(window)
      clickFirstRow(target, in: window)
      await settle(0.5)
      let afterSecond = responder(window)
      note("   from \(parked): \(name) click 1 -> \(afterFirst), click 2 -> \(afterSecond)")
      if !afterFirst.contains(wanted) {
        failures.append("the \(name) needed a second click: the first left the caret on \(afterFirst)")
      }
      model.clearSearch()
      await settle(0.5)
    }

    // 1d. The case the monitor in ``FileListCaret`` can get wrong: nothing
    //     focused at all, and the click lands on the *sidebar*. If the monitor
    //     hands the caret to the file list anyway, the sidebar needs a second
    //     click to take it back.
    if let outline = folderList(lists),
       let fileList = fileList(lists) {
      window.makeFirstResponder(nil)
      await settle(0.5)
      let row = outline.rect(ofRow: 0)
      let point = outline.convert(NSPoint(x: row.midX, y: row.midY), to: nil)
      let asSeenByTheFileList = fileList.convert(point, from: nil)
      note("   sidebar row at \(fmt(Double(point.x))),\(fmt(Double(point.y)))"
        + " reads as \(fmt(Double(asSeenByTheFileList.x))),\(fmt(Double(asSeenByTheFileList.y)))"
        + " in the file list, whose bounds are \(fmt(Double(fileList.bounds.width)))x\(fmt(Double(fileList.bounds.height)))"
        + " — contains=\(fileList.bounds.contains(asSeenByTheFileList))")
      clickFirstRow(outline, in: window)
      await settle(0.5)
      note("   from nothing: folder list click 1 -> \(responder(window))")
      if !responder(window).contains("Outline") {
        failures.append("with nothing focused, clicking the folder list gave the caret to \(responder(window))")
      }
    }

    // 1e. Component to component, which is the case actually reported and the
    //     one every check above walked around: each of these starts with the
    //     *other* component holding the caret, not with the filter or with
    //     nothing.
    if let fileList = fileList(lists),
       let outline = folderList(lists) {
      let hops: [(String, NSTableView, NSTableView, String)] = [
        ("file list -> folder list", fileList, outline, "Outline"),
        ("folder list -> file list", outline, fileList, "Table"),
      ]
      for (name, from, to, wanted) in hops {
        clickFirstRow(from, in: window)
        await settle(0.6)
        let start = responder(window)
        clickFirstRow(to, in: window)
        await settle(0.6)
        let first = responder(window)
        clickFirstRow(to, in: window)
        await settle(0.6)
        note("   \(name): from \(start), click 1 -> \(first), click 2 -> \(responder(window))"
  )
        if !first.contains(wanted) {
          failures.append("\(name) needed a second click: the first left the caret on \(first)")
        }
      }

      // And with the panel open, which is a second hosting controller: the
      // caret has to cross an AppKit split view item to get there and back.
      model.setPanel(true)
      await settle(1.0)
      if let field = firstView(
        in: window.contentView?.superview ?? window.contentView!, ofType: NSSegmentedControl.self) {
        clickFirstRow(fileList, in: window)
        await settle(0.5)
        let start = responder(window)
        click(field, in: window)
        await settle(0.6)
        let intoPanel = responder(window)
        clickFirstRow(fileList, in: window)
        await settle(0.6)
        let backOut = responder(window)
        note("   file list -> panel -> file list: \(start) / \(intoPanel) / \(backOut)")
        if !backOut.contains("Table") {
          failures.append("coming back from the panel needed a second click: the first left the caret on \(backOut)")
        }
      } else {
        note("   panel: no segmented control to click")
      }
      model.setPanel(false)
      await settle(0.6)
    }

    // 1f. Where the *keys* go after one click, which is what a person means
    //     by focus. Down-arrow after a single click into each component, and
    //     then again after a second click, so "it took two" is a measurement
    //     rather than an impression.
    if let fileList = fileList(lists),
       let outline = folderList(lists) {
      let downArrow: UInt16 = 125
      // Start with the caret unambiguously in the file list.
      clickFirstRow(fileList, in: window)
      await settle(0.6)

      // One click into the sidebar, then a key. If the sidebar has the focus
      // the space changes; if the file list still has it, the selection does.
      let spaceBefore = model.selectedSpace
      let selectionBefore = model.selection
      clickFirstRow(outline, in: window)
      await settle(0.6)
      press(downArrow, in: window)
      await settle(0.6)
      let afterOne = "space \(model.selectedSpace ?? "—") selection \(model.selection.count)"
      let sidebarAnswered = model.selectedSpace != spaceBefore || model.selection == selectionBefore
      press(downArrow, in: window)
      await settle(0.6)
      note("   one click into the folder list, then Down: \(afterOne)"
        + "  (was space \(spaceBefore ?? "—") selection \(selectionBefore.count))")
      if !sidebarAnswered {
        failures.append("after one click the folder list did not take the keys — Down changed the file selection instead")
      }

      // And the other way.
      clickFirstRow(outline, in: window)
      await settle(0.6)
      let selectionBefore2 = model.selection
      clickFirstRow(fileList, in: window)
      await settle(0.6)
      press(downArrow, in: window)
      await settle(0.6)
      note("   one click into the file list, then Down: selection \(selectionBefore2.count) -> \(model.selection.count)"
        + " first=\(model.selection.first.map { String($0.prefix(18)) } ?? "—")")
      if model.selection.isEmpty {
        failures.append("after one click the file list did not take the keys — Down selected nothing")
      }
    }

    // 1g. The reported sequence, step for step:
    //
    //   focus in Files, click the filter -> the filter has it
    //   click Files    -> reported as not moving
    //   click Spaces  -> reported as not moving
    //   Escape, then click Files   -> reported as working
    //   Escape, then click Spaces -> reported as not working
    //
    // The asymmetry in the last two is the interesting part, and it is the
    // shape ``FileListCaret`` would produce: Escape runs `clearSearch()`,
    // which asks for the caret *for the file list* — so "click Files works"
    // may be the caret already being there rather than the click doing
    // anything.
    if let fileList = fileList(lists),
       let outline = folderList(lists) {
      let escape: UInt16 = 53
      func step(_ what: String) { note("     \(what) -> \(responder(window))") }

      clickFirstRow(fileList, in: window)
      await settle(0.5)
      note("   [reported sequence] start: \(responder(window))")
      model.openSearch()
      await settle(0.8)
      step("filter")
      clickFirstRow(fileList, in: window)
      await settle(0.6)
      let filesFromFilter = responder(window)
      step("click Files")
      clickFirstRow(outline, in: window)
      await settle(0.6)
      let foldersFromFilter = responder(window)
      step("click Spaces")

      // Escape, then each list in turn, from a fresh filter each time.
      for (name, target, wanted) in [("Files", fileList, "Table"), ("Spaces", outline, "Outline")] {
        model.openSearch()
        await settle(0.8)
        press(escape, in: window)
        await settle(0.8)
        note("     Escape from the filter -> \(responder(window))")
        // Said out loud rather than passed over. A synthetic Escape does not
        // reach an `NSSearchField`'s field editor — the responder is still the
        // field afterwards — so the two checks below are not testing what they
        // are named after, and a green line here would be a lie.
        if responder(window).contains("Search") {
          failures.append(
            "the probe's Escape never reached the filter, so \"after Escape, click \(name)\" is untested")
          continue
        }
        clickFirstRow(target, in: window)
        await settle(0.6)
        note("     then click \(name) -> \(responder(window))")
        if !responder(window).contains(wanted) {
          failures.append("after Escape, clicking \(name) left the caret on \(responder(window))")
        }
      }
      if !filesFromFilter.contains("Table") {
        failures.append("from the filter, clicking Files left the caret on \(filesFromFilter)")
      }
      if !foldersFromFilter.contains("Outline") {
        failures.append("from the filter, clicking Spaces left the caret on \(foldersFromFilter)")
      }
      model.clearSearch()
      await settle(0.5)
    }

    // 1h. An empty filter folds back to the magnifier when it is left, the
    //     way Finder's does. Behaviour rather than focus, and it was the other
    //     half of what ``FilterFocus`` watches clicks for — so it needs a line
    //     of its own before that watching can be judged unnecessary.
    if let outline = folderList(lists) {
      model.openSearch()
      await settle(0.8)
      let opened = model.searchPresented
      clickFirstRow(outline, in: window)
      await settle(0.8)
      note("   empty filter, then a click away: presented \(opened) -> \(model.searchPresented)")
      if model.searchPresented {
        failures.append("an empty filter stayed open after a click away")
      }
      model.clearSearch()
      await settle(0.5)
    }

    // 2. Click the folder list in the sidebar. Same.
    if let outline = folderList(lists) {
      clickFirstRow(outline, in: window)
      await settle(0.6)
      note("   clicked the folder list -> \(responder(window))")
      if !responder(window).contains("Outline") {
        failures.append("clicking the folder list left the caret on \(responder(window))")
      }
    } else {
      failures.append("no folder list to click")
    }

    // 3. Ask for the filter, then leave it. The caret should not be stranded.
    model.openSearch()
    await settle(0.8)
    note("   Find… -> \(responder(window))")
    if !responder(window).contains("Search") && !responder(window).contains("TextView") {
      failures.append("Find… left the caret on \(responder(window))")
    }
    model.clearSearch()
    await settle(0.8)
    note("   cleared -> \(responder(window))")
    if responder(window).contains("Search") {
      failures.append("clearing the filter left the caret in a field that is gone")
    }
    if responder(window).contains("Window") {
      failures.append("clearing the filter left the caret on nothing at all")
    }
    // And from there, the thing a person does next.
    if let fileList = fileList(lists) {
      clickFirstRow(fileList, in: window)
      await settle(0.6)
      note("   clicked the file list after clearing -> \(responder(window))")
      if !responder(window).contains("Table") {
        failures.append("after clearing the filter, clicking the file list still left the caret on \(responder(window))")
      }
    }

    // 4. Resize the window. The caret is not the window's to take.
    if let outline = folderList(lists) {
      click(outline, in: window)
      await settle(0.5)
    }
    let before = responder(window)
    var narrower = window.frame
    narrower.size.width = 950
    window.setFrame(narrower, display: true)
    await settle(1.0)
    note("   resized 1200 -> 950: \(before) -> \(responder(window))")
    if responder(window) != before {
      failures.append("resizing the window moved the caret from \(before) to \(responder(window))")
    }

    _ = table
    note(failures.isEmpty
      ? "  FOCUS: pass — the filter waits to be asked, both lists take the caret when clicked, and a resize does not steal it"
      : "  FOCUS: FAIL")
    for failure in failures { note("    - \(failure)") }
  }

  /// Collapses or expands the sidebar, through the item rather than the menu.
  ///
  /// `NSApp.sendAction(#selector(NSSplitViewController.toggleSidebar))` found
  /// no target and did nothing at all — the whole sidebar suite reported
  /// "290 -> 290" and passed by measuring an animation that never ran.
  static func toggleSidebar(_ window: NSWindow) {
    guard let controller = sidebarSplit(window)?.delegate as? NSSplitViewController,
          let item = controller.splitViewItems.first else {
      note("   sidebar: no split view item to toggle")
      return
    }
    item.animator().isCollapsed.toggle()
  }

  static func sidebarToggle(_ window: NSWindow) async {
    var frame = window.frame
    frame.size.width = 1000
    window.setFrame(frame, display: true)
    await settle()
    widenSidebar(window, to: 290)
    await settle(0.5)

    for pass in 1...2 {
      let before = measure(window)
      var hiding: [Frame] = []
      toggleSidebar(window)
      await sampleFrames(1.2, into: &hiding) { measure(window) }
      note("  [sidebar pass \(pass)] hide: \(fmt(before.sidebar)) -> \(fmt(measure(window).sidebar))"
        + " over \(hiding.count) samples — \(worstGap(hiding))")

      var showing: [Frame] = []
      toggleSidebar(window)
      await sampleFrames(1.2, into: &showing) { measure(window) }
      let back = measure(window)
      note("   show: -> \(fmt(back.sidebar)) over \(showing.count) samples — \(worstGap(showing))")
      note("   browser moved \(fmt(showing.map { abs($0.browserX - before.browserX) }.max() ?? 0))pt sideways"
        + ", list \(fmt(showing.map(\.content).min() ?? 0))..\(fmt(showing.map(\.content).max() ?? 0))")
      if ProcessInfo.processInfo.environment["HECATIA_PROBE_FRAMES"] == "sidebar" {
        dumpRaw(showing)
      }
    }
  }

  static func dumpRaw(_ trace: [Frame]) {
    guard let first = trace.first else { return }
    for frame in trace {
      let elapsed = frame.at.timeIntervalSince(first.at) * 1000
      note("    +\(fmt(elapsed.rounded()))ms sidebar=\(fmt(frame.sidebar))"
        + " list=\(fmt(frame.content)) browserX=\(fmt(frame.browserX))")
    }
  }

  /// How narrow the file list can be dragged with the panel open.
  ///
  /// The divider can only travel as far as `inspectorColumnWidth`'s ceiling
  /// allows, so a low ceiling reads to a person as a list that simply refuses
  /// to go any narrower. At a 420pt ceiling the list bottomed out at 618pt in
  /// a 1000pt window — 60pt of travel out of a possible 460.
  static func dividerRange(_ model: FilesModel, _ window: NSWindow) async -> [String] {
    var frame = window.frame
    frame.size.width = 1000
    window.setFrame(frame, display: true)
    await settle()
    widenSidebar(window, to: 290)
    model.setPanel(true)
    await settle(0.5)
    guard let split = inspectorSplit(window) else { return ["divider: no panel split view"] }

    split.setPosition(0, ofDividerAt: 0)
    await settle(0.4)
    let narrowest = measure(window).content
    split.setPosition(split.frame.width, ofDividerAt: 0)
    await settle(0.4)
    let widest = measure(window).content
    note("   divider: the list drags from \(fmt(narrowest))pt to \(fmt(widest))pt")

    // Back to the width it had before this test, and *before* the panel is
    // closed, because SwiftUI persists the inspector's width across launches:
    // a drag left at the far end came back as the starting width on the next
    // run, so the probe was quietly changing the thing it was measuring — and
    // changing it in the real app's saved state too.
    split.setPosition(split.frame.width - Self.idealPanelWidth, ofDividerAt: 0)
    await settle(0.5)
    note("   divider restored: panel=\(fmt(measure(window).panel))pt")

    model.setPanel(false)
    await settle(0.4)
    // Half the room the panel is not using. Less than that and the divider is
    // decorative — which is what a 420pt ceiling made it.
    let travel = widest - narrowest
    return travel > 300 ? [] : ["divider: the list only travels \(fmt(travel))pt — the panel's ceiling is too low"]
  }

  /// What AppKit was told about each pane, which is what decides who gives way
  /// when the panel asks for room it has not got.
  static func describeSplits(_ window: NSWindow) {
    for (name, split) in [("sidebar", sidebarSplit(window)), ("panel", inspectorSplit(window))] {
      guard let split else { note("  \(name) split: absent"); continue }
      let controller = split.delegate as? NSSplitViewController
      let holds = controller?.splitViewItems.map { "\($0.holdingPriority.rawValue)" } ?? ["-"]
      let items = controller?.splitViewItems ?? []
      let described = items.map {
        "\($0.behavior == .sidebar ? "sidebar" : $0.behavior == .inspector ? "inspector" : "plain")"
          + "/full=\($0.allowsFullHeightLayout)/collapsed=\($0.isCollapsed)"
      }
      note("  \(name) split: \(type(of: split))"
        + " delegate=\(controller.map { String(describing: type(of: $0)) } ?? "none")"
        + " holding=[\(holds.joined(separator: ", "))]")
      note("    items: \(described.joined(separator: "  "))")
    }
  }

  static func inspector(_ model: FilesModel, _ window: NSWindow) async {
    var failures: [String] = []
    describeSplits(window)
    for width in [1400.0, 1100.0, 1000.0, 940.0, 900.0, 870.0] {
      var frame = window.frame
      frame.size.width = width
      window.setFrame(frame, display: true)
      await settle()
      widenSidebar(window, to: 290)
      await settle(0.4)

      let before = measure(window)
      note("  [@\(Int(width))] closed: sidebar=\(fmt(before.sidebar)) content=\(fmt(before.content)) win=\(fmt(before.window))")

      // The toolbar, sampled across the same animation. Reported at every
      // width because "the buttons flash when the panel opens" is a claim
      // about one frame in a quarter of a second, and no still picture and no
      // settled measurement can either confirm or refute it.
      var trace: [Frame] = []
      model.setPanel(true)
      await sampleFrames(1.4, into: &trace) { measure(window) }
      let after = measure(window)
      note("   open: sidebar=\(fmt(after.sidebar)) content=\(fmt(after.content))"
        + " win=\(fmt(after.window)) over \(trace.count) samples — \(worstGap(trace))")
      let contentHeight = Double(window.contentLayoutRect.height.rounded())
      note("   geometry: panel top=\(fmt(after.panelTop)) height=\(fmt(after.panelHeight))"
        + "  sidebar top=\(fmt(after.sidebarTop)) height=\(fmt(after.sidebarHeight))"
        + "  window content height=\(fmt(contentHeight))")
      // The check that was missing, and it had been reporting the answer all
      // along: a browser 165pt tall in a 648pt window was written in the line
      // above for three runs and read as a probe artefact. A pane shorter than
      // the window is not a layout worth judging the animation of.
      for (name, height) in [("panel", after.panelHeight), ("sidebar", after.sidebarHeight)] {
        if height < contentHeight - 4 {
          failures.append(
            "@\(Int(width)): the \(name) is \(fmt(height))pt tall in a \(fmt(contentHeight))pt window"
              + " — the layout is not filling it")
        }
      }
      failures += judge("open @\(Int(width))", before: before, trace: trace, revealing: true)
      dump(trace, at: width)

      var back: [Frame] = []
      model.setPanel(false)
      await sampleFrames(1.4, into: &back) { measure(window) }
      let closed = measure(window)
      note("   close: sidebar=\(fmt(closed.sidebar)) content=\(fmt(closed.content))"
        + " win=\(fmt(closed.window)) — \(worstGap(back))")
      failures += judge("close @\(Int(width))", before: after, trace: back, revealing: false)
      dump(back, at: width)

      if abs(closed.window - before.window) > 2 {
        failures.append("close @\(Int(width)): window kept \(fmt(closed.window - before.window))pt it borrowed")
      }
    }
    await panelByClick(model, window)
    failures += await dividerRange(model, window)
    note(failures.isEmpty
      ? "  PANEL: pass — the panel was revealed over about a quarter of a second, the sidebar held still, the window held still, and nothing overhung the edge"
      : "  PANEL: FAIL")
    for failure in failures { note("    - \(failure)") }
  }

  /// The three things that make the panel look broken, as checks.
  static func judge(
    _ label: String, before: Frame, trace: [Frame], revealing: Bool
  ) -> [String] {
    var failures: [String] = []
    // 1. The sidebar is not the panel's to borrow from.
    //
    // Reported with how long it was wrong for as well as by how much: a single
    // frame at the wrong width is a sampling artefact, and a fifth of a second
    // is the shrink-and-spring-back a person actually sees.
    if let worst = trace.map({ abs($0.sidebar - before.sidebar) }).max(), worst > 2 {
      failures.append(
        "\(label): sidebar moved \(fmt(worst))pt (was \(fmt(before.sidebar)))"
          + " for \(ms(trace) { abs($0.sidebar - before.sidebar) > 2 })")
    }
    // 2. Nothing may be laid out past the window's edge, where it cannot be
    //    seen moving and its arrival reads as a jump.
    if let worst = trace.map({ $0.splitWidth - $0.window }).max(), worst > 2 {
      failures.append(
        "\(label): layout ran \(fmt(worst))pt past the window edge"
          + " for \(ms(trace) { $0.splitWidth - $0.window > 2 })")
    }
    // 3. The panel's width is animated, not switched on.
    //
    // Measured on the panel itself rather than on the file list. The list
    // keeps its frame for the whole reveal and takes its new width in one step
    // at the end — which is correct and invisible, because by then the panel
    // is drawn over exactly the strip the list is giving up. Judging the list
    // instead is what produced the conclusion that `.inspector` "does not
    // animate at all", and sent this app down a 149-line detour to hide an
    // animation that was working.
    //
    // Asked of the opening only. Closing is animated too — measured at 870,
    // 900, 940, 1000 and 1100 the panel and the list walk back together over
    // about 280ms — but at 1400 the close completes inside 42ms while the open
    // at the same width still takes its full quarter second. That asymmetry is
    // SwiftUI's; nothing in this app touches it, and requiring it here would
    // mean a check that fails for a reason the app cannot fix. The other three
    // apply in both directions, which is what keeps a bad close visible.
    let widths = trace.map(\.panel)
    if revealing, let widest = widths.max(), widest > 2 {
      let moving = widths.filter { $0 > 2 && $0 < widest - 2 }.count
      if moving < 5 {
        failures.append(
          "\(label): the panel went from nothing to \(fmt(widest))pt in \(moving) intermediate frames — that is a switch, not a reveal")
      }
      var previous: Double?
      var biggest: Double = 0
      for width in widths {
        if let previous { biggest = max(biggest, abs(width - previous)) }
        previous = width
      }
      if biggest > widest / 2 {
        failures.append("\(label): the panel jumped \(fmt(biggest))pt in one frame")
      }
    }
    // 5. The browser beside the panel may not be *moved*, only resized.
    //
    // The check this probe was missing. A pane that is laid out at its old
    // width inside a slot that has already shrunk has to go somewhere, and
    // where it goes is off the left edge of the window — at full width, so
    // every column in it travels, and then travels back when the animation
    // ends and the real layout pass happens.
    if let worst = trace.map({ abs($0.browserX - before.browserX) }).max(), worst > 2 {
      failures.append(
        "\(label): the browser was pushed \(fmt(worst))pt sideways"
          + " for \(ms(trace) { abs($0.browserX - before.browserX) > 2 })")
    }
    // 4. The window is not the panel's to resize either. Opening the sidebar
    //    does not move it, and the sidebar is the behaviour being matched.
    if let worst = trace.map({ abs($0.window - before.window) }).max(), worst > 2 {
      failures.append("\(label): the window resized itself by \(fmt(worst))pt")
    }
    return failures
  }

  /// Every frame of one transition, when `HECATIA_PROBE_FRAMES` names a width.
  ///
  /// The judgements above say *that* a layout was wrong; this says what shape
  /// the wrongness had — an overhang that shrinks smoothly to zero is a panel
  /// sliding in from the right edge, and one that holds and then vanishes is a
  /// snap. The two produce identical summaries and look nothing alike.
  static func dump(_ trace: [Frame], at width: Double) {
    guard ProcessInfo.processInfo.environment["HECATIA_PROBE_FRAMES"] == "\(Int(width))",
          let first = trace.first else { return }
    for frame in trace {
      let elapsed = frame.at.timeIntervalSince(first.at) * 1000
      note("    +\(fmt(elapsed.rounded()))ms sidebar=\(fmt(frame.sidebar))"
        + " list=\(fmt(frame.content)) panel=\(fmt(frame.panel))"
        + " browserX=\(fmt(frame.browserX))"
        + " over=\(fmt(frame.splitWidth - frame.window))")
    }
  }

  /// The worst gap between two samples, which is where a dropped frame shows.
  ///
  /// The sampler asks for 1/60s. A gap much longer than that means the main
  /// thread was busy when the tick came due — which is the stutter, measured
  /// rather than described.
  static func worstGap(_ trace: [Frame]) -> String {
    var previous: Date?
    var worst: Double = 0
    var over32 = 0
    for frame in trace {
      if let previous {
        let gap = frame.at.timeIntervalSince(previous) * 1000
        worst = max(worst, gap)
        if gap > 32 { over32 += 1 }
      }
      previous = frame.at
    }
    return "worst gap \(fmt(worst.rounded()))ms, \(over32) over 32ms"
  }

  /// How long a run of frames matching `bad` lasted, in milliseconds — the
  /// number that decides whether a wrong layout is visible or is a sample.
  static func ms(_ trace: [Frame], _ bad: (Frame) -> Bool) -> String {
    let hits = trace.filter(bad)
    guard let first = hits.first, let last = hits.last else { return "0ms" }
    let span = last.at.timeIntervalSince(first.at) * 1000
    return "\(fmt(span.rounded()))ms over \(hits.count) frames"
  }

  static func fmt(_ value: Double) -> String { value.formatted(.number.precision(.fractionLength(0))) }

  static func sampleFrames(
    _ seconds: Double, into trace: inout [Frame], _ take: () -> Frame
  ) async {
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline {
      try? await Task.sleep(for: .seconds(1.0 / 60.0))
      trace.append(take())
    }
  }

  /// Every distinct toolbar layout seen across an animation, in order.
  ///
  /// A control that is torn down and rebuilt mid-animation shows up here as a
  /// signature that appears for a frame or two and then goes away again — the
  /// list ends where it started, with something else in the middle. A control
  /// that merely moves shows a smooth run of positions and no width changing.
  /// The distinction is the whole question behind "the buttons flash".
  static func sampleToolbar(_ seconds: Double, _ window: NSWindow) async -> [String] {
    // Sampled *before* the first sleep. The change that starts the animation
    // lands in the same turn of the run loop that asked for it, so a sampler
    // that sleeps first has already missed it — which is how the first two
    // passes of this came back saying nothing ever changes.
    var seen: [String] = [toolbarIdentity(window)]
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline {
      let signature = toolbarIdentity(window)
      if seen.last != signature { seen.append(signature) }
      try? await Task.sleep(for: .seconds(1.0 / 60.0))
    }
    return seen
  }

  /// Which *object* is drawing each toolbar item, and how visible it is.
  ///
  /// Geometry was the first guess and it is constant across both animations —
  /// no item moves, resizes, or is added. So a flash cannot be a reflow, and
  /// the two things left that would produce one are a view being torn down and
  /// replaced by a new one, and a view fading. This reports both: a short hash
  /// of each item view's identity, and its alpha where it is not 1.
  ///
  /// Identity rather than a count, because a rebuild replaces like with like —
  /// the item list looks identical before and after, and the only evidence
  /// that anything happened is that the objects are not the same objects.
  static func toolbarIdentity(_ window: NSWindow) -> String {
    // View-less items are reported as `-` rather than skipped. AppKit adds and
    // removes `splitViewSeparator` items as split items come and go, and those
    // carry no view — dropping them hid exactly the kind of change worth
    // seeing, and renumbered everything after it at the same time.
    (window.toolbar?.items ?? []).enumerated().map { index, item in
      guard let view = item.view else {
        return "\(index):-\(item.itemIdentifier.rawValue.hasPrefix("splitViewSeparator") ? "sep" : "")"
      }
      let id = UInt(bitPattern: ObjectIdentifier(view).hashValue) % 4096
      let alpha = view.alphaValue < 0.999 ? String(format: "a%.2f", view.alphaValue) : ""
      let hidden = view.isHidden ? "H" : ""
      return "\(index):#\(id)\(alpha)\(hidden)"
    }.joined(separator: " ")
  }

  /// Opens and closes the panel by *clicking its toolbar button*, and reports
  /// the toolbar strip frame by frame for each direction.
  ///
  /// The rest of this suite drives the panel through `setPanel`, and measured
  /// that way the two directions are indistinguishable — geometry, view
  /// identity, alpha and pixels all behave the same. That rules the model path
  /// out and leaves the click path, which nothing here had ever exercised: a
  /// press has a highlight, a focus ring and a first responder change that a
  /// direct mutation does not.
  static func panelByClick(_ model: FilesModel, _ window: NSWindow) async {
    guard let items = window.toolbar?.items, let last = items.last(where: { $0.view != nil }),
          let view = last.view
    else { return note("  [panel click] no toolbar item to click") }
    let bounds = view.convert(view.bounds, to: nil)
    let centre = NSPoint(x: bounds.midX, y: bounds.midY)
    note("  [panel click] toggle at \(fmt(Double(centre.x.rounded())))"
      + ",\(fmt(Double(centre.y.rounded()))) — panel open=\(model.inspectorVisible)")

    for (name, wanted) in [("open", true), ("close", false)] {
      if model.inspectorVisible != !wanted { model.setPanel(!wanted); await settle(0.6) }
      async let pixels = samplePixels(1.2, window)
      async let identity = sampleToolbar(1.2, window)
      send(at: centre, in: window)
      let runs = await pixels
      let seen = await identity
      note("  [panel click] \(name): panel=\(model.inspectorVisible)"
        + "  pixels \(describeRuns(runs))")
      if seen.count > 1 {
        note("    toolbar changed \(seen.count - 1) time(s) during \(name)")
        for step in seen { note("      \(step)") }
      }
      await settle(0.6)
    }
  }

  /// Distinct frames and how long each held, newest last.
  ///
  /// `12x` means twelve consecutive frames drew the same thing. A run of `1x`
  /// in the middle of long runs is a single frame nobody asked for.
  static func describeRuns(_ runs: [(UInt64, Int)]) -> String {
    let total = runs.reduce(0) { $0 + $1.1 }
    let shape = runs.map { "\($0.1)x" }.joined(separator: " ")
    return "\(runs.count) distinct over \(total) frames: \(shape)"
  }

  /// A checksum of the pixels in the toolbar strip.
  ///
  /// The last resort, and the only measurement that corresponds to what was
  /// reported. Geometry, view identity, alpha, hidden and the item list are
  /// all constant across both animations — so whatever flashes is not the
  /// toolbar's AppKit layer, and asking that layer more questions was not
  /// going to answer it. This asks the screen instead: the same region drawn
  /// every frame, reduced to a number, so a frame that differs from its
  /// neighbours and then never recurs is exactly a flash.
  ///
  /// `cacheDisplay` does not photograph AppKit views faithfully — see
  /// ``WindowSnapshot`` — but that caveat is about absolute appearance. This
  /// compares a region with itself one frame later, and an unfaithful
  /// rendering that is unfaithful the same way every frame still shows a
  /// change as a change.
  static func toolbarPixels(_ window: NSWindow) -> UInt64 {
    guard let content = window.contentView else { return 0 }
    // The strip the toolbar occupies, in the content view's own coordinates.
    let height = content.bounds.height - window.contentLayoutRect.height
    guard height > 1 else { return 0 }
    let strip = NSRect(
      x: 0, y: content.bounds.maxY - height, width: content.bounds.width, height: height)
    guard let bitmap = content.bitmapImageRepForCachingDisplay(in: strip) else { return 0 }
    content.cacheDisplay(in: strip, to: bitmap)
    guard let data = bitmap.bitmapData else { return 0 }
    let count = bitmap.bytesPerRow * bitmap.pixelsHigh
    var hash: UInt64 = 1469598103934665603
    // Every 97th byte: a full pass is 4 MB a frame at 60Hz and the sampler has
    // to keep up with the animation it is measuring. A stride that is coprime
    // with the row width still crosses every row and every channel.
    for offset in stride(from: 0, to: count, by: 97) {
      hash = (hash ^ UInt64(data[offset])) &* 1099511628211
    }
    return hash
  }

  /// The toolbar strip, sampled every frame, as a run-length list.
  static func samplePixels(_ seconds: Double, _ window: NSWindow) async -> [(UInt64, Int)] {
    var runs: [(UInt64, Int)] = []
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline {
      let hash = toolbarPixels(window)
      if runs.last?.0 == hash { runs[runs.count - 1].1 += 1 } else { runs.append((hash, 1)) }
      try? await Task.sleep(for: .seconds(1.0 / 60.0))
    }
    return runs
  }

  /// The toolbar's items by identifier, so an item appearing or disappearing
  /// is visible as itself rather than as a column count changing.
  static func toolbarIdentifiers(_ window: NSWindow) -> String {
    (window.toolbar?.items ?? [])
      .map { $0.itemIdentifier.rawValue.replacingOccurrences(of: "com.apple.SwiftUI.", with: "") }
      .joined(separator: ",")
  }

  // MARK: - Whether a version policy hides rows or marks them

  /// Pins a device that publishes nothing here, and checks the folder survives.
  ///
  /// The daemon's `List` applies the policy itself and omits any path it
  /// refuses — there is no per-path refusal in the wire format — so choosing
  /// Strict or pinning a device used to delete rows from the folder outright.
  static func policyMarking(_ model: FilesModel, _ node: NodeStore) async {
    var failures: [String] = []
    let before = model.rows.map(\.path).sorted()
    note("  [policy] Newest: \(before.count) rows, \(model.withheldPaths.count) withheld")
    if !model.withheldPaths.isEmpty {
      failures.append("Newest withheld \(model.withheldPaths.count) paths, which it never should")
    }

    // A device shaped exactly like this one but not this one, so the daemon
    // parses it and finds nothing published under it.
    let own = node.origin ?? "key:" + String(repeating: "y", count: 52)
    let stranger = own.hasPrefix("key:")
      ? "key:" + String(own.dropFirst(4).dropLast()) + (own.hasSuffix("y") ? "b" : "y")
      : "nobody@" + own
    note("  [policy] own=\(own)")
    note("  [policy] pinning \(stranger)")
    model.policy = .origin(stranger)
    await model.reload()
    await settle(1.0)
    let after = model.rows.map(\.path).sorted()
    note("  [policy] pinned a stranger: \(after.count) rows, "
      + "\(model.withheldPaths.count) withheld, banner=\(model.withheldSummary ?? "none"), "
      + "failure=\(model.loadFailure?.detail ?? "none")")
    if after != before {
      failures.append("the folder changed size under a policy: \(before.count) -> \(after.count)")
    }
    let files = model.rows.filter(\.isFile).count
    if model.withheldPaths.count != files {
      failures.append("\(model.withheldPaths.count) of \(files) files marked; a stranger publishes none")
    }
    if model.withheldSummary == nil {
      failures.append("nothing said the policy was withholding anything")
    }

    model.policy = .newest
    await model.reload()
    await settle(1.0)
    note("  [policy] back to Newest: \(model.rows.count) rows, \(model.withheldPaths.count) withheld")
    if !model.withheldPaths.isEmpty { failures.append("marks survived a return to Newest") }

    note(failures.isEmpty
      ? "  POLICY: pass — a policy marks what it will not open and removes nothing"
      : "  POLICY: FAIL")
    for failure in failures { note("    - \(failure)") }
  }

  // MARK: - Adding a folder that already has things in it

  /// Shares `HECATIA_PROBE_SHARE` and checks its files turn up.
  ///
  /// `SpaceAdd` starts a watcher, and a watcher reports changes — it says
  /// nothing about the files already sitting there. So the folder listed as
  /// empty, under a daemon message that says "indexing", until the scanner's
  /// own interval came round.
  static func addingAFullFolder(_ model: FilesModel, _ node: NodeStore) async {
    var failures: [String] = []
    guard let share = ProcessInfo.processInfo.environment["HECATIA_PROBE_SHARE"] else {
      note("  [add] HECATIA_PROBE_SHARE is not set")
      return
    }
    let expected = (try? FileManager.default.contentsOfDirectory(atPath: share))?
      .filter { !$0.hasPrefix(".") }.count ?? 0
    note("  [add] sharing \(share), which already holds \(expected) file(s)")
    await node.addSource(id: "probe-full", path: share)
    await settle(1.5)
    model.select(space: "probe-full")
    for _ in 0..<40 {
      await settle(0.25)
      if model.rows.count >= expected { break }
    }
    note("  [add] \(model.rows.count) row(s) listed, expected \(expected)")
    if model.rows.count < expected {
      failures.append("\(model.rows.count) of \(expected) files listed after adding the folder")
    }
    note(failures.isEmpty
      ? "  ADD: pass — a folder that already has files in it lists them"
      : "  ADD: FAIL")
    for failure in failures { note("    - \(failure)") }
  }

  // MARK: - Whether a change nobody told the app about arrives

  /// Writes a file into the shared directory behind the app's back.
  ///
  /// `HECATIA_PROBE_SHARE` names the folder the selected space indexes. The
  /// daemon's watcher publishes it; nothing tells the app. Until the listing
  /// watch existed the table was a snapshot of whenever it was last navigated.
  static func externalChange(_ model: FilesModel, _ node: NodeStore? = nil) async {
    guard let share = ProcessInfo.processInfo.environment["HECATIA_PROBE_SHARE"] else {
      note("  [external] HECATIA_PROBE_SHARE is not set")
      return
    }
    note("  [external] space=\(model.selectedSpace ?? "nil") rows=\(model.rows.count) "
      + "loading=\(model.isLoading) failure=\(model.loadFailure?.detail ?? "none") "
      + "spaces=\(node?.spaces.map(\.id) ?? []) connection=\(describe(node?.connection ?? .idle))")
    await model.reload()
    note("  [external] after an explicit reload: rows=\(model.rows.count) "
      + "failure=\(model.loadFailure?.detail ?? "none")")
    let before = model.rows.count
    let name = "from-outside-\(before).txt"
    let url = URL(fileURLWithPath: share).appendingPathComponent(name)
    try? Data("written straight into the folder\n".utf8).write(to: url)
    note("  [external] wrote \(name) into \(share); \(before) rows on screen")

    var arrivedAfter: Double?
    let start = Date()
    for tick in 0..<120 {
      try? await Task.sleep(for: .milliseconds(500))
      // The window has to be the key one for `ListingWatch` to run, and an app
      // launched from a terminal cannot always come forward — so the same call
      // the watch makes is driven here, on the watch's own cadence. What is
      // being tested is that a re-fold sees the change and adopts it.
      if tick % 24 == 23 { await model.refreshIfChanged() }
      if model.rows.contains(where: { $0.name == name }) {
        arrivedAfter = Date().timeIntervalSince(start)
        break
      }
    }
    if let arrivedAfter {
      note(String(format: "  [external] appeared after %.1fs with nothing pressed", arrivedAfter))
      note("  EXTERNAL: pass — a change the app did not make reaches the table")
    } else {
      note("  EXTERNAL: FAIL")
      note("    - the file never appeared; the table is still a snapshot")
    }
    try? FileManager.default.removeItem(at: url)
  }

  // MARK: - What a batch of uploads costs

  /// Uploads several files at once and counts the listings that follow.
  ///
  /// Each finished upload used to ask for its own listing, and every listing
  /// blanked the table on entry — so a ten-file drop tore the folder down and
  /// rebuilt it ten times, spinner and all, with the selection and the panel
  /// emptied each time.
  static func uploads(_ model: FilesModel) async {
    var failures: [String] = []
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent("hecatia-probe-\(model.rows.count)", isDirectory: true)
    try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    var urls: [URL] = []
    for index in 0..<6 {
      let url = directory.appendingPathComponent("probe-\(index).txt")
      try? Data("probe \(index)\n".utf8).write(to: url)
      urls.append(url)
    }
    let before = model.rows.count
    let listingsBefore = model.reloadCount
    note("  [upload] \(urls.count) files into \(model.locationTitle), \(before) rows to start")

    model.upload(urls: urls)
    // Long enough for six uploads and the coalesced listing behind them.
    for _ in 0..<40 {
      try? await Task.sleep(for: .milliseconds(250))
      if model.rows.count >= before + urls.count { break }
    }
    await settle(1.5)

    let listings = model.reloadCount - listingsBefore
    note("  [upload] \(model.rows.count) rows now, \(listings) listing(s) for \(urls.count) uploads")
    if model.rows.count < before + urls.count {
      failures.append("only \(model.rows.count - before) of \(urls.count) uploads appeared")
    }
    if listings > 2 {
      failures.append("\(listings) listings for one batch — the coalescing is not holding")
    }
    if model.rows.isEmpty {
      failures.append("the listing was left empty")
    }

    // And the background watch must still work afterwards. `scheduleReload`
    // left a spent Task handle in `pendingReload`, and `refreshIfChanged`
    // refuses to run while that is set — so one upload used to switch the
    // window's listing watch off for good.
    if let share = ProcessInfo.processInfo.environment["HECATIA_PROBE_SHARE"] {
      let name = "after-upload.txt"
      let url = URL(fileURLWithPath: share).appendingPathComponent(name)
      try? Data("written after an upload\n".utf8).write(to: url)
      var arrived = false
      for _ in 0..<40 {
        await settle(0.5)
        await model.refreshIfChanged()
        if model.rows.contains(where: { $0.name == name }) { arrived = true; break }
      }
      note("  [upload] a change after the upload \(arrived ? "was noticed" : "was NOT noticed")")
      if !arrived { failures.append("the listing watch stopped working after an upload") }
      try? FileManager.default.removeItem(at: url)
    }

    // Put the folder back the way it was found.
    let plan = await model.deletePlan(for: model.rows.filter { $0.name.hasPrefix("probe-") })
    model.delete(plan)
    await settle(2.5)
    note("  [upload] cleaned up, \(model.rows.count) rows")
    try? FileManager.default.removeItem(at: directory)

    note(failures.isEmpty
      ? "  UPLOAD: pass — every file arrived, and one batch costs one listing"
      : "  UPLOAD: FAIL")
    for failure in failures { note("    - \(failure)") }
  }

  // MARK: - Whether the app notices the daemon coming and going

  /// Watches `connection` while something else stops and starts the daemon.
  ///
  /// The one thing no unit test can cover: the app's own idea of whether the
  /// daemon is there, checked against a daemon that really is not.
  static func connectionTrace(_ node: NodeStore) async {
    let seconds = Double(ProcessInfo.processInfo.environment["HECATIA_PROBE_SECONDS"] ?? "") ?? 45
    note("  [connection] watching for \(Int(seconds))s")
    var last = ""
    let start = Date()
    while Date().timeIntervalSince(start) < seconds {
      try? await Task.sleep(for: .milliseconds(250))
      let now = describe(node.connection)
        + " last=" + (node.lastFailure.map { "\($0.code) \($0.detail)" } ?? "none")
      if now != last {
        note(String(format: "    +%5.1fs %@", Date().timeIntervalSince(start), now))
        last = now
      }
    }
    note("  [connection] ended \(describe(node.connection))")
  }

  static func describe(_ connection: NodeStore.Connection) -> String {
    switch connection {
    case .idle: return "idle"
    case .connecting: return "connecting"
    case .connected: return "connected"
    case .failed(let failure): return "failed(\(failure.detail))"
    case .needsUpdate: return "needsUpdate"
    }
  }

  // MARK: - What a delete would actually name

  /// Plans a delete for a real folder against the running daemon.
  ///
  /// Nothing is deleted: `deletePlan` only asks what is under the folder. That
  /// question used to be put to `rows`, which never holds a folder's children,
  /// so every folder planned zero paths and the app told the user the folder
  /// held nothing it publishes.
  static func deletePlans(_ model: FilesModel) async {
    var failures: [String] = []
    guard let folder = model.rows.first(where: \.isDirectory) else {
      note("  [delete] no folder in this listing to plan against")
      return
    }
    let plan = await model.deletePlan(for: [folder])
    note("  [delete] \u{201C}\(folder.name)\u{201D} -> \(plan.paths.count) paths, "
      + "folders=\(plan.folders), incomplete=\(plan.incomplete), summary=\(plan.summary)")
    if plan.paths.isEmpty {
      failures.append("a folder on screen planned zero paths — the old bug")
    }
    if !plan.paths.allSatisfy({ $0.path.hasPrefix(folder.path + "/") }) {
      failures.append("the plan names a path outside \(folder.path)")
    }

    if let file = model.rows.first(where: \.isFile) {
      let filePlan = await model.deletePlan(for: [file])
      note("  [delete] \u{201C}\(file.name)\u{201D} -> \(filePlan.paths.count) path(s)")
      if filePlan.paths.count != 1 { failures.append("one file planned \(filePlan.paths.count) paths") }
    }

    note(failures.isEmpty
      ? "  DELETE: pass — a folder expands into the paths the daemon publishes under it"
      : "  DELETE: FAIL")
    for failure in failures { note("    - \(failure)") }
  }

  // MARK: - What the right button offers, where

  /// Asks the view under a point for its menu, the way AppKit does.
  ///
  /// `rightMouseDown:` walks up the responder chain when a view has no menu of
  /// its own, which is the mechanism that gives the empty space below the last
  /// row a menu at all — so the only honest way to check it is to walk the
  /// same chain.
  static func menu(at point: NSPoint, in window: NSWindow) -> [String] {
    guard let root = window.contentView else { return [] }
    guard let event = NSEvent.mouseEvent(
      with: .rightMouseDown, location: point, modifierFlags: [], timestamp: 0,
      windowNumber: window.windowNumber, context: nil, eventNumber: 0,
      clickCount: 1, pressure: 1)
    else { return ["(could not build the event)"] }
    var view = root.hitTest(point)
    while let here = view {
      if let menu = here.menu(for: event) ?? here.menu {
        // Asked to build itself. Both lists fill their menu from
        // `menuNeedsUpdate`, so reading `items` straight off it reports every
        // menu in the window as empty — which this did, and called it a missing
        // menu. AppKit asks the delegate when it opens a tracking session, and
        // a probe cannot open one without blocking on it, so it asks directly:
        // the same call, with the `clickedRow` that `menu(for:)` has just set.
        // (`NSMenu.update()` is not it — that validates items and leaves a
        // delegate-filled menu as empty as it found it.)
        if let table = here as? NSTableView {
          note("     (menu asked at clickedRow=\(table.clickedRow))")
        }
        menu.delegate?.menuNeedsUpdate?(menu)
        return menu.items.map { $0.isSeparatorItem ? "\u{2014}" : $0.title }
      }
      view = here.superview
    }
    return []
  }

  static func menus(_ model: FilesModel, _ window: NSWindow) async {
    var failures: [String] = []
    // A *file* row, and the row it is actually drawn in: row 0 is a folder,
    // whose menu is a different and shorter one.
    guard let fileRow = model.visibleRows.firstIndex(where: \.isFile) else {
      note("  [menus] no file to point at")
      return
    }
    model.selection = [model.visibleRows[fileRow].id]
    await settle(0.6)

    guard let table = fileList(allTables(in: window.contentView)) else {
      note("  [menus] no file table")
      return
    }
    let rowFrame = table.rect(ofRow: fileRow)
    let onRow = table.convert(NSPoint(x: rowFrame.midX, y: rowFrame.midY), to: nil)
    let rowMenu = menu(at: onRow, in: window)
    note("  [menus] on a file row: \(rowMenu.joined(separator: " / "))")

    // And on a folder row, which offers a different and shorter menu.
    if let folderRow = model.visibleRows.firstIndex(where: \.isDirectory) {
      let folderFrame = table.rect(ofRow: folderRow)
      let onFolder = table.convert(
        NSPoint(x: folderFrame.midX, y: folderFrame.midY), to: nil)
      let folderMenu = menu(at: onFolder, in: window)
      note("  [menus] on a folder row: \(folderMenu.joined(separator: " / "))")
      if !folderMenu.contains("Open") {
        failures.append("a folder's menu does not offer Open: \(folderMenu)")
      }
    }
    if !rowMenu.contains("Quick Look") {
      failures.append("a row's menu does not offer Quick Look: \(rowMenu)")
    }
    // One pin item, pointing the way the file actually is — both used to be
    // offered at once, with the state readable nowhere.
    let pinItems = rowMenu.filter { $0.contains("Keeping Offline") || $0 == "Keep Offline" }
    if pinItems.count != 1 {
      failures.append("a row's menu offers \(pinItems.count) pin items: \(pinItems)")
    }

    // Below the last row, where the table itself declines.
    let below = table.convert(
      NSPoint(x: table.bounds.midX, y: table.bounds.maxY - 8), to: nil)
    let emptyMenu = menu(at: below, in: window)
    note("  [menus] on the empty area: \(emptyMenu.joined(separator: " / "))")
    if !emptyMenu.contains("Add Files\u{2026}") {
      failures.append("the empty area offers no Add Files: \(emptyMenu)")
    }

    note(failures.isEmpty
      ? "  MENUS: pass — a row and the empty area each answer, and the pin item is singular"
      : "  MENUS: FAIL")
    for failure in failures { note("    - \(failure)") }
  }

  // MARK: - Whether the search field takes the focus, and gives it back

  /// Each toolbar item's rendered width, which is how a control SwiftUI draws
  /// itself can still be seen to have appeared.
  static func toolbarWidths(_ window: NSWindow) -> String {
    (window.toolbar?.items ?? []).enumerated().map { index, item in
      "\(index):\(item.view.map { fmt($0.frame.width) } ?? "-")"
    }.joined(separator: " ")
  }

  /// Where each toolbar item starts, in the window's coordinates.
  ///
  /// Widths alone cannot show the thing that is wrong here: opening the filter
  /// makes one item 140pt wider, and a trailing toolbar area is right-aligned
  /// as a block, so every item declared before it slides left by that much.
  /// Nothing changes size; everything moves.
  static func toolbarPositions(_ window: NSWindow) -> String {
    (window.toolbar?.items ?? []).enumerated().compactMap { index, item in
      guard let view = item.view else { return nil }
      return "\(index)@\(fmt(Double(view.convert(view.bounds, to: nil).minX.rounded())))"
    }.joined(separator: " ")
  }

  static func focus(_ model: FilesModel, _ window: NSWindow) async {
    var failures: [String] = []
    for width in [1400.0, 1000.0, 900.0, 870.0] {
      var frame = window.frame
      frame.size.width = width
      window.setFrame(frame, display: true)
      await settle(0.8)
      model.searchPresented = false
      model.selection = []
      await settle(0.5)
      note("  [search @\(Int(width))] at rest: responder=\(responder(window)) widths=\(toolbarWidths(window))")
      note("   at rest positions: \(toolbarPositions(window))")

      // 1. Ask for the filter, the way Command-F does. Not by clicking the
      //    toolbar item any more: `.searchable` is drawn by macOS, so the item
      //    has no SwiftUI view for the probe to send a click to. What is being
      //    checked is unchanged — the field appears, and the caret is in it.
      model.openSearch()
      await settle(1.0)
      note("   opened positions: \(toolbarPositions(window))")
      let field0 = firstView(
        in: window.contentView?.superview ?? window.contentView!, ofType: NSSearchField.self)
      let openedWidth = Double(field0?.frame.width ?? 0)
      note("   opened -> presented=\(model.searchPresented) fieldWidth=\(fmt(openedWidth)) responder=\(responder(window))")
      if openedWidth < 100 {
        failures.append("@\(Int(width)): the field opened \(fmt(openedWidth))pt wide — it is not there")
      }
      if !responder(window).contains("SearchField") && !responder(window).contains("TextView") {
        failures.append("@\(Int(width)): opening the field left the caret on \(responder(window))")
      }

      // 2. Type. The filter should reach the model and the listing.
      guard let field = firstView(
        in: window.contentView?.superview ?? window.contentView!, ofType: NSSearchField.self)
      else {
        failures.append("@\(Int(width)): no search field in the window")
        continue
      }
      field.stringValue = "doc"
      NotificationCenter.default.post(name: NSControl.textDidChangeNotification, object: field)
      await settle(0.5)
      note("   typed 'doc' -> search='\(model.search)' rows=\(model.visibleRows.count)/\(model.rows.count)")
      if model.search != "doc" {
        failures.append("@\(Int(width)): typing did not reach the model")
      }
      if model.visibleRows.count >= model.rows.count {
        failures.append("@\(Int(width)): the filter did not narrow the listing")
      }

      // 3. Click the list. A filter in force keeps its field, and Command-F
      //    must be able to get back into it.
      if let table = fileList(allTables(in: window.contentView)) {
        _ = window.makeFirstResponder(table)
        await settle(0.8)
        note("   clicked the list -> presented=\(model.searchPresented) responder=\(responder(window))")
        if !model.searchPresented {
          failures.append("@\(Int(width)): a field with a filter in it folded away")
        }
        model.openSearch()
        await settle(0.8)
        note("   Find… again -> responder=\(responder(window))")
        if !responder(window).contains("SearchField") {
          failures.append("@\(Int(width)): Find could not get back into an open field")
        }
      }

      // 4. Empty it and leave: the magnifier comes back.
      if let field = firstView(
        in: window.contentView?.superview ?? window.contentView!, ofType: NSSearchField.self) {
        field.stringValue = ""
        NotificationCenter.default.post(name: NSControl.textDidChangeNotification, object: field)
        await settle(0.3)
        if let table = fileList(allTables(in: window.contentView)) {
          _ = window.makeFirstResponder(table)
        }
        await settle(0.8)
        note("   emptied and left -> presented=\(model.searchPresented)")
        if model.searchPresented {
          failures.append("@\(Int(width)): an emptied field did not fold back to a magnifier")
        }
      }

      // 5. Clearing the filter from somewhere else also folds it away.
      model.openSearch()
      await settle(0.5)
      model.search = "doc"
      await settle(0.4)
      model.clearSearch()
      await settle(0.6)
      note("   cleared from elsewhere -> presented=\(model.searchPresented)")
      if model.searchPresented {
        failures.append("@\(Int(width)): clearing the filter elsewhere left the field open")
      }
    }

    note(failures.isEmpty
      ? "  SEARCH: pass — opens focused, filters, survives losing the caret, folds away when empty"
      : "  SEARCH: FAIL")
    for failure in failures { note("    - \(failure)") }
  }

  // MARK: - The Settings window, and the checks that lost their anchor

  /// What can be measured about the window the Node window's panes moved into
  /// — and, more importantly, what cannot be measured yet.
  ///
  /// The old pane list was an AppKit table this app declared, so the probe
  /// asked for `PaneListController.PaneNSTableView` by type and knew it had the
  /// right view. That class went with ``NodeShell``. The sidebar is a SwiftUI
  /// `List` now, and SwiftUI's backing views are private: their class names are
  /// not API, they are not stable between releases, and this file has been
  /// burned by matching on one already — ``folderList`` asked for
  /// `SwiftUIOutlineListView` by name, the folder list stopped being one, and
  /// every focus check went on passing against a view it had never found. So no
  /// name is guessed here. The row-level checks are reported as owing an anchor
  /// until the sidebar has a type of this app's own to ask for, the way
  /// ``EntryNSTableView`` does.
  ///
  /// A silent pass would be worse than no check at all: it reads as coverage.
  static func settingsWindow() async {
    var failures: [String] = []
    SettingsRoute.open(.spaces)
    await settle(1.2)
    guard let window = NSApp.windows.first(where: {
      $0.title == WindowSnapshot.settingsTitle && $0.isVisible
    }) else {
      note("  [settings] no window titled \u{201C}\(WindowSnapshot.settingsTitle)\u{201D}")
      note("   windows: " + NSApp.windows.map {
        "\($0.title.isEmpty ? "(none)" : $0.title)/\(type(of: $0))"
      }.joined(separator: ", "))
      note("  SETTINGS: FAIL")
      return
    }

    let size = window.frame.size
    let occluded = Double((window.contentView?.bounds.height ?? 0) - window.contentLayoutRect.height)
    note("  [settings] \(fmt(Double(size.width)))x\(fmt(Double(size.height)))"
      + " key=\(window.isKeyWindow) class=\(type(of: window))")
    note("   occludedAtTop=\(fmt(occluded))"
      + " safeAreaInsets.top=\(fmt(Double(window.contentView?.safeAreaInsets.top ?? 0)))"
      + " toolbar items=\(window.toolbar?.items.count ?? -1)")
    if abs(Double(size.width) - 980) > 2 {
      failures.append(
        "the window is \(fmt(Double(size.width)))pt wide, not the 980 the design fixes"
          + " — 220 of sidebar and the 760 every page was drawn against")
    }
    // The height is reported and not judged. A `Settings` scene sizes itself to
    // its content and then adds chrome of its own, so 660 of content is not 660
    // of window, and by how much is the number ``PreferencesView`` says is
    // still to calibrate. A check against a figure nobody has measured is a
    // check that cries wolf.

    // Whether a *person* can resize it. Not asked by calling `setFrame`: that
    // resizes any window, mask or no mask, so a probe that dragged the frame
    // programmatically would report every fixed window as resizable and learn
    // nothing.
    let declaredResizable = window.styleMask.contains(.resizable)
    let byHand = declaredResizable && window.contentMinSize != window.contentMaxSize
    note("   style .resizable=\(declaredResizable) contentMin=\(window.contentMinSize)"
      + " contentMax=\(window.contentMaxSize) -> resizable by hand: \(byHand)")
    if byHand {
      failures.append("the window can be dragged to another size; the design fixes it at 980x660")
    }

    // The page is written from outside the scene, which is the whole of
    // ``SettingsRoute``'s job and the only part of this window a probe can
    // reach without a view to click. Said plainly because it matters: this
    // exercises the model. A green line here is not evidence that clicking a
    // sidebar row moves the page.
    for pane in [SettingsPane.network, .diagnostics, .members, .general] {
      SettingsRoute.open(pane)
      await settle(0.5)
      note("   route -> \(pane.rawValue): pane=\(SettingsRoute.shared.pane.rawValue)"
        + " topics=\(pane.topics.isEmpty ? "—" : pane.topics.map(\.rawValue).joined(separator: "+"))"
        + " title=\u{201C}\(window.title)\u{201D}")
      if SettingsRoute.shared.pane != pane {
        failures.append("SettingsRoute would not take \(pane.rawValue)")
      }
      // Fixed on purpose: the sidebar already says which page this is, and a
      // title that moves under a window with no other chrome reads as a
      // different window each time.
      if window.title != WindowSnapshot.settingsTitle {
        failures.append(
          "the title followed the page: \u{201C}\(window.title)\u{201D} on \(pane.rawValue)")
      }
    }

    // Printed as evidence for a person, never matched on — see this function's
    // comment for why a class name is not a handle.
    let tables = allTables(in: root(window))
    note("   table views present: " + (tables.isEmpty
      ? "none"
      : tables.map { String(describing: type(of: $0)) }.joined(separator: ", ")))
    note("  [settings] the sidebar's row-level check — click a row, read the page"
      + " back — needs re-anchoring after the Settings move. It was anchored on"
      + " PaneListController.PaneNSTableView, which went with NodeShell, and a"
      + " SwiftUI List offers no type of this app's own to put in its place.")

    note(failures.isEmpty
      ? "  SETTINGS: incomplete — the window's size and the route are checked, the sidebar's rows are not"
      : "  SETTINGS: FAIL")
    for failure in failures { note("    - \(failure)") }
  }

  /// Sends a real mouse down/up at a view's centre.
  /// Which of the window's table views is the folder list, and which is the
  /// file list.
  ///
  /// By what they are, not by a class name: the sidebar was a SwiftUI `List`
  /// reported as `SwiftUIOutlineListView` and is an `NSOutlineView` now, and a
  /// probe that matches on the old name simply stops finding it — which it did,
  /// silently, reporting "no folder list to click".
  static func folderList(_ tables: [NSTableView]) -> NSTableView? {
    tables.compactMap { $0 as? FolderListView.FolderNSOutlineView }.first
  }

  static func fileList(_ tables: [NSTableView]) -> NSTableView? {
    tables.compactMap { $0 as? EntryNSTableView }.first
  }

  /// The first row that is a row, not a section header.
  ///
  /// The sidebar's row 0 is `ListTableHeaderView` — the word "Folders" — and
  /// clicking it selects nothing and runs none of the app's selection code.
  /// Every focus check in this probe had been aiming there, which is why they
  /// all passed while the app was reported as broken.
  static func firstRealRow(of table: NSTableView) -> Int? {
    (0..<table.numberOfRows).first { row in
      guard let view = table.view(atColumn: 0, row: row, makeIfNecessary: false) else { return true }
      return !String(describing: type(of: view)).contains("HeaderView")
    }
  }

  /// What each row of an outline actually is, so a click can be aimed at a
  /// row that does something rather than at a section header.
  static func describeRows(_ table: NSTableView) -> String {
    (0..<min(table.numberOfRows, 6)).map { row in
      let view = table.view(atColumn: 0, row: row, makeIfNecessary: false)
      let text = view.map { firstText(in: $0) } ?? nil
      return "\(row):\(text ?? String(describing: view.map { type(of: $0) }))"
    }.joined(separator: " ")
  }

  private static func firstText(in view: NSView) -> String? {
    if let field = view as? NSTextField, !field.stringValue.isEmpty { return field.stringValue }
    for child in view.subviews {
      if let found = firstText(in: child) { return found }
    }
    return nil
  }

  /// Clicks a table's first row rather than the middle of the view.
  ///
  /// The middle of a ten-row table in a 700pt window is empty space below the
  /// last row: the click lands, changes nothing, and tells you nothing about
  /// whether a row would have taken the caret.
  static func clickFirstRow(_ table: NSTableView, in window: NSWindow) {
    guard let index = firstRealRow(of: table) else { click(table, in: window); return }
    let row = table.rect(ofRow: index)
    send(at: table.convert(NSPoint(x: row.midX, y: row.midY), to: nil), in: window)
  }

  static func click(_ view: NSView, in window: NSWindow) {
    send(at: view.convert(NSPoint(x: view.bounds.midX, y: view.bounds.midY), to: nil), in: window)
  }

  /// One key press and release, through the window rather than through a
  /// monitor.
  ///
  /// The first responder is the wrong thing to judge focus by here: measured,
  /// clicking into the versions panel does not move it at all — it stays on
  /// the file table while a person works in the panel, because SwiftUI runs
  /// its own focus inside each hosting view and AppKit never hears about it.
  /// What a person means by "this has the focus" is that the keys go there,
  /// so that is what this asks.
  static func press(_ keyCode: UInt16, in window: NSWindow) {
    // With the character the key actually produces. An event carrying an empty
    // `characters` is not interpreted by a field editor at all — measured, a
    // synthetic Escape with one never dismissed the filter, through either
    // `window.sendEvent` or `NSApp.sendEvent`.
    let characters: String
    switch keyCode {
    case 53: characters = "\u{1b}"                                  // Escape
    case 125: characters = String(UnicodeScalar(NSDownArrowFunctionKey)!)
    case 126: characters = String(UnicodeScalar(NSUpArrowFunctionKey)!)
    case 36: characters = "\r"                                      // Return
    default: characters = ""
    }
    let now = ProcessInfo.processInfo.systemUptime
    for (index, type) in [NSEvent.EventType.keyDown, .keyUp].enumerated() {
      guard let event = NSEvent.keyEvent(
        with: type, location: .zero, modifierFlags: [],
        timestamp: now + Double(index) * 0.02, windowNumber: window.windowNumber,
        context: nil, characters: characters, charactersIgnoringModifiers: characters,
        isARepeat: false, keyCode: keyCode)
      else { continue }
      // Through the application, not the window. A field editor is reached by
      // the app's own dispatch; `window.sendEvent` skips it, which is why a
      // synthetic Escape never dismissed the filter.
      NSApp.sendEvent(event)
    }
  }

  /// A press and a release at one point, with the timestamps a real click has.
  ///
  /// Both events used to carry `timestamp: 0`. AppKit's gesture recognizers
  /// read the interval between a press and its release, and a zero-length one
  /// is not a click to them — so a `NSClickGestureRecognizer` the app had
  /// installed simply never fired under the probe, and the probe reported the
  /// app as broken when it was the events that were.
  static func send(at point: NSPoint, in window: NSWindow) {
    let now = ProcessInfo.processInfo.systemUptime
    nextEventNumber += 1
    func event(_ type: NSEvent.EventType, _ offset: Double) -> NSEvent? {
      NSEvent.mouseEvent(
        with: type, location: point, modifierFlags: [], timestamp: now + offset,
        windowNumber: window.windowNumber, context: nil, eventNumber: nextEventNumber,
        clickCount: 1, pressure: type == .leftMouseDown ? 1 : 0)
    }
    guard let down = event(.leftMouseDown, 0), let up = event(.leftMouseUp, 0.05) else { return }
    // Posted into the app's own queue, not handed to `sendEvent` — and this is
    // the whole difference between a probe that measures the app and a probe
    // that hangs on it.
    //
    // `NSTableView.mouseDown` does not return when the click arrives: it runs
    // a tracking loop, pulling from the queue until the release comes, because
    // that is how a drag-selection is followed. Delivered by `sendEvent`, the
    // release is a line that is never reached — the press has not returned yet
    // — so the loop waits for an event that cannot arrive and the app stops
    // dead on the first click into a row. That was measured twice and blamed
    // on the app both times: once as "taking the caret in `mouseDown` hangs
    // the app", and once as "the file list will not take the caret". Neither
    // was true.
    //
    // Queued, both events reach the run loop the way the window server's do,
    // the tracking loop finds its release, and the caller's `settle` is what
    // lets them through.
    NSApp.postEvent(down, atStart: false)
    NSApp.postEvent(up, atStart: false)
  }

  static var nextEventNumber = 0

  static func allTables(in view: NSView?) -> [NSTableView] {
    guard let view else { return [] }
    var found: [NSTableView] = []
    if let table = view as? NSTableView { found.append(table) }
    for child in view.subviews { found.append(contentsOf: allTables(in: child)) }
    return found
  }
}

/// Runs the probe once the app has settled, then quits.
struct UIProbeDriver: ViewModifier {
  let node: NodeStore
  let model: FilesModel

  func body(content: Content) -> some View {
    content.task {
      guard UIProbe.name != nil else { return }
      // Generous, because a probe that runs before the window has settled
      // reports failures the app does not have — and a gate that cries wolf
      // gets ignored.
      try? await Task.sleep(for: .seconds(
        Double(ProcessInfo.processInfo.environment["HECATIA_PROBE_SETTLE"] ?? "") ?? 8))
      NSApp.activate(ignoringOtherApps: true)
      UIProbe.browser(model)?.makeKeyAndOrderFront(nil)
      try? await Task.sleep(for: .milliseconds(500))
      await UIProbe.run(model, node)
      NSApp.terminate(nil)
    }
  }
}
extension View {
  /// Inert unless `HECATIA_PROBE` is set. DEBUG only, along with everything
  /// above it — the extension has to be inside the same conditional as the
  /// `import SwiftUI` it needs, which is why the release build could not see
  /// `View` at all.
  @ViewBuilder func uiProbe(_ node: NodeStore, _ model: FilesModel) -> some View {
    modifier(UIProbeDriver(node: node, model: model))
  }
}
#endif
