#if DEBUG
import SwiftUI

/// Photographs the app's own windows, for looking at what shipped.
///
/// A window can always draw itself into a bitmap — that is `cacheDisplay`, and
/// it needs no screen-recording grant, unlike `screencapture`. It is also the
/// only way to see the real thing: `ImageRenderer` runs one layout pass with no
/// window behind it, so a `ScrollView`'s contents rasterise as nothing.
///
/// **It does not photograph AppKit views faithfully.** The folder list is an
/// `NSOutlineView` now, and in these captures its selected row comes out as a
/// flat black bar with the name invisible on it. Measured through the probe at
/// the same moment, the row is selected and emphasized, its cell's
/// `backgroundStyle` is `.emphasized`, and the label's colour is
/// `alternateSelectedControlTextColor` — white on the accent, which is what a
/// person sees. An hour went into chasing that black bar before the numbers
/// were asked instead of the picture. Use this for SwiftUI surfaces; ask the
/// probe, or a person, about AppKit ones.
///
/// DEBUG only, and inert unless `HECATIA_WINDOW_SNAPSHOT_DIR` names a folder.
/// It also writes a `geometry.txt` beside the images, because "is this a layout
/// bug or a capture artefact" is the first question every one of these raises.
///
/// One known blind spot: `cacheDisplay` composites what the window has drawn
/// into its own backing, and some SwiftUI-drawn layers — a sidebar `List`'s
/// rows, a pane header above a `ScrollView` — do not always land in it. Where a
/// window comes back partial, ``Snapshots`` renders the same view through
/// `ImageRenderer`, which has the opposite blind spot; between the two every
/// surface is visible in one of them.
@MainActor
enum WindowSnapshot {
  static var directory: URL? {
    ProcessInfo.processInfo.environment["HECATIA_WINDOW_SNAPSHOT_DIR"].map {
      URL(fileURLWithPath: $0)
    }
  }

  /// Seconds to let the app connect and fill its tables before the shutter.
  static var settleSeconds: Double {
    Double(ProcessInfo.processInfo.environment["HECATIA_SNAPSHOT_SETTLE"] ?? "") ?? 6
  }

  /// `HECATIA_SNAPSHOT_APPEARANCE=dark` photographs the app in dark mode.
  ///
  /// Set on the application, because the theme resolves semantic AppKit
  /// colours against `NSApp.effectiveAppearance` — a SwiftUI `colorScheme`
  /// override would change some of the colours and none of the materials.
  /// `HECATIA_SNAPSHOT_FAKE_TRANSFER=1` seeds a transfer that never finishes.
  ///
  /// The toolbar grows an item while a transfer exists, and what that does to
  /// the rest of the toolbar is exactly the thing that has to be looked at.
  static func seedFakeTransferIfAsked(_ queue: TransferQueue) {
    guard ProcessInfo.processInfo.environment["HECATIA_SNAPSHOT_FAKE_TRANSFER"] == "1" else {
      return
    }
    var transfer = Transfer(
      id: UUID(), direction: .download, name: "a-large-file.dmg",
      space: "demo", path: "a-large-file.dmg", total: 240_000_000)
    transfer.bytes = 96_000_000
    queue.add(transfer) { id in
      queue.update(id) { $0.state = .running }
      try? await Task.sleep(for: .seconds(600))
    }
  }

  /// `HECATIA_SNAPSHOT_TEST_SPACE=1` selects a file and presses the space bar.
  ///
  /// The event is posted into this app's own queue, so it needs no Accessibility
  /// grant — and it goes through `NSApp.sendEvent`, which is exactly the path a
  /// real key press takes and the one the local monitor sits on. What the
  /// monitor decided is written into `geometry.txt` beside the images.
  static func pressSpaceIfAsked(_ model: FilesModel) async -> String? {
    guard ProcessInfo.processInfo.environment["HECATIA_SNAPSHOT_TEST_SPACE"] == "1" else {
      return nil
    }
    guard let file = model.visibleRows.first(where: \.isFile) else { return "no file to select" }
    model.selection = [file.id]
    // The browser has to be the key window, and opening the other three left
    // one of them in front. A key press is only meaningful to the window it is
    // aimed at.
    // `NSRunningApplication` as well as `NSApp`: on recent macOS an app
    // launched from a terminal while something else is frontmost cannot always
    // bring itself forward, and only one of the two ever works.
    NSApp.activate(ignoringOtherApps: true)
    NSRunningApplication.current.activate(options: [.activateAllWindows])
    guard let window = NSApp.windows.first(where: { $0.title == model.locationTitle })
    else { return "browser window not found" }
    // Retried, because activation is a request to the window server that can
    // simply lose to whatever is frontmost. `await`, not
    // `RunLoop.run(until:)`: a synchronous spin holds the main actor, and
    // becoming the active application is work *on* that actor, so the wait
    // prevented the very thing it was waiting for.
    for _ in 0..<5 {
      NSApp.activate(ignoringOtherApps: true)
      NSRunningApplication.current.activate(options: [.activateAllWindows])
      window.makeKeyAndOrderFront(nil)
      try? await Task.sleep(for: .milliseconds(400))
      if window.isKeyWindow { break }
    }
    guard let event = NSEvent.keyEvent(
      with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0,
      windowNumber: window.windowNumber, context: nil, characters: " ",
      charactersIgnoringModifiers: " ", isARepeat: false, keyCode: 49)
    else { return "could not build the event" }
    QuickLookKeyMonitor.lastDecision = "no key seen"
    NSApp.sendEvent(event)
    let decision = QuickLookKeyMonitor.lastDecision
    guard window.isKeyWindow else {
      // An app launched from a terminal cannot always come forward, and a key
      // press means nothing to a window that is not key — so this cannot be
      // the full end-to-end here. What it still proves is that the monitor is
      // installed and reached the decision: anything other than "no key seen"
      // means the event went through `NSApp.sendEvent` into the local monitor
      // with this window's model attached. Every branch of the decision itself
      // is covered by `SpaceBarTests`.
      return "monitor reached, app not frontmost -> \(decision)"
    }
    return "selected \(file.name), then space -> \(decision)"
  }

  /// `HECATIA_SNAPSHOT_SEARCH=1` opens the filter field before the shutter,
  /// `HECATIA_SNAPSHOT_PANEL=1` the versions panel, and
  /// `HECATIA_SNAPSHOT_TRANSFERS=1` the transfer popover — which is its own
  /// window, so the capture picks it up like any other.
  static func openThingsIfAsked(_ model: FilesModel) {
    let environment = ProcessInfo.processInfo.environment
    if environment["HECATIA_SNAPSHOT_SEARCH"] == "1" { model.openSearch() }
    if environment["HECATIA_SNAPSHOT_PANEL"] == "1" { model.setPanel(true) }
    if environment["HECATIA_SNAPSHOT_TRANSFERS"] == "1" { model.showingTransfers = true }
    // `HECATIA_SNAPSHOT_POLICY=strict|origin=<id>` pins a version policy, so
    // what a policy marks rather than removes can be looked at.
    if let wire = environment["HECATIA_SNAPSHOT_POLICY"], let policy = VersionPolicy(wire: wire) {
      model.policy = policy
      Task { await model.reload() }
    }
    // No `HECATIA_SNAPSHOT_SETTINGS` knob any more: the driver opens that
    // window every run, because it is where the Node window's eight panes went
    // and the Node window was opened every run. `HECATIA_SNAPSHOT_SETTINGS_PANE`
    // chooses which of the nine pages it comes up on — see ``SettingsPane``.
  }

  /// ``PreferencesView``'s `navigationTitle`, which is how this file addresses
  /// that window.
  ///
  /// Fixed on purpose, and it does not follow the selected page — so the
  /// capture writes `synchronicity-settings.png` whichever page is showing,
  /// rather than a filename that moves with `HECATIA_SNAPSHOT_SETTINGS_PANE`.
  static let settingsTitle = "Synchronicity Settings"

  /// Opens the Settings window on `pane` and says whether it came up.
  ///
  /// The `Settings` scene has no window id, so `openWindow` cannot name it —
  /// this goes the way the app's own three entries into it go, through
  /// ``SettingsRoute``. Its pages are also the ones `ImageRenderer` cannot
  /// draw: every `Table` in them rasterises as a placeholder, so photographing
  /// the real window is the only way to look at one.
  ///
  /// The verdict is read back off `NSApp.windows` rather than off the
  /// `sendAction` inside ``SettingsRoute/showWindow()``. That call answering
  /// means a responder took the message, not that a window appeared, and it is
  /// the window this file exists to photograph.
  ///
  /// `async` because the verdict is worthless before the window server has had
  /// a turn: read in the same run-loop pass that asked, `NSApp.windows` does
  /// not have it yet and every run would report a window that did appear as
  /// missing.
  static func openSettings(on pane: SettingsPane) async {
    NSApp.activate(ignoringOtherApps: true)
    SettingsRoute.open(pane)
    try? await Task.sleep(for: .milliseconds(900))
    let up = NSApp.windows.contains { $0.title == settingsTitle && $0.isVisible }
    settingsResult = up
      ? "open on \(pane.rawValue)"
      : "did not appear (asked for \(pane.rawValue))"
  }

  /// `HECATIA_SNAPSHOT_WIDTH` narrows the window before the shutter, so what
  /// the toolbar does when it runs out of room can be looked at rather than
  /// guessed at.
  static func resizeIfAsked(_ window: NSWindow) {
    guard let text = ProcessInfo.processInfo.environment["HECATIA_SNAPSHOT_WIDTH"],
          let width = Double(text)
    else { return }
    var frame = window.frame
    frame.size.width = width
    window.setFrame(frame, display: true)
  }

  static func applyAppearance() {
    switch ProcessInfo.processInfo.environment["HECATIA_SNAPSHOT_APPEARANCE"] {
    case "dark": NSApp.appearance = NSAppearance(named: .darkAqua)
    case "light": NSApp.appearance = NSAppearance(named: .aqua)
    default: break
    }
  }

  /// Schedules a *fallback* capture from the app's own init, not from a view.
  ///
  /// The driver normally captures; this exists so that a window failing to
  /// appear is reported rather than silently producing nothing, which is how
  /// the window-restoration modal went unnoticed for an hour. The margin has
  /// to clear everything the driver does — opening the Activity and Settings
  /// windows, settling, pressing a key, probing — or it terminates the app out
  /// from under it.
  ///
  /// Hanging it off a `.task` made it depend on the very thing that has to be
  /// diagnosed when a window does not appear — it reported nothing, which is
  /// indistinguishable from "not set". From here it always runs and always
  /// says what `NSApp.windows` actually held.
  static func scheduleIfAsked() {
    guard let directory else { return }
    Task {
      try? await Task.sleep(for: .seconds(settleSeconds + 15))
      applyAppearance()
      captureAll(into: directory)
      NSApp.terminate(nil)
    }
  }

  /// Whether the Settings window came up, and on which page.
  ///
  /// Written by ``openSettings(on:)`` and read into `geometry.txt`, because a
  /// window that never appeared and a window that appeared blank produce the
  /// same thing here: no image.
  static var settingsResult: String?

  static func captureAll(into directory: URL, spaceResult: String? = nil) {
    try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    var used: Set<String> = []
    var notes: [String] = ["NSApp.windows: \(NSApp.windows.count)"]
    if let settingsResult { notes.append("settings: \(settingsResult)") }
    if let spaceResult { notes.append("space bar: \(spaceResult)") }
    for window in NSApp.windows {
      notes.append(
        "  candidate title=\(window.title.isEmpty ? "(none)" : window.title) "
          + "visible=\(window.isVisible) frame=\(window.frame) class=\(type(of: window))")
    }
    for window in NSApp.windows {
      // The frame view, not the content view: a macOS window with a unified
      // toolbar draws its toolbar *outside* the content view, so capturing the
      // content view alone leaves an undrawn strip across the top where the
      // toolbar should be — which reads as a white bar in a dark window and is
      // an artefact of the capture rather than anything the app painted.
      guard window.isVisible,
            let content = window.contentView?.superview ?? window.contentView,
            content.bounds.width > 1
      else { continue }
      var name = slug(window.title.isEmpty ? "untitled" : window.title)
      var suffix = 2
      while used.contains(name) {
        name = "\(slug(window.title))-\(suffix)"
        suffix += 1
      }
      used.insert(name)
      // A window opened programmatically has not necessarily drawn everything
      // it will draw; without this its list and its scroll contents come back
      // blank while its chrome does not.
      window.orderFrontRegardless()
      window.makeKey()
      content.layoutSubtreeIfNeeded()
      // A window opened programmatically has a layer tree that is still
      // settling; without spinning the run loop once per window its list and
      // its header come back blank while the middle of it does not.
      RunLoop.current.run(until: Date().addingTimeInterval(0.6))
      window.display()
      guard let bitmap = content.bitmapImageRepForCachingDisplay(in: content.bounds) else {
        continue
      }
      content.cacheDisplay(in: content.bounds, to: bitmap)
      guard let data = bitmap.representation(using: .png, properties: [:]) else { continue }
      try? data.write(to: directory.appendingPathComponent("\(name).png"))
      // `contentLayoutRect` and the safe-area inset are the two numbers that
      // settle "is the toolbar covering this". A window with
      // `.fullSizeContentView` has a content view the full height of the
      // frame, so `content.frame` alone says nothing: what matters is how much
      // of it the titlebar and toolbar sit over, and whether the view tree is
      // insetting itself by that much. A pane drawing its own header at y=0
      // inside a 52-point inset is the bug this line names.
      let layout = window.contentLayoutRect
      let inset = content.safeAreaInsets
      notes.append(
        "\(name): window \(window.frame) content \(window.contentView?.frame ?? .zero) "
          + "captured \(content.bounds) titlebarTransparent=\(window.titlebarAppearsTransparent) "
          + "style=\(window.styleMask.rawValue) toolbar=\(window.toolbar != nil) "
          + "contentLayoutRect=\(layout) safeAreaInsets=\(inset) "
          + "occludedAtTop=\((window.contentView?.bounds.height ?? 0) - layout.height)")
      // Where the real content starts, in window coordinates with the origin
      // at the top. A scroll view or table whose top is above `occludedAtTop`
      // is underneath the toolbar, whatever the safe-area inset claims.
      for (label, frame) in Self.contentTops(of: content) {
        notes.append("    \(name) ▸ \(label) topInWindow=\(frame)")
      }
      if ProcessInfo.processInfo.environment["HECATIA_SNAPSHOT_TREE"] == "1" {
        for line in Self.tree(of: content, depth: 0) { notes.append("      \(name) │ \(line)") }
      }
    }
    write(notes, to: directory)
  }

  /// The scroll views and tables in a window, by how far their top edge sits
  /// from the top of the content view.
  ///
  /// The one measurement that answers "is the toolbar covering this". A
  /// `safeAreaInsets.top` of 52 says only that AppKit reported the inset — not
  /// that the view tree honoured it, which is a different question and the one
  /// that decides whether a pane's first row is readable.
  private static func contentTops(of root: NSView) -> [(String, CGFloat)] {
    var found: [(String, CGFloat)] = []
    func walk(_ view: NSView) {
      let interesting = view is NSScrollView || view is NSTableView
      if interesting {
        let inWindow = view.convert(view.bounds, to: nil)
        // AppKit's y grows upward, so distance from the top is the content
        // view's height minus the subview's top edge.
        let fromTop = root.bounds.height - inWindow.maxY
        found.append((String(describing: type(of: view)), fromTop))
      }
      for child in view.subviews { walk(child) }
    }
    walk(root)
    return found
  }

  /// Raw frames, in the view's own parent coordinates and in the window's.
  ///
  /// Derived numbers are how the last two hours went wrong: a single
  /// "distance from the top" is a subtraction of two things, and when it comes
  /// out impossible there is no way to tell which of them was wrong. This
  /// prints both sides so the arithmetic can be checked rather than trusted.
  private static func tree(of view: NSView, depth: Int) -> [String] {
    guard depth < 11 else { return [] }
    let pad = String(repeating: "  ", count: depth)
    let inWindow = view.convert(view.bounds, to: nil)
    var out = [
      "\(pad)\(type(of: view)) frame=\(view.frame) inWindow=\(inWindow) hidden=\(view.isHidden)"
    ]
    for child in view.subviews { out += tree(of: child, depth: depth + 1) }
    return out
  }

  private static func write(_ notes: [String], to directory: URL) {
    try? notes.joined(separator: "\n").write(
      to: directory.appendingPathComponent("geometry.txt"), atomically: true, encoding: .utf8)
  }

  private static func slug(_ text: String) -> String {
    let allowed = text.lowercased().map { $0.isLetter || $0.isNumber ? $0 : "-" }
    return String(allowed).trimmingCharacters(in: CharacterSet(charactersIn: "-"))
  }
}

/// Opens every window, waits for the app to settle, photographs them, quits.
struct WindowSnapshotDriver: ViewModifier {
  @Environment(\.openWindow) private var openWindow
  /// Passed in rather than read from the environment. A `ViewModifier` reads
  /// the environment *it* sits in, which is outside the `.environmentObject`
  /// applied to the view it wraps — so `@EnvironmentObject` here trapped the
  /// moment it was read.
  let node: NodeStore
  let model: FilesModel

  func body(content: Content) -> some View {
    content.task {
      guard let directory = WindowSnapshot.directory else { return }
      WindowSnapshot.seedFakeTransferIfAsked(node.transfers)
      try? await Task.sleep(for: .seconds(2))
      if let browser = NSApp.windows.first(where: { $0.title == model.folderTitle }) {
        WindowSnapshot.resizeIfAsked(browser)
      }
      // One at a time, with a run-loop pass between. Opening them inside a
      // single pass — which nothing but this driver ever does — corrupted
      // SwiftUI's state badly enough to crash somewhere else entirely, with a
      // moving crash site.
      //
      // The `node` window is not in this list because the scene is gone: its
      // eight panes are pages of Settings now. Settings cannot be opened with
      // `openWindow` — a `Settings` scene has no id — so it goes through
      // ``WindowSnapshot/openSettings(on:)``, which waits the same 900ms.
      openWindow(id: "activity")
      try? await Task.sleep(for: .milliseconds(900))
      await WindowSnapshot.openSettings(on: .initial)
      // Settle, press the space bar, then capture. The capture cannot be
      // scheduled from here — a window that fails to appear would take this
      // task with it and report nothing — so `init` schedules a fallback and
      // this one wins the race when the window did appear.
      try? await Task.sleep(for: .seconds(WindowSnapshot.settleSeconds))
      WindowSnapshot.openThingsIfAsked(model)
      try? await Task.sleep(for: .milliseconds(900))
      let spaceResult = await WindowSnapshot.pressSpaceIfAsked(model)
      WindowSnapshot.applyAppearance()
      WindowSnapshot.captureAll(into: directory, spaceResult: spaceResult)
      NSApp.terminate(nil)
    }
  }
}
extension View {
  /// Inert unless `HECATIA_WINDOW_SNAPSHOT_DIR` is set. DEBUG only, along with
  /// everything above it: the extension has to be inside the same conditional
  /// as the `import SwiftUI` it needs, and outside it the release build could
  /// not see `View` at all — which is why `make release` had not compiled for
  /// some time.
  @ViewBuilder func snapshotDriver(_ node: NodeStore, _ model: FilesModel) -> some View {
    modifier(WindowSnapshotDriver(node: node, model: model))
  }
}
#endif
