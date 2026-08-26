import SwiftUI

/// Whether the in-process UI probe is driving this launch.
///
/// A file-level constant rather than a static on the controller: the
/// controller is nested in a generic type, and generic types cannot hold
/// static stored properties.
/// What the panel opens at, and the floor and ceiling it gets afterwards.
///
/// File-level rather than static members: they belong to a type nested in a
/// generic one, and a generic type cannot hold static stored properties.
private let idealPanelWidth: Double = 330
private let narrowestPanel: Double = 280
private let widestPanel: Double = 720

private let probeIsDriving: Bool = {
  #if DEBUG
  return ProcessInfo.processInfo.environment["HECATIA_PROBE"] != nil
  #else
  return false
  #endif
}()

/// The browser and its versions panel, as two AppKit split view items.
///
/// `.inspector` animates inside SwiftUI's own layout system, and SwiftUI does
/// not re-lay-out the pane beside it until the animation ends. For the ~200ms
/// in between, the browser is still sized for a window that no longer has that
/// width, and a view that does not fit its proposal is centred in it — so the
/// whole thing slides half the panel's width off the left edge and snaps back.
/// Measured at 165pt, for 200ms, at every window width, with *both* documented
/// placements of the modifier.
///
/// An `NSSplitViewItem` collapse is a different mechanism, not a better tuned
/// one: AppKit sets each pane's frame every frame, and an `NSHostingView`
/// re-lays-out its SwiftUI content synchronously when its frame changes. There
/// is never a moment when the browser is the wrong size, so there is never a
/// moment when anything has to be centred.
///
/// The panel is an `inspector` item rather than a plain one, which is what
/// gives it `allowsFullHeightLayout` — the full-height look the sidebar has
/// and `.inspector` on the detail column does not.
struct BrowserSplit<Browser: View, Panel: View>: NSViewControllerRepresentable {
  let panelVisible: Bool
  @ViewBuilder let browser: Browser
  @ViewBuilder let panel: Panel

  func makeNSViewController(context: Context) -> SplitController {
    let controller = SplitController()
    let browserHost = NSHostingController(rootView: browser)
    let panelHost = NSHostingController(rootView: panel)
    // Neither pane reports a size upwards.
    //
    // `NSHostingController` defaults to `.preferredContentSize`, which pushes
    // its SwiftUI content's intrinsic size out through the view controller —
    // and this one is inside a representable, so SwiftUI reads that back as
    // the size the whole split wants. The window then drew the entire browser
    // as a 165pt-tall band in the corner of an empty window. These panes are
    // sized by the split view, and by nothing else.
    browserHost.sizingOptions = []
    panelHost.sizingOptions = []
    controller.install(browser: browserHost, panel: panelHost)
    return controller
  }

  func updateNSViewController(_ controller: SplitController, context: Context) {
    controller.browserHost?.rootView = browser
    controller.panelHost?.rootView = panel
    controller.show(panel: panelVisible)
  }

  final class SplitController: NSSplitViewController {

    var browserHost: NSHostingController<Browser>?
    var panelHost: NSHostingController<Panel>?
    private var applied: Bool?
    /// Whether the thickness bounds have been widened from the opening width.
    private var released = false

    func install(browser: NSHostingController<Browser>, panel: NSHostingController<Panel>) {
      browserHost = browser
      panelHost = panel

      let browserItem = NSSplitViewItem(viewController: browser)
      browserItem.canCollapse = false
      browserItem.holdingPriority = .defaultLow
      // A floor, because the panel is the one that holds its width and this is
      // the one that gives. Without it there was nothing to stop the browser
      // being squeezed to 279pt — the sidebar at its 200pt minimum and a file
      // list 79pt wide, with the names cut to two characters and "10 items"
      // set one letter per line. Two hundred for the sidebar's own minimum,
      // and enough beside it for a Name column worth reading.
      browserItem.minimumThickness = 560
      addSplitViewItem(browserItem)

      let panelItem = NSSplitViewItem(inspectorWithViewController: panel)
      // Pinned to the opening width, and widened to its real range once it has
      // opened once — see ``show(panel:)``.
      //
      // Not a width constraint on the panel's own view: tried at `defaultHigh`
      // and again at 999, and the panel still opened at its floor both times.
      // `NSSplitViewController` decides an item's thickness itself and a
      // constraint on the hosted view does not enter that negotiation. The
      // thickness bounds are the API that does.
      panelItem.minimumThickness = idealPanelWidth
      panelItem.maximumThickness = idealPanelWidth
      // The width it opens at, which is neither of those two. Without it
      // AppKit starts the item at its minimum: measured, the panel opened at
      // 280pt rather than the 330 this app has always used.
      //
      panelItem.allowsFullHeightLayout = true
      panelItem.canCollapse = true
      // Added *expanded*, and collapsed a moment later by the first
      // `show(panel:)` without animating.
      //
      // Because an `NSSplitViewItem` restores the thickness it had before it
      // was collapsed, and an item that has never been open has none — AppKit
      // then expands it to `minimumThickness`, which put the panel at 281pt
      // instead of 330 however the width was asked for. Opening it once, at
      // the width below, is what gives it something to restore.
      addSplitViewItem(panelItem)

      // So the width a person drags the divider to survives a relaunch, the
      // way `inspectorColumnWidth`'s ideal did.
      //
      // Under a different name while the probe is driving, because the probe
      // drags this divider to both of its limits to measure the travel, and
      // AppKit writes the autosave as the divider moves rather than when the
      // app exits — so a probe run that is killed rather than quit left the
      // *real* app opening at the last extreme it was dragged to. That is
      // exactly how the browser came to open 279pt wide.
      splitView.autosaveName = probeIsDriving ? "browser-panel-probe" : "browser-panel"
    }

    func show(panel visible: Bool) {
      guard let item = splitViewItems.last, applied != visible else { return }
      let firstTime = applied == nil
      applied = visible
      guard !firstTime else {
        item.isCollapsed = !visible
        return
      }
      NSAnimationContext.runAnimationGroup { _ in
        item.animator().isCollapsed = !visible
      } completionHandler: { [weak self] in
        // `assumeIsolated` because AppKit runs this on the main thread but
        // types it `@Sendable`, and everything it touches here — the
        // controller, its items — is main-actor state.
        MainActor.assumeIsolated {
          // Widened once the panel has actually been open at its ideal. From
          // here the divider is the only thing that decides, and the split
          // view's autosave remembers where it was left.
          guard let self, visible, !self.released,
                let item = self.splitViewItems.last else { return }
          self.released = true
          item.minimumThickness = narrowestPanel
          item.maximumThickness = widestPanel
        }
      }
    }
  }
}

#if DEBUG
/// The split with two stand-in panes, labelled so which side is which is
/// obvious, and the toggle the toolbar's Versions button would be.
///
/// The toggle is inside the browser pane because the split fills whatever it
/// is given and there is nowhere outside it to put a control.
///
/// The divider carries the app's own autosave name, so dragging it here is
/// remembered wherever this preview runs.
private struct SplitPreview: View {
  @State private var showingPanel: Bool

  init(panelVisible: Bool) {
    _showingPanel = State(initialValue: panelVisible)
  }

  var body: some View {
    BrowserSplit(panelVisible: showingPanel) {
      pane(
        "Browser", "The sidebar and the file list, which never collapses.",
        tint: Theme.accent, button: showingPanel ? "Hide the Panel" : "Show the Panel")
    } panel: {
      pane(
        "Versions", "Opens at 330pt, and its floor and its ceiling are both that number until it has been closed and opened once — so the divider does not move yet.",
        tint: Theme.muted, button: nil)
    }
  }

  private func pane(
    _ title: String, _ detail: String, tint: Color, button: String?
  ) -> some View {
    VStack(spacing: Theme.Space.s) {
      Text(title).font(.title3.weight(.semibold))
      Text(detail)
        .font(.caption).foregroundStyle(Theme.muted)
        .multilineTextAlignment(.center)
        .fixedSize(horizontal: false, vertical: true)
      if let button {
        Button(button) { showingPanel.toggle() }
      }
    }
    .padding(Theme.Space.xl)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .background(tint.opacity(0.12))
  }
}

#Preview("Browser and panel") {
  SplitPreview(panelVisible: true)
    .frame(width: 980, height: 620)
}

#Preview("Panel closed") {
  // Shut on the very first update, and without animating: an item that has
  // never been open has no thickness to restore, so the panel is added
  // expanded and collapsed a moment later.
  SplitPreview(panelVisible: false)
    .frame(width: 980, height: 620)
}

#Preview("As narrow as the panes allow") {
  // 560 for the browser and 330 for the panel: below about this the split has
  // to take the width out of one of them.
  SplitPreview(panelVisible: true)
    .frame(width: 900, height: 480)
}
#endif
