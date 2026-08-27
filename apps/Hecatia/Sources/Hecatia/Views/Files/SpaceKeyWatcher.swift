import SwiftUI

/// Owns the local key monitor.
///
/// A class, held in `@State`, for two reasons the first version got wrong.
/// Its predecessor kept the monitor token and the `NSWindow` in `@State` and
/// wrote them from an `NSViewRepresentable`'s async callback — writing view
/// state from outside an update is exactly the corruption that then surfaced,
/// with a moving crash site, inside `NavigationSplitView.init`. And its monitor
/// closure captured the modifier struct, so an installed monitor that outlived
/// its view ran against a stale copy of it. Here the closure holds only a weak
/// reference: a monitor that outlives the watcher does nothing at all.
///
/// It publishes nothing — no view reads it, the key monitor does — so it is a
/// plain class kept alive by `@State` rather than an observable one.
@MainActor
final class SpaceKeyWatcher {
  /// Refreshed by the view rather than captured, so the monitor never decides
  /// from a copy of state that has since moved.
  weak var model: FilesModel?
  var isKeyWindow = false

  private var token: Any?

  func start() {
    guard token == nil else { return }
    token = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
      guard let self, self.handle(event) else { return event }
      return nil
    }
  }

  func stop() {
    if let token { NSEvent.removeMonitor(token) }
    token = nil
  }

  /// Whether the space bar belongs to the file list right now.
  ///
  /// The file list's own type, which is the whole test now.
  ///
  /// It used to sniff the class *name* for "TableView", because neither list
  /// was this app's: both were SwiftUI's, `NSOutlineView` is an `NSTableView`
  /// so the obvious test could not tell them apart, and a focused SwiftUI
  /// button is not an `NSButton` at all. ``EntryNSTableView`` is one type this
  /// app owns and can simply be asked about.
  ///
  /// Nothing focused counts as yes. That state is common — clicking the empty
  /// area of the file list used to land there — and Space has always previewed
  /// from it, so refusing would take away working behaviour to fix a different
  /// bug.
  private static func fileListHasTheCaret(_ responder: NSResponder?) -> Bool {
    if responder is NSWindow || responder == nil { return true }
    return responder is EntryNSTableView
  }

  private func handle(_ event: NSEvent) -> Bool {
    // The cheapest test first, before anything is computed for it. This runs
    // on *every* key down in the app, and `previewableSelection` below walks
    // the whole visible listing to answer — for every letter typed into every
    // field, only for `takesSpace` to discard it on its own first guard.
    guard event.charactersIgnoringModifiers == " " else { return false }
    guard let model else { return false }
    let responder = NSApp.keyWindow?.firstResponder
    let decision = QuickLookKeyMonitor.takesSpace(
      characters: event.charactersIgnoringModifiers,
      modifiers: event.modifierFlags,
      isKeyWindow: isKeyWindow,
      isEditingText: responder is NSText,
      fileListHasTheCaret: Self.fileListHasTheCaret(responder),
      selectionIsAFile: model.previewableSelection != nil)
    #if DEBUG
    QuickLookKeyMonitor.lastDecision = decision.reason
    #endif
    guard decision.yes, let entry = model.previewableSelection else { return false }
    model.requestPreview(entry)
    return true
  }
}
