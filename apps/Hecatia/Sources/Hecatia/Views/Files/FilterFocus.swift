import SwiftUI

/// Puts the caret in the toolbar's filter field when Command-F asks for it.
///
/// `.searchable` draws and places the field — that is the whole point of using
/// it — but it has no way to be focused from code before macOS 15's
/// `searchFocused(_:)`, and this app's Find command is older than that and
/// keeps working on 14. So one lookup for the field macOS made, and one
/// `makeFirstResponder`.
///
/// No retry loop. The version this replaces asked up to four run loop turns
/// apart because it was focusing a field it had *just* created, in a toolbar
/// item that was still being swapped in. This one focuses a field that has
/// been sitting in the toolbar since the window opened.
struct FilterFocus: NSViewRepresentable {
  /// Bumped by ``FilesModel/openSearch()``. A counter rather than a flag, so
  /// asking twice in a row is two requests.
  let request: Int
  /// Called when the field stops being edited, so an empty one can fold back
  /// to the magnifier.
  ///
  /// `.searchable` does not do that by itself: with `isPresented` still true it
  /// keeps the search active. The hand-built field this replaced folded itself
  /// back from its delegate's `controlTextDidEndEditing`, and dropping that
  /// when `.searchable` took over is what regressed.
  ///
  /// This used to need a mouse-down monitor as well, because clicking another
  /// view did not take the caret off the field and so `textDidEndEditing` never
  /// fired — reported as "click the filter, and then neither the file list nor
  /// the folder list can be clicked into". That was the SwiftUI lists' fault,
  /// not the field's. Against the `NSTableView` and `NSOutlineView` that
  /// replaced them the click ends the editing on its own, the notification
  /// arrives, and the probe reports the field folding back with the monitor
  /// gone — so it is gone.
  let onEditingEnded: () -> Void

  func makeNSView(context: Context) -> NSView { NSView() }

  func updateNSView(_ view: NSView, context: Context) {
    let coordinator = context.coordinator
    coordinator.onEditingEnded = onEditingEnded
    guard let window = view.window, let field = coordinator.field(in: window) else { return }
    guard coordinator.served != request else { return }
    coordinator.served = request
    #if DEBUG
    FocusTrace.claim("FilterFocus", "request \(request)")
    #endif
    // Not deferred, and that is a decision rather than an oversight.
    //
    // This line is the source of all sixteen "Modifying state during view
    // update" warnings the focus suite produces — measured by deferring it and
    // watching the count go to zero. But deferring it also breaks what it is
    // for: with the call a run loop turn later the probe reports "opening the
    // field left the caret on EntryNSTableView", "a field with a filter in it
    // folded away", and an emptied field no longer folding back. ⌘F stops
    // working.
    //
    // So the warning stands until someone has a fix that keeps the behaviour.
    // ``FileListCaret`` defers the same call safely because it runs on a
    // request raised as the field goes away, not on one racing the field's own
    // appearance.
    window.makeFirstResponder(field)
  }

  func makeCoordinator() -> Coordinator {
    Coordinator(served: request, onEditingEnded: onEditingEnded)
  }

  @MainActor
  final class Coordinator: NSObject {
    /// The request this view was *built* at, which counts as already served.
    ///
    /// It used to start at `Int.min` on the reasoning that "the first request
    /// is 1, so a coordinator starting at 0 would serve it". That is backwards:
    /// the counter starts at 0, so `Int.min` makes the launch value look
    /// unserved and the very first update takes the caret for a filter nobody
    /// asked for. Starting from whatever the counter reads when this view is
    /// made is right in both directions — it swallows nothing, because a
    /// coordinator built after a request has already been counted starts from
    /// that count and still sees the next one.
    var served: Int
    var onEditingEnded: () -> Void
    private weak var watching: NSSearchField?

    init(served: Int, onEditingEnded: @escaping () -> Void) {
      self.served = served
      self.onEditingEnded = onEditingEnded
    }

    /// The filter field, found once and remembered.
    ///
    /// This view is built with a closure, so SwiftUI can never decide two of
    /// them are equal and skip the update — `updateNSView` runs on every
    /// re-evaluation of the browser, which is once per keystroke while a
    /// filter is being typed. Walking the window each time to find a field
    /// that has not moved is the wrong shape for that.
    ///
    /// ``watching`` is the cache, and it is a *weak* reference, so it going
    /// nil is exactly the case that needs a fresh walk: macOS built a new
    /// field.
    func field(in window: NSWindow) -> NSSearchField? {
      if let watching, watching.window === window { return watching }
      guard let found = FilterFocus.filterField(
        in: window.contentView?.superview ?? window.contentView) else { return nil }
      watch(found)
      return found
    }

    /// Once per field, and again if macOS builds a new one.
    ///
    /// The target/action form rather than the closure one: the closure
    /// overload is `@Sendable`, and a coordinator is main-actor state, so
    /// capturing it there is a data race the compiler is right to refuse.
    private func watch(_ field: NSSearchField) {
      guard field !== watching else { return }
      if let watching {
        NotificationCenter.default.removeObserver(
          self, name: NSControl.textDidEndEditingNotification, object: watching)
      }
      watching = field
      NotificationCenter.default.addObserver(
        self, selector: #selector(editingEnded),
        name: NSControl.textDidEndEditingNotification, object: field)
    }

    @objc private func editingEnded() { onEditingEnded() }
  }

  private static func filterField(in view: NSView?) -> NSSearchField? {
    guard let view else { return nil }
    if let field = view as? NSSearchField { return field }
    for child in view.subviews {
      if let found = filterField(in: child) { return found }
    }
    return nil
  }
}

#if DEBUG
/// A real `NSSearchField`, because that is the class this view goes looking
/// for.
///
/// The app's field is `.searchable`'s, and `.searchable` builds one only when
/// there is a toolbar to put it in. This is the same class in the same window,
/// so the walk and the `makeFirstResponder` are the ones the app does.
private struct FilterFieldPreview: NSViewRepresentable {
  func makeNSView(context: Context) -> NSSearchField {
    let field = NSSearchField()
    field.placeholderString = "Filter"
    return field
  }

  func updateNSView(_ field: NSSearchField, context: Context) {}
}

/// Both halves at once: the request that takes the caret, and the notification
/// that says the field has been left.
///
/// Find puts the caret in the search field. Clicking the other field takes it
/// out again, which is what ends the editing — against AppKit's own controls it
/// needs no mouse-down monitor to notice.
private struct FilterFocusPreview: View {
  @State private var request = 0
  @State private var elsewhere = ""
  @State private var endings = 0

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.m) {
      HStack(spacing: Theme.Space.s) {
        FilterFieldPreview().frame(height: Theme.glyphTarget)
        Button("Find") { request += 1 }
          .keyboardShortcut("f")
      }
      TextField("Somewhere else for the caret", text: $elsewhere)
      Text(note).font(.caption).foregroundStyle(Theme.muted)
    }
    .padding(Theme.Space.xl)
    .background(FilterFocus(request: request) { endings += 1 })
  }

  private var note: String {
    switch endings {
    case 0: "The field has not been left yet."
    case 1: "Left once. In the app that is where an empty field folds back to the magnifier."
    default: "Left \(endings) times. In the app that is where an empty field folds back to the magnifier."
    }
  }
}

#Preview("Command-F") {
  FilterFocusPreview()
    .frame(width: 480)
}

#Preview("As narrow as a toolbar gets") {
  // The field takes what is left after the button, so the two share a row
  // rather than the field pushing the button off the end.
  FilterFocusPreview()
    .frame(width: 300)
}
#endif
