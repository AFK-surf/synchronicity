import SwiftUI

/// Answers the space bar with Quick Look, the way a Mac does.
///
/// Three approaches do not work here. `onKeyPress(.space)` never fires: the
/// table is an `NSTableView` and it takes the key first, for type-select. A
/// `Button` with `.keyboardShortcut(.space)` takes it far too early instead —
/// menu key equivalents are matched before the responder chain, so the search
/// field could no longer type a space. And a global monitor cannot tell which
/// window the key belongs to.
///
/// A *local* monitor can do all three: it runs before the responder chain, it
/// can see whether this window is the key one, and it can decline while a text
/// view is first responder — which is how Finder keeps Quick Look on Space
/// while its own search field still types one.
struct QuickLookKeyMonitor: ViewModifier {
  #if DEBUG
  /// What the monitor last decided, so the space bar can be tested rather than
  /// assumed. Written only here; read only by the snapshot self-test.
  @MainActor static var lastDecision: String = "no key seen"
  #endif

  let model: FilesModel
  /// `.key` exactly when this view's own window is the key window, which is
  /// the question a local monitor has to answer and the reason this no longer
  /// reaches for the `NSWindow` itself.
  @Environment(\.controlActiveState) private var activeState
  @State private var watcher = SpaceKeyWatcher()

  func body(content: Content) -> some View {
    content
      .onAppear {
        watcher.model = model
        watcher.isKeyWindow = activeState == .key
        watcher.start()
      }
      .onChange(of: activeState) { _, state in watcher.isKeyWindow = state == .key }
      .onDisappear { watcher.stop() }
  }

  /// The whole decision, with no AppKit in it, so it can be tested.
  ///
  /// Every clause is here because leaving it out breaks something real: a
  /// modified space belongs to a shortcut, a space typed into a field editor is
  /// a character, a background window must not answer another window's keys,
  /// and a folder has nothing to preview.
  static func takesSpace(
    characters: String?,
    modifiers: NSEvent.ModifierFlags,
    isKeyWindow: Bool,
    isEditingText: Bool,
    fileListHasTheCaret: Bool,
    selectionIsAFile: Bool
  ) -> (yes: Bool, reason: String) {
    guard characters == " " else { return (false, "not the space bar") }
    guard isKeyWindow else { return (false, "not the key window") }
    guard modifiers.intersection(.deviceIndependentFlagsMask)
      .isSubset(of: [.function, .numericPad])
    else { return (false, "a modified space belongs to a shortcut") }
    guard !isEditingText else { return (false, "a text field is taking the space") }
    // A monitor that returns nil eats the key, so anything else with the
    // focus never sees it: under Full Keyboard Access a focused button in this
    // window could not be pressed with Space while a file row was selected,
    // and the sidebar had its Space taken too.
    guard fileListHasTheCaret else { return (false, "something else has the focus") }
    guard selectionIsAFile else { return (false, "no file is selected") }
    return (true, "preview")
  }
}
