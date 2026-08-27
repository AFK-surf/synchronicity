import SwiftUI

/// Puts the caret back on the file list when the filter goes away.
///
/// `.searchable` removes its field when `isPresented` goes false, and the
/// caret was in that field, so it leaves with it — and from nothing focused
/// the arrow keys, the space bar and Command-Delete all do nothing until
/// something is clicked. ``FilesModel/searchPresented`` bumps
/// `listFocusRequest` whenever a field that was up goes away — Escape, the
/// field's clear button, this app's own Clear — and this puts the caret back
/// where the person was before they started filtering.
///
/// That is all it does now. It used to also watch for a click that landed on
/// the empty area below the last row and gave the caret to nobody, through a
/// local event monitor — the third mechanism tried, after a click recognizer
/// that never fired and a view planted above the background that never
/// received `mouseDown`. All of that was true of the SwiftUI `Table`. Against
/// the `NSTableView` that replaced it the click needs no help at all: with the
/// monitor removed the probe still reports the caret on the table after a
/// click into the empty area, because AppKit's own table does this and always
/// did.
struct FileListCaret: NSViewRepresentable {
  /// Bumped by ``FilesModel/searchPresented`` as the field goes away.
  let request: Int

  func makeNSView(context: Context) -> NSView { NSView() }

  func updateNSView(_ view: NSView, context: Context) {
    // The counter first. Nothing below is worth doing on a redraw that carries
    // no request, and finding the table means walking the window.
    let coordinator = context.coordinator
    guard coordinator.served != request else { return }
    coordinator.served = request
    guard let window = view.window, let table = EntryNSTableView.inWindow(window)
    else { return }
    // Off this pass, and off it for a reason that is not a style preference.
    //
    // `makeFirstResponder` is synchronous: before it returns, the search field
    // has resigned, and `.searchable` answers that by writing the state it
    // tracks its own presentation with. From inside `updateNSView` that is a
    // write during a view update — SwiftUI said so, naming this line, with
    // `_realMakeFirstResponder:` between the two frames:
    //
    //     #0  ZipLocation.set(_:transaction:)
    //     #35 -[NSWindow _realMakeFirstResponder:]
    //     #36 FileListCaret.updateNSView(_:context:)  :54
    //
    // ``FilterFocus`` makes the same call and does not warn, because it moves
    // the caret *to* the field; only leaving one makes SwiftUI write anything.
    // A run loop turn later the update is over and the write is ordinary.
    // ``TitleBar`` defers for the neighbouring reason.
    Task { @MainActor in
      // Read here rather than before the hop. The question is what holds the
      // caret at the moment it would be taken, and a turn has passed: the
      // request is raised as the field goes, and the click that came next may
      // have landed in between. Escape out of the filter and click the folder
      // list, and taking it now would pull the caret straight back out.
      //
      // Nothing focused, or the filter on its way out — the field, or the field
      // editor working on its behalf — are the two states this is for.
      let holder = window.firstResponder
      let free = holder == nil || holder is NSWindow
        || holder is NSSearchField || holder is NSText
      guard free else {
        #if DEBUG
        FocusTrace.claim("FileListCaret", "declined, \(String(describing: holder.map { type(of: $0) })) has it")
        #endif
        return
      }
      #if DEBUG
      FocusTrace.claim("FileListCaret", "request \(request)")
      #endif
      window.makeFirstResponder(table)
    }
  }

  func makeCoordinator() -> Coordinator { Coordinator(served: request) }

  @MainActor
  final class Coordinator: NSObject {
    /// The request this view was built at, which counts as already served —
    /// otherwise the first update would take the caret before anyone asked.
    var served: Int

    init(served: Int) { self.served = served }
  }
}

#if DEBUG
/// The request, with the two things it needs to mean anything: somewhere the
/// caret can already be, and a real ``EntryNSTableView`` for it to land on.
///
/// Click the field, then the button. The caret leaves the field and the file
/// list draws its focus ring — which is the whole of what this view does. It
/// would decline if the caret were on something that is neither a field nor
/// nothing at all, and that case draws no difference at all, so it has no
/// preview of its own.
private struct FileListCaretPreview: View {
  @State private var store: NodeStore
  @State private var model: FilesModel
  @State private var filter = ""
  @State private var request = 0

  init() {
    let store = NodeStore.preview()
    _store = State(initialValue: store)
    _model = State(
      initialValue: FilesModel.preview(rows: SampleData.rows, space: "notes", store: store))
  }

  var body: some View {
    VStack(spacing: 0) {
      HStack(spacing: Theme.Space.s) {
        TextField("Filter", text: $filter)
        // What ``FilesModel/searchPresented`` does as a field that was up goes
        // away — Escape, the clear button, this app's own Clear.
        Button("Take the Filter Away") { request += 1 }
      }
      .padding(Theme.Space.m)
      Divider()
      EntryTable(model: model)
    }
    .background(FileListCaret(request: request))
    .environment(store)
  }
}

#Preview("Caret back on the list") {
  FileListCaretPreview()
    .frame(width: 760, height: 420)
}
#endif
