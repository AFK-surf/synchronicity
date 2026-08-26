import SwiftUI

// MARK: - The controls

struct HistoryButton: View {
  enum Direction { case back, forward }

  let model: FilesModel
  let direction: Direction

  var body: some View {
    Button {
      direction == .back ? model.goBack() : model.goForward()
    } label: {
      // `Label`, not `Image`: the toolbar draws the glyph, and the overflow
      // menu draws the title. An image-only button lands in that menu as a
      // nameless row.
      Label(
        direction == .back ? "Back" : "Forward",
        systemImage: direction == .back ? "chevron.left" : "chevron.right")
    }
    .disabled(direction == .back ? !model.canGoBack : !model.canGoForward)
    .help(direction == .back ? "Back" : "Forward")
  }
}

#if DEBUG
/// The pair, in the `ToolbarItemGroup` they share: they are one control the way
/// Finder's is, and the shared container is drawn by the group, not by them.
private struct HistoryPreview: View {
  var navigate: (FilesModel) -> Void = { _ in }

  var body: some View {
    // A store with no daemon behind it, so the navigations below only move the
    // two history stacks: `reload` returns at its connection guard instead of
    // spending a deadline on a socket that is not there.
    let model = FilesModel.preview(
      rows: SampleData.rows, space: "notes", store: NodeStore.preview(connection: .idle))
    navigate(model)
    return NavigationStack {
      Color.clear.toolbar {
        ToolbarItemGroup(placement: .navigation) {
          HistoryButton(model: model, direction: .back)
          HistoryButton(model: model, direction: .forward)
        }
      }
    }
    .frame(width: 420, height: 120)
  }
}

#Preview("History") {
  HistoryPreview { model in
    model.open(SampleData.folder)  // into notes/journal
    model.goUp()                   // back out to notes
    model.goBack()                 // which leaves one step in each direction
  }
}

#Preview("Nowhere to go") {
  // What a window that has just opened looks like, and the state both buttons
  // spend most of their life in.
  HistoryPreview()
}
#endif
