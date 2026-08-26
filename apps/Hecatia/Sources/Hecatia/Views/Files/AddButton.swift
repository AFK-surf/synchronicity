import SwiftUI

struct AddButton: View {
  let model: FilesModel

  var body: some View {
    Button { model.importRequested = true } label: { Label("Add", systemImage: "plus") }
      .disabled(model.selectedSpace == nil)
      .help(model.selectedSpace == nil
        ? "Choose a space in the sidebar first"
        : "Add files to this space")
  }
}

#if DEBUG
#Preview("Add") {
  NavigationStack {
    Color.clear.toolbar {
      ToolbarItem {
        AddButton(model: FilesModel.preview(rows: SampleData.rows, space: "notes"))
      }
    }
  }
  .frame(width: 420, height: 140)
}

#Preview("No folder chosen") {
  // A model with no selection at all, which is what the window has before the
  // sidebar is touched. ``FilesModel/preview(rows:space:prefix:store:)`` always
  // selects one, so this state is only reachable through the real initialiser.
  NavigationStack {
    Color.clear.toolbar {
      ToolbarItem { AddButton(model: FilesModel(store: NodeStore.preview())) }
    }
  }
  .frame(width: 420, height: 140)
}
#endif
