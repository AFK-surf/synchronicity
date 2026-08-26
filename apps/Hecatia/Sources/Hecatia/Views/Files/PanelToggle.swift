import SwiftUI

struct PanelToggle: View {
  let model: FilesModel

  var body: some View {
    Button { model.togglePanel() } label: {
      // The right-hand panel, which is what this opens. `sidebar.trailing`
      // is the leading-sidebar glyph mirrored, and reads as the wrong panel.
      Label("Versions", systemImage: "sidebar.right")
    }
    .help(model.inspectorVisible ? "Hide the versions panel" : "Show the versions panel")
    .accessibilityLabel("Toggle the versions panel")
  }
}

#if DEBUG
#Preview("Panel hidden") {
  NavigationStack {
    Color.clear.toolbar {
      ToolbarItem {
        PanelToggle(model: FilesModel.preview(rows: SampleData.rows, space: "notes"))
      }
    }
  }
  .frame(width: 420, height: 140)
}

#Preview("Panel showing") {
  // The glyph is the same either way — the help text is the only thing that
  // changes, so the difference between the two is a hover apart.
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes")
  model.setPanel(true)
  return NavigationStack {
    Color.clear.toolbar { ToolbarItem { PanelToggle(model: model) } }
  }
  .frame(width: 420, height: 140)
}
#endif
