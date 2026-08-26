import SwiftUI

/// The whole location, clickable, along the bottom of the window.
///
/// Where Finder keeps its path bar, and for the reason Finder keeps it
/// there: the toolbar has the history buttons and the controls in it, and a
/// path put beside them either shares their container or starves them.
struct PathBar: View {
  let model: FilesModel

  var body: some View {
    HStack(spacing: Theme.Space.tiny) {
      ForEach(Array(model.breadcrumbs.enumerated()), id: \.offset) { index, crumb in
        if index > 0 {
          Image(systemName: "chevron.right")
            .imageScale(.small)
            .foregroundStyle(Theme.muted)
            .accessibilityHidden(true)
        }
        Button {
          model.jump(to: crumb.prefix)
        } label: {
          Label(crumb.name, systemImage: index == 0 ? "folder" : "folder.fill")
            .labelStyle(.titleAndIcon)
            .font(.caption)
            .lineLimit(1)
        }
        .buttonStyle(.plain)
        .foregroundStyle(index == model.breadcrumbs.count - 1 ? Color.primary : Theme.muted)
        .help(index == model.breadcrumbs.count - 1 ? "You are here" : "Go to \(crumb.name)")
      }
      Spacer(minLength: 0)
    }
    .padding(.horizontal, Theme.Space.l)
    .padding(.vertical, Theme.Space.snug)
    .overlay(alignment: .top) { Divider() }
    .accessibilityElement(children: .contain)
    .accessibilityLabel("Path: \(model.breadcrumbs.map(\.name).joined(separator: ", "))")
  }
}

#if DEBUG
#Preview("At the root") {
  PathBar(model: FilesModel.preview(rows: SampleData.rows, space: "notes"))
    .frame(width: 850)
}

#Preview("Deep in a folder") {
  PathBar(model: FilesModel.preview(
    rows: SampleData.rows, space: "notes", prefix: "receipts/2026"))
    .frame(width: 850)
}

#Preview("Squeezed") {
  // The narrowest the file list is ever asked to be: ``BrowserSplit`` floors
  // the sidebar and the list together at 560pt, and the sidebar's own minimum
  // is 200 of it.
  PathBar(model: FilesModel.preview(
    rows: SampleData.rows, space: "notes", prefix: "receipts/2026"))
    .frame(width: 360)
}
#endif
