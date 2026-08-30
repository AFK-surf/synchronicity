import SwiftUI

/// A table in a box, with a row of actions along its bottom edge.
///
/// The shape Finder's sharing list and System Settings' user list both use:
/// the table owns a rectangle, and ＋ and － live on its edge rather than in a
/// header at the top of the page, a table's height away from the rows they add
/// to and remove. Named actions — "Adopt From the Cluster…" — go on the same
/// bar, at the trailing end.
///
/// The box is this view's, not the table's: a `Table` draws no border of its
/// own, and the bar has to be inside the same rounded rectangle or it reads as
/// a second, unrelated control.
struct BorderedTable<Content: View, Actions: View>: View {
  @ViewBuilder var content: Content
  @ViewBuilder var actions: Actions

  var body: some View {
    VStack(spacing: 0) {
      content
      Divider()
      HStack(spacing: Theme.Space.xs) {
        actions
      }
      // Small controls, the size AppKit puts on a bar this height.
      .controlSize(.small)
      .padding(.horizontal, Theme.Space.xs)
      .padding(.vertical, Theme.Space.tiny)
      .frame(maxWidth: .infinity, alignment: .leading)
      // Chrome, not another row: a neutral system surface, so the bar reads as
      // the table's edge. Both appearances resolve because the colour is
      // AppKit's own rather than a literal.
      .background(Color(nsColor: .windowBackgroundColor))
    }
    .clipShape(RoundedRectangle(cornerRadius: Theme.Radius.s))
    .overlay {
      RoundedRectangle(cornerRadius: Theme.Radius.s).strokeBorder(Theme.line)
    }
  }
}

/// One glyph on the action bar, carrying the name the glyph does not say.
///
/// ＋ and － are shapes. `name` is what they do in words, and it is both the
/// tooltip and the spoken label — a button whose only content is an SF Symbol
/// is announced as nothing useful, and this is the one place in the design
/// where that is the default rather than the exception.
struct TableActionButton: View {
  let symbol: String
  let name: String
  let action: () -> Void

  var body: some View {
    Button(action: action) {
      Image(systemName: symbol).glyphButton()
    }
    .buttonStyle(.borderless)
    .help(name)
    .accessibilityLabel(name)
  }
}

#if DEBUG
private struct PreviewFolder: Identifiable {
  var id: String { name }
  let name: String
  let path: String
}

private let previewFolders = [
  PreviewFolder(name: "notes", path: "~/Documents/notes"),
  PreviewFolder(name: "archive", path: "/Volumes/Store/archive"),
  PreviewFolder(name: "photos", path: "~/Pictures/shared"),
]

#Preview("A table and what can be done to it") {
  BorderedTable {
    Table(previewFolders) {
      TableColumn("Name", value: \.name)
      TableColumn("Path", value: \.path)
    }
    .frame(height: 180)
  } actions: {
      TableActionButton(symbol: "plus", name: "Share another space") {}
      TableActionButton(symbol: "minus", name: "Stop sharing the selected space") {}
    Spacer()
    Button("Adopt From the Cluster…") {}
  }
  .padding(Theme.Space.xl)
  .frame(width: 720)
}

#Preview("Nothing selected") {
  // － is disabled rather than absent: a bar whose buttons come and go moves
  // the ones that stay.
  BorderedTable {
    Table(previewFolders) {
      TableColumn("Name", value: \.name)
      TableColumn("Path", value: \.path)
    }
    .frame(height: 180)
  } actions: {
      TableActionButton(symbol: "plus", name: "Share another space") {}
      TableActionButton(symbol: "minus", name: "Stop sharing the selected space") {}
      .disabled(true)
  }
  .padding(Theme.Space.xl)
  .frame(width: 720)
}

#Preview("An empty table") {
  BorderedTable {
    Table(Array<PreviewFolder>()) {
      TableColumn("Name", value: \.name)
      TableColumn("Path", value: \.path)
    }
    .frame(height: 120)
    .overlay {
      Text("No spaces shared yet.").font(.callout).foregroundStyle(Theme.muted)
    }
  } actions: {
      TableActionButton(symbol: "plus", name: "Share another space") {}
      TableActionButton(symbol: "minus", name: "Stop sharing the selected space") {}
      .disabled(true)
  }
  .padding(Theme.Space.xl)
  .frame(width: 720)
}
#endif
