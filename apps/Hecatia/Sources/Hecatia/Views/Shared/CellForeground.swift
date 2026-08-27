import SwiftUI

/// Foreground for a table cell that has to survive being selected.
///
/// SwiftUI inverts a selected row's *unstyled* content and leaves explicitly
/// coloured content exactly as it is, so an accent-blue folder glyph stayed
/// accent blue on the emphasized accent-blue fill — measured at 1.18:1, which
/// is invisible. This keeps the colour where it carries meaning and steps back
/// to the selection's own foreground where the selection has taken over.
private struct SelectionAwareForeground: ViewModifier {
  @Environment(\.backgroundProminence) private var prominence
  let unselected: Color

  func body(content: Content) -> some View {
    content.foregroundStyle(
      prominence == .increased ? AnyShapeStyle(.primary) : AnyShapeStyle(unselected))
  }
}

extension View {
  func cellForeground(_ unselected: Color) -> some View {
    modifier(SelectionAwareForeground(unselected: unselected))
  }
}

#if DEBUG
/// A file table row, carrying both of the colours this modifier governs: the
/// folder glyph's accent and the device column's secondary label.
private struct CellForegroundPreview: View {
  var body: some View {
    HStack(spacing: Theme.Space.s) {
      Image(systemName: "folder")
        .cellForeground(Theme.accent)
        .frame(width: 16)
      Text("journal")
      Spacer(minLength: Theme.Space.m)
      Text("nas@x.example")
        .font(.caption)
        .cellForeground(Theme.muted)
    }
    .padding(.horizontal, Theme.Space.s)
    .padding(.vertical, Theme.Space.snug)
  }
}

#Preview("An ordinary row") {
  CellForegroundPreview()
    .frame(width: 480)
    .background(Color(nsColor: .textBackgroundColor))
}

#Preview("On the selected row") {
  // `backgroundProminence` is set by the table on the row it has selected, so
  // a preview of one cell has to set it itself. Both colours step back here:
  // accent blue on the emphasized accent fill measures 1.18:1.
  CellForegroundPreview()
    .frame(width: 480)
    .background(Color(nsColor: .selectedContentBackgroundColor))
    .environment(\.backgroundProminence, .increased)
}
#endif
