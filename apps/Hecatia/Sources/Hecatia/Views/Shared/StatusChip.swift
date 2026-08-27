import SwiftUI

/// A small labelled status pill.
struct StatusChip: View {
  let text: String
  var tint: Color = Theme.muted
  var systemImage: String?

  /// `.increased` inside the selected row of a table or list.
  ///
  /// A chip on a selected row was drawing its own colours over the selection
  /// fill — an orange capsule and orange text on emphasized blue — because an
  /// explicit `foregroundStyle` is not the hierarchical style SwiftUI inverts.
  @Environment(\.backgroundProminence) private var prominence

  private var isSelected: Bool { prominence == .increased }

  var body: some View {
    HStack(spacing: Theme.Space.xs) {
      if let systemImage {
        Image(systemName: systemImage).imageScale(.small).fontWeight(.semibold)
      }
      Text(text).font(.caption)
    }
    .padding(.horizontal, Theme.Space.s)
    .padding(.vertical, Theme.Space.tiny)
    .background(isSelected ? AnyShapeStyle(.quaternary) : AnyShapeStyle(tint.opacity(0.14)),
                in: .capsule)
    // Never the tint on the tint's own wash: that pairing measures under 2:1.
    .foregroundStyle(isSelected ? AnyShapeStyle(.primary) : AnyShapeStyle(Theme.ink(tint)))
    .accessibilityElement(children: .combine)
    .accessibilityLabel(text)
  }
}

#if DEBUG
#Preview("Chrome") {
  HStack(spacing: Theme.Space.s) {
    StatusChip(text: "static", tint: Theme.accent)
    StatusChip(text: "3", tint: Theme.warning, systemImage: "arrow.triangle.branch")
    StatusChip(text: "attached", tint: Theme.online)
  }
  .padding(Theme.Space.xl)
  .frame(width: 520)
}
#endif
