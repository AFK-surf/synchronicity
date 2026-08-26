import SwiftUI

/// The copy glyph, which five views had each drawn for themselves.
///
/// `.help` is accessibility *help*, not a name, so the spoken label is a
/// separate parameter and a required one: a copy button that announces itself
/// as "button" says nothing about what it would copy.
struct CopyGlyphButton: View {
  /// What lands on the pasteboard — the whole value, even where the text
  /// beside it is truncated to fit.
  let value: String
  let help: String
  let accessibilityName: String

  var body: some View {
    Button(action: copy) {
      Image(systemName: "doc.on.doc").imageScale(.small).glyphButton()
    }
    .buttonStyle(.plain)
    .foregroundStyle(Theme.muted)
    .help(help)
    .accessibilityLabel(accessibilityName)
  }

  private func copy() {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(value, forType: .string)
  }
}

#if DEBUG
#Preview("Chrome") {
  // The text beside it is shortened and the button is not: what lands on the
  // pasteboard is the whole 64-character root.
  HStack(spacing: Theme.Space.s) {
    Text("a1a1a1a1a1a1a1a1…")
      .font(Theme.Font.mono(.subheadline))
      .foregroundStyle(Theme.muted)
    CopyGlyphButton(
      value: String(repeating: "a1", count: 32),
      help: "Copy the full value",
      accessibilityName: "Copy the content root")
  }
  .padding(Theme.Space.xl)
  .frame(width: 520)
}
#endif
