import SwiftUI

/// A label/value row used across the inspector and the Node panes.
struct DetailRow: View {
  let label: String
  let value: String
  var mono = false
  /// Truncated values copy in full, so nothing is hidden — only shortened.
  var copyable: String?

  var body: some View {
    HStack(alignment: .firstTextBaseline, spacing: Theme.Space.m) {
      Text(label)
        .foregroundStyle(Theme.muted)
        .frame(width: 96, alignment: .trailing)
      Text(value)
        .font(mono ? Theme.Font.mono() : nil)
        .textSelection(.enabled)
        .lineLimit(3)
        .truncationMode(.middle)
        .fixedSize(horizontal: false, vertical: true)
      if let copyable {
        CopyGlyphButton(
          value: copyable, help: "Copy the full value", accessibilityName: "Copy \(label)")
      }
      Spacer(minLength: 0)
    }
    .font(.callout)
    .accessibilityElement(children: .combine)
    .accessibilityLabel("\(label): \(value)")
  }
}

#if DEBUG
#Preview("Chrome") {
  VStack(alignment: .leading, spacing: Theme.Space.l) {
    DetailRow(label: "Path", value: "journal/2026/01-15.md", mono: true, copyable: "x")
    DetailRow(label: "Contents", value: "a1b2c3d4e5f60718…", mono: true, copyable: "full")
  }
  .padding(Theme.Space.xl)
  .frame(width: 520)
}
#endif
