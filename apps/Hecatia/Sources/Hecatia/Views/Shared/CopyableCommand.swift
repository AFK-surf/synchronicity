import SwiftUI

/// A shell command with a copy button, for the two places the app genuinely
/// needs the user to run something itself.
struct CopyableCommand: View {
  let text: String
  init(_ text: String) { self.text = text }

  var body: some View {
    HStack(spacing: Theme.Space.s) {
      Text(text)
        .font(Theme.Font.mono(.subheadline))
        .textSelection(.enabled)
        .lineLimit(2)
        .fixedSize(horizontal: false, vertical: true)
      Button {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
      } label: { Image(systemName: "doc.on.doc").imageScale(.small).glyphButton() }
      .buttonStyle(.plain).foregroundStyle(Theme.muted)
      .help("Copy")
      .accessibilityLabel("Copy this command line")
    }
    .padding(Theme.Space.s)
    .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: Theme.Radius.s))
    .overlay { RoundedRectangle(cornerRadius: Theme.Radius.s).stroke(Theme.line) }
    .frame(maxWidth: 520)
  }
}

#if DEBUG
#Preview("Chrome") {
  // 560 is the view's own 520 measure plus the padding around it, which is
  // the widest it is ever drawn however wide the window is.
  CopyableCommand(
    "synch --data-dir \"/Users/me/Library/Application Support/synchronicity\" daemon start")
    .padding(Theme.Space.xl)
    .frame(width: 560)
}

#Preview("A line too long to show") {
  // The zone's TXT record, which is the longest thing this ever carries. Two
  // lines is the limit, so what is past them is truncated on screen — the
  // button still puts the whole record on the pasteboard.
  CopyableCommand(
    "_synchronicity.cluster.example.com. IN TXT \"v=sync1 id=<name> nk=\(String(repeating: "y", count: 52)) apex=<apex>\"")
    .padding(Theme.Space.xl)
    .frame(width: 560)
}

#Preview("In a narrow window") {
  // Well under the 520 measure: the text gives up the width, and the copy
  // button keeps the target it is entitled to rather than being squeezed.
  CopyableCommand(
    "synch --data-dir \"/Users/me/Library/Application Support/synchronicity\" daemon start")
    .padding(Theme.Space.xl)
    .frame(width: 320)
}
#endif
