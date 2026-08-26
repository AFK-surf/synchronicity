import SwiftUI

/// A banner for a condition the user has to be told about wherever they are.
struct AlarmBanner: View {
  let text: String
  var tint: Color = Theme.warning
  var actionTitle: String?
  var action: (() -> Void)?

  var body: some View {
    HStack(alignment: .firstTextBaseline, spacing: Theme.Space.m) {
      Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(tint)
      Text(text).font(.callout).fixedSize(horizontal: false, vertical: true)
      Spacer(minLength: Theme.Space.s)
      if let actionTitle, let action {
        // The action is the accent, never the banner's tint: the tint says how
        // bad this is, and a second colour saying "click me" is the thing the
        // design rules forbid.
        Button(actionTitle, action: action).buttonStyle(.borderless)
      }
    }
    .padding(.horizontal, Theme.Space.l)
    .padding(.vertical, Theme.Space.m)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(tint.opacity(0.12))
    .overlay(alignment: .bottom) { Divider() }
    .accessibilityElement(children: .combine)
  }
}

#if DEBUG
#Preview("Chrome") {
  AlarmBanner(
    text: "A peer advertises a newer published position for this Mac than it holds.",
    tint: Theme.danger, actionTitle: "Resume…", action: {})
    .padding(Theme.Space.xl)
    .frame(width: 520)
}
#endif
