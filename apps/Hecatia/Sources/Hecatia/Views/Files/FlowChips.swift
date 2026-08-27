import SwiftUI

/// Device names, wrapped.
struct FlowChips: View {
  /// The raw values, which are what a command would name.
  let items: [String]
  /// How to print one for a person. A device key is an identifier, not a name.
  var label: (String) -> String = { $0 }

  var body: some View {
    ViewThatFits(in: .horizontal) {
      HStack(spacing: Theme.Space.xs) { chips }
      VStack(alignment: .leading, spacing: Theme.Space.xs) { chips }
    }
  }

  @ViewBuilder private var chips: some View {
    ForEach(items, id: \.self) { item in
      Text(label(item))
        .font(.caption2)
        .lineLimit(1).truncationMode(.middle)
        .padding(.horizontal, Theme.Space.snug).padding(.vertical, Theme.Space.tiny)
        .background(Theme.accentSoft, in: .capsule)
        .help(item)
    }
  }
}

#if DEBUG
#Preview("Agreement card") {
  // The card shown when nothing is wrong — where a user learns that a file is
  // several devices' assertions, before divergence can hurt them.
  VStack(alignment: .leading, spacing: Theme.Space.m) {
    FlowChips(items: SampleData.unanimous.versions[0].attestors)
  }
  .padding(Theme.Space.xl)
  .frame(width: 340)
}
#endif
