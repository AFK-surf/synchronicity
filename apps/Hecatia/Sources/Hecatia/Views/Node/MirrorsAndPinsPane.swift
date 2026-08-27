import SwiftUI

/// Mirrors and pins — `mirror *`, `pin *`.
///
/// Called "Replication" until the daemon gave that word a specific meaning it
/// never had here. A mirror selects one version per path by policy and writes
/// files to disk; a pin holds one named object root; the daemon's replication
/// holds *every* version of every path from every origin, as content, and is a
/// property of a space — it lives in Spaces. Three different things, and the
/// control plane's own Replication panel contains neither of the two here.
///
/// Two sections, stacked. The divider between them used to be draggable, and a
/// window that cannot be resized has nothing to offer a drag: every point one
/// table gains is one the other loses, and each already scrolls inside its own
/// box.
struct MirrorsAndPinsPane: View {
  @Binding var confirmation: ConfirmationRequest?

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: Theme.Space.section) {
        MirrorsSection(confirmation: $confirmation)
        PinsSection(confirmation: $confirmation)
      }
      .padding(Theme.Space.xl)
    }
  }
}

#if DEBUG
#Preview("Mirrors and pins") {
  MirrorsAndPinsPane(confirmation: .constant(nil))
    .environment(NodeStore.preview())
    .frame(width: 760, height: 560)
}

#Preview("Nothing pinned") {
  // `NodeStore.preview` always installs one mirror, so this is the emptiest
  // the page gets from the harness: a table with rows above one without.
  MirrorsAndPinsPane(confirmation: .constant(nil))
    .environment(NodeStore.preview(pins: []))
    .frame(width: 760, height: 560)
}
#endif
