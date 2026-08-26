import SwiftUI

/// What this app is, and what this Mac publishes as.
struct AboutTab: View {
  @Environment(NodeStore.self) private var node

  var body: some View {
    VStack(spacing: Theme.Space.m) {
      Image(systemName: "arrow.triangle.2.circlepath")
        .font(.largeTitle).foregroundStyle(Theme.accent)
      Text("Synchronicity").font(.title3.weight(.semibold))
      Text("Control protocol v\(ControlClient.controlVersion)")
        .font(.caption).foregroundStyle(Theme.muted)
      if let origin = node.origin {
        // The raw origin, because this pane is where an operator comes to read
        // it — but a device key is 56 characters in a 480pt window, so it is
        // allowed to wrap rather than to decide the window's width.
        Text(origin)
          .font(Theme.Font.mono(.subheadline))
          .textSelection(.enabled)
          .multilineTextAlignment(.center)
          .lineLimit(3)
          .fixedSize(horizontal: false, vertical: true)
          .padding(.horizontal, Theme.Space.xl)
      }
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }
}

#if DEBUG
#Preview("About") {
  AboutTab()
    .environment(NodeStore.preview())
    .frame(width: 480, height: 300)
}

#Preview("Named by its device key") {
  // The 56-character case the wrap above exists for, at the width the Settings
  // window fixes: the origin gives way, not the window.
  AboutTab()
    .environment(NodeStore.preview(status: NodeStatus(
      naming: .named(
        origin: "key:\(String(repeating: "y", count: 52))",
        signingAs: "a1b2c3d4e5"))))
    .frame(width: 480, height: 300)
}

#Preview("Not named yet") {
  // A node the zone has not named publishes under nothing, so there is no
  // origin to print and this pane is the name and the protocol version alone.
  AboutTab()
    .environment(NodeStore.preview(status: NodeStatus(
      naming: .waitingToBeNamed(
        domain: "cluster.example.com",
        deviceKey: String(repeating: "y", count: 52),
        txtRecord: "_synchronicity.cluster.example.com. IN TXT \"v=sync1 id=<name>\""))))
    .frame(width: 480, height: 300)
}
#endif
