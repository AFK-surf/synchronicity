import SwiftUI

/// The connection lives here as a *status*, not a form. Connecting is done on
/// launch; this says what happened and offers the one action that helps.
struct SidebarConnectionFooter: View {
  @Environment(NodeStore.self) private var node

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.snug) {
      Divider()
      switch node.connection {
      case .connected:
        HStack(spacing: Theme.Space.s) {
          Circle().fill(Theme.online).frame(width: 7, height: 7)
          Text(node.isWaitingToBeNamed ? "Waiting to be named" : node.displayName)
            .font(.caption).lineLimit(1).truncationMode(.middle)
            .help(node.origin ?? "Connected to the daemon")
          Spacer(minLength: Theme.Space.s)
          // The seam into the device list. It used to be the widest thing in
          // the toolbar, which pushed four other controls into an overflow
          // chevron at the default window size — and it is a status, so the
          // status area is where it belongs.
          //
          // ``SettingsRoute``, not an environment action: the sidebar is behind
          // the split's `NSHostingController`, and a `Settings` scene has no
          // window id for `openWindow` to name in any case.
          Button(node.peerSummary) { SettingsRoute.open(.network) }
            .buttonStyle(.borderless)
            .font(.caption)
            .lineLimit(1)
            .help(node.nodeSummary)
            .accessibilityLabel("\(node.peerSummary). Open Settings ▸ Network")
        }
      case .connecting:
        HStack(spacing: Theme.Space.s) {
          ProgressView().controlSize(.mini)
          Text("Connecting…").font(.caption).foregroundStyle(Theme.muted)
          Spacer()
        }
      case .idle, .failed, .needsUpdate:
        HStack(spacing: Theme.Space.s) {
          Circle().fill(Theme.warning).frame(width: 7, height: 7)
          Text("Not connected").font(.caption).foregroundStyle(Theme.muted)
          Spacer()
          Button("Retry") { node.connect() }
            .buttonStyle(.borderless).font(.caption)
        }
      }
    }
    .padding(.horizontal, Theme.Space.m)
    .padding(.bottom, Theme.Space.s)
    .accessibilityElement(children: .combine)
  }
}

#if DEBUG
#Preview("Connected") {
  SidebarConnectionFooter()
    .environment(NodeStore.preview())
    .frame(width: 230)
}

#Preview("Connected, at the sidebar's minimum") {
  // 200pt is as narrow as the sidebar goes. The name gives first — it is the
  // one thing here that truncates rather than wraps — and the device count
  // keeps its line.
  SidebarConnectionFooter()
    .environment(NodeStore.preview())
    .frame(width: 200)
}

#Preview("Waiting to be named") {
  // Connected, and still nothing to call this Mac: the zone has not answered.
  SidebarConnectionFooter()
    .environment(NodeStore.preview(status: NodeStatus(
      naming: .waitingToBeNamed(
        domain: "cluster.example.com",
        deviceKey: String(repeating: "y", count: 52),
        txtRecord: "_synchronicity.cluster.example.com. IN TXT \"v=sync1 id=<name>\""))))
    .frame(width: 230)
}

#Preview("Connecting") {
  SidebarConnectionFooter()
    .environment(NodeStore.preview(connection: .connecting, status: nil))
    .frame(width: 230)
}

#Preview("Not connected") {
  SidebarConnectionFooter()
    .environment(NodeStore.preview(connection: .idle, status: nil))
    .frame(width: 230)
}

#Preview("Daemon too old") {
  // Drawn exactly like Not connected, deliberately: a version mismatch has
  // already taken the whole window over — see ``FirstRunView`` — and a footer
  // saying it a second time would be the only place in the sidebar shouting.
  SidebarConnectionFooter()
    .environment(NodeStore.preview(
      connection: .needsUpdate(DaemonFailure(
        code: .versionMismatch,
        detail: "This daemon speaks control protocol 3; this app speaks 4.")),
      status: nil))
    .frame(width: 230)
}
#endif
