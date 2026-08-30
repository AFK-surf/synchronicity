import SwiftUI

/// The four states a browser window can be in before it is a browser.
///
/// Each is a real screen with the one action that helps, rather than an alert
/// over an empty list. The old app had one placeholder for all of them and
/// showed "Connect to your daemon" even when it was connected.
struct FirstRunView: View {
  enum State {
    case connecting
    /// Not connected, and not trying to be — the state after the app's own
    /// Stop Background Service. It used to be drawn as "Connecting to the
    /// daemon…", so the window spun forever beside a sidebar that already said
    /// "Not connected".
    case notConnected
    case cannotConnect(DaemonFailure)
    case versionMismatch(DaemonFailure)
    case waitingToBeNamed
    case noSpaces(() -> Void)
  }

  @Environment(NodeStore.self) private var node
  let state: State

  var body: some View {
    VStack(spacing: Theme.Space.l) {
      switch state {
      case .connecting:
        ProgressView()
        Text("Connecting to the daemon…").foregroundStyle(Theme.muted)

      case .notConnected:
        icon("bolt.horizontal.circle", Theme.warning)
        Text("Not connected").font(.title2.weight(.semibold))
        Text("This app is not talking to a daemon. Nothing is being published, replicated, or synchronised until it is.")
          .foregroundStyle(Theme.muted)
          .multilineTextAlignment(.center)
          .frame(maxWidth: 460)
        VStack(alignment: .leading, spacing: Theme.Space.snug) {
          // `daemon start`, not `daemon run`. `run` holds the terminal for the
          // daemon's whole life, so closing that window stops publishing, replicas
          // and the browser — the app was handing someone a command whose
          // consequence it never mentioned. `start` spawns a detached child,
          // puts the log in the data directory, and returns once the control
          // socket answers, which is also what makes Connect work immediately
          // afterwards rather than after a poll.
          Text("If none is running, start one:").font(.caption).foregroundStyle(Theme.muted)
          CopyableCommand("synch --data-dir \"\(node.dataDirectory.path)\" daemon start")
        }
        Button("Connect") { node.connect() }.keyboardShortcut(.defaultAction)

      case .cannotConnect(let failure):
        icon("bolt.horizontal.circle", Theme.warning)
        Text("No daemon is running").font(.title2.weight(.semibold))
        message(failure)
        VStack(alignment: .leading, spacing: Theme.Space.snug) {
          Text("Start one, then choose Retry:").font(.caption).foregroundStyle(Theme.muted)
          CopyableCommand("synch --data-dir \"\(node.dataDirectory.path)\" daemon start")
        }
        HStack {
          Button("Retry") { node.connect() }.keyboardShortcut(.defaultAction)
          SettingsLink { Text("Change Data Folder…") }
        }

      case .versionMismatch(let failure):
        icon("arrow.up.circle", Theme.warning)
        Text("Update needed").font(.title2.weight(.semibold))
        message(failure)
        Button("Retry") { node.connect() }

      case .waitingToBeNamed:
        icon("person.crop.circle.badge.questionmark", Theme.warning)
        Text("Waiting to be named").font(.title2.weight(.semibold))
        Text("This Mac is pointed at a membership zone that has not named it yet, so it has no identity to publish under. Until it does, only these settings work.")
          .foregroundStyle(Theme.muted)
          .multilineTextAlignment(.center)
          .frame(maxWidth: 460)
        if case .waitingToBeNamed(_, _, let txt) = node.status?.naming {
          VStack(alignment: .leading, spacing: Theme.Space.snug) {
            Text("Publish this record in the zone:").font(.caption).foregroundStyle(Theme.muted)
            CopyableCommand(txt)
          }
        }
        // The third way out, and for a delegate the only one.
        //
        // Both of the others assume the zone will eventually name this Mac.
        // A delegate belongs to the cluster and is named by no zone in it, so
        // for one of those "Check Now" re-asks a question that will keep
        // answering "not this key" forever, and "Use a Different Zone…"
        // re-sends the same name-expecting `domain set`. The daemon's own
        // refusal text names the remedy — `domain set <domain> --delegate` —
        // and the reduced control socket serves `DomainSet` precisely so it
        // can be run from here. Until this button existed it needed a terminal.
        if case .waitingToBeNamed(let domain, _, _) = node.status?.naming {
          Text("If this Mac is a delegate, the zone is not going to name it — it joins under its device key instead.")
            .font(.caption).foregroundStyle(Theme.muted)
            .multilineTextAlignment(.center)
            .frame(maxWidth: 460)
          HStack {
            Button("Check Now") {
              node.enqueue {
                await node.run(Operations.require("domain.refresh"), Cmd.domainRefresh)
                await node.refresh([.status])
              }
            }
            Button("This Mac Is a Delegate") {
              node.enqueue {
                await node.run(
                  Operations.require("domain.set"), Cmd.domainSet(domain, delegate: true),
                  commandLine: "synch domain set \(Shell.quote(domain)) --delegate")
                await node.refresh([.status, .domains])
              }
            }
            .help("Joins the cluster under this Mac's device key, expecting no record of its own. Takes effect at the next daemon start.")
            // This was a disabled button whose tooltip asked the user to do by
            // hand what it names. ``SettingsRoute`` rather than an environment
            // action: this screen is behind the split's `NSHostingController`,
            // and a `Settings` scene has no window id to open anyway.
            Button("Use a Different Zone…") { SettingsRoute.open(.members) }
              .help("Opens Settings ▸ Members, where the membership zone is set")
          }
        }

      case .noSpaces(let add):
        icon("folder.badge.plus", Theme.accent)
        Text("Add a space to get started").font(.title2.weight(.semibold))
        Text("Pick a folder on this Mac to create a space. Its files become available to every device you trust, and theirs become visible here.")
          .foregroundStyle(Theme.muted)
          .multilineTextAlignment(.center)
          .frame(maxWidth: 420)
        Button("Add a Space…") { add() }
          .keyboardShortcut(.defaultAction)
          .buttonStyle(.borderedProminent)
      }
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .padding(Theme.Space.section)
  }

  private func icon(_ name: String, _ tint: Color) -> some View {
    Image(systemName: name).font(.largeTitle).fontWeight(.light).foregroundStyle(tint)
      .accessibilityHidden(true)
  }

  private func message(_ failure: DaemonFailure) -> some View {
    VStack(spacing: Theme.Space.snug) {
      Text(failure.detail)
        .multilineTextAlignment(.center)
        .foregroundStyle(Theme.muted)
      if let suggestion = failure.recoverySuggestion {
        Text(suggestion).font(.caption).foregroundStyle(Theme.muted)
          .multilineTextAlignment(.center)
      }
    }
    .frame(maxWidth: 480)
  }
}

#if DEBUG
#Preview("No daemon") {
  FirstRunView(state: .cannotConnect(DaemonFailure(
    code: .unavailable,
    detail: "No daemon is running for /Users/me/Library/Application Support/synchronicity: nothing is listening on control.sock.")))
  .environment(NodeStore.preview(connection: .idle))
  .frame(width: 720, height: 460)
}

#Preview("Waiting to be named") {
  FirstRunView(state: .waitingToBeNamed)
    .environment(NodeStore.preview(status: NodeStatus(
      naming: .waitingToBeNamed(
        domain: "cluster.example.com",
        deviceKey: String(repeating: "y", count: 52),
        txtRecord: "_synchronicity.cluster.example.com. IN TXT \"v=sync1 id=<name> nk=\(String(repeating: "y", count: 52)) apex=<apex>\""))))
    .frame(width: 720, height: 460)
}

#Preview("No spaces") {
  FirstRunView(state: .noSpaces {})
    .environment(NodeStore.preview(spaces: []))
    .frame(width: 720, height: 460)
}

#Preview("Connecting") {
  FirstRunView(state: .connecting)
    .environment(NodeStore.preview(connection: .connecting, status: nil))
    .frame(width: 720, height: 460)
}

#Preview("Not connected") {
  FirstRunView(state: .notConnected)
    .environment(NodeStore.preview(connection: .idle, status: nil))
    .frame(width: 720, height: 460)
}

#Preview("Daemon too old") {
  FirstRunView(state: .versionMismatch(DaemonFailure(
    code: .versionMismatch,
    detail: "This daemon speaks control protocol 3; this app speaks 4.")))
  .environment(NodeStore.preview(
    connection: .needsUpdate(DaemonFailure(
      code: .versionMismatch,
      detail: "This daemon speaks control protocol 3; this app speaks 4.")),
    status: nil))
  .frame(width: 720, height: 460)
}
#endif
