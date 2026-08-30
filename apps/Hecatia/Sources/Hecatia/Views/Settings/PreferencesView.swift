import SwiftUI

/// The settings window: nine pages behind one source list.
///
/// The version this replaces was a two-tab `TabView`, and the eight operator
/// panes lived in a `Window` of their own that nothing on the path of someone
/// moving a file ever opened. A version before *that* put keys, zones, trust
/// and mirrors into a six-tab Settings scene and ran real operations there — "a
/// preferences window doing surgery" — and was rolled back into the Node
/// window. Both objections are answered rather than forgotten: the list has no
/// six-item ceiling to hit, and every dangerous operation keeps the gate it
/// had, up to and including the typed confirmation and ``AdvancedToggle``.
struct PreferencesView: View {
  @Environment(NodeStore.self) private var node
  /// Handed in rather than owned. The first-run screen, the alarm banner and
  /// the browser sidebar's connection footer all select a page from outside
  /// this scene — see ``SettingsRoute``.
  @Bindable var route: SettingsRoute
  @State private var confirmation: ConfirmationRequest?

  var body: some View {
    NavigationSplitView {
      List(selection: selection) {
        ForEach(SettingsPane.Group.allCases) { group in
          Section(group.rawValue) {
            ForEach(group.panes) { pane in
              Label(pane.rawValue, systemImage: pane.icon).tag(pane)
            }
          }
        }
      }
      .navigationSplitViewColumnWidth(min: 200, ideal: 220, max: 260)
      // Not collapsible. Collapsing is driven by the toolbar's sidebar button,
      // and a settings window that has lost its navigation has nothing left to
      // bring it back with — the reason the Node window's split refused to
      // collapse too.
      .toolbar(removing: .sidebarToggle)
    } detail: {
      VStack(spacing: 0) {
        // Window-level, above every page. A daemon in trouble has nothing to
        // do with which page is being read, and these used to be on Overview —
        // the one page this window no longer has.
        ForEach(node.alarms) { alarm in
          AlarmBanner(text: alarm.text, tint: alarm.isRecovery ? Theme.danger : Theme.warning)
        }
        page
      }
      .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
    // Fixed, and not the selected page's name: the sidebar already says which
    // page this is, and a title that changes under a window with no other
    // chrome reads as a different window each time.
    .navigationTitle("Synchronicity Settings")
    // For a page that sends the reader to another page.
    .environment(\.settingsRoute, route)
    .confirmedAction($confirmation)
    // Every button on every page writes `node.alert` on failure, and this is
    // now the only window most of them can be pressed from.
    .modifier(DaemonAlert())
    // Polled only for the page being read: the daemon takes a global mutex for
    // every store read, and `peers` does one request per peer. A window that
    // refreshed all nine pages would hold the daemon down for as long as it
    // was open.
    .task(id: route.pane) {
      await node.refresh(route.pane.topics)
    }
    // 220 of sidebar and the 760 the Node window took as its minimum content
    // width — the width every page has already been designed against.
    //
    // The height is the number still to calibrate, and this comment is where
    // to start: a `Settings` scene sizes its window to the content and then
    // adds chrome of its own, measured at `safeAreaInsets.top = 88` (a
    // titlebar, and three toolbar items SwiftUI installs although nothing here
    // declares a toolbar). So a page is drawn into 660 less that, and if one
    // scrolls when it should not, this is the number to move.
    .frame(width: 980, height: 660)
  }

  /// The sidebar's selection, which is never empty.
  ///
  /// `List` only offers an optional selection binding, and a settings window
  /// with nothing selected is a blank right-hand side with no way back — so
  /// clearing the selection keeps the page instead.
  private var selection: Binding<SettingsPane?> {
    Binding(get: { route.pane }, set: { if let pane = $0 { route.pane = pane } })
  }

  @ViewBuilder private var page: some View {
    // Only the node's own pages need a daemon. General is where someone comes
    // *because* nothing is connected — the data folder and Reconnect are both
    // there — About names the app, and Activity is a transcript this app wrote
    // itself.
    if route.pane.group == .node, !node.connection.isConnected {
      notConnected
    } else {
      switch route.pane {
      case .general: GeneralSettingsTab()
      case .about: AboutTab()
      case .keys: KeysPane(confirmation: $confirmation)
      case .members: MembersPane(confirmation: $confirmation)
      case .network: NetworkPane()
      case .spaces: SpacesPane(confirmation: $confirmation)
      case .pins: PinsPane(confirmation: $confirmation)
      case .remote: RemoteAccessPane(confirmation: $confirmation)
      case .diagnostics: DiagnosticsPane(confirmation: $confirmation)
      }
    }
  }

  private var notConnected: some View {
    ContentUnavailableView {
      Label("Not connected", systemImage: "bolt.horizontal.circle")
    } description: {
      // What went wrong, in the daemon's own words where there are any.
      Text(reason)
    } actions: {
      Button("Try Now") { node.connect() }
      Button("Data Folder…") { route.pane = .general }
    }
  }

  /// Why there is no connection.
  private var reason: String {
    switch node.connection {
    case .failed(let failure):
      return failure.recoverySuggestion.map { "\(failure.detail) \($0)" } ?? failure.detail
    case .needsUpdate(let failure):
      return failure.detail
    case .connecting:
      return "Connecting to the daemon…"
    case .idle, .connected:
      return "This app is not talking to a daemon. Nothing is being shared, mirrored or synchronised until it is."
    }
  }
}

#if DEBUG
#Preview("Settings") {
  PreferencesView(route: SettingsRoute(pane: .general))
    .environment(NodeStore.preview())
}

#Preview("A node page") {
  // Spaces rather than General: the node group is where the sidebar spends
  // most of its rows, and where the alarm banner and the topic refresh apply.
  PreferencesView(route: SettingsRoute(pane: .spaces))
    .environment(NodeStore.preview())
}

#Preview("Something is wrong") {
  // The banner is above the page, not on it, so every page shows it. Spaces
  // is chosen here only to prove that.
  PreferencesView(route: SettingsRoute(pane: .spaces))
    .environment(NodeStore.preview(status: SampleData.alarmedStatus))
}

#Preview("Nothing connected") {
  // General still answers — it is the page that fixes this — and a node page
  // says why rather than showing an empty table.
  PreferencesView(route: SettingsRoute(pane: .network))
    .environment(NodeStore.preview(
      connection: .failed(DaemonFailure(
        code: .unavailable, detail: "Nothing is listening on control.sock.")),
      status: nil))
}

#Preview("Diagnostics") {
  // The page that carries the way into the Activity window, which is not a page
  // of this window and deliberately so.
  PreferencesView(route: SettingsRoute(pane: .diagnostics))
    .environment(NodeStore.preview())
}
#endif
