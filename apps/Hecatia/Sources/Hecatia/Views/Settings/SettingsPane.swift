import SwiftUI

/// One page of the Settings window.
///
/// The Node window's eight panes, less Overview, plus the two tabs Settings
/// already had. A source list rather than a tab bar, for the reason the Node
/// window was built in the first place: a tab bar stops scaling at about six
/// items, and this has eight.
///
/// Activity is deliberately not among them. It is a live log, and a log is read
/// beside the thing it is a log of — which a settings window cannot be. It
/// keeps its own window, and Diagnostics carries the way in.
enum SettingsPane: String, CaseIterable, Identifiable {
  case general = "General"
  case about = "About"
  case keys = "Identity & Keys"
  case members = "Members"
  case network = "Network"
  case spaces = "Spaces"
  /// Mirrors and pins. Not the daemon's "replication", which is a per-space
  /// policy and lives in Spaces — the daemon deliberately put it on the
  /// command that already names spaces. Two different things under one word
  /// was a collision waiting to be read wrong, and the control plane's own
  /// Replication panel contains neither of these.
  case mirrorsAndPins = "Mirrors & Pins"
  case remote = "Remote Access"
  case diagnostics = "Diagnostics"

  var id: String { rawValue }

  /// The two headings the sidebar puts these under.
  ///
  /// Declaration order above is the order within a group, so a group's items
  /// need no ordering of their own.
  enum Group: String, CaseIterable, Identifiable {
    /// The app's own settings. Both answer with no daemon behind them.
    case app = "General"
    /// This node's configuration: every page that reads the daemon.
    case node = "Node"

    var id: String { rawValue }

    var panes: [SettingsPane] { SettingsPane.allCases.filter { $0.group == self } }
  }

  var group: Group {
    switch self {
    case .general, .about: return .app
    case .keys, .members, .network, .spaces, .mirrorsAndPins, .remote, .diagnostics: return .node
    }
  }

  /// Which page the window opens on.
  ///
  /// General, the first item, which is where a macOS settings window starts —
  /// except under `HECATIA_SNAPSHOT_SETTINGS_PANE` in a DEBUG build: the pages
  /// with a `Table` in them cannot be drawn by the offscreen renderer at all,
  /// it substitutes a placeholder, so the only way to look at one is to
  /// photograph the real window with that page already showing.
  static var initial: SettingsPane {
    #if DEBUG
    if let name = ProcessInfo.processInfo.environment["HECATIA_SNAPSHOT_SETTINGS_PANE"],
       let wanted = SettingsPane(rawValue: name) {
      return wanted
    }
    #endif
    return .general
  }

  var icon: String {
    switch self {
    // The two the `TabView` this replaces already used.
    case .general: return "gear"
    case .about: return "info.circle"
    case .keys: return "key"
    case .members: return "person.2"
    case .network: return "network"
    case .spaces: return "square.stack.3d.up"
    case .mirrorsAndPins: return "externaldrive"
    case .remote: return "cloud"
    case .diagnostics: return "stethoscope"
    }
  }

  /// Which slices this page reads, so the window can refresh only what it
  /// shows — and only while it is showing it.
  ///
  /// Empty is a real answer: General edits a path and two defaults, and costs
  /// the daemon nothing.
  var topics: [Topic] {
    switch self {
    case .general: return []
    case .about: return [.status]
    case .keys: return [.keys]
    case .members: return [.members, .domains]
    case .network: return [.peers]
    case .spaces: return [.spaces, .replication]
    case .mirrorsAndPins: return [.mirrors, .pins]
    case .remote: return [.cloud, .s3]
    case .diagnostics: return [.status]
    }
  }
}

#if DEBUG
#Preview("Every page") {
  // The sidebar's contents on their own: nine rows, three groups, and a glyph
  // for each — a symbol name that does not resolve draws nothing at all, and
  // this is where that shows up.
  List {
    ForEach(SettingsPane.Group.allCases) { group in
      Section(group.rawValue) {
        ForEach(group.panes) { pane in
          Label(pane.rawValue, systemImage: pane.icon)
        }
      }
    }
  }
  .frame(width: 220, height: 460)
}
#endif
