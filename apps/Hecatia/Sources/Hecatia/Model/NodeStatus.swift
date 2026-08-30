import Foundation

/// What `daemon status` says, in the shape the app branches on.
///
/// The daemon has two incompatible renderings here — a named node and one the
/// zone has not named yet — and which one arrives decides which top-level
/// screen the app shows, so the distinction is modelled rather than inferred
/// at each call site.
struct NodeStatus: Sendable, Equatable {
  enum Naming: Sendable, Equatable {
    case named(origin: String, signingAs: String)
    /// The reduced control surface: only `id`, `daemon status`, `domain *`
    /// and `daemon stop` are served, everything else answers `unavailable`.
    case waitingToBeNamed(domain: String, deviceKey: String, txtRecord: String)
  }

  var naming: Naming
  var address: String?
  var spaceNames: [String] = []
  var sourceCount: Int?
  var replicaCount: Int?
  var headSeq: UInt64?
  var peersSeen: Int?
  var trustSummary: String?
  /// Lines the daemon shouted in uppercase: clock and recovery alarms. Kept as
  /// its own words; the app only decides where to put them.
  var alarms: [Alarm] = []
  /// Anything the parser did not recognise, so nothing is silently dropped.
  var unparsedLines: [String] = []

  enum Alarm: Sendable, Equatable, Identifiable {
    case clockUnusable(String)
    case clockSteppedBack(String)
    case inRecovery(String)

    var id: String { text }
    var text: String {
      switch self {
      case .clockUnusable(let t), .clockSteppedBack(let t), .inRecovery(let t): t
      }
    }
    var isRecovery: Bool { if case .inRecovery = self { true } else { false } }
  }

  var isNamed: Bool { if case .named = naming { true } else { false } }
  var origin: String? { if case .named(let o, _) = naming { o } else { nil } }
  var needsRecovery: Bool { alarms.contains { $0.isRecovery } }
}
