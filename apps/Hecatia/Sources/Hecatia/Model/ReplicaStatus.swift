import Foundation

/// One space's replication report, from `replica ls <id>`.
///
/// The daemon's own presentation rules travel with the data, because getting
/// them wrong is how a replica that is stuck reads as one that is busy
/// (`docs/REPLICATION.md` §8):
///
/// - `unreachable` is **never** folded into the backlog. Those objects have no
///   provider and are probably already gone; the difference between them and a
///   backlog is the whole reason to run a replica. The daemon has already
///   subtracted them from the `wanted` line it prints.
/// - `view: incomplete` is shown *instead of and ahead of* the releasing count,
///   not beside it. Paused releases are the difference between a replica that
///   is behaving and one that is stuck.
/// - `claims` are claims. This node cannot check another node's disk, so they
///   are never rendered as verified coverage.
struct ReplicaStatus: Hashable, Sendable {
  /// Bytes this node holds on one origin's behalf.
  ///
  /// A named struct rather than a tuple: a `[(origin: String, bytes: Int64)]`
  /// is neither `Equatable` nor `Hashable`, so it took a hand-written
  /// conformance for the whole type — twenty lines that had to be revisited
  /// every time a field was added, and would silently stop comparing one if it
  /// was not.
  struct OriginShare: Hashable, Sendable, Identifiable {
    var id: String { origin }
    let origin: String
    let bytes: Int64
  }

  /// Objects held on this node right now.
  var held = 0
  var heldBytes: Int64 = 0
  /// Held, but scheduled to go once the grace period is up.
  var releasing = 0
  var releasingBytes: Int64 = 0
  /// Rendered by the daemon with `unreachable` already subtracted, so this is
  /// the true backlog and needs no arithmetic here.
  var wanted = 0
  var wantedBytes: Int64 = 0
  /// No provider has answered for these. The alarm, not the backlog.
  var unreachable = 0
  var unreachableBytes: Int64 = 0
  /// Too few peers advertise these to let them go.
  var heldBack = 0
  /// A ceiling on bytes held for this space, if one is set.
  var budgetBytes: Int64?
  var budgetReached = false
  /// nil when releases are running; the daemon's reason when they are paused.
  var pausedReason: String?
  /// The daemon's own phrasing, kept verbatim — `(soonest leaves in 3d)`.
  var soonestRelease: String?
  var oldestWant: String?
  /// Who published the bytes this node is holding, biggest first, capped at 8
  /// by the daemon.
  var byOrigin: [OriginShare] = []
  /// What other nodes *say* they hold. Never verified.
  var claims: [String] = []

  var isReplicating = true
  /// Anything the parser could not read, kept so a format change degrades to a
  /// visibly incomplete report rather than a confidently wrong one.
  var unrecognized: [String] = []

  /// The one thing worth interrupting someone over.
  var isAlarming: Bool { unreachable > 0 || pausedReason != nil }
}
