import Foundation

/// A folder this node indexes, as `space ls` reports it.
struct Space: Identifiable, Hashable, Sendable {
  let id: String
  /// The absolute local directory, or nil for a space with no checkout.
  ///
  /// Optional since the daemon grew detached spaces: a dedicated replica holds
  /// a space's bytes as objects with no directory to put them in, and reports
  /// `—` in this column. It used to be `String`, so those rows failed to parse
  /// and the machine whose whole job is holding the cluster's bytes showed no
  /// folders at all.
  let localPath: String?
  /// The third column of `space ls`, verbatim: `—`, `replicate tree`, or
  /// `replicate tree · grace 7d · 4096 B held · 2 wanted`.
  ///
  /// Kept as the daemon's own text rather than re-parsed into fields. The
  /// numbers in it are a *summary*; the report that can actually be acted on
  /// comes from `space ls <id>` and lands in ``ReplicaStatus``. Re-deriving
  /// them from here would be two sources for one fact.
  let replicationSummary: String?
  /// Parsed out of the summary, because the UI has to branch on it: whether to
  /// offer "Replicate Now", whether Stop Sharing needs to mention released
  /// bytes, whether to fetch a detail report at all.
  let replicate: ReplicaPolicy?

  init(
    id: String, localPath: String?, replicationSummary: String? = nil,
    replicate: ReplicaPolicy? = nil
  ) {
    self.id = id
    self.localPath = localPath
    self.replicationSummary = replicationSummary
    self.replicate = replicate
  }

  var isReplicating: Bool { replicate != nil }
  /// A replica with nowhere to put files — `space add <id> --detached
  /// --replicate`. It holds objects and indexes nothing.
  var isDetached: Bool { localPath == nil }

  /// What to show where a path would go.
  var pathLabel: String { localPath ?? "No local copy — holds content only" }
}
