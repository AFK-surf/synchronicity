import Foundation

/// One peer, from `peers`.
struct PeerInfo: Identifiable, Hashable, Sendable {
  var id: String { key }
  let key: String
  /// Origins this key currently holds, or `(untrusted)`.
  let origins: String
  /// The rest of the row verbatim. It is what gets *displayed*: the daemon
  /// computed it against its own clock and rewording it would only make it
  /// less true.
  let detail: String
  /// The same durations recovered as bounded intervals, which is what lets the
  /// table be ordered by staleness. Display still uses `detail`.
  let lastSeen: Age?
  let lastSync: Age?

  static func == (a: PeerInfo, b: PeerInfo) -> Bool { a.key == b.key && a.detail == b.detail }
  func hash(into hasher: inout Hasher) { hasher.combine(key) }

  var lastSeenSort: TimeInterval { lastSeen?.sortKey ?? .greatestFiniteMagnitude }
  var lastSyncSort: TimeInterval { lastSync?.sortKey ?? .greatestFiniteMagnitude }
  var lastSeenText: String { lastSeen?.text ?? "—" }
  var lastSyncText: String { lastSync?.text ?? "—" }

  /// Not heard from in over an hour. Conservative: a bucket that straddles the
  /// threshold does not trip it.
  var isStale: Bool { lastSeen?.isAtLeast(3600) ?? false }
}
