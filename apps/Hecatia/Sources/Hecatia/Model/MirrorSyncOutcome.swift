import Foundation

/// What one `mirror sync` run actually did to each mirror.
///
/// `synch mirror sync` iterates the mirrors and propagates the first error, so
/// a failure part-way through leaves the mirrors after it untouched and says
/// nothing about them — while the daemon's own standing loop, which is
/// per-mirror tolerant, keeps them up to date. The client cannot make the
/// command finish, but the daemon does emit one line per mirror it completed,
/// and the mirror list is ordered, so which ones were never reached is exactly
/// recoverable.
struct MirrorSyncOutcome: Sendable, Equatable {
  var succeeded: [String] = []
  var failed: String?
  var notAttempted: [String] = []

  var isClean: Bool { failed == nil && notAttempted.isEmpty }

  /// Reads the run against the mirror list the daemon iterates, which is
  /// ordered by local path (`views.rs`, `ORDER BY local_path`).
  static func read(
    lines: [String],
    progress: [String],
    mirrors: [MirrorEntry],
    failed didFail: Bool
  ) -> MirrorSyncOutcome {
    let ordered = mirrors.map(\.localPath).sorted()
    // A completed mirror writes a line beginning with its own path.
    let done = ordered.filter { path in
      lines.contains { $0.hasPrefix(path + "  ") }
    }
    guard didFail else {
      return MirrorSyncOutcome(succeeded: done, failed: nil, notAttempted: [])
    }
    // The one it was working on announced itself on the progress channel
    // ("<path> …") before the pass that then threw.
    let announced = ordered.filter { path in
      progress.contains { $0.hasPrefix(path + " ") }
    }
    let culprit = announced.last(where: { !done.contains($0) })
      ?? ordered.first(where: { !done.contains($0) })
    let reached = Set(done + [culprit].compactMap { $0 })
    return MirrorSyncOutcome(
      succeeded: done,
      failed: culprit,
      notAttempted: ordered.filter { !reached.contains($0) })
  }

  var summary: String {
    if isClean {
      return succeeded.count == 1 ? "1 mirror updated" : "\(succeeded.count) mirrors updated"
    }
    var parts: [String] = []
    if !succeeded.isEmpty { parts.append("\(succeeded.count) updated") }
    if failed != nil { parts.append("1 failed") }
    if !notAttempted.isEmpty { parts.append("\(notAttempted.count) not attempted") }
    return parts.joined(separator: " · ")
  }
}
