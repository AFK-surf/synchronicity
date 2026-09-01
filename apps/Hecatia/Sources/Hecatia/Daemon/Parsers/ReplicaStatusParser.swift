import Foundation

/// The reader for `replica ls <id>` — one space's replication report.
///
/// Anchored on the label vocabulary, which is closed and written out in
/// `render::replica_status`: `held`, `releasing`, `wanted`, `unreachable`,
/// `held back`, `budget`, `view`, `from`, `claim`. Deliberately **not**
/// anchored on the `{:>9}`/`{:>14}` column widths — a replica with a
/// nine-figure object count overruns them, and those are the reports someone is
/// reading because something is wrong.
///
/// Total, like every parser here: a line it cannot place comes back in
/// `unrecognized` and is shown as raw text rather than dropped.
extension Listings {

  static func replicaStatus(_ lines: [String]) -> ReplicaStatus {
    var out = ReplicaStatus()
    var sawHeader = false

    for line in lines where !line.trimmingCharacters(in: .whitespaces).isEmpty {
      // The header is the only unindented line: "{id}   indexed {path}   {…}".
      guard line.hasPrefix(" ") else {
        sawHeader = true
        if line.contains("not replicated") { out.isReplicating = false }
        continue
      }
      let body = line.trimmingCharacters(in: .whitespaces)

      if let rest = Anchor.after("held back", in: body), body.hasPrefix("held back") {
        out.heldBack = Self.count(rest) ?? 0
      } else if body.hasPrefix("held") {
        let (objects, bytes) = Self.pair(Anchor.after("held", in: body))
        out.held = objects ?? 0
        out.heldBytes = bytes ?? 0
      } else if body.hasPrefix("releasing") {
        let (objects, bytes) = Self.pair(Anchor.after("releasing", in: body))
        out.releasing = objects ?? 0
        out.releasingBytes = bytes ?? 0
        out.soonestRelease = Self.parenthetical(body, after: "soonest leaves in ")
      } else if body.hasPrefix("wanted") {
        let (objects, bytes) = Self.pair(Anchor.after("wanted", in: body))
        out.wanted = objects ?? 0
        out.wantedBytes = bytes ?? 0
        out.oldestWant = Self.parenthetical(body, after: "oldest ")
      } else if body.hasPrefix("unreachable") {
        let (objects, bytes) = Self.pair(Anchor.after("unreachable", in: body))
        out.unreachable = objects ?? 0
        out.unreachableBytes = bytes ?? 0
      } else if body.hasPrefix("budget") {
        // `budget {n} B, {m} B of it used` — two byte counts on one line, and
        // the ceiling is the first. Taking the first standalone `B` token got
        // `m`, because the first is written `B,` with the comma attached; the
        // line then reported the budget as however much was used, which reads
        // as permanently full. The number immediately after the label is the
        // one that is always the ceiling, in both the plain and the "reached"
        // wording.
        let rest = Anchor.after("budget", in: body) ?? ""
        out.budgetBytes = Anchor.tokens(rest).first.flatMap { Int64($0) }
        out.budgetReached = rest.contains("reached")
      } else if body.hasPrefix("view") {
        let rest = Anchor.after("view", in: body) ?? ""
        // Incomplete synchronization is reported as `incomplete: {why}`.
        out.incompleteReason = Anchor.after("incomplete: ", in: rest)
      } else if body.hasPrefix("from ") {
        // `from {origin:<32} {bytes:>14} B`. Split on tokens rather than on
        // the padding: an origin is a single token — a name or a `key:` form —
        // and a 52-character key overruns `{:<32}` and leaves one space.
        let fields = Anchor.tokens(String(body.dropFirst(5)))
        if let origin = fields.first, let bytes = Self.bytes(body) {
          out.byOrigin.append(.init(origin: String(origin), bytes: bytes))
        } else {
          out.unrecognized.append(line)
        }
      } else if body.hasPrefix("claim") {
        // Kept whole. A claim is another node's word about its own disk and
        // this one cannot check it, so it is quoted, never totalled.
        out.claims.append(Anchor.after("claim", in: body) ?? body)
      } else {
        out.unrecognized.append(line)
      }
    }

    // A report with no header is not a report. Better an empty status the UI
    // can say "no answer" about than a zeroed one it renders as "nothing held".
    guard sawHeader else {
      var empty = ReplicaStatus()
      empty.isReplicating = false
      empty.unrecognized = lines
      return empty
    }
    return out
  }

  /// `{objects} objects  {bytes} B` — the shape of the four counted lines.
  private static func pair(_ rest: String?) -> (Int?, Int64?) {
    guard let rest else { return (nil, nil) }
    return (count(rest), bytes(rest))
  }

  /// The integer before `objects`.
  private static func count(_ text: String) -> Int? {
    Anchor.trailingInt(in: text, unit: "objects")
  }

  /// The integer before a standalone `B`.
  ///
  /// Scanned token by token rather than with `trailingInt(unit: "B")`, because
  /// `B` occurs inside `budget` and inside origin names, and the first match
  /// wins there for the wrong reason.
  private static func bytes(_ text: String) -> Int64? {
    let tokens = Anchor.tokens(text)
    for (index, token) in tokens.enumerated() where token == "B" && index > 0 {
      if let value = Int64(tokens[index - 1]) { return value }
    }
    return nil
  }

  /// The daemon's own phrasing out of a trailing `(… {marker}{value})`, kept
  /// verbatim: these are prose durations (`3d`, `just now`) and re-parsing them
  /// into a `Date` would be a guess. See DAEMON-ISSUES E3.
  private static func parenthetical(_ line: String, after marker: String) -> String? {
    guard let rest = Anchor.after(marker, in: line) else { return nil }
    return rest.split(separator: ")").first.map {
      $0.trimmingCharacters(in: .whitespaces)
    }
  }
}
