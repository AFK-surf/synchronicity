import Foundation

/// Readers for the two renderings of a path's version set.
///
/// There are two because they are not equally good, and the better one is not
/// the obvious one. `Resolve` under the `strict` policy refuses a divergent
/// path by returning **every version, losslessly** — full canonical origins,
/// untruncated roots, raw sizes, raw unix-nanosecond mtimes, raw seqs. That is
/// the primary source. `status` renders the same set for a human and truncates
/// a root to 16 characters and an origin to `OriginId::short()`, so it is used
/// only to add the attestor lists that `Resolve` has no field for.
enum Versions {

  /// Kinds the daemon prints, which is a closed set and therefore an anchor.
  ///
  /// Closed, but not frozen: v3 added `socket` to `render::kind_name`, and a
  /// token missing from here does not produce a wrong kind — `humanVersion`
  /// guards on the lookup, so the *whole line* fails and lands in
  /// `unrecognized`. A socket path's attestor lists would have gone missing
  /// from the Versions inspector with nothing said about it.
  ///
  /// The lossless form cannot be helped the same way and deliberately is not:
  /// `identity_text` renders a socket as a bare content root, exactly as it
  /// renders a file, so `kind(ofIdentity:)` below has nothing to read, and
  /// `merge` keeps the lossless kind. Nothing displays `EntryVersion.kind`
  /// today, so that disagreement is invisible rather than wrong — but it is
  /// there, and a Versions inspector that ever shows a kind would show File
  /// for a row the file list calls Socket. What the human form buys here is
  /// the attestor list, not the label.
  static let kinds: [String: RemoteEntry.Kind] = [
    "file": .file, "dir": .directory, "symlink": .symlink, "deleted": .tombstone,
    "socket": .socket,
  ]

  // MARK: - the lossless form, from a strict Resolve's refusal

  /// Reads `EngineError::Divergent`'s body:
  ///
  ///     {space}/{path} has {n} versions and the policy is strict:
  ///       {identity} size {n} mtime {n} seq {n} asserted by {a, b}
  ///
  /// Anchored on the trailing `size`/`mtime`/`seq`/`asserted by` literals with
  /// their numeric values, so an identity containing spaces — a symlink
  /// target — cannot be mistaken for the fields after it.
  static func fromStrictRefusal(_ message: String, space: String, path: String) -> PathVersions? {
    var versions: [EntryVersion] = []
    for raw in message.split(separator: "\n").dropFirst() {
      let line = raw.trimmingCharacters(in: .whitespaces)
      guard let version = losslessVersion(line) else { continue }
      versions.append(version)
    }
    guard !versions.isEmpty else { return nil }
    return PathVersions(space: space, path: path, versions: versions)
  }

  private static func losslessVersion(_ line: String) -> EntryVersion? {
    let parts = Anchor.tokens(line).map(String.init)
    guard
      let by = parts.firstIndex(where: { $0 == "asserted" }),
      by + 1 < parts.count, parts[by + 1] == "by",
      by >= 6,
      parts[by - 2] == "seq", let seq = UInt64(parts[by - 1]),
      parts[by - 4] == "mtime",
      parts[by - 6] == "size", let size = UInt64(parts[by - 5])
    else { return nil }
    let identity = parts[..<(by - 6)].joined(separator: " ")
    let attestors = parts[(by + 2)...]
      .joined(separator: " ")
      .split(separator: ",")
      .map { $0.trimmingCharacters(in: .whitespaces) }
      .filter { !$0.isEmpty }
    return EntryVersion(
      identity: identity,
      kind: kind(ofIdentity: identity),
      size: size,
      seq: seq,
      attestors: attestors
    )
  }

  /// `identity_text()` names the kind in its own shape, which is why a version
  /// line carries no separate kind column in this rendering.
  private static func kind(ofIdentity identity: String) -> RemoteEntry.Kind {
    if identity == "(deleted)" { return .tombstone }
    if identity.hasPrefix("-> ") { return .symlink }
    if identity == "(no content)" { return .unknown }
    return .file
  }

  // MARK: - the human form, from `status`, for its attestor lists

  /// Reads `render::version_set`:
  ///
  ///     {space}/{path}  {n} version(s)[  ⑂{n}]
  ///         {identity:<18} {kind:<8} {size:>12}  seq {seq:<6} {a, b}
  ///
  /// Anchored on the literal `seq` token with a numeric value after it and the
  /// closed kind vocabulary before it — never on the column widths, which are
  /// minimums the daemon overruns on any long identity.
  static func fromStatus(_ lines: [String]) -> ParseResult<PathVersions> {
    var out = ParseResult<PathVersions>()
    var currentPath: (space: String, path: String)?
    var current: [EntryVersion] = []

    func flush() {
      if let key = currentPath, !current.isEmpty {
        out.rows.append(PathVersions(space: key.space, path: key.path, versions: current))
      }
      current = []
    }

    for line in lines where !line.isEmpty {
      if line.hasPrefix("    ") {
        guard let version = humanVersion(line) else {
          out.unrecognized.append(line)
          continue
        }
        current.append(version)
        continue
      }
      flush()
      guard let reference = Anchor.tokens(line).first,
            let slash = reference.firstIndex(of: "/")
      else {
        out.unrecognized.append(line)
        currentPath = nil
        continue
      }
      currentPath = (
        String(reference[reference.startIndex..<slash]),
        String(reference[reference.index(after: slash)...])
      )
    }
    flush()
    return out
  }

  private static func humanVersion(_ line: String) -> EntryVersion? {
    let parts = Anchor.tokens(line).map(String.init)
    guard
      let seqIndex = parts.firstIndex(where: { $0 == "seq" }),
      seqIndex + 1 < parts.count, let seq = UInt64(parts[seqIndex + 1]),
      seqIndex >= 3,
      let size = UInt64(parts[seqIndex - 1]),
      let kind = kinds[parts[seqIndex - 2]]
    else { return nil }
    let identity = parts[..<(seqIndex - 2)].joined(separator: " ")
    let attestors = parts[(seqIndex + 2)...]
      .joined(separator: " ")
      .split(separator: ",")
      .map { $0.trimmingCharacters(in: .whitespaces) }
      .filter { !$0.isEmpty }
    return EntryVersion(identity: identity, kind: kind, size: size, seq: seq, attestors: attestors)
  }

  /// Adds `status`'s attestor lists to the lossless versions, matched on seq
  /// and size. Where the match fails the lossless version is kept as-is: a
  /// missing attestor list is a gap, a wrong one would be a lie about who
  /// holds a user's file.
  static func merge(lossless: PathVersions, attestorsFrom human: PathVersions?) -> PathVersions {
    guard let human else { return lossless }
    let byKey = Dictionary(
      human.versions.map { (Key(seq: $0.seq, size: $0.size), $0.attestors) },
      uniquingKeysWith: { first, _ in first }
    )
    let merged = lossless.versions.map { version -> EntryVersion in
      guard version.attestors.isEmpty,
            let attestors = byKey[Key(seq: version.seq, size: version.size)]
      else { return version }
      return EntryVersion(
        identity: version.identity,
        kind: version.kind,
        size: version.size,
        seq: version.seq,
        attestors: attestors
      )
    }
    return PathVersions(space: lossless.space, path: lossless.path, versions: merged)
  }

  /// Whether a structured Resolve entry and a rendered status version describe
  /// the same assertion.
  ///
  /// Resolve no longer carries a publishing seq. The content identity is the
  /// stable join key instead: exact in strict-refusal data, or a 16-character
  /// root prefix in `status`'s human rendering. Kind and size keep a truncated
  /// prefix from being accepted on its own.
  static func matches(_ entry: RemoteEntry, version: EntryVersion) -> Bool {
    guard entry.kind == version.kind, entry.size == version.size else { return false }
    let resolved = entry.versionIdentity
    if resolved == version.identity { return true }
    return entry.rootHex != nil
      && version.identity.count == 16
      && resolved.hasPrefix(version.identity)
  }

  private struct Key: Hashable { let seq: UInt64; let size: UInt64 }

  // MARK: - Undoing OriginId::short()

  /// `OriginId::short()`, reimplemented so a truncated origin can be matched
  /// back to a whole one.
  ///
  /// A named origin is rendered in full; a key-identified one is cut to `key:`
  /// plus **10 of its 52** characters. That truncated form is not a valid
  /// reference — `synch adopt path` will not accept it — so on a cluster with no
  /// membership zone, where every origin is key-identified, the attestor
  /// column of `status` names devices in a form nothing can act on.
  static func short(_ origin: String) -> String {
    guard origin.hasPrefix("key:") else { return origin }
    return "key:" + origin.dropFirst(4).prefix(10)
  }

  /// Restores full origins to a version set read from `status`.
  ///
  /// The truncation is a prefix, so it is invertible against a list of origins
  /// this node already knows — trusted devices, delegated devices, this Mac,
  /// and whatever the current listing named. A prefix that matches exactly one
  /// candidate is that candidate; one that matches none or several is left
  /// truncated rather than guessed at, and reported so the caller can fall back
  /// to asking the daemon per origin.
  static func restoreOrigins(
    _ set: PathVersions,
    knownOrigins: [String]
  ) -> (set: PathVersions, unresolved: [String]) {
    var byShort: [String: [String]] = [:]
    for origin in Set(knownOrigins) where !origin.isEmpty {
      byShort[short(origin), default: []].append(origin)
    }
    var unresolved: [String] = []
    let restored = set.versions.map { version -> EntryVersion in
      let attestors = version.attestors.map { attestor -> String in
        if !attestor.hasPrefix("key:") { return attestor }
        // Already whole: a full key origin is 4 + 52 characters.
        if attestor.count > 4 + 10 { return attestor }
        guard let candidates = byShort[attestor], candidates.count == 1 else {
          unresolved.append(attestor)
          return attestor
        }
        return candidates[0]
      }
      return EntryVersion(
        identity: version.identity, kind: version.kind, size: version.size,
        seq: version.seq, attestors: attestors)
    }
    return (
      PathVersions(space: set.space, path: set.path, versions: restored),
      unresolved
    )
  }

  /// Whether an attestor string can be used as a reference in a command.
  ///
  /// The adopt button is gated on this: offering "Use this version" for a
  /// device the app can only name as `key:ybndrfg8ej` would produce a command
  /// the daemon refuses.
  ///
  /// The placeholders are refused for the same reason. Where the daemon holds
  /// no name for a key it renders one in parentheses — `(untrusted)` in a
  /// `peers` row, `(deleted)` for a tombstoned version — and a parenthesis is
  /// not a character an origin can contain, so the shape is the test.
  static func isActionable(_ origin: String) -> Bool {
    guard !origin.isEmpty, !origin.hasPrefix("(") else { return false }
    guard origin.hasPrefix("key:") else { return true }
    return origin.dropFirst(4).count == Anchor.deviceKeyLength
  }
}
