import Foundation

/// Folds the daemon's flat listing into the rows for one directory level.
///
/// The daemon publishes leaves only — there is no directory record in the
/// unified tree — so every folder row here is synthesised from a path prefix.
enum Listing {

  /// The separator-aware remainder of `path` below `prefix`, or nil when the
  /// path is not actually inside it.
  ///
  /// The daemon matches a listing prefix as a raw byte range, so asking for
  /// `docs` also returns `docs-old/a` and `docsly.md`. The request side now
  /// sends `docs/`, and this is the second half of the same guard: anything
  /// that still arrives outside the folder is dropped rather than folded into
  /// a subfolder that does not exist.
  static func remainder(of path: String, under prefix: String) -> Substring? {
    guard !prefix.isEmpty else { return path.isEmpty ? nil : Substring(path) }
    let bound = prefix.hasSuffix("/") ? prefix : prefix + "/"
    guard path.hasPrefix(bound) else { return nil }
    let rest = path.dropFirst(bound.count)
    return rest.isEmpty ? nil : rest
  }

  // `collapse` used to live here, doing in one pass over a whole listing what
  // `LevelBuilder` — in LevelBuilder.swift — now does as the listing streams,
  // the point of the change being that memory is bounded by the level being
  // shown rather than by the size of the subtree under it. It had no callers
  // left.

  // (The delete confirmation used to count descendants from the listing here.
  // It cannot: a level holds no rows under a folder row. It asks the daemon —
  // see `FilesModel.leaves(under:)`.)
}
