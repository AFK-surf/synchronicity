import Foundation

/// What a replicating space holds. The daemon's grammar, round-tripped exactly.
///
/// Distinct from ``VersionPolicy``, which picks *one* version for a read. This
/// picks how much history a node keeps on disk, and the two are not
/// interchangeable — `tree` is not `newest`, because a tree replica holds every
/// version the current tree names, from every origin.
enum ReplicaPolicy: String, CaseIterable, Hashable, Sendable {
  /// Hold what the tree names, and release a root once it stops naming it.
  case tree
  /// Hold everything ever seen, and release nothing.
  case archive

  /// `ReplicaPolicy::render()` emits exactly this, and `FromStr` reads exactly
  /// this, so the string is the wire form in both directions.
  var wire: String { rawValue }

  var label: String {
    switch self {
    case .tree: return "Tree"
    case .archive: return "Archive"
    }
  }

  /// Said in the second person, for the sheet that turns this on.
  var explanation: String {
    switch self {
    case .tree:
      return "Hold every version the folder currently names. When a file stops "
        + "being named, its bytes are released after the grace period."
    case .archive:
      return "Hold everything this Mac has ever seen, and release nothing. "
        + "The grace period does not apply."
    }
  }
}
