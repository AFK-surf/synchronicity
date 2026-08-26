import Foundation

/// One origin's assertion about a path.
///
/// The product never merges: each of these stays individually addressable as
/// `<origin>:<space>/<path>`, and a version is what a policy selects *between*.
struct EntryVersion: Identifiable, Hashable, Sendable {
  /// The content root (files) or the kind/target pair (symlinks, tombstones)
  /// that distinguishes this version from the others.
  let identity: String
  let kind: RemoteEntry.Kind
  let size: UInt64
  let seq: UInt64
  /// Every origin asserting this same identity. Agreement is the common case
  /// and renders as several attestors on one version, not several versions.
  let attestors: [String]

  var id: String { "\(identity)#\(seq)#\(attestors.joined(separator: ","))" }
  var isTombstone: Bool { kind == .tombstone }
  var sizeLabel: String { ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file) }

  /// The origin a command about this version would be sent to, or `nil` when
  /// no attestor is a reference the daemon accepts.
  ///
  /// One definition, because there were four. `VersionCard` enabled its
  /// buttons on `contains(where: isActionable)`, `FilesModel.adopt` and
  /// `FileOperations.materialize` each took `first(where: isActionable)`, and
  /// the confirmation between them named plain `attestors.first` — so a list
  /// beginning with a key `status` had truncated,
  /// `["key:ybndrfg8ej", "nas@x.example"]`, offered the button, named the key,
  /// and fetched from the NAS.
  var actionableAttestor: String? { attestors.first(where: Versions.isActionable) }

  /// The same version under a different attestor list.
  ///
  /// The three readers that rewrite one — `Versions.merge`,
  /// `Versions.restoreOrigins` and `FilesModel.probeOrigins` — change only the
  /// attestors, and each re-typed every field to do it. A field added to this
  /// type would have had to be added to all three or be dropped by all three.
  func attested(by attestors: [String]) -> EntryVersion {
    EntryVersion(identity: identity, kind: kind, size: size, seq: seq, attestors: attestors)
  }
}

/// Every version of one path, newest first.
struct PathVersions: Sendable, Equatable {
  let space: String
  let path: String
  let versions: [EntryVersion]

  var isDivergent: Bool { versions.count > 1 }
  /// True when every publisher asserts the same thing. Worth saying out loud:
  /// it is how a user learns the model before divergence can hurt them.
  var isUnanimous: Bool { versions.count == 1 }
  var attestorCount: Int { versions.reduce(0) { $0 + $1.attestors.count } }
}
