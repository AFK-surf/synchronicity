import Foundation

/// Folds a streamed listing into one directory level as it arrives.
///
/// The daemon's prefix listing is recursive and has no delimiter, so a deep
/// folder streams every descendant. Only the immediate children are kept, so
/// the app's memory is bounded by the level being shown rather than by the
/// size of the subtree under it.
struct LevelBuilder {
  let space: String
  let prefix: String

  private var files: [String: RemoteEntry] = [:]
  private var folderNames: [String] = []
  private var seenFolders: Set<String> = []
  private(set) var descendants = 0

  init(space: String, prefix: String) {
    self.space = space
    self.prefix = prefix
  }

  mutating func add(_ entry: RemoteEntry) {
    guard let rest = Listing.remainder(of: entry.path, under: prefix) else { return }
    descendants += 1
    guard let slash = rest.firstIndex(of: "/") else {
      files[entry.path] = entry
      return
    }
    let name = String(rest[rest.startIndex..<slash])
    guard !name.isEmpty else { return }
    let path = prefix.isEmpty ? name : "\(prefix)/\(name)"
    if seenFolders.insert(path).inserted { folderNames.append(path) }
  }

  /// The level, unsorted.
  ///
  /// Deliberately unsorted: the table draws `FilesModel.visibleRows`, which
  /// orders by whichever column header is chosen, and everything else that
  /// reads `rows` — the delete plan, the divergent count, the id lookup — is
  /// order-independent. Collating here was therefore pure waste, and it was
  /// expensive waste: measured on 50,000 entries in a release build, this one
  /// `localizedStandardCompare` sort took 2.02 seconds on the main actor with
  /// no `await` anywhere in it, which is the window hard-frozen for two
  /// seconds after a large folder finishes loading.
  func rows() -> [RemoteEntry] {
    let folders = folderNames.map { path in
      RemoteEntry(
        origin: "", space: space, path: path, kind: .directory,
        size: 0, modified: .distantPast, versions: 1, isSynthesizedDirectory: true)
    }
    return folders + files.values
  }
}
