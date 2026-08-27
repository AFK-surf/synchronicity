import Foundation

/// One path of the unified tree, as `List` and `Resolve` answer it.
///
/// Every field the daemon sends is kept, including `contentRoot`, which a
/// listing does not render but the Versions inspector uses to identify the
/// selected contents.
struct RemoteEntry: Identifiable, Hashable, Sendable {
  /// `unknown` is this app's word for a parse failure — an `EntryKind` this
  /// build has never heard of — so a kind the daemon *does* define needs a
  /// case of its own or the two become the same row. `socket` is v3's: content
  /// that is an eBPF object the publishing origin will execute for a peer that
  /// connects to it. There is no socket UI behind this and this is not the
  /// start of one; it is only the difference between "a program" and "we could
  /// not read this".
  enum Kind: Hashable, Sendable {
    case file, directory, symlink, tombstone, socket, unknown
  }

  /// Identity is (space, path) — a directory row synthesised for one level and
  /// a file at the same path are different rows and must not collide.
  ///
  /// Stored, not computed. `selection.contains($0.id)` runs once per row on
  /// every key-down in the browser, and as a computed property that was a
  /// fresh interpolated `String` per row per keystroke.
  let id: String

  let origin: String
  let space: String
  let path: String
  let kind: Kind
  let size: UInt64
  let modified: Date
  let versions: UInt32
  /// The 32-byte object root, for files. Rendered as hex where it is shown.
  let contentRoot: Data?
  let symlinkTarget: String?
  /// True for the rows this app synthesises for a directory level; the daemon
  /// publishes leaves only.
  let isSynthesizedDirectory: Bool

  init(
    origin: String,
    space: String,
    path: String,
    kind: Kind,
    size: UInt64,
    modified: Date,
    versions: UInt32,
    contentRoot: Data? = nil,
    symlinkTarget: String? = nil,
    isSynthesizedDirectory: Bool = false
  ) {
    self.origin = origin
    self.space = space
    self.path = path
    self.kind = kind
    self.size = size
    self.modified = modified
    self.versions = versions
    self.contentRoot = contentRoot
    self.symlinkTarget = symlinkTarget
    self.isSynthesizedDirectory = isSynthesizedDirectory
    self.id = "\(space)/\(path)#\(kind == .directory ? "d" : "f")"
    self.name = path.split(separator: "/").last.map(String.init) ?? path
  }

  /// The last path component. Stored for the same reason ``id`` is: it is the
  /// primary sort key, so as a computed property it split the whole path again
  /// on every comparison — n log n splits to sort one folder.
  let name: String
  var isDirectory: Bool { kind == .directory }
  var isFile: Bool { kind == .file }
  /// More than one version means some origin disagrees and nothing has merged.
  var hasVersions: Bool { versions > 1 }
}

extension RemoteEntry {
  var kindLabel: String {
    switch kind {
    case .file: return "File"
    case .directory: return "Folder"
    case .symlink: return "Symlink"
    case .tombstone: return "Deleted"
    case .socket: return "Socket"
    case .unknown: return "Item"
    }
  }

  /// A synthesised folder has no size, mtime, origin or version count of its
  /// own — it is a rendering of a prefix, not a published record — so the
  /// columns that would otherwise show a random child's values stay empty.
  var sizeLabel: String {
    isDirectory ? "—" : ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file)
  }

  var modifiedLabel: String {
    // `.distantPast` is the sentinel for an mtime the daemon could not give —
    // and formatting a sentinel prints it, which in this locale is
    // "1年1月1日 9:18". A column that says nothing is better than one that says
    // that.
    guard !isSynthesizedDirectory, modified != .distantPast else { return "—" }
    return modified.formatted(date: .abbreviated, time: .shortened)
  }

  var iconName: String {
    switch kind {
    case .directory: return "folder.fill"
    case .symlink: return "arrowshape.turn.up.right.fill"
    case .tombstone: return "trash.fill"
    default: return "doc.fill"
    }
  }

  var rootHex: String? { contentRoot.map { $0.map { String(format: "%02x", $0) }.joined() } }

  /// The same identity text the daemon uses for a version. Structured Resolve
  /// responses no longer carry a publishing sequence number, so origin probes
  /// are matched by the actual version identity instead.
  var versionIdentity: String {
    switch kind {
    case .tombstone: return "(deleted)"
    case .symlink: return "-> \(symlinkTarget ?? "(unknown target)")"
    default: return rootHex ?? "(no content)"
    }
  }
}
