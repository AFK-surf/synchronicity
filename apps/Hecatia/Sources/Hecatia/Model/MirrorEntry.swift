import Foundation

/// A materialized view of the unified tree on local disk, from `mirror ls`.
struct MirrorEntry: Identifiable, Hashable, Sendable {
  var id: String { localPath }
  let space: String
  let localPath: String
  let policy: String
}
