import Foundation

/// One bucket of the S3 gateway's map: a name, the folder it serves, and which
/// version of each path reads return.
struct GatewayBucket: Identifiable, Hashable, Sendable {
  enum Access: String, CaseIterable, Hashable, Sendable {
    case readOnly = "read-only"
    case readWrite = "read-write"
  }
  let name: String
  let space: String
  let access: Access
  let policy: VersionPolicy

  var id: String { name }
}
