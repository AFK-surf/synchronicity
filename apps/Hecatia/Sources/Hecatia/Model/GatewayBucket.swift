import Foundation

/// One bucket of the S3 gateway's map: a name, the folder it serves, and which
/// version of each path reads return.
struct GatewayBucket: Identifiable, Hashable, Sendable {
  let name: String
  let space: String
  let policy: VersionPolicy

  var id: String { name }
}
