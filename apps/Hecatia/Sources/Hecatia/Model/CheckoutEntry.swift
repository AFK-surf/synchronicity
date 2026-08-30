import Foundation

/// A replica's newest-view checkout on local disk.
struct CheckoutEntry: Identifiable, Hashable, Sendable {
  var id: String { localPath }
  let space: String
  let localPath: String
  let policy: String
}
