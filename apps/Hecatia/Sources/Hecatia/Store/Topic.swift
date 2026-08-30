import Foundation

/// A slice of daemon state a view reads and an operation invalidates.
///
/// Every mutating operation declares which of these it dirties, so a refresh
/// after a command is a property of the command rather than something each
/// call site has to remember. Forgetting one is how a table ends up
/// contradicting the chip beside it.
enum Topic: String, CaseIterable, Sendable {
  case status        // daemon status, id
  case spaces        // source ls plus replica ls
  case listing       // the browser's current folder
  case members       // trust ls, delegate ls
  case domains       // domain ls
  case peers         // peer ls
  case keys          // key ls
  case pins          // pin ls
  case replication   // replica ls <id> — per-space replica coverage
  case cloud         // control-plane status
  case uploads       // ListUploads
  case s3            // GetConfig
}
