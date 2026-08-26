import Foundation

/// What a total parser returns: the rows it understood, and every line it did
/// not, so an unexpected format degrades to a visibly incomplete table rather
/// than a silently wrong one.
struct ParseResult<Row>: Sendable where Row: Sendable {
  var rows: [Row] = []
  var unrecognized: [String] = []

  var isClean: Bool { unrecognized.isEmpty }
}
