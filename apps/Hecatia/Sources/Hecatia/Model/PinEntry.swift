import Foundation

/// Content held offline regardless of what else is collected, from `pin ls`.
///
/// `pin ls` used to list only what an operator pinned. It now lists every
/// object anything holds, replicas included — one space's replica can be
/// hundreds of thousands of rows — and names the holder in its own column. Only
/// the operator's own pins belong under "Kept offline": a replica's claim was
/// never a choice someone made, and `pin rm` refuses it, so offering to remove
/// one is offering an action that is guaranteed to fail.
struct PinEntry: Identifiable, Hashable, Sendable {
  var id: String { root }
  let root: String
  /// The daemon's size column, verbatim.
  let size: String
  /// The holders column: `operator`, `replica:media`, or
  /// `replica:media (leaving in 3d)`, comma-joined when there is more than one.
  let holders: String
  /// The paths this root is currently named by, verbatim.
  let paths: String

  /// Whether an operator pinned this — the only kind `pin rm` will remove.
  ///
  /// A substring test rather than an equality one, because the column is a
  /// comma-joined list and an object can be both operator-pinned and
  /// replica-held at once. That case is exactly the one where removing the pin
  /// succeeds and the bytes still do not go anywhere, which is what the
  /// daemon's `(still held by …)` reply is for.
  var isOperatorPinned: Bool {
    holders.split(separator: ",").contains { $0.trimmingCharacters(in: .whitespaces) == "operator" }
  }

  /// Held by something other than the operator as well.
  var hasOtherHolders: Bool {
    holders.split(separator: ",").contains { part in
      let name = part.trimmingCharacters(in: .whitespaces)
      return !name.isEmpty && name != "operator"
    }
  }

  /// What the old single-column model showed, for the places that want one
  /// line of detail rather than four fields.
  var detail: String {
    [size, holders, paths].filter { !$0.isEmpty }.joined(separator: "  ")
  }
}
