import Foundation

/// One membership zone's health, from `domain ls`.
struct DomainHealth: Identifiable, Hashable, Sendable {
  var id: String { domain }
  let domain: String
  let bindingCount: Int?
  /// The rest of the line verbatim: refresh times are rendered as English
  /// durations by the daemon and are not parsed back into dates.
  let detail: String
  let lastError: String?
}
