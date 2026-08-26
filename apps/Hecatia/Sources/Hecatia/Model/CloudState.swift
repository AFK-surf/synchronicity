import Foundation

/// Whether the control plane can reach this node, from `cloud status`.
struct CloudState: Sendable, Equatable {
  var enabled: Bool?
  var domains: [DomainAttach] = []
  var notes: [String] = []

  struct DomainAttach: Identifiable, Hashable, Sendable {
    /// One row per *endpoint*, not per domain: `cloud status` prints a line
    /// for each, precisely so that one replica being down is its own line —
    /// and identifying them by the domain collided them in every `ForEach`,
    /// which is exactly where the failing replica's error was supposed to
    /// appear. The detail distinguishes them, since it is the rest of the
    /// daemon's own line.
    var id: String { "\(domain)#\(detail)" }
    let domain: String
    let detail: String
    let lastError: String?
  }
}
