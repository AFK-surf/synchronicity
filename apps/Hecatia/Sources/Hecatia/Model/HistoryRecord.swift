import Foundation

/// One publish in an origin's own history, from `synch log`.
struct HistoryRecord: Identifiable, Hashable, Sendable {
  let id = UUID()
  /// Rendered verbatim: `log` is prose the app deliberately does not parse.
  let text: String
}
