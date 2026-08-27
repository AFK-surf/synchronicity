import Foundation

/// One upload or download.
///
/// Addressed by `id` everywhere, never by position in the queue. The crash
/// this replaces came from an index captured when a batch started and used
/// after an unrelated operation had emptied the array.
struct Transfer: Identifiable, Sendable, Equatable {
  enum Direction: Sendable, Equatable { case upload, download }
  enum State: Sendable, Equatable {
    case waiting
    case running
    case completed(detail: String?)
    case failed(String)
    case cancelled
  }

  let id: UUID
  let direction: Direction
  let name: String
  let space: String
  let path: String
  var bytes: Int64 = 0
  var total: Int64 = 0
  var state: State = .waiting
  /// Set when the payload went through the multipart calls, so the UI can say
  /// an interrupted transfer is resumable rather than lost.
  var uploadID: String?
  /// Where a download picked up from, when it continued a partial file rather
  /// than starting over. Zero for one that started at the beginning.
  var resumedFrom: Int64 = 0
  /// When it was added to the queue, and when it stopped being active.
  ///
  /// A finished row is a history entry, and a history entry that does not say
  /// when is a list of things that happened at no particular time. Stamped by
  /// ``TransferQueue`` rather than by each call site, so a state written from
  /// anywhere is dated.
  var startedAt: Date = .now
  var finishedAt: Date?

  var progress: Double {
    guard total > 0 else { return 0 }
    return min(1, Double(bytes) / Double(total))
  }

  var isActive: Bool {
    switch state { case .waiting, .running: return true; default: return false }
  }

  var isFinished: Bool { !isActive }

  var statusLabel: String {
    switch state {
    case .waiting: return "Waiting"
    case .running:
      guard total > 0 else { return "Starting…" }
      let done = ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
      let all = ByteCountFormatter.string(fromByteCount: total, countStyle: .file)
      return "\(done) of \(all)"
    case .completed(let detail):
      guard let detail else {
        return total > 0
          ? total.formatted(.byteCount(style: .file))
          : "Done"
      }
      return detail
    case .failed(let why): return why
    case .cancelled: return "Cancelled"
    }
  }
}
