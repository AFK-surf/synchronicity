#if DEBUG
import Foundation

/// Reports how long the main actor went without running anything.
///
/// `await` does not block a thread, so "the UI is blocked" is never visible in
/// the shape of the code — it is visible only in the gaps between the moments
/// the main actor was free. This ticks on the main actor as fast as it is
/// allowed to and prints every gap longer than it asked for, which is exactly
/// the stutter, in milliseconds, with a name for what was in flight when it
/// happened.
///
/// Inert unless `HECATIA_WATCHDOG` is set. DEBUG only: it exists to answer a
/// question, not to ship.
@MainActor
enum MainActorWatchdog {
  /// How late a tick has to be before it is worth printing. One frame at 60Hz
  /// is 16.7ms; a gap under ~50ms is scheduling noise on a busy machine, and a
  /// gap over it is something a person can see.
  private static let interesting: Double = 50

  private(set) static var worst: Double = 0
  private(set) static var stalls = 0
  /// What the app says it is doing, for the line the watchdog prints.
  static var doing = "idle"

  static func startIfAsked() {
    guard ProcessInfo.processInfo.environment["HECATIA_WATCHDOG"] != nil else { return }
    FileHandle.standardError.write(Data("watchdog: watching the main actor\n".utf8))
    Task { @MainActor in
      let started = Date.now
      var last = Date.now
      while !Task.isCancelled {
        // Eight milliseconds, so a tick that is merely a frame late is not
        // reported and one that waited behind real work is.
        try? await Task.sleep(for: .milliseconds(8))
        let now = Date.now
        let gap = now.timeIntervalSince(last) * 1000
        last = now
        guard gap > interesting else { continue }
        stalls += 1
        worst = max(worst, gap)
        let since = now.timeIntervalSince(started)
        let line = "watchdog: +\(String(format: "%6.1f", since))s  gone \(Int(gap.rounded()))ms  during “\(doing)”\n"
        FileHandle.standardError.write(Data(line.utf8))
      }
    }
  }

  /// Names what is in flight, so a stall can be attributed rather than guessed.
  static func during<T>(_ what: String, _ work: () async -> T) async -> T {
    let previous = doing
    doing = what
    defer { doing = previous }
    return await work()
  }

  static var summary: String {
    stalls == 0
      ? "watchdog: the main actor never went away for more than \(Int(interesting))ms"
      : "watchdog: \(stalls) stalls, worst \(Int(worst.rounded()))ms"
  }
}
#endif
