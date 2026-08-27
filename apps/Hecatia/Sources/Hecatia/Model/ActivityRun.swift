import Foundation

/// One `Run` command and everything it said.
///
/// Every command in the product can be delivered correctly through this with
/// no parsing at all, which is what makes adding the next operation additive:
/// the transcript is already right, and a typed reading of it is an upgrade
/// rather than a prerequisite.
struct ActivityRun: Identifiable, Sendable, Equatable {
  enum Outcome: Sendable, Equatable {
    case running
    /// The stream ended without a gRPC status. This — not the text — is what
    /// success means.
    case succeeded
    case failed(DaemonFailure)
    case cancelled
  }

  let id: UUID
  let title: String
  /// The equivalent `synch` invocation, so an operator can check what the app
  /// is about to do, and reproduce it.
  let commandLine: String
  let startedAt: Date
  var finishedAt: Date?
  var output = RunOutput()
  var outcome: Outcome = .running

  var isRunning: Bool { if case .running = outcome { return true } else { return false } }

  var duration: TimeInterval? {
    finishedAt.map { $0.timeIntervalSince(startedAt) }
  }

  /// The newest progress line, which is what a running command shows.
  var latestProgress: String? { output.latestProgress }
}
