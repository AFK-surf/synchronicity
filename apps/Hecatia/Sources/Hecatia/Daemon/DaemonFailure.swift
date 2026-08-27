import Foundation
import GRPC
import NIOHPACK

/// Why a control call failed, as the daemon classifies it.
///
/// The daemon answers every failure with a gRPC status *and* an
/// `x-synch-error-code` trailer, because it distinguishes more cases than gRPC
/// has codes for (`crates/synch-cli/src/control/proto.rs`). Both are read: the
/// trailer when it arrives, the status code as the fallback, so a call that
/// dies before trailers are delivered still classifies.
enum ControlErrorCode: String, Sendable, CaseIterable {
  case unauthorized
  case versionMismatch = "version-mismatch"
  case notInitialized = "not-initialized"
  case notFound = "not-found"
  case invalid
  case internalError = "internal"
  case divergent
  case unavailable

  /// The daemon's own mapping, read backwards. `FailedPrecondition` covers two
  /// codes, which is exactly the ambiguity the trailer exists to resolve.
  static func from(status code: GRPCStatus.Code) -> ControlErrorCode {
    switch code {
    case .unauthenticated: .unauthorized
    case .failedPrecondition: .versionMismatch
    case .notFound: .notFound
    case .invalidArgument: .invalid
    case .aborted: .divergent
    case .unavailable: .unavailable
    default: .internalError
    }
  }

  static let trailerName = "x-synch-error-code"
}

/// A failed control call, carrying the daemon's own words.
///
/// The daemon writes its messages as instructions to a person — "what went
/// wrong, in the words the CLI prints" — so they are shown verbatim rather
/// than reworded. Only the *suggestion* beside them is ours.
struct DaemonFailure: LocalizedError, Sendable, Equatable {
  let code: ControlErrorCode
  /// The daemon's message, or a description of a transport failure.
  let detail: String
  /// Which operation was in flight, for the alert's title.
  let operation: String?
  /// A remedy this particular failure knows better than its code does.
  ///
  /// The canned suggestions below are written for a failure the *daemon*
  /// returned while serving a call. A failure the app synthesises — "nothing
  /// is answering" — has the same code and a different remedy, and printing
  /// the canned one under it produced flat contradictions: "No daemon is
  /// running" above "The daemon is running but cannot serve this yet".
  let suggestion: String?

  init(
    code: ControlErrorCode, detail: String, operation: String? = nil,
    suggestion: String? = nil
  ) {
    self.code = code
    self.detail = detail
    self.operation = operation
    self.suggestion = suggestion
  }

  /// Classifies a thrown error. Trailers win over the status code; anything
  /// that is not a `GRPCStatus` at all is a transport fault.
  static func classify(
    _ error: any Error,
    trailers: HPACKHeaders? = nil,
    operation: String? = nil
  ) -> DaemonFailure {
    if let failure = error as? DaemonFailure { return failure }
    if error is CancellationError {
      return DaemonFailure(code: .unavailable, detail: "Cancelled.", operation: operation)
    }
    guard let status = error as? GRPCStatus else {
      // A connection-pool error is the transport saying it cannot reach the
      // other end at all — which is `unavailable`, not "the daemon failed
      // while serving this". The distinction matters because it is the one
      // signal that tells a daemon that has *stopped* apart from one that is
      // merely slow: a deadline expiry arrives as a `GRPCStatus` and keeps
      // `internalError`.
      if error is GRPCConnectionPoolError {
        return DaemonFailure(
          code: .unavailable,
          detail: "Nothing is listening on the control socket.",
          operation: operation
        )
      }
      return DaemonFailure(
        code: .internalError,
        detail: (error as NSError).localizedDescription,
        operation: operation
      )
    }
    let fromTrailer = trailers?.first(name: ControlErrorCode.trailerName)
      .flatMap(ControlErrorCode.init(rawValue:))
    return DaemonFailure(
      code: fromTrailer ?? ControlErrorCode.from(status: status.code),
      detail: status.message ?? String(describing: status.code),
      operation: operation
    )
  }

  var errorDescription: String? { detail }

  /// What the user can do about it. Deliberately separate from `detail`: the
  /// daemon owns the diagnosis, the app owns the remedy.
  var recoverySuggestion: String? {
    if let suggestion { return suggestion }
    switch code {
    case .unauthorized:
      return "The daemon mints a new control token every time it starts. Reconnecting re-reads it."
    case .versionMismatch:
      return "This app and the daemon speak different versions of the control protocol. Update whichever is older."
    case .notInitialized:
      return "That data directory has no node identity yet. Run `synch init` in it first."
    case .notFound: return nil
    case .invalid: return nil
    case .internalError:
      return "The daemon failed while serving this. `synch doctor` reports on its health."
    case .divergent:
      return "The path has more than one version. Choose one in the file's Versions inspector."
    case .unavailable:
      // Deliberately does not assert that a daemon is running: this is also
      // the code for nothing at all answering on the control socket, which is
      // exactly the screen that used to print "the daemon is running" under a
      // heading saying it was not.
      return "Either nothing is listening on the control socket, or the daemon is not ready to serve this yet. The message above names which."
    }
  }

  /// Whether reconnecting with a freshly-read token is worth trying. A token
  /// mismatch means the daemon restarted, not that the user typed something
  /// wrong, so it is recoverable without asking them anything.
  var isStaleConnection: Bool { code == .unauthorized }

  var title: String {
    guard let operation else { return "Synchronicity" }
    return "Couldn’t \(operation)"
  }
}
