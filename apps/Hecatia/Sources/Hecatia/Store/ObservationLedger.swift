import Foundation

/// When this app first saw a piece of daemon state hold its current value.
///
/// The daemon records `CloudDomainStatus.since_ns` and never renders it, so
/// "attached for 3 h" is unavailable. What *is* available is when this app
/// first observed the current value, measured on this Mac's own clock. That is
/// a strictly weaker fact and it is labelled as one — "since 14:02, when this
/// app started watching" — but for a tunnel that flaps it is the fact the user
/// actually wants, and it gets more accurate the longer the app runs.
@MainActor
final class ObservationLedger {
  private var firstSeen: [String: (value: String, at: Date)] = [:]

  /// Records `value` for `key` and returns when it was first observed holding
  /// that value. A changed value restarts the clock.
  @discardableResult
  func observe(_ key: String, value: String, now: Date = .now) -> Date {
    if let existing = firstSeen[key], existing.value == value {
      return existing.at
    }
    firstSeen[key] = (value, now)
    return now
  }

  func since(_ key: String) -> Date? { firstSeen[key]?.at }

  func forget(_ key: String) { firstSeen[key] = nil }
}
