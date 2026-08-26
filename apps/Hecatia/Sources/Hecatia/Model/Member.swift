import Foundation

/// One trusted or delegated device, from `trust ls` and `delegate ls`.
struct Member: Identifiable, Hashable, Sendable {
  enum Source: String, Sendable {
    case staticTrust = "Static"
    case zone = "Zone"
    case granted = "Granted"
  }
  var id: String { "\(source.rawValue)/\(key)/\(origin ?? "")" }
  let key: String
  let origin: String?
  let source: Source
  /// For a delegation: the folders it covers, exactly as the daemon joined
  /// them. Never split on the comma — a folder id may contain one.
  let scope: String?
  let expiry: String?
  let issuer: String?
  let note: String?
  /// The expiry recovered as a bounded interval, for ordering and for warning
  /// before something lapses. `expiry` is still what gets displayed.
  var expiresIn: Age? = nil

  /// Lapsed, or cut off by its issuer losing its own rooted binding.
  ///
  /// Three words, because two listings fill this field: `delegate ls` writes a
  /// remaining duration or "expired"/"cut off", and `trust ls` writes a
  /// liveness verdict — "live" or "lapsed" — in the same column. A lapsed
  /// binding used to render exactly like a healthy one.
  var isDead: Bool { expiry == "expired" || expiry == "cut off" || expiry == "lapsed" }
  /// Under a day left. Conservative for the same reason `isStale` is.
  var isExpiringSoon: Bool {
    guard let age = expiresIn, !age.isNever, !isDead else { return false }
    return (age.upper ?? age.lower) <= 86_400
  }
}
