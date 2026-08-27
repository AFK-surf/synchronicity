import Foundation

/// What can be recovered from the daemon's English durations.
///
/// `render::ago` and `render::remaining` destroy the instant: they compute
/// against the *daemon's* clock at render time and emit a bucket — `3m ago`
/// means "between 180 and 239 seconds when this line was written". The raw
/// value never crosses the socket, so the exact time is gone for good.
///
/// The bucket is not nothing, though. It is a bounded interval, and a bounded
/// interval sorts, compares against a coarse threshold, and can be re-anchored
/// to the reading client's own clock. Recovering that much is the difference
/// between a monitoring table that cannot be ordered at all and one that is
/// ordered correctly except within a single bucket.
struct Age: Sendable, Hashable {
  /// The narrowest interval the rendering allows, in seconds.
  let lower: TimeInterval
  /// `nil` for an open-ended bucket, and for `never`.
  let upper: TimeInterval?
  /// True for `never` — the daemon's rendering of a zero timestamp, which is
  /// "has not happened", not "happened a long time ago".
  let isNever: Bool
  /// What the daemon actually wrote. Always what gets displayed.
  let text: String

  /// Sorts oldest-last. `never` sorts after everything, because "not yet" is
  /// not the same as "a long time ago" and must not be ordered among ages.
  var sortKey: TimeInterval { isNever ? .greatestFiniteMagnitude : lower }

  /// Whether the age is definitely at least `seconds`. Conservative: a bucket
  /// that straddles the threshold answers false, so an alert never fires on a
  /// value that might be under it.
  func isAtLeast(_ seconds: TimeInterval) -> Bool { !isNever && lower >= seconds }
}

extension Anchor {
  /// Reads `render::ago`: `never` | `just now` | `{n}s ago` | `{n}m ago` |
  /// `{n}h ago` | `{n}d ago`.
  ///
  /// The buckets come straight from the match arms, so the interval is exactly
  /// what the daemon could have meant and never wider.
  static func age(_ text: String) -> Age? {
    let value = text.trimmingCharacters(in: .whitespaces)
    if value == "never" {
      return Age(lower: 0, upper: nil, isNever: true, text: value)
    }
    if value == "just now" {
      // The `s < 0` arm: the stamp is in the daemon's future, so the age is at
      // most zero.
      return Age(lower: 0, upper: 0, isNever: false, text: value)
    }
    guard value.hasSuffix(" ago") else { return nil }
    let head = Substring(value.dropLast(4))
    return bucket(head, text: value)
  }

  /// `{n}s|m|h|d` as a bounded interval, for both readers above.
  ///
  /// Integer division in Rust truncates, so `{n}<unit>` means
  /// [n·span, (n+1)·span). The day bucket is open-ended: there is no larger
  /// unit to roll into.
  private static func bucket(_ digitsAndUnit: Substring, text: String) -> Age? {
    guard let unit = digitsAndUnit.last,
          let count = Double(digitsAndUnit.dropLast()), count >= 0
    else { return nil }
    let span: TimeInterval
    switch unit {
    case "s": span = 1
    case "m": span = 60
    case "h": span = 3600
    case "d": span = 86400
    default: return nil
    }
    return Age(
      lower: count * span,
      upper: unit == "d" ? nil : (count + 1) * span,
      isNever: false,
      text: text)
  }

  /// Reads `render::remaining`: `expired` | `{n}s` | `{n}m` | `{n}h` | `{n}d`,
  /// plus `delegate ls`'s own `never` and `cut off`.
  ///
  /// Returned as a time *until*, so a smaller `lower` is more urgent.
  static func remainingAge(_ text: String) -> Age? {
    let value = text.trimmingCharacters(in: .whitespaces)
    switch value {
    case "never":
      return Age(lower: 0, upper: nil, isNever: true, text: value)
    case "expired", "cut off":
      return Age(lower: 0, upper: 0, isNever: false, text: value)
    default: break
    }
    guard let unit = value.last, let count = Double(value.dropLast()), count >= 0 else {
      return nil
    }
    let span: TimeInterval
    switch unit {
    case "s": span = 1
    case "m": span = 60
    case "h": span = 3600
    case "d": span = 86400
    default: return nil
    }
    return Age(
      lower: count * span,
      upper: unit == "d" ? nil : (count + 1) * span,
      isNever: false,
      text: value)
  }
}
