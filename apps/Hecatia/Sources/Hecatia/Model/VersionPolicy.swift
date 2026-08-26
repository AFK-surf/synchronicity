import Foundation

/// How a read picks one version. The daemon's grammar, round-tripped exactly.
enum VersionPolicy: Hashable, Sendable {
  case newest
  case origin(String)
  case strict

  /// `VersionPolicy::render()` on the daemon side emits exactly this, so the
  /// string round-trips losslessly and never needs to be guessed at.
  var wire: String {
    switch self {
    case .newest: return "newest"
    case .strict: return "strict"
    case .origin(let id): return "origin=\(id)"
    }
  }

  init?(wire: String) {
    switch wire {
    case "newest": self = .newest
    case "strict": self = .strict
    default:
      guard wire.hasPrefix("origin="), wire.count > 7 else { return nil }
      self = .origin(String(wire.dropFirst(7)))
    }
  }

  var label: String {
    switch self {
    case .newest: return "Newest"
    case .strict: return "Strict"
    case .origin(let id): return "From \(id)"
    }
  }
}
