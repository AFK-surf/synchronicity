import Foundation

/// Readers for the daemon's tabular `Run` listings.
///
/// Every one of these is total: what it cannot read comes back in
/// `unrecognized` and is rendered as a raw row, never dropped. Where a field is
/// rendered lossily by the daemon — an English "3m ago", a comma-joined list
/// whose members may contain commas — it is kept as text on purpose and is not
/// re-parsed into something that would be a guess.
enum Listings {

  // MARK: - pin ls  ·  "{root}  {size}  {holders}  {paths}"

  /// Four columns, and the holders one decides what the app may offer.
  ///
  /// The listing used to be operator pins only, and this kept everything after
  /// the root as one opaque string. `pin ls` now reports every object anything
  /// holds — a replica's claims are rows in the same table, hundreds of
  /// thousands of them — and names the holder in a column of its own.
  static func pins(_ lines: [String]) -> ParseResult<PinEntry> {
    var out = ParseResult<PinEntry>()
    for line in lines where !line.isEmpty {
      let fields = Anchor.columns(line)
      guard let root = fields.first, Anchor.isRoot(Substring(root)) else {
        out.unrecognized.append(line)
        continue
      }
      // A root with no paths naming it is normal — that is most of what a
      // replica holds — so only the holders column is required.
      guard fields.count >= 3 else {
        out.unrecognized.append(line)
        continue
      }
      out.rows.append(
        PinEntry(
          root: root, size: fields[1], holders: fields[2],
          paths: fields.count > 3 ? fields[3...].joined(separator: "  ") : ""))
    }
    return out
  }

  // MARK: - peers  ·  "{key}  {origins}  last-seen … last-sync … rtt …µs"

  static func peers(_ lines: [String]) -> ParseResult<PeerInfo> {
    var out = ParseResult<PeerInfo>()
    for line in lines where !line.isEmpty {
      guard let key = Anchor.tokens(line).first, Anchor.isDeviceKey(key) else {
        out.unrecognized.append(line)
        continue
      }
      // Displayed verbatim — the daemon computed it against its own clock —
      // but also read into bounded intervals so the table can be ordered by
      // staleness, which a string like "3m ago" cannot be.
      let detail = line.dropFirst(key.count).trimmingCharacters(in: .whitespaces)
      let origins = Anchor.before("  last-seen ", in: detail) ?? ""
      out.rows.append(
        PeerInfo(
          key: String(key),
          origins: origins,
          detail: detail,
          lastSeen: Anchor.field(after: "last-seen ", in: line).flatMap(Anchor.age),
          lastSync: Anchor.field(after: "last-sync ", in: line).flatMap(Anchor.age)))
    }
    return out
  }

  // MARK: - trust ls  ·  "{:<32} {} {:<7} {}{}"

  static func trust(_ lines: [String]) -> ParseResult<Member> {
    var out = ParseResult<Member>()
    for line in lines where !line.isEmpty {
      let parts = Anchor.tokens(line)
      // Anchored on the bare 52-char device key. An origin rendered as
      // `key:<52>` is one token *with* its prefix, so it never matches here.
      guard let keyIndex = parts.firstIndex(where: { Anchor.isDeviceKey($0) }) else {
        out.unrecognized.append(line)
        continue
      }
      let origin = parts[..<keyIndex].joined(separator: " ")
      let rest = Array(parts[(keyIndex + 1)...])
      // The daemon's own vocabulary, exhaustively. `BindingSource::as_str`
      // returns "static", "dns" *or* "delegated", and collapsing everything
      // that was not "static" to `.zone` meant every device that had been
      // granted access was also listed as an unrestricted zone member — with
      // "all folders" beside it, because `trust ls` carries no scope. An
      // unknown fourth value goes to the parser-drift channel rather than
      // being silently called something it is not.
      let sourceText = rest.first.map(String.init) ?? ""
      let source: Member.Source
      switch sourceText {
      case "static": source = .staticTrust
      case "dns": source = .zone
      case "delegated": source = .granted
      default:
        out.unrecognized.append(line)
        continue
      }
      // The fourth column is a liveness verdict — "live", "lapsed" — not a
      // duration, and the Members table labels that column Expires. It goes
      // where it is true rather than where it fits.
      let verdict = rest.count > 1 ? String(rest[1]) : nil
      let note = rest.dropFirst(2).joined(separator: " ")
      out.rows.append(
        Member(
          key: String(parts[keyIndex]),
          origin: origin.isEmpty ? nil : origin,
          source: source,
          scope: nil,
          expiry: verdict,
          issuer: nil,
          note: note.isEmpty ? nil : note
        )
      )
    }
    return out
  }

  // MARK: - delegate ls  ·  "{key} {:<28} {:<10} ← {issuer}"

  static let noDelegationsLine = "no delegations"

  static func delegations(_ lines: [String]) -> ParseResult<Member> {
    var out = ParseResult<Member>()
    for line in lines where !line.isEmpty {
      if line == noDelegationsLine { continue }
      let parts = Anchor.tokens(line)
      guard let key = parts.first, Anchor.isDeviceKey(key) else {
        out.unrecognized.append(line)
        continue
      }
      // ` ← ` (U+2190) is written unconditionally, so it separates the scope
      // and expiry from the issuer exactly.
      let afterKey = line.dropFirst(key.count).trimmingCharacters(in: .whitespaces)
      let issuer = Anchor.after("← ", in: afterKey)
      let left = Anchor.before("←", in: afterKey) ?? afterKey
      // The expiry is the trailing token from a closed vocabulary — `never`,
      // `expired`, `cut off`, or `{n}s|m|h|d`. Everything before it is the
      // comma-joined folder list, which is NOT split: a folder id may itself
      // contain a comma, so splitting it would invent scopes that do not exist.
      var scopeText = left
      var expiry: String?
      let leftParts = Anchor.tokens(left)
      if leftParts.count >= 2, leftParts[leftParts.count - 2] == "cut", leftParts.last == "off" {
        expiry = "cut off"
        scopeText = leftParts.dropLast(2).joined(separator: " ")
      } else if let last = leftParts.last, Anchor.isRemaining(last) {
        expiry = String(last)
        scopeText = leftParts.dropLast().joined(separator: " ")
      }
      out.rows.append(
        Member(
          key: String(key),
          origin: nil,
          source: .granted,
          scope: scopeText.isEmpty ? nil : scopeText,
          expiry: expiry,
          issuer: issuer,
          note: nil,
          expiresIn: expiry.flatMap(Anchor.remainingAge)
        )
      )
    }
    return out
  }

  // MARK: - domain ls  ·  render::domain_health

  static func domains(_ lines: [String]) -> ParseResult<DomainHealth> {
    var out = ParseResult<DomainHealth>()
    for line in lines where !line.isEmpty {
      if line.hasPrefix("pending:") {
        out.unrecognized.append(line)
        continue
      }
      guard let domain = Anchor.tokens(line).first else {
        out.unrecognized.append(line)
        continue
      }
      let detail = line.dropFirst(domain.count).trimmingCharacters(in: .whitespaces)
      out.rows.append(
        DomainHealth(
          domain: String(domain),
          bindingCount: Anchor.trailingInt(in: line, unit: "binding(s)"),
          detail: detail,
          lastError: Anchor.after("LAST ERROR: ", in: line)
        )
      )
    }
    return out
  }

  // MARK: - key ls  ·  "{key} {:<8} bound by {n} of {m} reachable peer(s)"

  static func deviceKeys(_ lines: [String]) -> ParseResult<DeviceKey> {
    var out = ParseResult<DeviceKey>()
    for line in lines where !line.isEmpty {
      // The indented rows are one peer's verdict on the key above them; they
      // belong to the detail sheet, not the key table.
      if line.hasPrefix("    ") || line.hasPrefix("  ") { continue }
      let parts = Anchor.tokens(line)
      guard let key = parts.first, Anchor.isDeviceKey(key), parts.count >= 2 else {
        out.unrecognized.append(line)
        continue
      }
      out.rows.append(
        DeviceKey(
          key: String(key),
          state: DeviceKey.State(rawValue: String(parts[1])) ?? .unknown,
          peersHolding: Anchor.after("bound by ", in: line)
        )
      )
    }
    return out
  }

  /// `id`'s key rows: `"  {key} ({state})"`.
  static func identityKeys(_ lines: [String]) -> [DeviceKey] {
    lines.compactMap { line in
      guard line.hasPrefix("  ") else { return nil }
      let parts = Anchor.tokens(line)
      guard let key = parts.first, Anchor.isDeviceKey(key) else { return nil }
      let state = parts.count > 1
        ? String(parts[1]).trimmingCharacters(in: CharacterSet(charactersIn: "()"))
        : ""
      return DeviceKey(key: String(key), state: DeviceKey.State(rawValue: state) ?? .unknown)
    }
  }

  // MARK: - control-plane status  ·  "control-plane: {state}" then "{:<32} {:<10} {endpoint}{error}"

  static func cloud(_ output: RunOutput) -> CloudState {
    var state = CloudState()
    for line in output.lines {
      if let value = Anchor.after("control-plane: ", in: line) {
        state.enabled = value.hasPrefix("enabled")
        continue
      }
      guard let domain = Anchor.tokens(line).first else { continue }
      let detail = line.dropFirst(domain.count).trimmingCharacters(in: .whitespaces)
      state.domains.append(
        CloudState.DomainAttach(
          domain: String(domain),
          detail: detail,
          lastError: Anchor.after("last error: ", in: line)
        )
      )
    }
    // `(no attach attempts yet)` arrives on the progress channel rather than as
    // a line — the only status in this family that does — so it is read from
    // there instead of being lost.
    state.notes = output.progress
    return state
  }
}
