import Foundation

/// Shared anchors for reading the daemon's rendered text.
///
/// The one rule these exist to enforce: **never split on a fixed column.** The
/// daemon's `{:<20}` widths are minimums and never truncations, so a folder id
/// of 63 bytes or a `key:<52-char z-base-32>` origin blows straight through
/// them — the CLI's own trust table misaligns on the most common row shape.
/// Every parser here anchors on a field that identifies itself instead: a
/// 52-character z-base-32 key, a 64-character hex root, an absolute path, or a
/// literal the daemon writes unconditionally.
enum Anchor {
  /// z-base-32, the alphabet iroh renders device keys in.
  static let zbase32 = Set("ybndrfg8ejkmcpqxot1uwisza345h769")
  /// A device key is a 32-byte value in z-base-32: always exactly 52 chars.
  static let deviceKeyLength = 52
  /// An object root is 32 bytes of lowercase hex.
  static let rootLength = 64

  static func isDeviceKey(_ token: Substring) -> Bool {
    token.count == deviceKeyLength && token.allSatisfy { zbase32.contains($0) }
  }

  static func isDeviceKey(_ token: String) -> Bool { isDeviceKey(Substring(token)) }

  static func isRoot(_ token: Substring) -> Bool {
    token.count == rootLength && token.allSatisfy { $0.isHexDigit && !$0.isUppercase }
  }

  /// Splits a line at its first `/`, which is where an absolute local path
  /// begins. Space ids cannot contain `/` (`validate_space` forbids it) and
  /// the client makes every path absolute before sending it, so this separates
  /// head from path exactly — including when the id itself contains spaces,
  /// which the daemon permits and a whitespace split would mangle.
  ///
  /// Only for rows whose path is the **last** field, which is `mirror ls`.
  /// `space ls` used this and was wrong from the day a third column landed
  /// after the path: everything from the first `/` to end of line includes it.
  /// Use ``columns(_:)`` for anything with a field after the path.
  static func splitAtFirstPath(_ line: String) -> (head: String, path: String)? {
    guard let slash = line.firstIndex(of: "/") else { return nil }
    let head = line[line.startIndex..<slash].trimmingCharacters(in: .whitespaces)
    let path = String(line[slash...])
    guard !path.isEmpty else { return nil }
    return (head, path)
  }

  /// The line's whitespace-separated tokens, empties dropped.
  static func tokens(_ line: String) -> [Substring] {
    line.split(whereSeparator: { $0 == " " || $0 == "\t" })
  }

  /// A row split into its columns, on runs of two or more spaces.
  ///
  /// The daemon lays its tables out with `{:<20} {:<28} {}`-style padding, so
  /// the obvious reader splits at fixed offsets. That is wrong in both
  /// directions: a value shorter than its column is followed by padding, and
  /// one *longer* than its column overruns it and pushes everything right, so
  /// the offsets stop meaning anything on exactly the rows worth reading — a
  /// long path, a nine-digit object count.
  ///
  /// What is actually invariant is that padding is always at least two spaces
  /// wide, while the values that contain a space contain only one: `3m ago`,
  /// `just now`, `cut off`, `replicate tree · grace 7d`. So two-in-a-row is the
  /// separator, at any width, and a single space is data.
  static func columns(_ line: String) -> [String] {
    var out: [String] = []
    var field = ""
    var spaces = 0
    for character in line {
      if character == " " || character == "\t" {
        spaces += 1
        continue
      }
      if spaces >= 2, !field.isEmpty {
        out.append(field)
        field = ""
      } else if spaces == 1, !field.isEmpty {
        field.append(" ")
      }
      spaces = 0
      field.append(character)
    }
    if !field.isEmpty { out.append(field) }
    return out
  }

  /// Everything after `marker`, or nil. Used for the literals the daemon
  /// always writes — `LAST ERROR: `, ` ← `, `last-seen ` — which are anchors in
  /// the same sense a key is: they identify themselves.
  static func after(_ marker: String, in line: String) -> String? {
    guard let range = line.range(of: marker) else { return nil }
    return String(line[range.upperBound...]).trimmingCharacters(in: .whitespaces)
  }

  static func before(_ marker: String, in line: String) -> String? {
    guard let range = line.range(of: marker) else { return nil }
    return String(line[line.startIndex..<range.lowerBound]).trimmingCharacters(in: .whitespaces)
  }

  /// The value of a `{label} {value}` field, up to the next double space.
  ///
  /// The daemon separates a row's fields with two spaces and several of its
  /// values contain one — `3m ago`, `just now`, `cut off` — so a whitespace
  /// split cuts them in half. Two spaces is the actual separator.
  static func field(after label: String, in line: String) -> String? {
    guard let rest = after(label, in: line) else { return nil }
    return rest.components(separatedBy: "  ").first?.trimmingCharacters(in: .whitespaces)
  }

  /// The daemon's `remaining()` vocabulary, which is a closed set: this is what
  /// makes the expiry column separable from a folder list that may itself
  /// contain spaces and commas.
  static func isRemaining(_ token: Substring) -> Bool {
    if token == "never" || token == "expired" { return true }
    guard let last = token.last, "smhd".contains(last) else { return false }
    let digits = token.dropLast()
    return !digits.isEmpty && digits.allSatisfy(\.isNumber)
  }

  static func trailingInt(in line: String, unit: String) -> Int? {
    // e.g. "cluster.example.com  3 binding(s)" -> 3
    //
    // The space between the number and the unit has to go first: the daemon
    // writes `"{} {} binding(s)"`, so reading backwards from the unit hit the
    // separator immediately and returned nil for every line it was given.
    guard let range = line.range(of: unit) else { return nil }
    let before = line[line.startIndex..<range.lowerBound]
      .reversed().drop(while: \.isWhitespace)
    let digits = before.prefix(while: \.isNumber).reversed()
    return Int(String(digits))
  }
}
