import Foundation

/// Quoting, for the command lines the app shows and offers to copy.
///
/// A space id, a mirror's local path and a folder name are all allowed to
/// contain spaces — `validate_space` forbids only a slash, control characters
/// and 63 bytes — so `synch space rm Family Photos` was a command that means
/// something else, offered under a button labelled "Copy as a synch command".
enum Shell {
  /// The token as a shell would have to be given it.
  ///
  /// Single quotes, because inside them a shell interprets nothing at all; an
  /// embedded quote is closed, escaped and reopened, which is the one thing
  /// single quotes cannot contain.
  static func quote(_ token: String) -> String {
    guard !token.isEmpty else { return "''" }
    let safe = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "@%+=:,./-_"))
    guard token.unicodeScalars.contains(where: { !safe.contains($0) }) else { return token }
    return "'" + token.replacing("'", with: "'\\''") + "'"
  }
}
