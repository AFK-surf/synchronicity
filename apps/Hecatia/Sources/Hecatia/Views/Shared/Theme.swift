import SwiftUI

/// Colours and type, resolved from AppKit so both appearances match the system
/// without a second palette.
///
/// Deliberately small. The old theme painted `windowBackgroundColor` over the
/// sidebar, which replaced the system's vibrant material with a flat fill; the
/// sidebar now uses `.listStyle(.sidebar)` and no background of its own.
///
/// **One colour means "you can act on this"**, and it is ``accent`` — the
/// user's own accent colour, not a brand hex. The four below it report a
/// *state*: they tint a chip, a badge, a banner or a glyph that says what
/// something is, and they are never what makes a control look like a control.
/// The measurements live beside this in `DesignTokens.swift`; the rules both
/// come from are in docs/DESIGN.md.
enum Theme {
  static let accent = Color.accentColor
  static let accentSoft = Color.accentColor.opacity(0.12)
  static let online = Color(nsColor: .systemGreen)
  static let warning = Color(nsColor: .systemOrange)
  static let danger = Color(nsColor: .systemRed)
  static let muted = Color(nsColor: .secondaryLabelColor)
  static let line = Color(nsColor: .separatorColor)

  /// The readable form of a state colour, for text drawn on that colour's own
  /// wash.
  ///
  /// `systemGreen` text on a 14% `systemGreen` fill measures about 1.9:1 in the
  /// light appearance, and `systemOrange` about 2.1:1 — below even the 3:1
  /// floor for large text, let alone the 4.5:1 for a caption. The hue is the
  /// state signal and has to stay, so what changes is the lightness: darkened
  /// where the wash is pale, left alone where the wash is already dark and the
  /// saturated colour is the readable one.
  static func ink(_ tint: Color) -> Color { inks[tint] ?? makeInk(tint) }

  /// The five states this app actually has, resolved once rather than per row.
  private static let inks: [Color: Color] = [
    accent: makeInk(accent), online: makeInk(online), warning: makeInk(warning),
    danger: makeInk(danger), muted: makeInk(muted),
  ]

  private static func makeInk(_ tint: Color) -> Color {
    Color(nsColor: NSColor(name: nil) { appearance in
      var resolved = NSColor.labelColor
      // Resolved *inside* the appearance being asked about: a system colour is
      // itself dynamic, and reading it outside would answer for whichever
      // appearance happened to be current.
      appearance.performAsCurrentDrawingAppearance {
        let base = NSColor(tint)
        if appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua {
          resolved = base
        } else {
          resolved = base.usingColorSpace(.sRGB)?.blended(withFraction: 0.45, of: .black) ?? base
        }
      }
      return resolved
    })
  }

  enum Font {
    /// Monospaced, for values whose characters have to line up under each
    /// other: hashes, device keys, paths, and the transcripts of everything
    /// the app refuses to parse.
    ///
    /// Relative to a text style rather than a point size, so it grows with the
    /// user's Larger Text setting like every other string in the app. It is
    /// also the only font configured anywhere here — the design is the system
    /// font at the system sizes, and monospaced is a functional exception, not
    /// a typographic choice.
    static func mono(_ style: SwiftUI.Font.TextStyle = .callout) -> SwiftUI.Font {
      .system(style, design: .monospaced)
    }
  }
}
