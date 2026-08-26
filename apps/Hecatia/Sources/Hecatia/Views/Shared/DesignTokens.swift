import SwiftUI

// The measurements, in one place, so there is a grammar rather than a habit.
//
// Before this the view layer used three corner radii on no ladder at all — 7,
// 9 and 12 — and fourteen distinct spacing values chosen a view at a time.
// `Scripts/design-audit.sh` now refuses a raw number in either position, which
// is what keeps the grammar closed rather than merely tidy today.
//
// See docs/DESIGN.md for which of the reference system's rules these come from
// and which were rejected for conflicting with a macOS convention.
extension Theme {

  /// The 8pt ladder.
  ///
  /// The reference permits sub-base values "for tight typographic adjustments"
  /// and reserves the ladder for structure. That is exactly the split here:
  /// ``tiny`` and ``snug`` set a caption against the line above it; everything
  /// that separates one component from another comes from the ladder.
  enum Space {
    /// A caption directly under the line it belongs to.
    static let tiny: Double = 2
    /// A glyph against its label.
    static let snug: Double = 6

    static let xs: Double = 4
    static let s: Double = 8
    static let m: Double = 12
    static let l: Double = 16
    static let xl: Double = 20
    static let xxl: Double = 24
    /// The air a whole section gets.
    static let section: Double = 32
  }

  /// The radius grammar: four steps, and nothing between them.
  ///
  /// The values are the reference's own ladder. `Capsule` is the fifth step and
  /// is reserved for what a capsule means here — a status chip — rather than
  /// used as a button shape, because on this platform a pill-shaped button
  /// reads as a web page.
  enum Radius {
    /// An inline chip of text.
    static let xs: CGFloat = 5
    /// A compact control or a well.
    static let s: CGFloat = 8
    /// A card.
    static let m: CGFloat = 11
    /// A container that holds cards.
    static let l: CGFloat = 18
  }

  /// The size a borderless glyph button occupies.
  ///
  /// A `Button` whose label is an `Image` is otherwise exactly as big as the
  /// glyph, which on a copy button is about ten points square. The generous
  /// target is the reference's rule and the platform's; this is the number
  /// that keeps them.
  static let glyphTarget: CGFloat = 22

  /// How wide a paragraph, and the controls that belong beside it, may run.
  ///
  /// A line of prose stops being readable before it stops fitting. The settings
  /// window gives a page 760 points, and a sentence handed all of it is a line
  /// the eye loses its place returning from — so the footers under
  /// ``SettingsSection``, and the cards that are not tables, stop here instead.
  ///
  /// It is named rather than repeated because four surfaces line up against it
  /// and each used to carry its own number: 620 in the pane header, 640 in
  /// Remote Access, and two more guesses besides. Two columns that almost line
  /// up read as a mistake, which is what those 20 points were.
  static let measure: Double = 620
}

extension View {
  /// Gives a borderless glyph button a target worth aiming at.
  func glyphButton() -> some View {
    frame(width: Theme.glyphTarget, height: Theme.glyphTarget)
      .contentShape(.rect)
  }
}
