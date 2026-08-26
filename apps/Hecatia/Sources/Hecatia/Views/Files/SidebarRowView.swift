import AppKit

/// Draws a folder row's selection.
///
/// AppKit's own source-list selection did not survive being put over a
/// transparent background: the selected row came out as a flat black bar with
/// the folder's name invisible on it, and the cell was never told it was
/// selected — the symbol kept its accent tint, so `backgroundStyle` had stayed
/// `.normal` while something else painted the bar.
///
/// Drawing it here is a few lines and cannot composite wrongly: the system's
/// own selection colours, the emphasized one only while the window is the one
/// being typed into, and `backgroundStyle` set to match so the cell above
/// colours its text for the background it is actually on.
final class SidebarRowView: NSTableRowView {
  override func drawSelection(in dirtyRect: NSRect) {
    guard selectionHighlightStyle != .none, isSelected else { return }
    let colour = isEmphasized
      ? NSColor.selectedContentBackgroundColor
      : NSColor.unemphasizedSelectedContentBackgroundColor
    colour.setFill()
    // The inset and the radius a source list uses, so it sits in the sidebar
    // the way every other one does.
    let shape = NSBezierPath(
      roundedRect: bounds.insetBy(dx: Theme.Space.xs, dy: 0),
      xRadius: Theme.Radius.s, yRadius: Theme.Radius.s)
    shape.fill()
  }

  override var isEmphasized: Bool {
    didSet { updateCellBackgroundStyle() }
  }

  override var isSelected: Bool {
    didSet { updateCellBackgroundStyle() }
  }

  private func updateCellBackgroundStyle() {
    let style: NSView.BackgroundStyle = (isSelected && isEmphasized) ? .emphasized : .normal
    for view in subviews {
      (view as? NSTableCellView)?.backgroundStyle = style
    }
  }
}

#if DEBUG
import SwiftUI

/// A ``SidebarRowView`` with a real ``SidebarCell`` in it, which is the only
/// arrangement that shows what it does: the row paints the fill and tells the
/// cell what background its text is on.
private struct SidebarRowPreview: NSViewRepresentable {
  let text: String
  var selected = true
  /// False for a window that is not the one being typed into: the fill goes to
  /// the unemphasized grey, and the name has to stay legible on that too.
  var emphasized = true

  func makeNSView(context: Context) -> SidebarRowView {
    let row = SidebarRowView()
    let cell = SidebarCell()
    cell.configure(text: text, symbol: "folder", tint: .controlAccentColor, secondary: false)
    cell.translatesAutoresizingMaskIntoConstraints = false
    // Added before the flags below are set: each of them walks the subviews to
    // hand the background style down, and a cell that is not there yet is not
    // told.
    row.addSubview(cell)
    NSLayoutConstraint.activate([
      cell.leadingAnchor.constraint(equalTo: row.leadingAnchor),
      cell.trailingAnchor.constraint(equalTo: row.trailingAnchor),
      cell.topAnchor.constraint(equalTo: row.topAnchor),
      cell.bottomAnchor.constraint(equalTo: row.bottomAnchor),
    ])
    row.isSelected = selected
    row.isEmphasized = emphasized
    return row
  }

  func updateNSView(_ row: SidebarRowView, context: Context) {
    row.isSelected = selected
    row.isEmphasized = emphasized
  }
}

#Preview("A selected row") {
  SidebarRowPreview(text: "notes")
    .frame(width: 230, height: 24)
}

#Preview("Selected, window in the background") {
  SidebarRowPreview(text: "notes", emphasized: false)
    .frame(width: 230, height: 24)
}

#Preview("Not selected") {
  // Nothing of its own is drawn at all: `drawSelection` returns early, and
  // what shows is the sidebar's material.
  SidebarRowPreview(text: "notes", selected: false)
    .frame(width: 230, height: 24)
}
#endif
