import AppKit

/// One row of the folder list: a glyph, a name, and sometimes a second line.
///
/// Built by hand rather than from a nib, and deliberately plain: the source
/// list draws the material and the selection, so this only has to lay out the
/// text against the symbol. The measurements come from ``Theme`` through
/// ``DesignTokens`` so the AppKit list and the SwiftUI views around it agree
/// about spacing.
final class SidebarCell: NSTableCellView {
  private let symbol = NSImageView()
  private let title = NSTextField(labelWithString: "")
  private let subtitle = NSTextField(labelWithString: "")

  /// A second line under the name, for a replica's retention and checkout.
  var detail: String? {
    didSet {
      subtitle.stringValue = detail ?? ""
      subtitle.isHidden = detail == nil
      titleCentre?.isActive = detail == nil
      titleTop?.isActive = detail != nil
    }
  }

  override init(frame: NSRect) {
    super.init(frame: frame)
    build()
  }

  required init?(coder: NSCoder) {
    super.init(coder: coder)
    build()
  }

  private func build() {
    symbol.translatesAutoresizingMaskIntoConstraints = false
    symbol.imageScaling = .scaleProportionallyDown
    title.translatesAutoresizingMaskIntoConstraints = false
    title.lineBreakMode = .byTruncatingMiddle
    subtitle.translatesAutoresizingMaskIntoConstraints = false
    subtitle.lineBreakMode = .byTruncatingMiddle
    subtitle.font = .preferredFont(forTextStyle: .caption1)
    subtitle.textColor = .secondaryLabelColor
    subtitle.isHidden = true

    addSubview(symbol)
    addSubview(title)
    addSubview(subtitle)
    textField = title
    imageView = symbol

    // The title is centred on the row when it is alone and rides above the
    // detail line when there is one, so a source row and a replica row share a
    // baseline instead of the folder sitting high.
    titleCentre = title.centerYAnchor.constraint(equalTo: centerYAnchor)
    titleTop = title.topAnchor.constraint(equalTo: topAnchor, constant: Theme.Space.tiny)
    titleCentre?.isActive = true

    NSLayoutConstraint.activate([
      symbol.leadingAnchor.constraint(equalTo: leadingAnchor, constant: Theme.Space.s),
      symbol.centerYAnchor.constraint(equalTo: centerYAnchor),
      symbol.widthAnchor.constraint(equalToConstant: 18),

      title.leadingAnchor.constraint(equalTo: symbol.trailingAnchor, constant: Theme.Space.s),
      title.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -Theme.Space.s),

      subtitle.leadingAnchor.constraint(equalTo: title.leadingAnchor),
      subtitle.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -Theme.Space.s),
      subtitle.topAnchor.constraint(equalTo: title.bottomAnchor),
    ])
  }

  private var titleCentre: NSLayoutConstraint?
  private var titleTop: NSLayoutConstraint?

  /// Follows the row's selection, which is what makes a selected name legible.
  ///
  /// An `NSTableCellView` inverts its `textField` for a selected row, and
  /// pinning the colour in `configure` defeated it — the folder's name went
  /// dark-on-dark and simply vanished when the row was selected.
  override var backgroundStyle: NSView.BackgroundStyle {
    didSet {
      guard !isHeader else { return }
      let onSelection = backgroundStyle == .emphasized
      title.textColor = onSelection ? .alternateSelectedControlTextColor : .labelColor
      subtitle.textColor = onSelection
        ? .alternateSelectedControlTextColor.withAlphaComponent(0.7)
        : .secondaryLabelColor
      symbol.contentTintColor = onSelection ? .alternateSelectedControlTextColor : tint
    }
  }

  private var isHeader = false
  private var tint: NSColor?

  func configure(text: String, symbol name: String?, tint: NSColor?, secondary: Bool) {
    isHeader = secondary
    self.tint = tint
    title.stringValue = text
    // A source list's section header is smaller and heavier than its rows,
    // which is what tells them apart without a rule between them.
    title.font = secondary
      ? .systemFont(ofSize: NSFont.smallSystemFontSize, weight: .semibold)
      : .preferredFont(forTextStyle: .body)
    title.textColor = secondary ? .secondaryLabelColor : .labelColor
    if let name {
      symbol.image = NSImage(systemSymbolName: name, accessibilityDescription: nil)
      symbol.contentTintColor = tint
      symbol.isHidden = false
    } else {
      symbol.image = nil
      symbol.isHidden = true
    }
    detail = nil
  }
}

#if DEBUG
import SwiftUI

/// One ``SidebarCell``, configured the way ``FolderListView`` and
/// ``NodeShell`` configure one.
private struct SidebarCellPreview: NSViewRepresentable {
  let text: String
  var symbol: String?
  var tint: NSColor?
  var secondary = false
  var detail: String?
  /// Handed down by the row rather than chosen by the cell — see
  /// ``SidebarRowView``.
  var background: NSView.BackgroundStyle = .normal

  func makeNSView(context: Context) -> SidebarCell {
    let cell = SidebarCell()
    apply(to: cell)
    return cell
  }

  func updateNSView(_ cell: SidebarCell, context: Context) { apply(to: cell) }

  private func apply(to cell: SidebarCell) {
    cell.configure(text: text, symbol: symbol, tint: tint, secondary: secondary)
    // After `configure`, which ends by clearing it.
    cell.detail = detail
    cell.backgroundStyle = background
  }
}

#Preview("A shared folder") {
  // 230 is the browser sidebar's ideal width, and a `.default` row is one line.
  SidebarCellPreview(text: "notes", symbol: "folder", tint: .controlAccentColor)
    .frame(width: 230, height: 24)
}

#Preview("A folder with no local copy") {
  // An API source has no directory on this Mac, so it is not drawn as a
  // folder pointing at a folder that does not exist.
  SidebarCellPreview(text: "media", symbol: "shippingbox", tint: .controlAccentColor)
    .frame(width: 230, height: 24)
}

#Preview("A replica, with its policy") {
  // The detail line is what moves the title off the row's centre.
  SidebarCellPreview(text: "notes", symbol: "arrow.down.doc", detail: "notes \u{00b7} Newest")
    .frame(width: 230, height: 40)
}

#Preview("A section header") {
  // Smaller and heavier, which is the only thing separating a header from the
  // rows under it — there is no rule drawn between them.
  SidebarCellPreview(text: "Spaces", secondary: true)
    .frame(width: 230, height: 24)
}

#Preview("Selected") {
  // The fill belongs to ``SidebarRowView`` and is only stood in for here. What
  // the cell does with `.emphasized` is invert its own text, which is the
  // thing this preview is for: without it the name went dark on dark.
  SidebarCellPreview(
    text: "family photos", symbol: "folder", tint: .controlAccentColor,
    background: .emphasized)
    .frame(width: 230, height: 24)
    .background(Color(nsColor: .selectedContentBackgroundColor))
}

#Preview("A long name, narrow") {
  // 180 is the Node window's sidebar minimum, the narrowest one of these gets.
  // The title truncates in the middle rather than at the end.
  SidebarCellPreview(
    text: "Family Photos 2019 Originals", symbol: "folder", tint: .controlAccentColor)
    .frame(width: 180, height: 24)
}
#endif
