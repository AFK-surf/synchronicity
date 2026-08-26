import SwiftUI

/// A table cell whose contents are a SwiftUI view.
///
/// The table around it is AppKit because a SwiftUI `Table` could not be
/// clicked into — see ``EntryTableView``. The cells do not have to be:
/// hosting them keeps every row looking exactly as it did, drawn by the same
/// `EntryNameCell`, `StatusChip` and `Theme` the rest of the app uses, and
/// keeps the design in one place instead of two.
final class HostingCell<Content: View>: NSTableCellView {
  private var host: NSHostingView<Content>?

  func setContent(_ content: Content) {
    if let host {
      host.rootView = content
      return
    }
    let host = NSHostingView(rootView: content)
    host.translatesAutoresizingMaskIntoConstraints = false
    // The row's height is the table's to decide, and a hosting view that
    // reports its content's size fights it.
    host.sizingOptions = []
    addSubview(host)
    NSLayoutConstraint.activate([
      host.leadingAnchor.constraint(equalTo: leadingAnchor),
      host.trailingAnchor.constraint(equalTo: trailingAnchor),
      host.topAnchor.constraint(equalTo: topAnchor),
      host.bottomAnchor.constraint(equalTo: bottomAnchor),
    ])
    self.host = host
  }
}

#if DEBUG
/// A ``HostingCell`` holding one view, the way ``EntryTableView`` fills one.
private struct HostingCellPreview<Content: View>: NSViewRepresentable {
  let content: Content

  func makeNSView(context: Context) -> HostingCell<Content> {
    let cell = HostingCell<Content>()
    cell.setContent(content)
    return cell
  }

  func updateNSView(_ cell: HostingCell<Content>, context: Context) {
    // The second call is the interesting one: a reused cell swaps its root
    // view rather than adding a second hosting view under the first.
    cell.setContent(content)
  }
}

/// The Name column's cell, boxed the way the table boxes it: `AnyView` is the
/// content type ``EntryTableView`` actually instantiates.
@MainActor
private func previewHostedName(_ entry: RemoteEntry) -> AnyView {
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes")
  return AnyView(
    EntryNameCell(
      entry: entry, model: model, opensUnderPolicy: true,
      withheldChip: "other device",
      withheldHelp: "nas@x.example does not publish this, so the version policy will not open it.",
      spokenLabel: "\(entry.name), \(entry.kindLabel), \(entry.sizeLabel)"))
}

#Preview("A hosted name cell") {
  // The frame is not decoration: `sizingOptions = []` means the cell proposes
  // no size at all, so a preview has to say what the table would. 320 by a
  // `.default` row is the Name column at its ideal width.
  HostingCellPreview(content: previewHostedName(SampleData.readme))
    .frame(width: 320, height: 24)
}

#Preview("Hosted, at the column's minimum") {
  HostingCellPreview(content: previewHostedName(
    SampleData.entry(path: "apple-silicon-teardown-analyze.zip", size: 9_140_000)))
    .frame(width: 200, height: 24)
}

#Preview("A hosted chip") {
  // Any view, not just the name cell — the Versions column puts a chip in the
  // same cell type, at 70 points.
  HostingCellPreview(content: AnyView(
    StatusChip(text: "3", tint: Theme.warning, systemImage: "arrow.triangle.branch")))
    .frame(width: 70, height: 24)
}
#endif
