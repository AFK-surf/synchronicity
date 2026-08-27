import SwiftUI

/// A file list row's name, icon and policy flag.
///
/// Its own `View` rather than a closure inside the `Table`, because a table
/// cell's builder runs on every layout pass and this window has two animations
/// that resize the table for a quarter of a second at a time. Everything the
/// cell needs is a stored property here, so SwiftUI can compare them and skip
/// a row that has not changed — measured, the version that rebuilt each row
/// per frame dropped one to two frames in every sidebar animation, and the
/// table was the only part of the window that did.
struct EntryNameCell: View {
  let entry: RemoteEntry
  let model: FilesModel
  /// Whether the version policy will open this row. Computed by the caller
  /// once per row rather than by every pass over the cell.
  let opensUnderPolicy: Bool
  let withheldChip: String
  let withheldHelp: String
  let spokenLabel: String

  var body: some View {
    HStack(spacing: Theme.Space.s) {
      Image(systemName: entry.iconName)
        .cellForeground(entry.isDirectory ? Theme.accent : Theme.muted)
        .frame(width: 16)
      Text(entry.name).lineLimit(1).truncationMode(.middle)
      if !opensUnderPolicy {
        // Marked rather than hidden: a policy must never make a listing look
        // smaller than it is, so the row stays and says which device does not
        // publish it. (It used to claim to dim the row, which it never did.)
        StatusChip(text: withheldChip, tint: Theme.muted)
          // The name yields, not the flag: a truncated "other de…" says less
          // than a truncated filename does.
          .fixedSize()
          .help(withheldHelp)
      }
    }
    .help(entry.path)
    .accessibilityLabel(spokenLabel)
    // Only files. `onDrag` must return a provider, so a folder row used to
    // begin a drag carrying one with no type identifiers at all — nothing
    // could accept it, and nothing said why.
    .modifier(DragOutIfFile(entry: entry, model: model))
  }
}

/// Which device publishes a row, by its name.
///
/// A `View` for the same reason as ``EntryNameCell``: the table's cell
/// builders run on every layout pass, and this one was allocating a name
/// string per row per pass through `NodeStore.label(forOrigin:)`.
struct DeviceCell: View {
  let name: String
  let key: String

  var body: some View {
    Text(name)
      .font(.caption).cellForeground(Theme.muted)
      .lineLimit(1).truncationMode(.middle)
      .help(key.isEmpty ? "No device publishes this row" : key)
  }
}

#if DEBUG
/// One cell, with the strings ``EntryTable`` computes per row spelled out
/// rather than asked of a model: this is a preview of the cell, not of the
/// policy. A folder has no size of its own, so its spoken label claims none.
@MainActor
private func previewNameCell(
  _ entry: RemoteEntry, model: FilesModel, opensUnderPolicy: Bool = true
) -> EntryNameCell {
  var spoken = [entry.name, entry.kindLabel]
  if !entry.isDirectory { spoken.append(entry.sizeLabel) }
  return EntryNameCell(
    entry: entry, model: model, opensUnderPolicy: opensUnderPolicy,
    withheldChip: "other device",
    withheldHelp: "nas@x.example does not publish this, so the version policy will not open it.",
    spokenLabel: spoken.joined(separator: ", "))
}

#Preview("A file") {
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes")
  // 320 is the Name column's ideal width, from `EntryTableView.Column.widths`.
  return previewNameCell(SampleData.readme, model: model)
    .padding(Theme.Space.s)
    .frame(width: 320)
}

#Preview("A folder") {
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes")
  return previewNameCell(SampleData.folder, model: model)
    .padding(Theme.Space.s)
    .frame(width: 320)
}

#Preview("Withheld by the policy") {
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes")
  return previewNameCell(SampleData.conflicted, model: model, opensUnderPolicy: false)
    .padding(Theme.Space.s)
    .frame(width: 320)
}

#Preview("Withheld, at the column's minimum") {
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes")
  // 200 is as narrow as the Name column goes. The chip is `.fixedSize()`, so
  // what gives here is the filename and never the flag.
  return previewNameCell(
    SampleData.entry(path: "apple-silicon-teardown-analyze.zip", size: 9_140_000),
    model: model, opensUnderPolicy: false)
    .padding(Theme.Space.s)
    .frame(width: 200)
}

#Preview("On the selected row") {
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes")
  // Both cells step back to the selection's own foreground: an accent-blue
  // glyph and a secondary-label device name are both invisible on the
  // emphasized fill, which is what `cellForeground` is for.
  return HStack(spacing: Theme.Space.m) {
    previewNameCell(SampleData.readme, model: model)
    DeviceCell(name: "This Mac", key: "laptop@cluster.example.com")
      .frame(width: 130, alignment: .leading)
  }
  .padding(Theme.Space.s)
  .frame(width: 480)
  .background(Color(nsColor: .selectedContentBackgroundColor))
  .environment(\.backgroundProminence, .increased)
}

#Preview("A device") {
  // 130 is the Device column's ideal width.
  DeviceCell(name: "nas@x.example", key: "nas@x.example")
    .padding(Theme.Space.s)
    .frame(width: 130)
}

#Preview("No device publishes it") {
  // A synthesised folder row has no origin, and `NodeStore.label(forOrigin:)`
  // answers an em dash for one.
  DeviceCell(name: "\u{2014}", key: "")
    .padding(Theme.Space.s)
    .frame(width: 130)
}
#endif
