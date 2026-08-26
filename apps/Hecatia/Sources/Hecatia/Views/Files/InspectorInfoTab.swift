import SwiftUI

/// The Info tab: what this entry is, where it came from, and the two things
/// that can be done to it here.
struct InspectorInfoTab: View {
  @Environment(NodeStore.self) private var node
  let entry: RemoteEntry
  let model: FilesModel
  @Binding var confirmation: ConfirmationRequest?

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.l) {
      HStack(spacing: Theme.Space.m) {
        Image(systemName: entry.iconName)
          .font(.largeTitle)
          .foregroundStyle(entry.isDirectory ? Theme.accent : Theme.muted)
          .accessibilityHidden(true)
        VStack(alignment: .leading, spacing: Theme.Space.tiny) {
          Text(entry.name)
            .font(.title3.weight(.semibold))
            .lineLimit(2).truncationMode(.middle)
            .fixedSize(horizontal: false, vertical: true)
          Text(entry.kindLabel).foregroundStyle(Theme.muted).font(.callout)
        }
        Spacer(minLength: 0)
      }

      Divider()

      VStack(alignment: .leading, spacing: Theme.Space.s) {
        DetailRow(label: "Space", value: entry.space)
        DetailRow(label: "Path", value: entry.path, mono: true, copyable: entry.path)
        if !entry.isSynthesizedDirectory {
          DetailRow(label: "Size", value: entry.sizeLabel)
          DetailRow(label: "Modified", value: entry.modifiedLabel)
          DetailRow(
            label: "Device", value: node.label(forOrigin: entry.origin),
            copyable: entry.origin.isEmpty ? nil : entry.origin)
          DetailRow(label: "Published", value: "seq \(entry.seq)")
        }
        if let target = entry.symlinkTarget {
          DetailRow(label: "Links to", value: target, mono: true, copyable: target)
        }
        if let root = entry.rootHex {
          // Truncated to fit, copies in full. This is the only thing in the app
          // that hides information rather than actions, and it hides characters
          // rather than facts.
          DetailRow(
            label: "Contents", value: String(root.prefix(16)) + "…", mono: true, copyable: root)
        }
      }

      if entry.isFile {
        Divider()
        let pinned = model.isPinned(entry)
        HStack(spacing: Theme.Space.s) {
          Button("Quick Look", systemImage: "eye", action: preview)
          Button(
            pinned ? "Stop Keeping Offline" : "Keep Offline",
            systemImage: pinned ? "pin.slash" : "pin",
            action: togglePin)
          .help(pinned
            ? "Let these bytes be reclaimed when nothing else needs them"
            : "Hold these bytes on this Mac even if nothing else needs them")
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
      }
    }
  }

  private func preview() {
    model.requestPreview(entry)
  }

  private func togglePin() {
    confirmation = model.pinRequest(entry, pinned: !model.isPinned(entry))
  }
}

#if DEBUG
/// The tab at the width the panel actually gives it.
///
/// `BrowserSplit` opens the inspector at 330pt and lets its divider down to
/// 280, and `FileInspector` pads the content by `l` — so 298pt and 248pt are
/// the two widths this tab is ever laid out in.
private struct InfoTabPreview: View {
  let entry: RemoteEntry
  var width: CGFloat = 330
  var store: NodeStore = NodeStore.preview()

  var body: some View {
    InspectorInfoTab(
      entry: entry,
      model: FilesModel.preview(rows: SampleData.rows, space: "notes", store: store),
      confirmation: .constant(nil))
      .environment(store)
      .padding(Theme.Space.l)
      .frame(width: width, alignment: .leading)
  }
}

#Preview("Info") {
  InfoTabPreview(entry: SampleData.conflicted)
}

#Preview("Info, at the narrowest panel") {
  InfoTabPreview(entry: SampleData.conflicted, width: 280)
}

#Preview("Kept offline") {
  // The pin is built around this entry's own content root: `isPinned` matches
  // an entry to a pin by root and not by path, so a pin naming the same path
  // would still read as "Keep Offline".
  InfoTabPreview(
    entry: SampleData.readme,
    store: NodeStore.preview(pins: [
      PinEntry(
        root: SampleData.readme.rootHex ?? "", size: "4218 B", holders: "operator",
        paths: "notes/README.md")
    ]))
}

#Preview("A folder") {
  // A synthesised row: no size, mtime, device or seq of its own, and neither
  // of the two actions — a prefix is not something this Mac can keep offline.
  InfoTabPreview(entry: SampleData.folder)
}

#Preview("A symlink") {
  // The "Links to" row, which nothing in `SampleData` has: a symlink's target
  // is the only content it has to show.
  InfoTabPreview(entry: RemoteEntry(
    origin: "nas@x.example", space: "notes", path: "journal/current",
    kind: .symlink, size: 0, modified: SampleData.day(-4), versions: 1,
    seq: 91, symlinkTarget: "/Volumes/Big Disk/notes/journal/2026-01-15.md"))
}
#endif
