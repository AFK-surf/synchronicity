import SwiftUI
import QuickLook

/// Explicit operator pins.
///
/// Shows operator pins only. `pin ls` reports every object anything holds now
/// — a replicating folder's claims are rows in the same table, and one space
/// can be four hundred thousand of them — so ``NodeStore`` filters them out
/// before they get here. Listing them would bury the handful someone actually
/// chose under a wall of bare hashes, and `pin rm` refuses every one of them.
struct PinsSection: View {
  @Environment(NodeStore.self) private var node
  @Environment(\.openWindow) private var openWindow
  @Binding var confirmation: ConfirmationRequest?
  @State private var selection: PinEntry.ID?
  @State private var quickLookURL: URL?

  /// A `Table` brings no height with it, and the
  /// window this is on can no longer be resized to give it one.
  private let tableHeight: CGFloat = 200

  var body: some View {
    SettingsSection("Kept Offline", footer: footer, warnings: node.parseWarnings[.pins] ?? []) {
      BorderedTable {
        table
      } actions: {
        // Pinning is chosen against a file, and the file is in the browser —
        // which is what the empty state below has always said to do. A ＋ that
        // opens that window is the shortest true answer; there is no target to
        // name from here.
        TableActionButton(symbol: "plus", name: "Keep a File Offline…") {
          openWindow(id: "files")
        }
        TableActionButton(symbol: "minus", name: "Stop Keeping…") {
          if let pin = selected { requestUnpin(pin) }
        }
        .disabled(selected == nil)
        Spacer()
        // Reading by content root, which is the only way to get at an object no
        // current entry names — most of what an archive replica holds. `pin ls`
        // is the one place the daemon prints a root at full width, so it is the
        // one place these can be offered: `status` and `log` cut it to 16 hex
        // and `parse_root` wants all 64 (DAEMON-ISSUES D6).
        Button("Quick Look") { if let pin = selected { preview(pin) } }
          .disabled(selected == nil)
        Button("Save a Copy…") {
          if let pin = selected { node.saveByRoot(pin.root, name: name(for: pin)) }
        }
        .disabled(selected == nil)
        Button("Refresh") { Task { await node.refresh([.pins]) } }
      }
    }
    .quickLookPreview($quickLookURL)
  }

  @ViewBuilder private var table: some View {
    if node.loading.contains(.pins), node.pins.isEmpty {
      ProgressView().controlSize(.small)
        .frame(maxWidth: .infinity).frame(height: tableHeight)
    } else if node.pins.isEmpty {
      ContentUnavailableView(
        "Nothing pinned", systemImage: "pin.slash",
        description: Text(
          node.heldByReplicas > 0
            ? "Choose a file in the Files window and click Keep Offline to hold its bytes here. \(node.heldByReplicas) other objects are held on this Mac by a replicating space — see Spaces."
            : "Choose a file in the Files window and click Keep Offline to hold its bytes here."))
        // A floor rather than a fixed height, for the reason this section
        // records: a fixed one clips an empty state that wants more room, and
        // this one grows by a line whenever a replicating folder is holding
        // objects of its own.
        .frame(maxWidth: .infinity, minHeight: tableHeight)
    } else {
      Table(node.pins, selection: $selection) {
        TableColumn("Contents") { pin in
          Text(String(pin.root.prefix(16)) + "…")
            .font(Theme.Font.mono(.subheadline)).textSelection(.enabled).help(pin.root)
        }
        .width(min: 130, ideal: 160, max: 200)
        TableColumn("Size") { pin in
          Text(pin.size).font(.caption).foregroundStyle(Theme.muted).monospacedDigit()
        }
        .width(min: 70, ideal: 90, max: 130)
        TableColumn("Also held by") { pin in
          // Worth its own column because it changes what Stop Keeping does:
          // with a replica holding the same root, removing the operator pin
          // succeeds and frees nothing.
          if pin.hasOtherHolders {
            Text(pin.holders.replacingOccurrences(of: "operator, ", with: ""))
              .font(.caption).foregroundStyle(Theme.muted)
              .lineLimit(1).truncationMode(.middle).help(pin.holders)
          } else {
            Text("—").font(.caption).foregroundStyle(Theme.muted)
          }
        }
        .width(min: 80, ideal: 130, max: 190)
        // The column left without a ceiling: paths are the longest thing in
        // the table and the only ones worth the leftover width.
        TableColumn("What names it") { pin in
          Text(pin.paths).font(.caption).foregroundStyle(Theme.muted)
            .lineLimit(1).truncationMode(.middle)
            .textSelection(.enabled).help(pin.paths)
        }
      }
      .frame(height: tableHeight)
      .contextMenu(forSelectionType: PinEntry.ID.self) { ids in
        if let pin = node.pins.first(where: { ids.contains($0.id) }) {
          Button("Quick Look") { preview(pin) }
          Button("Save a Copy…") { node.saveByRoot(pin.root, name: name(for: pin)) }
          Divider()
          Button("Stop Keeping…", role: .destructive) { requestUnpin(pin) }
        }
      }
    }
  }

  /// The sentence under the table, plus the count of what this table is not
  /// showing. A replica's claims are held on this Mac too and cannot be
  /// removed here, and that is the whole reason the number is worth printing.
  private var footer: String {
    var text = "A pin holds one object's bytes on this Mac even when nothing else needs them. To hold every version of a whole space, use Replication in Spaces."
    if node.heldByReplicas > 0, !node.pins.isEmpty {
      text += " \(node.heldByReplicas) more objects are held here by a replicating space; they are not pins and cannot be removed here."
    }
    return text
  }

  private func preview(_ pin: PinEntry) {
    Task { quickLookURL = await node.readByRoot(pin.root, name: name(for: pin)) }
  }

  /// What to call the file once it is out of the object store.
  ///
  /// The paths column is what names the object *now*; an archived version may
  /// be named by nothing at all, and then the root is the only name it has.
  private func name(for pin: PinEntry) -> String {
    let first = pin.paths.split(separator: " · ").first.map(String.init) ?? ""
    guard !first.isEmpty, !first.hasPrefix("(") else { return String(pin.root.prefix(12)) }
    return (first as NSString).lastPathComponent
  }

  private var selected: PinEntry? {
    selection.flatMap { id in node.pins.first { $0.id == id } }
  }

  private func requestUnpin(_ pin: PinEntry) {
    let root = pin.root
    // Say which of the two things this actually does. With another holder on
    // the same root — a replicating folder — the pin goes and the bytes stay,
    // and the old sentence promised the opposite. The daemon reports what
    // remains in its own reply, which the app shows in the transcript.
    let consequence = pin.hasOtherHolders
      ? "The pin goes, but a replicating space still holds these bytes, so nothing is freed on this Mac yet. They go when that space releases them."
      : "The bytes become eligible for collection when nothing else needs them. They are not deleted now, and any file that still names them keeps working."
    confirmation = ConfirmationRequest(
      title: "Stop keeping this offline?",
      consequence: consequence,
      verb: "Stop Keeping",
      gate: .confirm,
      commandLine: "synch pin rm \(root)",
      perform: {
        node.enqueue {
          await node.run(
            Operations.require("pin.rm"), Cmd.pinRm(root),
            commandLine: "synch pin rm \(root)")
        }
      }
    )
  }
}

#if DEBUG
#Preview("Kept offline") {
  // The second pin is held by a replica as well, which is the whole reason
  // "Also held by" is a column: Stop Keeping succeeds on that row and frees
  // nothing.
  PinsSection(confirmation: .constant(nil))
    .environment(NodeStore.preview())
    .padding(Theme.Space.xl)
    .frame(width: 760)
}

#Preview("Nothing pinned") {
  PinsSection(confirmation: .constant(nil))
    .environment(NodeStore.preview(pins: []))
    .padding(Theme.Space.xl)
    .frame(width: 760)
}
#endif
