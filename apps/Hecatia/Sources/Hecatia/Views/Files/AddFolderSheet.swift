import SwiftUI

/// Add a filesystem source. Replica configuration is a separate action.
struct AddSourceSheet: View {
  @Environment(NodeStore.self) private var node
  @Environment(\.dismiss) private var dismiss

  @State private var directory: URL?
  @State private var identifier = ""

  private var suggestedID: String {
    identifier.isEmpty ? (directory?.lastPathComponent ?? "") : identifier
  }

  private var isValid: Bool {
    guard problem == nil, !suggestedID.isEmpty else { return false }
    return directory != nil
  }

  /// Why this name will not do, if it will not.
  ///
  /// The first three are the daemon's own rule for a space id. The colon is
  /// not: `validate_space` accepts one, and then every command that takes a
  /// *reference* — Versions, History, Compare, Use This Version — parses the
  /// text before a colon as a device name and fails with "bad origin",
  /// naming something the person never typed. The daemon disagrees with
  /// itself here; the app takes the narrower rule, because the wider one
  /// produces a folder whose inspector does not work.
  ///
  /// Reachable without typing anything unusual: a Finder folder whose display
  /// name contains a slash has a colon in its POSIX name, and that is what
  /// this sheet offers as the default.
  private var problem: String? {
    guard directory != nil else { return nil }
    guard !suggestedID.isEmpty else { return nil }
    if suggestedID.contains("/") { return "A space name cannot contain a slash." }
    if suggestedID.contains(":") {
      return "A space name cannot contain a colon: a colon is how a device is named when referring to a file, so Versions could not read this space's history."
    }
    if suggestedID.utf8.count > 63 { return "That name is too long — 63 bytes at most." }
    if suggestedID.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) {
      return "That name contains a character the daemon will not accept."
    }
    return nil
  }

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.l) {
      Text("Publish a Source").font(.title3.weight(.semibold))
      Text("Its files are indexed and published to every device you trust. Content retention is configured independently after the source exists.")
        .font(.callout).foregroundStyle(Theme.muted)
        .fixedSize(horizontal: false, vertical: true)

      HStack(spacing: Theme.Space.m) {
        Text(directory?.path ?? "No folder chosen")
          .font(Theme.Font.mono(.subheadline))
          .lineLimit(1).truncationMode(.middle)
          .frame(maxWidth: .infinity, alignment: .leading)
        Button("Choose…") { choose() }
      }

      VStack(alignment: .leading, spacing: Theme.Space.xs) {
        TextField("Name other devices will see", text: $identifier, prompt: Text(directory?.lastPathComponent ?? "name"))
          .textFieldStyle(.roundedBorder)
        if let problem {
          Text(problem).font(.caption).foregroundStyle(Theme.ink(Theme.danger))
            .fixedSize(horizontal: false, vertical: true)
        } else {
          Text("This name is shared across every device — it is how they refer to the same space.")
            .font(.caption).foregroundStyle(Theme.muted)
        }
      }

      HStack {
        Spacer()
        Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Add") { add() }.keyboardShortcut(.defaultAction).disabled(!isValid)
      }
    }
    .padding(Theme.Space.xxl)
    .frame(width: 480)
  }

  private func choose() {
    let panel = NSOpenPanel()
    panel.canChooseDirectories = true
    panel.canChooseFiles = false
    panel.allowsMultipleSelection = false
    panel.prompt = "Choose"
    if panel.runModal() == .OK { directory = panel.url }
  }

  private func add() {
    guard directory != nil else { return }
    let id = suggestedID
    let path = directory?.path ?? ""
    node.enqueue {
      await node.addSource(id: id, path: path)
    }
    dismiss()
  }
}

#if DEBUG
#Preview("Add space") {
  AddSourceSheet()
    .environment(NodeStore.preview())
}
#endif
