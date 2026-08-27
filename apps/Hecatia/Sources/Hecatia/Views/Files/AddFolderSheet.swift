import SwiftUI

/// `space add` — the first thing a new user does.
struct AddSpaceSheet: View {
  @Environment(NodeStore.self) private var node
  @Environment(\.dismiss) private var dismiss

  @State private var directory: URL?
  @State private var identifier = ""
  @State private var replicate = false
  @State private var policy: ReplicaPolicy = .tree
  @State private var detached = false

  private var suggestedID: String {
    identifier.isEmpty ? (directory?.lastPathComponent ?? "") : identifier
  }

  /// A detached space needs no directory, and cannot have one.
  ///
  /// The daemon's own rule: `path` is required unless `--detached` or
  /// `--replicate` is given, and a detached space is one with deliberately no
  /// local checkout — it holds the folder's content as objects and indexes
  /// nothing. It is the "dedicated replica" deployment, and the app could not
  /// create one at all.
  private var isValid: Bool {
    guard problem == nil, !suggestedID.isEmpty else { return false }
    return detached || directory != nil
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
    guard directory != nil || detached else { return nil }
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
      Text("Add a Space").font(.title3.weight(.semibold))
      Text(detached
        ? "This Mac will hold this space\u{2019}s content for the cluster without keeping a copy you can open. Nothing appears in Finder."
        : "Its files are indexed and published to every device you trust. Nothing is copied anywhere on this Mac.")
        .font(.callout).foregroundStyle(Theme.muted)
        .fixedSize(horizontal: false, vertical: true)

      if !detached {
        HStack(spacing: Theme.Space.m) {
          Text(directory?.path ?? "No folder chosen")
            .font(Theme.Font.mono(.subheadline))
            .lineLimit(1).truncationMode(.middle)
            .frame(maxWidth: .infinity, alignment: .leading)
          Button("Choose…") { choose() }
        }
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

      Divider()

      VStack(alignment: .leading, spacing: Theme.Space.xs) {
        Toggle("Also hold other devices\u{2019} versions of these files", isOn: $replicate)
        if replicate {
          Picker("Hold", selection: $policy) {
            ForEach(ReplicaPolicy.allCases, id: \.self) { Text($0.label).tag($0) }
          }
          .pickerStyle(.segmented)
          .labelsHidden()
          .accessibilityLabel("Replication policy")
          Text(policy.explanation)
            .font(.caption).foregroundStyle(Theme.muted)
            .fixedSize(horizontal: false, vertical: true)
          // Only offered with replication on, because that is the only case
          // the daemon accepts it in — a space with neither a directory nor a
          // reason to hold content is nothing at all.
          Toggle("This Mac holds the content but keeps no copy in Finder", isOn: $detached)
          if detached {
            Text("A dedicated replica. Nothing appears on disk and nothing is indexed here \u{2014} this Mac exists to hold the cluster\u{2019}s bytes.")
              .font(.caption).foregroundStyle(Theme.muted)
              .fixedSize(horizontal: false, vertical: true)
          }
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
    guard detached || directory != nil else { return }
    let id = suggestedID
    let path = directory?.path ?? ""
    let holding = replicate ? policy : nil
    let noCheckout = detached
    node.enqueue {
      await node.addSpace(id: id, path: path, detached: noCheckout, replicate: holding)
    }
    dismiss()
  }
}

#if DEBUG
#Preview("Add space") {
  AddSpaceSheet()
    .environment(NodeStore.preview())
}
#endif
