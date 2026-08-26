import SwiftUI

/// `mirror add`.
struct MirrorSheet: View {
  @Environment(NodeStore.self) private var node
  @Environment(\.dismiss) private var dismiss

  @State private var space = ""
  @State private var directory: URL?
  @State private var policy: VersionPolicy = .newest

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.l) {
      Text("Mirror a Space").font(.title3.weight(.semibold))
      Text("Writes the shared view of a space into a normal directory on this Mac, so other apps can open it. The directory is written to, not read from.")
        .font(.callout).foregroundStyle(Theme.muted)
        .fixedSize(horizontal: false, vertical: true)

      Picker("Space", selection: $space) {
        Text("Choose…").tag("")
        ForEach(node.spaces) { Text($0.id).tag($0.id) }
      }

      HStack(spacing: Theme.Space.m) {
        Text(directory?.path ?? "No directory chosen")
          .font(Theme.Font.mono(.subheadline)).lineLimit(1).truncationMode(.middle)
          .frame(maxWidth: .infinity, alignment: .leading)
        Button("Choose…", action: choose)
      }

      Picker("Version", selection: $policy) {
        Text("Newest").tag(VersionPolicy.newest)
        Text("Strict — skip anything with more than one version").tag(VersionPolicy.strict)
      }

      HStack {
        Spacer()
        Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Mirror") { add() }
          .keyboardShortcut(.defaultAction)
          .disabled(space.isEmpty || directory == nil)
      }
    }
    .padding(Theme.Space.xxl).frame(width: 520)
  }

  private func choose() {
    let panel = NSOpenPanel()
    panel.canChooseDirectories = true
    panel.canChooseFiles = false
    panel.prompt = "Choose"
    if panel.runModal() == .OK { directory = panel.url }
  }

  private func add() {
    guard let directory else { return }
    let path = directory.path
    let chosen = space
    let wire = policy
    node.enqueue {
      await node.run(
        Operations.require("mirror.add"),
        Cmd.mirrorAdd(space: chosen, path: path, policy: wire),
        commandLine: "synch mirror add \(chosen) \(path) --policy \(wire.wire)")
    }
    dismiss()
  }
}

#if DEBUG
#Preview("Add a mirror") {
  MirrorSheet().environment(NodeStore.preview())
}
#endif
