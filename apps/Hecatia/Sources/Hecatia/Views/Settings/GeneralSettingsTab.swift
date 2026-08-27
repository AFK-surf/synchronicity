import SwiftUI

/// Where the daemon is, and the two questions the app is allowed to stop asking.
struct GeneralSettingsTab: View {
  @Environment(NodeStore.self) private var node
  @AppStorage("showTransfersAutomatically") private var showTransfers = true
  @AppStorage("confirmDeletes") private var confirmDeletes = true

  var body: some View {
    @Bindable var node = node
    Form {
      Section {
        HStack(spacing: Theme.Space.s) {
          TextField("Data folder", text: $node.dataDirectoryPath)
            .font(Theme.Font.mono(.subheadline))
            .accessibilityLabel("Data folder")
            // Typing a path does not reconnect on every keystroke — the
            // Reconnect button below does it once, deliberately.
            .onSubmit { node.connect() }
          Button("Choose…") { choose() }
        }
        Text("The folder given to `synch daemon start` — the one holding control.sock.")
          .font(.caption).foregroundStyle(Theme.muted)
        Button("Reconnect") { node.connect() }
      }
      Section {
        // Both of these did nothing at all until now — nothing read either
        // one — so they say exactly what they govern rather than gesturing at
        // it, and the second says what it does *not* govern.
        Toggle("Open the transfer list when one starts", isOn: $showTransfers)
        Toggle("Ask before deleting", isOn: $confirmDeletes)
        Text("Deleting publishes that this Mac no longer has the file. Turning this off skips that one question; the confirmations for things that cannot be undone are not affected.")
          .font(.caption).foregroundStyle(Theme.muted)
          .fixedSize(horizontal: false, vertical: true)
      }
    }
    .formStyle(.grouped)
  }

  private func choose() {
    let panel = NSOpenPanel()
    panel.canChooseDirectories = true
    panel.canChooseFiles = false
    panel.prompt = "Choose"
    if panel.runModal() == .OK, let url = panel.url {
      node.dataDirectoryPath = url.path
      node.connect()
    }
  }
}

#if DEBUG
#Preview("General") {
  GeneralSettingsTab()
    .environment(NodeStore.preview())
    .frame(width: 480, height: 420)
}

#Preview("Nothing connected") {
  // Nothing here dims when no daemon is answering, deliberately: the data
  // folder and Reconnect are the two controls this tab exists for precisely
  // when that is the state.
  GeneralSettingsTab()
    .environment(NodeStore.preview(connection: .idle, status: nil))
    .frame(width: 480, height: 420)
}

#Preview("Larger text") {
  // The Settings window fixes the width and only a minimum height, because
  // these captions grow with the user's Larger Text setting. No height here
  // either, so the preview shows how tall the form actually asks to be.
  GeneralSettingsTab()
    .environment(NodeStore.preview())
    .dynamicTypeSize(.accessibility1)
    .frame(width: 480)
}
#endif
