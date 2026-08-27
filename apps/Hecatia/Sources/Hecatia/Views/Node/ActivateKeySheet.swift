import SwiftUI

/// `key activate <key> [--bind HOST:PORT]`.
struct ActivateKeySheet: View {
  @Environment(NodeStore.self) private var node
  @Environment(\.dismiss) private var dismiss

  let key: DeviceKey
  @State private var bind = ""

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.l) {
      Text("Switch signing to the new key").font(.title3.weight(.semibold))
      Text("Everything this Mac publishes from now on is signed with the new key. Any device that has not learned it yet rejects what this Mac publishes until it does.")
        .font(.callout).foregroundStyle(Theme.muted)
        .fixedSize(horizontal: false, vertical: true)

      VStack(alignment: .leading, spacing: Theme.Space.xs) {
        TextField("Address for the new endpoint, HOST:PORT (optional)", text: $bind)
          .textFieldStyle(.roundedBorder).font(Theme.Font.mono(.subheadline))
        Text("Leave empty to take an ephemeral port. A deployment with a fixed address names the next one here — the old address stays with the retiring key until it is retired.")
          .font(.caption).foregroundStyle(Theme.muted)
          .fixedSize(horizontal: false, vertical: true)
      }

      CopyableCommand(commandLine)

      HStack {
        Spacer()
        Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Switch") { activate() }.keyboardShortcut(.defaultAction)
      }
    }
    .padding(Theme.Space.xxl).frame(width: 520)
  }

  private var commandLine: String {
    bind.isEmpty ? "synch key activate \(key.key)" : "synch key activate \(key.key) --bind \(Shell.quote(bind))"
  }

  private func activate() {
    let address = bind.isEmpty ? nil : bind
    let line = commandLine
    node.enqueue {
      await node.run(
        Operations.require("key.activate"),
        Cmd.keyActivate(key.key, bind: address),
        commandLine: line)
    }
    dismiss()
  }
}

#if DEBUG
#Preview("Activate a staged key") {
  ActivateKeySheet(key: DeviceKey(
    key: String(repeating: "n", count: 52), state: .staged,
    peersHolding: "1 of 3 reachable peer(s)"))
    .environment(NodeStore.preview())
}
#endif
