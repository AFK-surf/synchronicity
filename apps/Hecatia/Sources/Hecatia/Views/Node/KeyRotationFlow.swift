import SwiftUI

/// The four ordered steps, with the safety in the enabling rather than in a
/// dialog.
///
/// The card carries no title of its own any more: the ``SettingsSection``
/// around it names the procedure and explains it underneath, which is where
/// every other block on the page puts those two things.
struct KeyRotationFlow: View {
  @Environment(NodeStore.self) private var node
  @Binding var activating: DeviceKey?
  @Binding var confirmation: ConfirmationRequest?

  private var staged: DeviceKey? { node.deviceKeys.first { $0.state == .staged } }
  private var retiring: [DeviceKey] { node.deviceKeys.filter { $0.state == .retiring } }

  var body: some View {
    GroupBox {
      VStack(alignment: .leading, spacing: Theme.Space.m) {
        RotationStep(
          number: 1, title: "Generate a new key",
          done: staged != nil || !retiring.isEmpty,
          detail: "Creates a second key alongside the current one. Nothing changes for anyone yet."
        ) {
          Button("Generate") { generate() }
            .disabled(staged != nil)
        }

        RotationStep(
          number: 2, title: "Publish it where the other devices look",
          done: false,
          detail: "If you use a membership zone, update its record. If you trust devices individually, add the new key on each of them."
        ) {
          if let staged {
            Button("Copy New Key") { copy(staged.key) }
          }
        }

        RotationStep(
          number: 3, title: "Check that they have it",
          done: false,
          detail: "Ask each device what it holds. Do not go further until the count is everybody."
        ) {
          Button("Ask the Other Devices…") { askPeers() }
            .disabled(node.askingPeersAboutKeys)
        }

        RotationStep(
          number: 4, title: "Switch signing over, then retire the old key",
          done: false,
          detail: "Retiring deletes the old secret. There is no undo and no backup."
        ) {
          if let staged {
            Button("Switch to the New Key") { activating = staged }
          }
          ForEach(retiring) { key in
            Button("Retire \(String(key.key.prefix(8)))…", role: .destructive) { requestRetire(key) }
              .disabled(!node.advancedUnlocked)
          }
        }

        AdvancedToggle()
      }
      .padding(Theme.Space.s)
    }
  }

  private func generate() {
    node.enqueue {
      // No refresh here: `run` already refreshes what the operation
      // declares as its dirties, and `key.rotate` declares exactly
      // these two — so this asked the daemon for them twice.
      await node.run(Operations.require("key.rotate"), Cmd.keyRotate)
    }
  }

  private func copy(_ key: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(key, forType: .string)
  }

  private func askPeers() {
    node.enqueue { await node.askPeersAboutKeys() }
  }

  private func requestRetire(_ key: DeviceKey) {
    confirmation = ConfirmationRequest(
      title: "Retire this key?",
      consequence: "The secret is deleted. This Mac can never sign or serve under this key again, and its endpoint closes. There is no undo and no backup — if any device still has only this key bound, it will stop accepting anything this Mac publishes.",
      verb: "Retire",
      gate: .typed,
      typedPhrase: "retire",
      commandLine: "synch key retire \(key.key)",
      perform: {
        node.enqueue {
          await node.run(
            Operations.require("key.retire"), Cmd.keyRetire(key.key),
            commandLine: "synch key retire \(key.key)")
        }
      }
    )
  }
}

#if DEBUG
#Preview("Replacing a key") {
  // A key is already staged, which is the middle of the procedure: step 1 is
  // done and steps 2 to 4 have their controls. The state before it — Generate
  // on its own — needs a store whose device keys are only the active one.
  //
  // `Theme.measure` is the width the page gives this card, and the window is
  // fixed, so it is the only width the flow is ever drawn at.
  KeyRotationFlow(activating: .constant(nil), confirmation: .constant(nil))
    .environment(NodeStore.preview())
    .padding(Theme.Space.xl)
    .frame(width: Theme.measure)
}

#Preview("Operations that cannot be undone shown") {
  // Step 4's Retire is dead until this box is ticked, and the confirmation
  // behind it is still the typed one. Moving the page into the settings window
  // changed where the flow is drawn and nothing about what it lets through.
  let store = NodeStore.preview()
  store.advancedUnlocked = true
  return KeyRotationFlow(activating: .constant(nil), confirmation: .constant(nil))
    .environment(store)
    .padding(Theme.Space.xl)
    .frame(width: Theme.measure)
}

#Preview("Larger text") {
  // Every step's explanation shares its line with the step's buttons, so this
  // is where the four of them wrap badly together or not at all.
  KeyRotationFlow(activating: .constant(nil), confirmation: .constant(nil))
    .environment(NodeStore.preview())
    .dynamicTypeSize(.accessibility1)
    .padding(Theme.Space.xl)
    .frame(width: Theme.measure)
}
#endif
