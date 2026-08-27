import SwiftUI

/// `trust add` — admitting one device by its key.
struct TrustDeviceSheet: View {
  @Environment(NodeStore.self) private var node
  @Environment(\.dismiss) private var dismiss

  @State private var key = ""
  @State private var note = ""
  @State private var address = ""
  @State private var showAdvanced = false

  private var isValid: Bool { Anchor.isDeviceKey(key.trimmingCharacters(in: .whitespaces)) }

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.l) {
      Text("Trust a Device").font(.title3.weight(.semibold))
      Text("Paste the device key from the other machine — it is the first thing `synch id` prints there. Trust is one-directional, so that machine must do the same for this one.")
        .font(.callout).foregroundStyle(Theme.muted)
        .fixedSize(horizontal: false, vertical: true)

      VStack(alignment: .leading, spacing: Theme.Space.xs) {
        TextField("Device key", text: $key)
          .textFieldStyle(.roundedBorder).font(Theme.Font.mono(.callout))
        if !key.isEmpty && !isValid {
          Text("A device key is 52 characters of z-base-32.")
            .font(.caption).foregroundStyle(Theme.danger)
        }
      }

      TextField("Note (optional)", text: $note).textFieldStyle(.roundedBorder)

      DisclosureGroup("Advanced", isExpanded: $showAdvanced) {
        VStack(alignment: .leading, spacing: Theme.Space.xs) {
          TextField("Direct address, HOST:PORT (optional)", text: $address)
            .textFieldStyle(.roundedBorder).font(Theme.Font.mono(.subheadline))
          // There used to be a "Publish under this name" field here, sending
          // `TrustAdd.as_origin`. The daemon deleted that field: a device is
          // trusted by its key, and the name — if it has one — comes from a
          // membership zone. Naming one by hand is no longer a thing that can
          // be done, so the field is gone rather than left to do nothing.
          Text("This device will appear under its key until a membership zone names it.")
            .font(.caption).foregroundStyle(Theme.muted)
        }
        .padding(.top, Theme.Space.snug)
      }
      .font(.callout)

      HStack {
        Spacer()
        Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Trust") { add() }.keyboardShortcut(.defaultAction).disabled(!isValid)
      }
    }
    .padding(Theme.Space.xxl).frame(width: 520)
  }

  private func add() {
    let trimmed = key.trimmingCharacters(in: .whitespaces)
    node.enqueue {
      await node.run(
        Operations.require("trust.add"),
        Cmd.trustAdd(key: trimmed, note: note, addr: address),
        commandLine: "synch trust add \(Shell.quote(trimmed))")
    }
    dismiss()
  }
}

#if DEBUG
#Preview("Trust a device") {
  TrustDeviceSheet().environment(NodeStore.preview())
}
#endif
