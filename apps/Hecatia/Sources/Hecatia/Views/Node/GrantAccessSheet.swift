import SwiftUI

/// `delegate add` — space-scoped, expiring access for one device.
struct GrantAccessSheet: View {
  @Environment(NodeStore.self) private var node
  @Environment(\.dismiss) private var dismiss

  @State private var key = ""
  @State private var chosen: Set<String> = []
  /// The ticked spaces the device may read but not publish into.
  @State private var readOnly: Set<String> = []
  @State private var duration = "7d"
  @State private var note = ""

  private var isValid: Bool {
    Anchor.isDeviceKey(key.trimmingCharacters(in: .whitespaces)) && !chosen.isEmpty
  }

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.l) {
      Text("Grant Access").font(.title3.weight(.semibold))
      Text("The device sees only the spaces you tick, down to the filenames. It cannot pass the access on. A read-only space is shown to it in full and refuses its changes.")
        .font(.callout).foregroundStyle(Theme.muted)
        .fixedSize(horizontal: false, vertical: true)

      TextField("Device key", text: $key)
        .textFieldStyle(.roundedBorder).font(Theme.Font.mono(.callout))

      VStack(alignment: .leading, spacing: Theme.Space.xs) {
        Text("Spaces").font(.caption).foregroundStyle(Theme.muted)
        ForEach(node.spaces) { space in
          HStack {
            Toggle(space.id, isOn: Binding(
              get: { chosen.contains(space.id) },
              set: { on in
                if on { chosen.insert(space.id) } else {
                  chosen.remove(space.id)
                  readOnly.remove(space.id)
                }
              }
            ))
            .toggleStyle(.checkbox)
            Spacer()
            Toggle("Read-only", isOn: Binding(
              get: { readOnly.contains(space.id) },
              set: { on in if on { readOnly.insert(space.id) } else { readOnly.remove(space.id) } }
            ))
            .toggleStyle(.checkbox)
            .disabled(!chosen.contains(space.id))
            .accessibilityLabel("\(space.id) read-only")
          }
        }
        if node.spaces.isEmpty {
          Text("This Mac has no spaces to grant yet.").font(.caption).foregroundStyle(Theme.muted)
        }
      }

      HStack(spacing: Theme.Space.s) {
        Text("Expires in").font(.callout)
        TextField("7d", text: $duration).textFieldStyle(.roundedBorder).frame(width: 80)
          .accessibilityLabel("Expires in")
        Text("e.g. 30m, 12h, 7d").font(.caption).foregroundStyle(Theme.muted)
      }

      TextField("Note (optional)", text: $note).textFieldStyle(.roundedBorder)

      HStack {
        Spacer()
        Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Grant") { grant() }.keyboardShortcut(.defaultAction).disabled(!isValid)
      }
    }
    .padding(Theme.Space.xxl).frame(width: 500)
  }

  private func grant() {
    let trimmed = key.trimmingCharacters(in: .whitespaces)
    // A space is read-write or read-only, never both: the daemon refuses a
    // grant naming one twice, so the split is made here.
    let readable = chosen.subtracting(readOnly).sorted()
    let readOnlySpaces = chosen.intersection(readOnly).sorted()
    let flags = readable.map { "--space \(Shell.quote($0))" }
      + readOnlySpaces.map { "--read-only \(Shell.quote($0))" }
    node.enqueue {
      await node.run(
        Operations.require("delegate.add"),
        Cmd.delegateAdd(
          key: trimmed, spaces: readable, readOnly: readOnlySpaces, until: duration, note: note),
        commandLine: "synch delegate add \(trimmed) " + flags.joined(separator: " "))
    }
    dismiss()
  }
}

#if DEBUG
#Preview("Grant access") {
  GrantAccessSheet().environment(NodeStore.preview())
}
#endif
