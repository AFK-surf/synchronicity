import SwiftUI

/// `domain set`.
struct ZoneSheet: View {
  @Environment(NodeStore.self) private var node
  @Environment(\.dismiss) private var dismiss
  @State private var domain = ""
  @State private var isDelegate = false
  @State private var loaded = false

  /// Is this Mac a delegate already?
  ///
  /// Inferred, because the daemon does not report it: `domain ls` prints the
  /// zone and its health and says nothing about `membership_expects_name`.
  /// What it does expose is the origin, and the two cases are distinguishable
  /// through it — a node the zone names publishes under that name, a delegate
  /// is key-identified. So: key-form origin plus a configured zone is a
  /// delegate, and there is nothing else it can be.
  ///
  /// It is only a default for the checkbox. The person can say otherwise, and
  /// on a node with no identity yet there is nothing to infer from, so the
  /// wording below asks rather than assumes. Recorded as a daemon gap in
  /// docs/DAEMON-ISSUES.md.
  private var looksLikeDelegate: Bool {
    guard !node.domains.isEmpty, let origin = node.status?.origin else { return false }
    return Anchor.isDeviceKey(origin)
  }

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.l) {
      Text("Use a Membership Zone").font(.title3.weight(.semibold))
      // Both halves. This used to say only that the zone must name this Mac,
      // stated as an absolute — and the exception is exactly the case the app
      // handles worst, because getting it wrong strands the node.
      Text("A DNSSEC-signed zone names every device in the cluster, so you stop admitting them one at a time. Belonging to a zone and being named by one are separate: most devices are named by theirs, and a delegate belongs to the cluster without being named by it.")
        .font(.callout).foregroundStyle(Theme.muted)
        .fixedSize(horizontal: false, vertical: true)
      HStack(spacing: Theme.Space.s) {
        Text("Zone").frame(width: 44, alignment: .trailing)
        // Named, not merely exemplified. The placeholder is a field's label on
        // screen and to VoiceOver, so this one announced itself as
        // "cluster.example.com" — the example, not the name.
        TextField("cluster.example.com", text: $domain)
          .textFieldStyle(.roundedBorder).font(Theme.Font.mono(.callout))
          .accessibilityLabel("Zone name")
      }

      VStack(alignment: .leading, spacing: Theme.Space.xs) {
        Toggle("This Mac is a delegate — the zone will not name it", isOn: $isDelegate)
        Text(isDelegate
          ? "It joins the cluster under its device key and expects no record of its own."
          : "It waits for the zone to publish a record naming it, and has no identity until that arrives.")
          .font(.caption).foregroundStyle(Theme.muted)
          .fixedSize(horizontal: false, vertical: true)
      }

      HStack {
        Spacer()
        Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Use It") { apply() }
          .keyboardShortcut(.defaultAction)
          .disabled(domain.trimmingCharacters(in: .whitespaces).isEmpty)
      }
    }
    .padding(Theme.Space.xxl).frame(width: 520)
    .onAppear {
      guard !loaded else { return }
      loaded = true
      isDelegate = looksLikeDelegate
      domain = node.domains.first?.domain ?? ""
    }
  }

  private func apply() {
    let value = domain.trimmingCharacters(in: .whitespaces)
    let delegate = isDelegate
    node.enqueue {
      await node.run(
        Operations.require("domain.set"), Cmd.domainSet(value, delegate: delegate),
        commandLine: "synch domain set \(Shell.quote(value))\(delegate ? " --delegate" : "")")
    }
    dismiss()
  }
}

#if DEBUG
#Preview("Set the zone") {
  ZoneSheet().environment(NodeStore.preview())
}
#endif
