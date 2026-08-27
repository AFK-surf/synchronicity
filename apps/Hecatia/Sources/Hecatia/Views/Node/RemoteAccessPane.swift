import SwiftUI

/// The control-plane tunnel, and the separate `synch-s3` gateway under it.
struct RemoteAccessPane: View {
  @Environment(NodeStore.self) private var node
  @Binding var confirmation: ConfirmationRequest?
  @State private var addingBucket = false
  @State private var addingKey = false
  @State private var newSecret: NewAccessKey?

  private var enabled: Bool { node.cloud.enabled ?? true }

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: Theme.Space.section) {
        // No name of its own: the sidebar already says Remote Access, and the
        // toggle under it says the same thing again.
        SettingsSection(
          footer: "Whether the control plane may reach this Mac to browse its spaces from a dashboard. On by default. Which spaces a dashboard may browse is the control plane\u{2019}s decision, not this Mac\u{2019}s \u{2014} nothing is uploaded anywhere.",
          warnings: node.parseWarnings[.cloud] ?? []
        ) {
          Toggle("Allow remote browsing", isOn: Binding(get: { enabled }, set: { toggle($0) }))
        }

        SettingsSection(
          "Domains",
          footer: "One row per endpoint rather than per domain, so a domain served by two edges is two rows and a failing replica is a line of its own. The daemon records when a state last changed and does not print it, so a row can only say when this app first saw the state it is in."
        ) {
          domains
        }

        GatewaySection(
          addingBucket: $addingBucket,
          addingKey: $addingKey,
          confirmation: $confirmation)
      }
      .padding(Theme.Space.xl)
    }
    .sheet(isPresented: $addingBucket) { BucketSheet() }
    .sheet(isPresented: $addingKey) { AccessKeySheet { newSecret = $0 } }
    .sheet(item: $newSecret) { SecretShownOnceSheet(key: $0) }
    // No `.task` fetching `.cloud` or `.s3` here: the settings window already
    // refreshes `pane.topics` when this page is shown, so this was the same
    // fetch twice on every visit.
  }

  /// The attach state, in a box with the button that re-reads it.
  ///
  /// Rows rather than a `Table`: each is as tall as the daemon's own wording
  /// makes it, and a row that carries an error is two lines taller than one
  /// that does not.
  private var domains: some View {
    BorderedTable {
      VStack(alignment: .leading, spacing: Theme.Space.m) {
        ForEach(node.cloud.domains) { domain in
          VStack(alignment: .leading, spacing: Theme.Space.tiny) {
            Text(domain.domain)
              .font(Theme.Font.mono(.subheadline))
              .lineLimit(1).truncationMode(.middle)
              .help(domain.domain).textSelection(.enabled)
            Text(domain.detail)
              .font(.caption)
              .foregroundStyle(domain.lastError == nil ? Theme.muted : Theme.danger)
              .fixedSize(horizontal: false, vertical: true)
              .textSelection(.enabled)
            // Said in these words because it is a weaker fact than the one the
            // daemon has: this app can only report when it first saw the state.
            if let since = node.observed.since("cloud/\(domain.id)") {
              Text("unchanged since \(since.formatted(date: .omitted, time: .shortened)), when this app started watching")
                .font(.caption2).foregroundStyle(Theme.muted)
            }
          }
        }
        // The empty state arrives on the progress channel rather than as a
        // line — the only status in this family that does — so it is read from
        // there instead of vanishing.
        ForEach(node.cloud.notes, id: \.self) { note in
          Text(note).font(.callout).foregroundStyle(Theme.muted)
            .fixedSize(horizontal: false, vertical: true)
        }
        if node.cloud.domains.isEmpty, node.cloud.notes.isEmpty {
          Text("Nothing has attached yet.")
            .font(.callout).foregroundStyle(Theme.muted)
        }
      }
      .padding(Theme.Space.m)
      .frame(maxWidth: .infinity, alignment: .leading)
    } actions: {
      Button("Refresh") { Task { await node.refresh([.cloud]) } }
    }
  }

  private func toggle(_ on: Bool) {
    confirmation = ConfirmationRequest(
      title: on ? "Allow remote browsing?" : "Stop remote browsing?",
      consequence: on
        ? "This Mac answers the control plane\u{2019}s requests again. Nothing is uploaded anywhere; the control plane asks and this Mac serves."
        : "This Mac stops answering the control plane and drops any open tunnel. Local sharing between your own devices is unaffected.",
      verb: on ? "Allow" : "Stop",
      gate: .confirm,
      isDestructive: !on,
      perform: {
        node.enqueue {
          let operation = Operations.require(on ? "cloud.enable" : "cloud.disable")
          await node.run(operation, on ? Cmd.cloudEnable : Cmd.cloudDisable)
        }
      }
    )
  }
}

#if DEBUG
#Preview("Remote access") {
  RemoteAccessPane(confirmation: .constant(nil))
    .environment(NodeStore.preview())
    .frame(width: 760, height: 560)
}

#Preview("Nothing published") {
  // No buckets and no keys: both gateway tables stand empty, and each says
  // what its own emptiness costs.
  RemoteAccessPane(confirmation: .constant(nil))
    .environment(NodeStore.preview(buckets: [], keyIDs: []))
    .frame(width: 760, height: 560)
}

#Preview("Remote browsing off") {
  // The switch off and nothing attached — the state a Mac is in between being
  // told to stop and being told to start again.
  RemoteAccessPane(confirmation: .constant(nil))
    .environment(NodeStore.preview(cloud: CloudState(enabled: false)))
    .frame(width: 760, height: 560)
}

#Preview("Larger text") {
  // The footers are what grow, and this page has four of them: it is the page
  // most likely to outgrow the fixed window and scroll.
  RemoteAccessPane(confirmation: .constant(nil))
    .environment(NodeStore.preview())
    .dynamicTypeSize(.accessibility1)
    .frame(width: 760, height: 560)
}
#endif
