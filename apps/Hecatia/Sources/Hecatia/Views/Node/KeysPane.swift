import SwiftUI

/// This Mac's signing keys, and the one procedure that replaces them.
///
/// Rotation is not destructive and gets no scary dialog; it is *consequential*
/// and gets an ordered flow. Four separate buttons would let someone activate a
/// key before the other devices have seen it and strand this node — one
/// resumable procedure, which only enables retiring once the count says it is
/// safe, cannot.
struct KeysPane: View {
  @Environment(NodeStore.self) private var node
  @Binding var confirmation: ConfirmationRequest?
  @State private var selection: DeviceKey.ID?
  @State private var activating: DeviceKey?

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: Theme.Space.section) {
        keys
        rotation
        if !node.keyReport.isEmpty { report }
      }
      .padding(Theme.Space.xl)
    }
    .sheet(item: $activating) { key in ActivateKeySheet(key: key) }
  }

  /// The keys themselves, in a section with no name.
  ///
  /// The sidebar row this page is reached by already says "Identity & Keys",
  /// and a heading here would be that again, two inches lower.
  private var keys: some View {
    SettingsSection(
      footer: "The key this Mac signs with. “Seen by” stays empty until the other devices have been asked.",
      warnings: node.parseWarnings[.keys] ?? []
    ) {
      BorderedTable {
        Table(node.deviceKeys, selection: $selection) {
          // The column that absorbs the slack: a key is 52 characters and the
          // other two hold a word and a tally.
          TableColumn("Key") { key in
            HStack(spacing: Theme.Space.snug) {
              Text(key.key)
                .font(Theme.Font.mono(.subheadline)).lineLimit(1).truncationMode(.middle)
                .textSelection(.enabled).help(key.key)
              // Trusting is reciprocal — the other device has to be given this
              // one's key — and this key could not be copied anywhere in the
              // app. Every *other* device's key has had a Copy since the
              // beginning; this Mac's own had none, and inside a Table the
              // row's click handling makes drag-to-select unreliable, so even
              // selecting it was not dependable.
              CopyGlyphButton(
                value: key.key,
                help: "Copy this device key",
                accessibilityName: "Copy this device key")
            }
          }
          .width(min: 180)
          TableColumn("State") { key in
            StatusChip(text: key.state.rawValue, tint: tint(key.state))
          }
          .width(min: 70, ideal: 80, max: 110)
          TableColumn("Seen by") { key in
            Text(key.peersHolding ?? "not asked").font(.caption).foregroundStyle(Theme.muted)
              .lineLimit(1).help(key.peersHolding ?? "not asked")
          }
          .width(min: 100, ideal: 160, max: 200)
        }
        // Tall enough for what is in it, rather than 150pt of scroll view
        // nested inside the page's own scroll view — which never used the
        // window's height and gave two scrollbars to four rows.
        //
        // Held at the floor rather than allowed under it. `count * 28 + 40`
        // is under 120 for anything up to two keys — which is what a Mac
        // normally has, and it is *every* Mac before `key ls` has answered —
        // and an ideal below its own minimum is a frame SwiftUI rejects
        // whole, logging "Contradictory frame constraints specified." and
        // "Invalid frame dimension (negative or non-finite)." together on
        // every pass through this pane. Measured: it fires at 0, 1 and 2
        // keys and stops at 3, which is where 28n + 40 crosses 120.
        .frame(
          minHeight: 120,
          idealHeight: max(120, Double(node.deviceKeys.count) * 28 + 40))
        .frame(maxHeight: 320)
      } actions: {
        Spacer()
        // On the store: `key ls` dials every peer and takes minutes, and as
        // this pane's own state the spinner vanished and both buttons came
        // back the moment you looked at another pane.
        if node.askingPeersAboutKeys { ProgressView() }
        Button("Ask the Other Devices…") { askPeers() }
          .disabled(node.askingPeersAboutKeys)
          // Named honestly: it dials each device in turn and one that is
          // switched off costs the full timeout before the tally is complete.
          .help("Contacts every trusted device in turn. This can take a minute, and longer if one is switched off.")
      }
    }
  }

  /// The rotation flow, which is a procedure rather than a list.
  ///
  /// It keeps its card: the four steps are ordered and each one's controls
  /// belong to its own line, which a table of rows cannot say.
  private var rotation: some View {
    SettingsSection(
      "Replace This Mac’s Key",
      footer: "Four steps, in order. The other devices have to learn the new key before the old one can go, so a step only comes alive once the one before it is safe."
    ) {
      KeyRotationFlow(activating: $activating, confirmation: $confirmation)
    }
  }

  /// What the last round of asking returned, in the daemon's own words.
  private var report: some View {
    SettingsSection("What Each Device Answered") {
      GroupBox {
        TranscriptView(lines: node.keyReport).frame(height: 140)
      }
    }
  }

  private func tint(_ state: DeviceKey.State) -> Color {
    switch state {
    case .active: return Theme.online
    case .staged: return Theme.accent
    case .retiring: return Theme.warning
    case .unknown: return Theme.muted
    }
  }

  private func askPeers() {
    node.enqueue { await node.askPeersAboutKeys() }
  }
}

#if DEBUG
#Preview("Keys") {
  // 760 × 560 is the settings window's content side: 980 less the sidebar, and
  // 660 less the chrome a `Settings` scene puts above the page.
  KeysPane(confirmation: .constant(nil))
    .environment(NodeStore.preview())
    .frame(width: 760, height: 560)
}

#Preview("Larger text") {
  // The footers are the part that grows, and `Theme.measure` caps their line
  // length rather than their number of lines — so this is where the page has
  // to start scrolling instead of clipping.
  KeysPane(confirmation: .constant(nil))
    .environment(NodeStore.preview())
    .dynamicTypeSize(.accessibility1)
    .frame(width: 760, height: 560)
}
#endif
