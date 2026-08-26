import SwiftUI

/// Whether this Mac learns its members from a DNSSEC-signed zone, and what
/// that zone currently says.
struct MembershipZoneCard: View {
  @Environment(NodeStore.self) private var node
  @Binding var settingZone: Bool
  @Binding var confirmation: ConfirmationRequest?

  var body: some View {
    SettingsSection(
      "Membership zone",
      footer: "A DNSSEC-signed zone names the devices this Mac accepts. A binding it supplies comes back at the next successful check, so removing one by hand only lasts until then.",
      warnings: node.parseWarnings[.domains] ?? []
    ) {
      GroupBox {
        HStack(alignment: .top, spacing: Theme.Space.m) {
          state
          Spacer(minLength: Theme.Space.m)
          actions
        }
        .padding(Theme.Space.snug)
      }
    }
  }

  private var state: some View {
    VStack(alignment: .leading, spacing: Theme.Space.xs) {
      if node.domains.isEmpty {
        Text("Not using one. Devices are trusted individually.")
          .font(.caption).foregroundStyle(Theme.muted)
      } else {
        ForEach(node.domains) { domain in
          VStack(alignment: .leading, spacing: Theme.Space.tiny) {
            HStack(spacing: Theme.Space.snug) {
              Text(domain.domain).font(Theme.Font.mono(.subheadline))
                .lineLimit(1).truncationMode(.middle)
                .textSelection(.enabled).help(domain.domain)
              // Parsed since the beginning and read by nothing. It is the
              // one number that says whether a zone is actually naming
              // anybody, which is what "is this working" means here.
              if let count = domain.bindingCount {
                StatusChip(
                  text: count == 1 ? "1 device" : "\(count) devices", tint: Theme.muted)
              }
            }
            Text(domain.detail).font(.caption).foregroundStyle(
              domain.lastError == nil ? Theme.muted : Theme.ink(Theme.danger))
              .fixedSize(horizontal: false, vertical: true)
          }
        }
      }
      if let pending = node.zonePending {
        Text(pending).font(.caption).foregroundStyle(Theme.warning)
      }
    }
  }

  /// The three things that can be done to a zone, in one column of equal
  /// width.
  ///
  /// A `Grid` rather than a `VStack`: a grid cell fills its column, and the
  /// column is as wide as the longest label — so the three read as one control
  /// group at any text size, instead of three ragged buttons that happen to be
  /// stacked. A hard-coded width would have to be re-measured every time a verb
  /// changed or Larger Text was turned on.
  ///
  /// The column is only as wide as the longest label, though; a button inside
  /// it still draws at its own width and sits centred in the cell, which is
  /// what made "Check Now" float above a wider "Use a Zone…" instead of lining
  /// up with it. `maxWidth: .infinity` is what actually makes the three equal.
  ///
  /// And `fixedSize` is what keeps them where they belong. Without it the
  /// greedy cells make the *grid* greedy too: it takes everything the
  /// `Spacer` beside it would have taken, then draws its one narrow column
  /// against its own leading edge — equal-width buttons stranded in the middle
  /// of the card rather than against its trailing edge. Measured across three
  /// candidates; this is the only one that is both equal and flush.
  private var actions: some View {
    Grid(horizontalSpacing: 0, verticalSpacing: Theme.Space.snug) {
      GridRow {
        Button("Check Now") { checkNow() }
          .frame(maxWidth: .infinity)
      }
      GridRow {
        Button(node.domains.isEmpty ? "Use a Zone…" : "Change…") { settingZone = true }
          .frame(maxWidth: .infinity)
      }
      if !node.domains.isEmpty {
        GridRow {
          Button("Stop Using…", role: .destructive) { requestClearZone() }
            .frame(maxWidth: .infinity)
            .disabled(!node.advancedUnlocked)
        }
      }
    }
    .controlSize(.small)
    .fixedSize(horizontal: true, vertical: false)
  }

  private func checkNow() {
    node.enqueue {
      // `domain.refresh` declares both of these, and `.members` alone
      // is two more commands — so this was four extra round trips
      // through the daemon's global store mutex.
      await node.run(Operations.require("domain.refresh"), Cmd.domainRefresh)
    }
  }

  private func requestClearZone() {
    let origin = node.origin ?? "this Mac"
    confirmation = ConfirmationRequest(
      title: "Stop using the membership zone?",
      consequence: "At the next restart this Mac is renamed to its device key. Its published history under \(origin) is dropped from its own view and republished from the beginning, and any access it granted is revoked.",
      verb: "Stop Using",
      gate: .typed,
      typedPhrase: "clear",
      commandLine: "synch domain clear",
      perform: {
        node.enqueue {
          await node.run(Operations.require("domain.clear"), Cmd.domainClear)
        }
      }
    )
  }
}

#if DEBUG
#Preview("Membership zone") {
  // Two zones, and the second one is failing. Its NXDOMAIN is reported in the
  // same detail line the healthy zone uses for its refresh times — only the
  // colour separates them.
  MembershipZoneCard(settingZone: .constant(false), confirmation: .constant(nil))
    .environment(NodeStore.preview())
    .padding(Theme.Space.xl)
    .frame(width: 760)
}

#Preview("Not using a zone") {
  // Two buttons rather than three, and the column narrows to the wider of the
  // two verbs it still has.
  MembershipZoneCard(settingZone: .constant(false), confirmation: .constant(nil))
    .environment(NodeStore.preview(domains: []))
    .padding(Theme.Space.xl)
    .frame(width: 760)
}

#Preview("Advanced unlocked") {
  // Stop Using is dead until the disclosure at the foot of the page is open, so
  // this is the only state in which that button can be looked at alive.
  let store = NodeStore.preview()
  store.advancedUnlocked = true
  return MembershipZoneCard(settingZone: .constant(false), confirmation: .constant(nil))
    .environment(store)
    .padding(Theme.Space.xl)
    .frame(width: 760)
}

#Preview("Larger text") {
  // What the grid is for: the three verbs grow, the column grows with them, and
  // the three stay one width.
  MembershipZoneCard(settingZone: .constant(false), confirmation: .constant(nil))
    .environment(NodeStore.preview())
    .dynamicTypeSize(.accessibility1)
    .padding(Theme.Space.xl)
    .frame(width: 760)
}
#endif
