import SwiftUI

/// Who may read and write these spaces — `trust ls`, `delegate ls`, `domain *`.
///
/// One table with a Source column rather than two: static trust, zone
/// membership and space-scoped grants are three ways of answering the same
/// question, and splitting them made the answer harder to read.
struct MembersPane: View {
  @Environment(NodeStore.self) private var node
  @Binding var confirmation: ConfirmationRequest?

  @State private var selection: Member.ID?
  @State private var addingTrust = false
  @State private var grantingAccess = false
  @State private var settingZone = false

  private var selected: Member? { node.members.first { $0.id == selection } }

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: Theme.Space.section) {
        SettingsSection(
          footer: "Devices allowed to read and write your spaces. Trust is one-directional — each side admits the other.",
          warnings: node.parseWarnings[.members] ?? []
        ) {
          BorderedTable {
            table
          } actions: {
            TableActionButton(symbol: "plus", name: "Trust a device") { addingTrust = true }
            TableActionButton(symbol: "minus", name: removalName) { requestRemoval() }
              .disabled(!canRemove)
            Spacer()
            Button("Grant Access…") { grantingAccess = true }
              .help("Give one device access to only some spaces, with an expiry")
          }
        }

        MembershipZoneCard(settingZone: $settingZone, confirmation: $confirmation)

        // Below both, because it gates one operation on each: － when the
        // selected row is trust rather than a grant, and the zone card's Stop
        // Using.
        SettingsSection(
          footer: "Stop Trusting and Stop Using a Zone stay disabled until this is on."
        ) {
          AdvancedToggle()
        }
      }
      .padding(Theme.Space.xl)
    }
    .sheet(isPresented: $addingTrust) { TrustDeviceSheet() }
    .sheet(isPresented: $grantingAccess) { GrantAccessSheet() }
    .sheet(isPresented: $settingZone) { ZoneSheet() }
  }

  private var table: some View {
    Table(node.members, selection: $selection) {
      // Every column but Spaces is bounded. One column has to absorb the
      // slack, and it is the one whose content has no length anyone can
      // predict — a grant may name a dozen folders.
      TableColumn("Device") { member in
        Text(member.key)
          .font(Theme.Font.mono(.subheadline)).lineLimit(1).truncationMode(.middle)
          .textSelection(.enabled).help(member.key)
      }
      .width(min: 120, ideal: 180, max: 240)

      TableColumn("Known as") { member in
        Text(member.origin ?? "—").lineLimit(1).truncationMode(.middle)
          .textSelection(.enabled).help(member.origin ?? "Bound under its device key alone")
      }
      .width(min: 90, ideal: 130, max: 180)

      TableColumn("Source") { member in
        StatusChip(text: member.source.rawValue, tint: tint(member.source))
      }
      .width(min: 70, ideal: 80, max: 100)

      TableColumn("Spaces") { member in
        // Rendered as the daemon joined it and never split: a folder id may
        // contain a comma, so splitting would invent scopes that do not exist.
        Text(member.scope ?? "all")
          .font(.caption).foregroundStyle(Theme.muted)
          .lineLimit(1).truncationMode(.middle)
          .textSelection(.enabled).help(member.scope ?? "all spaces")
      }

      // "State", not "Expires": `delegate ls` puts a remaining duration here
      // and `trust ls` puts a liveness verdict, and only one of those is an
      // expiry.
      TableColumn("State") { member in
        // Three states, not two. `isExpiringSoon` was computed from the
        // interval the parser already recovers and then read by nothing, so a
        // grant with an hour left drew exactly like one with a year — and the
        // one thing a person can act on before it happens was invisible.
        HStack(spacing: Theme.Space.xs) {
          if member.isExpiringSoon {
            Image(systemName: "clock.badge.exclamationmark")
              .imageScale(.small).foregroundStyle(Theme.warning)
              .accessibilityLabel("Lapses within a day")
          }
          Text(member.expiry ?? "—").font(.caption)
            .cellForeground(
              member.isDead ? Theme.danger : (member.isExpiringSoon ? Theme.warning : Theme.muted))
        }
        .help(member.isExpiringSoon
          ? "This grant lapses within a day. Renew it before it does, or the device stops being accepted."
          : (member.expiry ?? "This binding does not expire"))
      }
      .width(min: 60, ideal: 80, max: 110)
    }
    // A `Table` in a `ScrollView` has no height of its own to offer, so it is
    // given one: about six rows, which leaves the zone card on the page at 660.
    .frame(height: 220)
    .overlay {
      if node.members.isEmpty {
        Text("No devices are trusted yet.").font(.callout).foregroundStyle(Theme.muted)
      }
    }
    .contextMenu(forSelectionType: Member.ID.self) { ids in
      if let member = node.members.first(where: { ids.contains($0.id) }) {
        if member.source == .granted {
          Button("Revoke Access…", role: .destructive) { requestRevoke(member) }
        } else {
          Button("Stop Trusting…", role: .destructive) { requestUntrust(member) }
            .disabled(!node.advancedUnlocked)
          Button("Drop Just This Key…", role: .destructive) { requestDropKey(member) }
            .disabled(!node.advancedUnlocked || member.origin == nil)
            .help("Keep trusting this device, but forget this one key — the cleanup after a key rotation")
        }
        Button("Copy Device Key") {
          NSPasteboard.general.clearContents()
          NSPasteboard.general.setString(member.key, forType: .string)
        }
      }
    }
  }

  // MARK: - The － button

  /// What － does to the selected row, in words.
  ///
  /// A glyph says "remove" and nothing else, and the two removals here are not
  /// the same act: revoking a grant is a record this Mac owns, and untrusting
  /// cuts off a device and everything it granted.
  private var removalName: String {
    guard let member = selected else { return "Remove the selected device" }
    return member.source == .granted
      ? "Revoke this device’s access"
      : "Stop trusting this device"
  }

  /// Grants come off without the disclosure; trust does not. Same gate as the
  /// context menu's, which is the only other way to reach either.
  private var canRemove: Bool {
    guard let member = selected else { return false }
    return member.source == .granted || node.advancedUnlocked
  }

  private func requestRemoval() {
    guard let member = selected else { return }
    if member.source == .granted {
      requestRevoke(member)
    } else {
      requestUntrust(member)
    }
  }

  private func tint(_ source: Member.Source) -> Color {
    switch source {
    case .staticTrust: return Theme.accent
    case .zone: return Theme.online
    case .granted: return Theme.warning
    }
  }

  // MARK: - Gates

  /// What the strongest gate asks to be typed.
  ///
  /// The origin itself when it is a name someone could type, and its last
  /// eight characters when it is a device key.
  static func typeablePhrase(for origin: String) -> String {
    guard origin.hasPrefix("key:") || origin.count > 24 else { return origin }
    return String(origin.suffix(8))
  }

  private func requestUntrust(_ member: Member) {
    // The blast radius is computed, because §3.5's cascade is otherwise
    // invisible: removing an issuer cuts off every device it granted.
    let origin = member.origin ?? member.key
    let name = node.label(forOrigin: origin)
    let cascade = node.members.count(where: { $0.source == .granted && $0.issuer == member.origin })
    var consequence = "This Mac stops accepting anything \(name) publishes."
    if cascade > 0 {
      consequence += " It also cuts off \(cascade) device\(cascade == 1 ? "" : "s") that \(name) granted access to."
    }
    consequence += member.source == .zone
      ? " A zone-sourced binding comes back at the next successful zone check; removing it here is temporary."
      : " A static binding does not come back on its own."
    confirmation = ConfirmationRequest(
      title: "Stop trusting \(name)?",
      consequence: consequence,
      verb: "Stop Trusting",
      gate: .typed,
      // A phrase that can be typed. A device trusted without a published name
      // is bound under its key, so `origin` is `key:` and 52 characters of
      // z-base-32 — this gate asked the operator to type that, which is not a
      // deliberate act, it is a copy and paste. The command still carries the
      // full origin; only what has to be typed is short.
      typedPhrase: Self.typeablePhrase(for: origin),
      commandLine: "synch trust rm \(Shell.quote(origin))",
      perform: {
        node.enqueue {
          await node.run(
            Operations.require("trust.rm"), Cmd.trustRm(origin: origin, key: nil),
            commandLine: "synch trust rm \(Shell.quote(origin))")
        }
      }
    )
  }

  /// `trust rm <origin> --key <key>`: §3.4's cleanup step, which drops one
  /// binding and leaves the origin's other keys trusted.
  private func requestDropKey(_ member: Member) {
    guard let origin = member.origin else { return }
    let others = node.members.count(where: { $0.origin == origin && $0.key != member.key })
    confirmation = ConfirmationRequest(
      title: "Drop this key’s binding?",
      consequence: others > 0
        ? "\(origin) stays trusted through its \(others) other key\(others == 1 ? "" : "s"). Only this one is forgotten — the cleanup after a key rotation has finished."
        : "This is the only key bound to \(origin), so dropping it stops trusting that device entirely.",
      verb: "Drop",
      gate: .consequence,
      commandLine: "synch trust rm \(Shell.quote(origin)) --key \(member.key)",
      perform: {
        node.enqueue {
          await node.run(
            Operations.require("trust.rm"), Cmd.trustRm(origin: origin, key: member.key),
            commandLine: "synch trust rm \(Shell.quote(origin)) --key \(member.key)")
        }
      }
    )
  }

  private func requestRevoke(_ member: Member) {
    confirmation = ConfirmationRequest(
      title: "Revoke access for this device?",
      consequence: "The grant is deleted from this Mac’s own records, and every other device learns it through ordinary replication. The device keeps whatever it has already downloaded.",
      verb: "Revoke",
      gate: .confirm,
      commandLine: "synch delegate rm \(member.key)",
      perform: {
        node.enqueue {
          await node.run(
            Operations.require("delegate.rm"), Cmd.delegateRm(key: member.key),
            commandLine: "synch delegate rm \(member.key)")
        }
      }
    )
  }
}

#if DEBUG
#Preview("Members") {
  MembersPane(confirmation: .constant(nil))
    .environment(NodeStore.preview())
    .frame(width: 760, height: 560)
}

#Preview("No members") {
  // The table keeps its height and says so, rather than collapsing to a header
  // and leaving the ＋ nothing to sit under.
  MembersPane(confirmation: .constant(nil))
    .environment(NodeStore.preview(members: []))
    .frame(width: 760, height: 560)
}

#Preview("Advanced unlocked") {
  // － is dead for a trusted device until the disclosure at the foot of the page
  // is open, so this is the only state in which that half of the bar is alive.
  let store = NodeStore.preview()
  store.advancedUnlocked = true
  return MembersPane(confirmation: .constant(nil))
    .environment(store)
    .frame(width: 760, height: 560)
}
#endif
