import SwiftUI

/// One device-group's version of a file, and the two things that can be done
/// with it.
struct VersionCard: View {
  @Environment(NodeStore.self) private var node
  let version: EntryVersion
  let entry: RemoteEntry
  let model: FilesModel
  @Binding var confirmation: ConfirmationRequest?
  let isSelected: Bool

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.s) {
      HStack(spacing: Theme.Space.s) {
        Image(systemName: version.isTombstone ? "trash" : "doc")
          .foregroundStyle(version.isTombstone ? Theme.danger : Theme.accent)
        VStack(alignment: .leading, spacing: Theme.Space.tiny) {
          Text(version.isTombstone ? "Deleted" : version.sizeLabel)
            .font(.callout.weight(.semibold))
          Text("seq \(version.seq)").font(.caption).foregroundStyle(Theme.muted)
        }
        Spacer()
        if isSelected { StatusChip(text: "Opens now", tint: Theme.accent) }
      }

      if !version.attestors.isEmpty {
        FlowChips(items: version.attestors, label: node.label(forOrigin:))
      }

      if !version.isTombstone, version.identity.count >= 16 {
        // Truncated to fit, and recoverable: the full identity is what tells
        // two versions apart, and it existed nowhere else in the app.
        DetailRow(
          label: "Contents", value: String(version.identity.prefix(16)) + "\u{2026}",
          mono: true, copyable: version.identity)
      }

      HStack(spacing: Theme.Space.s) {
        if !version.isTombstone {
          Button("Preview", action: preview)
            .disabled(!canAct)
        }
        Button(version.isTombstone ? "Adopt the Deletion" : "Use This Version", action: requestAdopt)
          .disabled(!canAct)
      }
      .buttonStyle(.bordered)
      .controlSize(.small)

      if !canAct {
        // `status` renders an attestor through `OriginId::short()`, which cuts
        // a key-identified origin to 10 of its 52 characters. That is not a
        // reference the daemon accepts, so acting on it would send a command
        // that cannot work. The app says so rather than offering a button that
        // fails.
        Label(
          "This app cannot name the device that holds this version well enough to fetch from it.",
          systemImage: "exclamationmark.triangle")
          .font(.caption).foregroundStyle(Theme.warning)
          .fixedSize(horizontal: false, vertical: true)
      }
    }
    .padding(Theme.Space.m)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: Theme.Radius.m))
    .overlay {
      RoundedRectangle(cornerRadius: Theme.Radius.m)
        .stroke(isSelected ? Theme.accent.opacity(0.5) : Theme.line, lineWidth: 1)
    }
  }

  /// Whether the version names a device in a form a command will accept.
  private var canAct: Bool { version.actionableAttestor != nil }

  private func preview() {
    model.requestPreview(entry, version: version)
  }

  private func requestAdopt() {
    // The buttons are disabled without one, so this is a guard rather than a
    // placeholder name: there is no honest sentence to write about a device
    // this app cannot address.
    guard let target = version.actionableAttestor else { return }
    // The same device the command below will contact, in the same words the
    // chips above this button use. Both halves used to be their own
    // derivation, and the sentence printed its origin raw — so a dialog asked
    // about `key:ao6bbsx33q…` two lines under a chip reading "This Mac", and
    // on a list beginning with a truncated key it asked about one device and
    // fetched from another.
    let who = node.label(forOrigin: target)
    // This Mac can be the device that serves a version — its own origin is in
    // the attestor lists, in full form, so it passes `isActionable` and the
    // buttons are offered for it. There is nothing to fetch in that case, and
    // the remote wording said there was: "This fetches This Mac’s copy of
    // notes.md, writes it into your folder, and publishes it as this Mac’s
    // own" is a round trip to yourself, and reads as a contradiction because
    // it is one.
    let isLocal = target == node.origin
    var consequence: String
    if version.isTombstone {
      consequence = isLocal
        ? "This publishes that this Mac’s copy of \(entry.name) is gone."
        : "This deletes this Mac’s copy of \(entry.name) and publishes that it is gone, adopting \(who)’s deletion."
    } else {
      consequence = isLocal
        ? "This republishes this Mac’s copy of \(entry.name) as the current version."
        : "This fetches \(who)’s copy of \(entry.name), writes it into your folder, and publishes it as this Mac’s own."
    }
    consequence += " Your current contents are pinned first, so they stay fetchable — but the restore would publish as a new version, not as the old one returning."
    confirmation = ConfirmationRequest(
      title: version.isTombstone ? "Adopt the deletion?" : "Use \(who)’s version?",
      consequence: consequence,
      verb: version.isTombstone ? "Adopt" : "Use It",
      gate: .consequence,
      isDestructive: true,
      perform: { Task { await model.adopt(version, of: entry, from: target) } }
    )
  }
}

#if DEBUG
/// Cards at the width the panel gives them, stacked the way the tab stacks
/// them: `BrowserSplit` opens the inspector at 330pt and lets its divider down
/// to 280, and `FileInspector` pads the content by `l`.
private struct VersionCardsPreview: View {
  let versions: [EntryVersion]
  var entry: RemoteEntry = SampleData.conflicted
  var width: CGFloat = 330
  var store: NodeStore = NodeStore.preview()

  var body: some View {
    let model = FilesModel.preview(rows: SampleData.rows, space: "notes", store: store)
    VStack(alignment: .leading, spacing: Theme.Space.l) {
      ForEach(versions) { version in
        VersionCard(
          version: version, entry: entry, model: model, confirmation: .constant(nil),
          // The test `InspectorVersionsTab` makes, made the same way here: the
          // version whose identity starts with the row's own content root is
          // the one this window opens.
          isSelected: version.identity.hasPrefix(entry.rootHex ?? "\u{0}"))
      }
    }
    .environment(store)
    .padding(Theme.Space.l)
    .frame(width: width, alignment: .leading)
  }
}

#Preview("Divergent") {
  VersionCardsPreview(versions: SampleData.versions.versions)
}

#Preview("Divergent, at the narrowest panel") {
  // Where the attestor chips stop fitting on one line and `FlowChips` takes
  // the column instead.
  VersionCardsPreview(versions: SampleData.versions.versions, width: 280)
}

#Preview("Deleted on one device") {
  // `(deleted)` is the identity the daemon renders for a tombstone, and the
  // card that is offering to adopt a deletion says so in every part of itself.
  VersionCardsPreview(versions: [
    EntryVersion(
      identity: "(deleted)", kind: .tombstone, size: 0, seq: 96,
      attestors: ["phone@x.example"]),
    SampleData.versions.versions[0],
  ])
}

#Preview("A device this app cannot name") {
  // `key:` and 10 of 52 characters is what `status` prints for a device with no
  // membership name, and it is not a reference the daemon accepts — so the card
  // offers nothing and says why.
  VersionCardsPreview(versions: [
    EntryVersion(
      identity: String(repeating: "d4", count: 32), kind: .file, size: 1_482_311, seq: 90,
      attestors: ["key:ybndrfg8ej"])
  ])
}

#Preview("One device this app cannot name, and one it can") {
  // The case that was never looked at: the two previews above are all-actionable
  // and all-unactionable, and between them the card's three ways of picking a
  // device always agreed. Here they did not — the buttons are offered, and both
  // the confirmation and the fetch must be about `nas@x.example`, never the
  // truncated key above it.
  VersionCardsPreview(versions: [
    EntryVersion(
      identity: String(repeating: "e5", count: 32), kind: .file, size: 1_482_311, seq: 91,
      attestors: ["key:ybndrfg8ej", "nas@x.example"])
  ])
}
#endif
