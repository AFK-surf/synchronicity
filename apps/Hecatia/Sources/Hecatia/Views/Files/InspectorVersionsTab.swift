import SwiftUI

/// The Versions tab: whether this file's devices agree, and what to do when
/// they do not.
struct InspectorVersionsTab: View {
  @Environment(NodeStore.self) private var node
  let entry: RemoteEntry
  let model: FilesModel
  @Binding var confirmation: ConfirmationRequest?

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.l) {
      if model.versionsLoading {
        HStack(spacing: Theme.Space.s) { ProgressView().controlSize(.small); Text("Reading versions…") }
          .foregroundStyle(Theme.muted)
      } else if let set = model.versions {
        if set.isUnanimous {
          // Shown even when there is nothing wrong. This is where a user learns
          // the model — that a file is several devices' assertions and they
          // currently agree — before divergence can hurt them.
          agreementCard(set)
        } else {
          Text("\(set.versions.count) versions")
            .font(.headline)
          Text("These devices do not have the same contents for this file. Nothing has been merged — choose the one you want to keep.")
            .font(.callout).foregroundStyle(Theme.muted)
            .fixedSize(horizontal: false, vertical: true)
          ForEach(set.versions) { version in
            VersionCard(
              version: version, entry: entry, model: model, confirmation: $confirmation,
              isSelected: version.identity.hasPrefix(entry.rootHex ?? "\u{0}"))
          }
        }
      } else {
        Text("No version information.").foregroundStyle(Theme.muted)
      }
    }
  }

  private func agreementCard(_ set: PathVersions) -> some View {
    let version = set.versions[0]
    let names = version.attestors
    return VStack(alignment: .leading, spacing: Theme.Space.s) {
      Label {
        Text(agreementText(names))
          .fixedSize(horizontal: false, vertical: true)
      } icon: {
        Image(systemName: "checkmark.seal.fill").foregroundStyle(Theme.ink(Theme.online))
      }
      .font(.callout)
      if !names.isEmpty {
        FlowChips(items: names, label: node.label(forOrigin:))
      }
      Text("seq \(version.seq) · \(version.sizeLabel)")
        .font(.caption).foregroundStyle(Theme.muted)
    }
    .padding(Theme.Space.m)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(Theme.online.opacity(0.09), in: RoundedRectangle(cornerRadius: Theme.Radius.m))
  }

  private func agreementText(_ origins: [String]) -> String {
    // Through the same labeller the chips thirteen lines above use. This
    // sentence printed its origins raw, so the card read "Only
    // key:ao6bbsx33q…55m1qejcdh3m11o has this file." directly beneath a chip
    // that called the same device This Mac — the fault `VersionCard`'s
    // confirmation had, one card away.
    let names = origins.map(node.label(forOrigin:))
    switch names.count {
    case 0: return "One version of this file."
    case 1: return "Only \(names[0]) has this file."
    case 2: return "\(names[0]) and \(names[1]) have the same file."
    default:
      return "\(names.dropLast().joined(separator: ", ")) and \(names[names.count - 1]) all have the same file."
    }
  }
}

#if DEBUG
#Preview("No version information") {
  // The only state this tab can be put into from outside `FilesModel`.
  // `versions` is `private(set)` and the loading state is too, so the agreed
  // and divergent renderings are reachable only through `loadVersions` — which
  // asks a daemon, and a preview has none. The divergent card is previewed
  // where it can be built directly, in `VersionCard`.
  let store = NodeStore.preview()
  return InspectorVersionsTab(
    entry: SampleData.conflicted,
    model: FilesModel.preview(rows: SampleData.rows, space: "notes", store: store),
    confirmation: .constant(nil))
    .environment(store)
    .padding(Theme.Space.l)
    .frame(width: 330, alignment: .leading)
}
#endif
