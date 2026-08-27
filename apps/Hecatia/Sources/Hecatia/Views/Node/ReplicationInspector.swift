import SwiftUI

/// One folder's replication, under the folder table.
///
/// The daemon settled the presentation rules and this follows them, because
/// getting them wrong is how a replica that is stuck reads as one that is busy
/// (`docs/REPLICATION.md` §8):
///
/// - `unreachable` is its own line, in warning colour, and is never added into
///   the backlog. Those objects have no provider; they are probably already
///   gone. The daemon has already subtracted them from `wanted`.
/// - "releases paused" replaces the releasing count rather than sitting beside
///   it, and comes first. A paused view is the difference between converging
///   and stuck, and it is the thing to read first.
/// - Claims are quoted as claims. This Mac cannot check another node's disk,
///   so a claim is never drawn as coverage.
struct ReplicationInspector: View {
  let space: Space
  let status: ReplicaStatus?
  let onConfigure: () -> Void
  let onSyncNow: () -> Void

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.m) {
      HStack(spacing: Theme.Space.s) {
        Text(space.id).font(.headline)
        if let policy = space.replicate {
          StatusChip(
            text: "Replicating · \(policy.label)", tint: Theme.accent,
            systemImage: "arrow.trianglehead.2.clockwise")
        }
        Spacer()
        Button("Replication…") { onConfigure() }
        if space.isReplicating {
          Button("Replicate Now") { onSyncNow() }
        }
      }

      Text(space.pathLabel)
        .font(Theme.Font.mono(.subheadline))
        .foregroundStyle(Theme.muted)
        .lineLimit(1).truncationMode(.middle)

      if space.isReplicating {
        if let status, status.isReplicating {
          coverage(status)
        } else {
          // Asked for and not answered yet, or answered with something this
          // app could not read. Either way, saying nothing is better than
          // drawing zeroes that look like "nothing is held".
          Text("Waiting for this space’s replication report.")
            .font(.callout).foregroundStyle(Theme.muted)
        }
      } else {
        Text("This Mac publishes this space but does not hold other devices’ versions of it.")
          .font(.callout).foregroundStyle(Theme.muted)
          .fixedSize(horizontal: false, vertical: true)
      }
    }
    // No padding of its own. This is the content of a ``SettingsSection`` now,
    // and the page it sits on is what sets the margin — a block that padded
    // itself would sit further in than the table above it.
    .frame(maxWidth: .infinity, alignment: .leading)
  }

  @ViewBuilder
  private func coverage(_ status: ReplicaStatus) -> some View {
    VStack(alignment: .leading, spacing: Theme.Space.s) {
      // First, and instead of the releasing line: a replica whose releases are
      // paused is not behaving, and that outranks every count under it.
      if let why = status.pausedReason {
        Label("Releases paused: \(why)", systemImage: "pause.circle")
          .font(.callout).foregroundStyle(Theme.ink(Theme.warning))
          .fixedSize(horizontal: false, vertical: true)
      }

      HStack(alignment: .top, spacing: Theme.Space.section) {
        figure("Held", "\(status.held)", Bytes.short(status.heldBytes), tint: nil)
        if status.wanted > 0 {
          figure(
            "Wanted", "\(status.wanted)", Bytes.short(status.wantedBytes),
            note: status.oldestWant.map { "oldest \($0)" }, tint: nil)
        }
        if status.releasing > 0, status.pausedReason == nil {
          figure(
            "Releasing", "\(status.releasing)", Bytes.short(status.releasingBytes),
            note: status.soonestRelease.map { "soonest in \($0)" }, tint: nil)
        }
        if status.unreachable > 0 {
          figure(
            "Unreachable", "\(status.unreachable)", Bytes.short(status.unreachableBytes),
            tint: Theme.warning)
        }
      }

      if status.unreachable > 0 {
        Text("No device has answered for these. They are probably gone, and they are not part of the backlog above.")
          .font(.caption).foregroundStyle(Theme.ink(Theme.warning))
          .fixedSize(horizontal: false, vertical: true)
      }
      if status.heldBack > 0 {
        Text("\(status.heldBack) held back — too few devices advertise these to let them go.")
          .font(.caption).foregroundStyle(Theme.muted)
      }
      if let budget = status.budgetBytes {
        Text(
          status.budgetReached
            ? "Budget \(Bytes.short(budget)) reached — nothing new is being fetched, and no release was shortened for it."
            : "Budget \(Bytes.short(budget)), \(Bytes.short(status.heldBytes)) used.")
          .font(.caption).foregroundStyle(status.budgetReached ? Theme.ink(Theme.warning) : Theme.muted)
          .fixedSize(horizontal: false, vertical: true)
      }

      if !status.byOrigin.isEmpty {
        VStack(alignment: .leading, spacing: Theme.Space.tiny) {
          Text("Whose content this is").font(.caption).foregroundStyle(Theme.muted)
          ForEach(status.byOrigin) { row in
            HStack(spacing: Theme.Space.s) {
              Text(row.origin).font(Theme.Font.mono(.caption))
              Text(Bytes.short(row.bytes)).font(.caption).foregroundStyle(Theme.muted)
            }
          }
        }
        .padding(.top, Theme.Space.xs)
      }

      if !status.claims.isEmpty {
        VStack(alignment: .leading, spacing: Theme.Space.tiny) {
          // "says" is the whole point of the wording. This Mac has no way to
          // check another's disk, so a claim is reported as speech.
          Text("What other devices say they hold").font(.caption).foregroundStyle(Theme.muted)
          ForEach(status.claims, id: \.self) { claim in
            Text(claim).font(.caption).foregroundStyle(Theme.muted)
              .fixedSize(horizontal: false, vertical: true)
          }
        }
        .padding(.top, Theme.Space.xs)
      }
    }
  }

  private func figure(
    _ label: String, _ value: String, _ bytes: String, note: String? = nil, tint: Color?
  ) -> some View {
    VStack(alignment: .leading, spacing: Theme.Space.tiny) {
      Text(label.uppercased()).font(.caption2).foregroundStyle(Theme.muted)
      Text(value).font(.title3.weight(.semibold))
        .foregroundStyle(tint.map { Theme.ink($0) } ?? .primary)
        .monospacedDigit()
      Text(bytes).font(.caption).foregroundStyle(Theme.muted)
      if let note {
        Text(note).font(.caption2).foregroundStyle(Theme.muted)
      }
    }
    .accessibilityElement(children: .combine)
    .accessibilityLabel("\(label): \(value) objects, \(bytes)\(note.map { ", \($0)" } ?? "")")
  }
}

/// Byte counts, said the way a person reads them.
///
/// The daemon prints raw bytes because a machine is reading it. `4096 B` under
/// a heading that says how much disk this is costing is the wrong unit for the
/// question, and `880000000000 B` is unreadable.
enum Bytes {
  static func short(_ count: Int64) -> String {
    ByteCountFormatter.string(fromByteCount: count, countStyle: .file)
  }
}

#if DEBUG
/// The folder with this id from ``SampleData``.
///
/// Traps rather than substituting a stand-in: a preview assembled out of a
/// fixture that has since been renamed is showing something the app cannot.
private func sampleSpace(_ id: String) -> Space {
  SampleData.spaces.first { $0.id == id }!
}

/// The report where Folders puts it: a section of the settings page, at the
/// one width that page has.
///
/// 760 less the page's margins is 720, and that is the only measurement this
/// view is ever asked for — the settings window is fixed at 980 × 660 and the
/// sidebar takes 220 of it.
private struct InspectorPreview: View {
  let space: Space
  var status: ReplicaStatus?

  var body: some View {
    SettingsSection {
      ReplicationInspector(space: space, status: status, onConfigure: {}, onSyncNow: {})
    }
    .padding(Theme.Space.xl)
    .frame(width: 760)
  }
}

#Preview("Replication") {
  // One unreachable object, drawn as its own warning figure. The daemon has
  // already taken it out of the wanted count beside it, so the two do not add
  // up to the backlog and are not meant to.
  InspectorPreview(
    space: sampleSpace("archive"), status: SampleData.replicaStatus["archive"])
}

#Preview("Releases paused") {
  // The detached replica: nowhere on disk to put files, a budget, and a pause
  // that replaces the releasing count rather than sitting beside it.
  InspectorPreview(space: sampleSpace("media"), status: SampleData.replicaStatus["media"])
}

#Preview("Waiting for the report") {
  // Replicating, and `space ls <id>` has not answered yet. Zeroes here would
  // read as "nothing is held".
  InspectorPreview(space: sampleSpace("archive"))
}

#Preview("Not replicating") {
  InspectorPreview(space: sampleSpace("notes"))
}

#Preview("Larger text") {
  // Four figures across one row is what breaks first, and the width no longer
  // has any give in it to absorb the growth.
  InspectorPreview(
    space: sampleSpace("archive"), status: SampleData.replicaStatus["archive"])
    .dynamicTypeSize(.accessibility1)
}
#endif
