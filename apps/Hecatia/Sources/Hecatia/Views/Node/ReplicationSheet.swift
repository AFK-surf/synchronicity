import SwiftUI

/// `space set` — turning replication on, off, or adjusting it for one folder.
///
/// The daemon put replication on the command that already names spaces rather
/// than inventing a noun for it, and this follows: it is a property of a
/// folder, reached from the folder, not a separate thing to go and configure.
struct ReplicationSheet: View {
  @Environment(NodeStore.self) private var node
  @Environment(\.dismiss) private var dismiss

  let space: Space
  /// Bytes this folder's replication is currently holding, so the sheet can say
  /// what "release" would actually let go of instead of saying "some".
  var heldBytes: Int64 = 0

  @State private var choice: Choice = .off
  @State private var graceDays = 7.0
  @State private var limitBudget = false
  @State private var budgetGB = 100.0
  @State private var release = false
  @State private var loaded = false

  enum Choice: Hashable {
    case off
    case policy(ReplicaPolicy)
  }

  private var isTurningOff: Bool { choice == .off && space.isReplicating }

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.l) {
      Text("Replication for “\(space.id)”").font(.title3.weight(.semibold))
      Text("A replicating space holds other devices’ versions of its files on this Mac, as content rather than as files. Nothing appears in Finder — a mirror is what puts files on disk.")
        .font(.callout).foregroundStyle(Theme.muted)
        .fixedSize(horizontal: false, vertical: true)

      Picker("Hold", selection: $choice) {
        Text("Don’t replicate").tag(Choice.off)
        ForEach(ReplicaPolicy.allCases, id: \.self) { policy in
          Text(policy.label).tag(Choice.policy(policy))
        }
      }
      .pickerStyle(.radioGroup)

      if case .policy(let policy) = choice {
        Text(policy.explanation)
          .font(.caption).foregroundStyle(Theme.muted)
          .fixedSize(horizontal: false, vertical: true)
          .padding(.leading, Theme.Space.xl)

        // Grace only applies to `tree`. Under `archive` nothing is ever
        // released, so a grace period would be a control with no effect —
        // the daemon does not even print the line.
        if policy == .tree {
          HStack(spacing: Theme.Space.m) {
            Text("Grace").frame(width: 64, alignment: .trailing)
            Stepper(value: $graceDays, in: 0...365, step: 1) {
              Text(graceDays == 1 ? "1 day" : "\(Int(graceDays)) days")
            }
            .accessibilityLabel("Grace period in days")
          }
          Text("How long a released version is still held after the space stops naming it.")
            .font(.caption).foregroundStyle(Theme.muted)
            .padding(.leading, Theme.Space.xxl)
        }

        Toggle("Limit what this space may hold", isOn: $limitBudget)
        if limitBudget {
          HStack(spacing: Theme.Space.m) {
            Text("Budget").frame(width: 64, alignment: .trailing)
            Stepper(value: $budgetGB, in: 1...100_000, step: 10) {
              Text("\(Int(budgetGB)) GB")
            }
            .accessibilityLabel("Budget in gigabytes")
          }
          Text("At the ceiling nothing new is fetched. No release is shortened to make room.")
            .font(.caption).foregroundStyle(Theme.muted)
            .padding(.leading, Theme.Space.xxl)
        }
      }

      if isTurningOff {
        Divider()
        Toggle(isOn: $release) {
          Text("Also release the \(Bytes.short(heldBytes)) it is holding")
        }
        Text(release
          ? "Those bytes stop being held here. Anything no other device holds is gone from this Mac."
          : "What it holds stays on this Mac. Turning replication off alone does not free any space.")
          .font(.caption)
          .foregroundStyle(release ? Theme.ink(Theme.danger) : Theme.muted)
          .fixedSize(horizontal: false, vertical: true)
      }

      HStack {
        Spacer()
        Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
        Button(isTurningOff ? "Stop Replicating" : "Apply") { apply() }
          .keyboardShortcut(.defaultAction)
          .disabled(!hasChange)
      }
    }
    .padding(Theme.Space.xxl).frame(width: 520)
    .onAppear(perform: loadCurrent)
  }

  /// The daemon refuses an empty `space set` rather than treating it as a
  /// no-op, so Apply is not offered when there is provably nothing to send.
  ///
  /// Only one case is provable: "off" on a folder that already does not
  /// replicate. Any chosen policy always carries a grace and a budget, and this
  /// sheet cannot know the folder's current ones — `space ls`'s summary line
  /// does not include the budget — so it does not pretend to and always sends.
  private var hasChange: Bool {
    if case .off = choice { return space.isReplicating }
    return true
  }

  private func loadCurrent() {
    guard !loaded else { return }
    loaded = true
    choice = space.replicate.map(Choice.policy) ?? .off
  }

  private func apply() {
    let id = space.id
    switch choice {
    case .off:
      let alsoRelease = release
      node.enqueue { await node.setReplication(id: id, stop: true, release: alsoRelease) }
    case .policy(let policy):
      let grace = policy == .tree ? Int64(graceDays * 86_400) : nil
      let budget = limitBudget ? UInt64(budgetGB * 1_000_000_000) : nil
      node.enqueue {
        await node.setReplication(id: id, replicate: policy, grace: grace, budget: budget)
      }
    }
    dismiss()
  }
}

#if DEBUG
#Preview("Replication") {
  ReplicationSheet(
    space: Space(id: "media", localPath: "/Volumes/Big/Media"), heldBytes: 4_096_000_000
  )
  .environment(NodeStore.preview())
}
#endif
