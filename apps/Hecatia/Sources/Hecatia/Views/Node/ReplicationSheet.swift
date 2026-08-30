import SwiftUI

/// Add, remove, or adjust the replica role for one namespace.
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
  @State private var pinHeld = false
  @State private var materialize = false
  @State private var checkoutPath = ""
  @State private var loaded = false

  enum Choice: Hashable {
    case off
    case policy(ReplicaPolicy)
  }

  private var isTurningOff: Bool { choice == .off && space.isReplicating }

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.l) {
      Text("Replication for “\(space.id)”").font(.title3.weight(.semibold))
      Text("A replica durably holds content from other devices. It can optionally materialize one newest-view checkout for ordinary applications.")
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

        // Grace only applies to `current`. Under `forever` nothing is ever
        // released, so a grace period would be a control with no effect —
        // the daemon does not even print the line.
        if policy == .current {
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

        Toggle("Materialize a checkout", isOn: $materialize)
        if materialize {
          TextField("Checkout directory", text: $checkoutPath)
            .textFieldStyle(.roundedBorder)
        }
      }

      if isTurningOff {
        Divider()
        Toggle(isOn: $pinHeld) {
          Text("Keep the \(Bytes.short(heldBytes)) it holds as explicit pins")
        }
        Text(pinHeld
          ? "The replica is removed, but operator pins continue retaining every held object."
          : "Replica holds are released. Cache policy may remove content that no remaining role or pin retains.")
          .font(.caption)
          .foregroundStyle(pinHeld ? Theme.muted : Theme.ink(Theme.danger))
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

  /// Apply is not offered when there is provably nothing to send.
  ///
  /// Only one case is provable without retaining a second editable snapshot:
  /// "off" on a folder that already does not replicate.
  private var hasChange: Bool {
    if case .off = choice { return space.isReplicating }
    return true
  }

  private func loadCurrent() {
    guard !loaded else { return }
    loaded = true
    choice = space.replicate.map(Choice.policy) ?? .off
    if let grace = space.graceSeconds {
      graceDays = Double(grace) / 86_400
    }
    if let budget = space.budgetBytes {
      limitBudget = true
      budgetGB = Double(budget) / 1_000_000_000
    }
    materialize = space.checkoutPath != nil
    checkoutPath = space.checkoutPath ?? ""
  }

  private func apply() {
    let id = space.id
    switch choice {
    case .off:
      let preserve = pinHeld
      node.enqueue { await node.removeReplica(id: id, pinHeld: preserve) }
    case .policy(let policy):
      let originalGraceDays = space.graceSeconds.map { Double($0) / 86_400 }
      let graceChanged = policy == .current
        && (space.replicate != .current || originalGraceDays != graceDays)
      let grace = graceChanged ? Int64((graceDays * 86_400).rounded()) : nil
      let originalBudgetGB = space.budgetBytes.map { Double($0) / 1_000_000_000 }
      let budgetChanged = limitBudget
        && (originalBudgetGB == nil || originalBudgetGB != budgetGB)
      let budget = budgetChanged ? UInt64((budgetGB * 1_000_000_000).rounded()) : nil
      let noBudget = space.isReplicating && space.budgetBytes != nil && !limitBudget
      node.enqueue {
        await node.configureReplica(
          id: id, retention: policy, grace: grace, budget: budget, noBudget: noBudget,
          checkout: materialize ? checkoutPath : nil,
          noCheckout: !materialize && space.checkoutPath != nil)
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
