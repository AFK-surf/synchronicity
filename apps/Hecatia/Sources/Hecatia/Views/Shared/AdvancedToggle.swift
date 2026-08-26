import SwiftUI

/// The disclosure that reveals operations which cannot be undone.
///
/// One view rather than the five identical copies this replaces, because the
/// wording is a promise the app makes and five copies of a promise drift.
struct AdvancedToggle: View {
  @Environment(NodeStore.self) private var node

  var body: some View {
    @Bindable var node = node
    Toggle("Show operations that cannot be undone", isOn: $node.advancedUnlocked)
      .toggleStyle(.checkbox)
      .font(.caption)
      .foregroundStyle(Theme.muted)
  }
}

#if DEBUG
/// The shape every pane uses this in: one operation that stays dead until the
/// box is ticked, with the disclosure under it.
private struct AdvancedTogglePreview: View {
  @Environment(NodeStore.self) private var node

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.l) {
      Button("Stop…", role: .destructive) {}
        .disabled(!node.advancedUnlocked)
      AdvancedToggle()
    }
    .padding(Theme.Space.xl)
    .frame(maxWidth: .infinity, alignment: .leading)
  }
}

#Preview("Locked") {
  // 620 is the measure a Node pane gives its content.
  AdvancedTogglePreview()
    .environment(NodeStore.preview())
    .frame(width: 620)
}

#Preview("Unlocked") {
  // The only state in which the operations behind it can be looked at alive.
  // Not persisted: a disclosure that survives a relaunch is not one, so this
  // is a store seeded by hand rather than a stored setting.
  let store = NodeStore.preview()
  store.advancedUnlocked = true
  return AdvancedTogglePreview()
    .environment(store)
    .frame(width: 620)
}
#endif
