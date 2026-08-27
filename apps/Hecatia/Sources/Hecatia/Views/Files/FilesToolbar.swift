import SwiftUI

/// The browser's toolbar: navigation, the version control, and the two panels.
///
/// Every control here is its own small `View` that observes what it draws,
/// rather than a `Button` reading `model.` inside this struct. `ToolbarContent`
/// is not a `View`: it is re-evaluated when the enclosing view's body runs, and
/// SwiftUI is free to decide that a `FilesToolbar` built from the same model
/// reference is the same toolbar and skip it. It does. Measured by dumping
/// `NSToolbar.items` and their view classes: a back button that stayed dim
/// after navigating, an
/// Add button that stayed dim after choosing a folder, a policy label that kept
/// the old policy's word. An `@ObservedObject` inside a real `View` subscribes
/// for itself and cannot be skipped.
struct FilesToolbar: ToolbarContent {
  @Environment(NodeStore.self) private var node
  let model: FilesModel

  var body: some ToolbarContent {
    // History is one control, the way Finder's is: a pair, not two buttons that
    // happen to be adjacent. A `ToolbarItemGroup` is what draws that — and it
    // is the *only* thing in this group now, so the shared container it draws
    // is exactly right rather than a bubble around unrelated things.
    ToolbarItemGroup(placement: .navigation) {
      HistoryButton(model: model, direction: .back)
      HistoryButton(model: model, direction: .forward)
    }

    // Declared on the leading side rather than drifting there: a split view's
    // toolbar fills its leading area first, so a trailing item lands over the
    // sidebar anyway — and the three that stayed trailing then had no room and
    // were folded into an overflow chevron.
    if #available(macOS 26.0, *) {
      ToolbarSpacer(.fixed, placement: .navigation)
    }

    ToolbarItem(placement: .navigation) {
      VersionPolicyMenu(
        model: model, ownOrigin: node.origin, label: node.label(forOrigin:))
    }

    // Adding joins the leading side, where macOS was already putting it. What
    // is left trailing is one item, deliberately: a `ToolbarItemGroup` of two
    // collapses into a single button with a menu when macOS thinks it is short
    // of room — which is what turned this toggle into something you had to
    // open a menu to reach — and two separate items are wide enough to fall
    // into an overflow chevron instead. One item can do neither.
    ToolbarItem(placement: .navigation) {
      AddButton(model: model)
    }

    // A group, even of one. A lone `ToolbarItem(placement: .primaryAction)`
    // drifts to the leading edge on macOS 26 — a split view's toolbar fills
    // that side first — while a group stays where it was placed. And a group
    // of *one* cannot do the other thing a group does, which is collapse into
    // a button with a menu when macOS thinks it is short of room.
    ToolbarItemGroup(placement: .primaryAction) {
      TransfersButton(model: model, queue: node.transfers)
      PanelToggle(model: model)
    }

  }
}

// MARK: - The filter field

#if DEBUG
#Preview("Toolbar") {
  let store = NodeStore.preview(transfers: SampleData.transfers)
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes", store: store)
  return NavigationStack {
    Color.clear.toolbar { FilesToolbar(model: model) }
  }
  .environment(store)
  .frame(width: 820, height: 160)
}

#endif
