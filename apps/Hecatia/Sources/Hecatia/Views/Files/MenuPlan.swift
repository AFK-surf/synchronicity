import AppKit

/// A context menu described as data.
///
/// The file list is an `NSTableView` now, and AppKit wants an `NSMenu` where
/// SwiftUI wanted a `@ViewBuilder`. Writing the menu as a list keeps it
/// readable as a list — which is what a menu is — instead of as a sequence of
/// `addItem` calls with the titles and the actions on different lines.
struct MenuPlan {
  enum Entry {
    case item(String, enabled: Bool = true, destructive: Bool = false, action: () -> Void)
    case separator
  }

  var entries: [Entry]

  init(_ entries: [Entry]) { self.entries = entries }

  func makeMenu() -> NSMenu {
    let menu = NSMenu()
    fill(menu)
    return menu
  }

  /// Into a menu that already exists, for the `NSMenuDelegate` shape: AppKit
  /// hands `menuNeedsUpdate` the menu it is about to show, and a fresh one
  /// built beside it is not the one that opens.
  func fill(_ menu: NSMenu) {
    menu.removeAllItems()
    for entry in entries {
      switch entry {
      case .separator:
        menu.addItem(.separator())
      case .item(let title, let enabled, let destructive, let action):
        let item = ClosureMenuItem(title: title, action: action)
        item.isEnabled = enabled
        if destructive, #available(macOS 26.0, *) {
          // The system's own destructive styling, so Delete reads the way it
          // does everywhere else rather than by wording alone.
          item.attributedTitle = NSAttributedString(
            string: title, attributes: [.foregroundColor: NSColor.systemRed])
        }
        menu.addItem(item)
      }
    }
  }
}

/// A menu item that carries its own action, so the menu can be built from a
/// list of closures rather than from a target with one selector per entry.
final class ClosureMenuItem: NSMenuItem {
  private let run: () -> Void

  init(title: String, action: @escaping () -> Void) {
    run = action
    super.init(title: title, action: #selector(fire), keyEquivalent: "")
    target = self
  }

  @available(*, unavailable)
  required init(coder: NSCoder) { fatalError("not from a nib") }

  @objc private func fire() { run() }
}
