import SwiftUI

/// Names the window, and titles it.
///
/// Two different strings: the titlebar shows the folder, the way Finder's
/// does, while the *window* is named by the whole location so the Window menu
/// and Mission Control can tell two browsers apart. `.navigationTitle` can
/// only do one of those.
struct TitleBar: NSViewRepresentable {
  /// Drawn in the titlebar.
  let title: String
  /// What the window is called everywhere else.
  let windowName: String

  func makeNSView(context: Context) -> NSView {
    let view = NSView(frame: .zero)
    apply(to: view)
    return view
  }

  func updateNSView(_ nsView: NSView, context: Context) {
    apply(to: nsView)
  }

  private func apply(to view: NSView) {
    let title = title
    let windowName = windowName
    // The view has no window yet when it is made, and AppKit settles the title
    // bar after the update it is asked in, so this lands one pass later.
    Task { @MainActor in
      guard let window = view.window else { return }
      if window.title != title { window.title = title }
      // `setAccessibilityTitle` is what the Window menu and the switcher read
      // when it differs from the drawn one.
      if window.accessibilityTitle() != windowName {
        window.setAccessibilityTitle(windowName)
      }
    }
  }
}

#if DEBUG
/// The two strings, written out — because the view itself draws nothing.
///
/// What it changes is `window.title` and the window's accessibility title, one
/// pass after it is asked to, and a preview canvas has no titlebar to show
/// that in. So the strings are shown instead, each labelled with where it
/// lands, over the real view installed as a background exactly as
/// ``FilesWindow`` installs it.
private struct TitleBarPreview: View {
  let title: String
  let windowName: String

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.s) {
      Text("Drawn in the titlebar: \u{201c}\(title)\u{201d}")
      Text("Window menu, Mission Control, the switcher: \u{201c}\(windowName)\u{201d}")
        .foregroundStyle(Theme.muted)
    }
    .padding(Theme.Space.xl)
    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    .background(TitleBar(title: title, windowName: windowName))
  }
}

#Preview("Inside a folder") {
  // Asked of the model that computes them in the app, rather than typed out:
  // the two differ, and the whole reason this view exists is that
  // `.navigationTitle` can only set one of them.
  let store = NodeStore.preview()
  let model = FilesModel.preview(
    rows: SampleData.rows, space: "notes", prefix: "journal", store: store)
  return TitleBarPreview(title: model.folderTitle, windowName: model.locationTitle)
    .frame(width: 900, height: 200)
}

#Preview("At the top of a folder") {
  // At the root of a folder the two are the same string, so a window opened
  // here shows nothing of the split — which is why the nested case above is
  // the one to look at.
  let store = NodeStore.preview()
  let model = FilesModel.preview(rows: SampleData.rows, space: "notes", store: store)
  return TitleBarPreview(title: model.folderTitle, windowName: model.locationTitle)
    .frame(width: 900, height: 200)
}
#endif
