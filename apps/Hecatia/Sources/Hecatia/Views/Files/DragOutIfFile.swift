import SwiftUI
import UniformTypeIdentifiers

/// Lets a file row be dragged out to Finder, and a folder row not be.
///
/// `onDrag` has to return an `NSItemProvider`, so the old code returned an
/// empty one for a directory: a drag that started, carried no type identifier
/// any destination could accept, and explained nothing when it was dropped.
/// Applied conditionally instead, a folder simply does not begin a drag.
///
/// One known limit, stated rather than hidden: dragging a multiple selection
/// carries only the row under the pointer. An `NSItemProvider` vends alternate
/// representations of *one* item, not several files, so a whole-selection drag
/// needs an AppKit drag source handing the table several
/// `NSFilePromiseProvider`s — which `.onDrag` cannot reach from here.
struct DragOutIfFile: ViewModifier {
  let entry: RemoteEntry
  let model: FilesModel

  func body(content: Content) -> some View {
    if entry.isFile {
      content.onDrag {
        // The file is streamed on demand — it is a promise, so a 4 GB file is
        // not read before the drag starts.
        let provider = NSItemProvider()
        provider.suggestedName = entry.name
        provider.registerFileRepresentation(
          forTypeIdentifier: UTType.data.identifier, fileOptions: [], visibility: .all
        ) { completion in
          Task { @MainActor in
            if let url = await model.materialize(entry) {
              completion(url, false, nil)
            } else {
              completion(nil, false, CocoaError(.fileNoSuchFile))
            }
          }
          return nil
        }
        return provider
      }
    } else {
      content
    }
  }
}
