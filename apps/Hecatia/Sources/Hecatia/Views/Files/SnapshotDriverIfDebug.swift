import SwiftUI

/// Carries the debug snapshot driver in DEBUG builds and nothing in release.
struct SnapshotDriverIfDebug: ViewModifier {
  let node: NodeStore
  let model: FilesModel

  func body(content: Content) -> some View {
    #if DEBUG
    content.snapshotDriver(node, model).uiProbe(node, model)
    #else
    content
    #endif
  }
}
