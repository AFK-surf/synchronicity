import SwiftUI

/// Lets the menu bar act on whichever browser window is frontmost.
struct FilesModelKey: FocusedValueKey {
  typealias Value = FilesModel
}

extension FocusedValues {
  var filesModel: FilesModel? {
    get { self[FilesModelKey.self] }
    set { self[FilesModelKey.self] = newValue }
  }
}
