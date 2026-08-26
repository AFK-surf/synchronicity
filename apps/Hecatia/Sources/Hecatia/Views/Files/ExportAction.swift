import SwiftUI

// MARK: - Environment plumbing

struct ExportAction: Sendable {
  let run: @MainActor @Sendable (RemoteEntry) -> Void
  @MainActor func callAsFunction(_ entry: RemoteEntry) { run(entry) }
}

private struct ExportKey: EnvironmentKey {
  static let defaultValue = ExportAction { _ in }
}

extension EnvironmentValues {
  var exportEntry: ExportAction {
    get { self[ExportKey.self] }
    set { self[ExportKey.self] = newValue }
  }
}
