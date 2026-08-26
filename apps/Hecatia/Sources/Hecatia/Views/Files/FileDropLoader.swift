import SwiftUI
import UniformTypeIdentifiers

enum FileDropLoader {
  @MainActor
  static func urls(from providers: [NSItemProvider]) async -> [URL] {
    var urls: [URL] = []
    for provider in providers {
      let url: URL? = await withCheckedContinuation { continuation in
        _ = provider.loadDataRepresentation(forTypeIdentifier: UTType.fileURL.identifier) { data, _ in
          guard let data, let url = URL(dataRepresentation: data, relativeTo: nil) else {
            continuation.resume(returning: nil)
            return
          }
          continuation.resume(returning: url)
        }
      }
      if let url { urls.append(url) }
    }
    return urls
  }
}
