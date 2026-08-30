import SwiftUI
import QuickLook
import UniformTypeIdentifiers

// MARK: - Window modifiers
//
// Split out because one chained `body` of this size stops type-checking in
// reasonable time, and because each group is a separate concern anyway.

/// Import, export, details and confirmation, attached once per window.
struct BrowserDialogs: ViewModifier {
  @Bindable var model: FilesModel
  @Binding var confirmation: ConfirmationRequest?
  @Binding var addingSpace: Bool
  @Binding var exporting: RemoteEntry?
  @Binding var quickLookURL: URL?
  let space: String?
  let prefix: String

  func body(content: Content) -> some View {
    content
      .confirmedAction($confirmation)
      .quickLookPreview($quickLookURL)
      .fileImporter(
        isPresented: $model.importRequested,
        allowedContentTypes: [.item],
        allowsMultipleSelection: true
      ) { result in
        switch result {
        case .success(let urls): model.upload(urls: urls)
        // A panel that could not hand over what was chosen is a failed user
        // action, not a cancelled one, and it used to close saying nothing.
        case .failure(let error):
          guard (error as? CocoaError)?.code != .userCancelled else { return }
          model.store.alert = DaemonFailure.classify(error, operation: "add those files")
        }
      }
      .fileExporter(
        isPresented: Binding(get: { exporting != nil }, set: { if !$0 { exporting = nil } }),
        document: PlaceholderDocument(),
        contentType: .data,
        defaultFilename: exporting?.name ?? "download"
      ) { result in
        // The panel picks the destination; the bytes are then streamed to it
        // with a progress row and a cancel, never read into memory first.
        if case .success(let url) = result, let entry = exporting {
          model.download(entry, to: url)
        }
        exporting = nil
      }
      .sheet(isPresented: $addingSpace) { AddSourceSheet() }
      .sheet(isPresented: $model.compareRequested) {
        if let space { CompareSheet(space: space, prefix: prefix) }
      }
  }
}

/// `fileExporter` needs a document even though the bytes are streamed
/// separately; this stands in for one and writes nothing.
private struct PlaceholderDocument: FileDocument {
  static var readableContentTypes: [UTType] { [.data] }
  init() {}
  init(configuration: ReadConfiguration) throws {}
  func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
    FileWrapper(regularFileWithContents: Data())
  }
}
