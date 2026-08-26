import SwiftUI

/// An upload the daemon still holds parts for, from a previous run.
struct ResumableRow: View {
  @Environment(NodeStore.self) private var node
  let upload: ResumableUpload
  @State private var confirmation: ConfirmationRequest?

  var body: some View {
    HStack(spacing: Theme.Space.m) {
      Image(systemName: "clock.arrow.circlepath").foregroundStyle(Theme.accent).frame(width: 22)
      VStack(alignment: .leading, spacing: Theme.Space.tiny) {
        Text(upload.name).font(.callout).lineLimit(1).truncationMode(.middle)
        Text("Interrupted in \(upload.space) \u{2014} add the same file again to carry on from its parts")
          .font(.caption).foregroundStyle(Theme.muted)
          .fixedSize(horizontal: false, vertical: true)
      }
      Spacer(minLength: Theme.Space.xs)
      // Behind the gate its operation declares. `rpc.abortUpload` is
      // `.confirm`, and this call site applied nothing: one click threw away
      // the only parts the daemon holds for what may be a very large file,
      // right beside a line promising they were still there.
      Button("Discard", action: requestDiscard)
        .buttonStyle(.borderless).font(.caption)
    }
    .padding(.horizontal, Theme.Space.l).padding(.vertical, Theme.Space.s)
    .confirmedAction($confirmation)
  }

  private func requestDiscard() {
    confirmation = ConfirmationRequest(
      title: "Discard the parts of \u{201C}\(upload.name)\u{201D}?",
      consequence: "The daemon throws away what it has already received. Adding the same file to \(upload.space) again would have continued from those parts; after this it starts over.",
      verb: "Discard",
      gate: Operations.require("rpc.abortUpload").gate,
      commandLine: "synch upload abort \(upload.id)",
      perform: { discard() })
  }

  private func discard() {
    Task {
      do {
        // The space comes from the listing that found it, not from a guess.
        let existed = try await node.client.abortUpload(
          id: upload.id, space: upload.space, path: upload.path)
        node.transfers.dropResumable(id: upload.id)
        if !existed {
          node.alert = DaemonFailure(
            code: .notFound,
            detail: "The daemon has no parts for \(upload.name) any more, so there was nothing to discard. It is gone from this list either way.",
            operation: nil)
        }
      } catch {
        node.alert = DaemonFailure.classify(error, operation: "discard \(upload.name)")
      }
    }
  }
}

#if DEBUG
#Preview("An interrupted upload") {
  let store = NodeStore.preview(resumable: SampleData.resumable)
  return ResumableRow(upload: SampleData.resumable[0])
    .environment(store)
    .frame(width: 380)
}

#Preview("Narrow") {
  // 380 is the popover this row lives in. Narrower, the sentence that promises
  // the parts are still there wraps and the row grows: it is fixed against
  // truncation, because half of that promise says the opposite of the whole.
  let store = NodeStore.preview(resumable: SampleData.resumable)
  return ResumableRow(upload: SampleData.resumable[0])
    .environment(store)
    .frame(width: 240)
}
#endif
