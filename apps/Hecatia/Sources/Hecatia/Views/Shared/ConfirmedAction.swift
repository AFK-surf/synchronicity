import SwiftUI

/// The confirmation an operation gets, chosen by its consequence.
///
/// Four strengths, and which one an operation gets is a field on its
/// ``Operation`` value rather than a decision each call site makes. Half the
/// value of the weaker gates is correcting the user's guess about what the
/// operation does — "the files already in this folder stay exactly where they
/// are" — which is why the consequence text is a parameter and not boilerplate.
struct ConfirmedAction: ViewModifier {
  @Binding var request: ConfirmationRequest?
  @Environment(NodeStore.self) private var node

  func body(content: Content) -> some View {
    content
      .confirmationDialog(
        request?.title ?? "",
        isPresented: Binding(
          get: { request != nil && request?.gate != .typed },
          set: { if !$0 { request = nil } }
        ),
        presenting: request
      ) { pending in
        Button(pending.verb, role: pending.isDestructive ? .destructive : nil) {
          pending.perform()
          request = nil
        }
        Button("Cancel", role: .cancel) { request = nil }
      } message: { pending in
        Text(pending.consequence)
      }
      .sheet(
        item: Binding(
          get: { request?.gate == .typed ? request : nil },
          set: { if $0 == nil { request = nil } }
        )
      ) { pending in
        TypedConfirmationSheet(request: pending) { request = nil }
      }
  }
}

extension View {
  func confirmedAction(_ request: Binding<ConfirmationRequest?>) -> some View {
    modifier(ConfirmedAction(request: request))
  }
}

#if DEBUG
/// The request the weaker gates get, from `source rm` — the operation whose
/// consequence is mostly a correction of what the user thinks it does.
private func previewStopSharing() -> ConfirmationRequest {
  ConfirmationRequest(
    title: "Stop sharing “archive”?",
    consequence: "The files already in this folder stay exactly where they are. Other devices stop being offered them, and this Mac stops answering for them.",
    verb: "Stop Sharing",
    gate: .consequence,
    perform: {})
}

/// A pane in miniature: something that raises a request, and the modifier on
/// the view around it.
private struct ConfirmedActionPreview: View {
  let request: ConfirmationRequest
  @State private var pending: ConfirmationRequest?

  init(_ request: ConfirmationRequest, raised: Bool = false) {
    self.request = request
    _pending = State(initialValue: raised ? request : nil)
  }

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.m) {
      DetailRow(label: "Folder", value: "archive")
      DetailRow(label: "Files", value: "4,118")
      Button("\(request.verb)…", role: .destructive) { pending = request }
    }
    .padding(Theme.Space.xl)
    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    .confirmedAction($pending)
  }
}

#Preview("Nothing pending") {
  ConfirmedActionPreview(previewStopSharing())
    .environment(NodeStore.preview())
    .frame(width: 520, height: 240)
}

#Preview("A consequence to confirm") {
  ConfirmedActionPreview(previewStopSharing(), raised: true)
    .environment(NodeStore.preview())
    .frame(width: 520, height: 240)
}

#Preview("The typed gate") {
  // `.typed` is the one gate drawn as a sheet rather than as a confirmation
  // dialog, and both presentations hang off this single modifier — so the
  // request's own gate is what decides which of them appears.
  ConfirmedActionPreview(
    ConfirmationRequest(
      title: "Stop the background service?",
      consequence: "Publishing, replication, checkouts, and remote browsing stop immediately. This app loses its connection, and nothing on that socket can start the service again — you will need a terminal.",
      verb: "Stop",
      gate: .typed,
      typedPhrase: "stop",
      commandLine: "synch daemon stop",
      perform: {}),
    raised: true)
    .environment(NodeStore.preview())
    .frame(width: 560, height: 460)
}
#endif
