import SwiftUI

/// The strongest gate: type the object's name.
///
/// Behind a disclosure that resets on quit, because a disclosure that survives
/// a relaunch is not one.
struct TypedConfirmationSheet: View {
  let request: ConfirmationRequest
  let dismiss: () -> Void
  @State private var typed = ""

  private var matches: Bool {
    guard let phrase = request.typedPhrase else { return true }
    return typed == phrase
  }

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.l) {
      HStack(alignment: .firstTextBaseline, spacing: Theme.Space.m) {
        Image(systemName: "exclamationmark.octagon.fill")
          .font(.title2).foregroundStyle(Theme.danger)
        Text(request.title).font(.title3.weight(.semibold))
      }
      Text(request.consequence)
        .font(.callout)
        .fixedSize(horizontal: false, vertical: true)

      if let phrase = request.typedPhrase {
        VStack(alignment: .leading, spacing: Theme.Space.snug) {
          Text("Type \(phrase) to confirm")
            .font(.caption).foregroundStyle(Theme.muted)
          TextField("", text: $typed)
            .textFieldStyle(.roundedBorder)
            .font(Theme.Font.mono(.body))
            .accessibilityLabel("Type \(phrase) to confirm")
        }
      }

      if let command = request.commandLine {
        // Shown here and never in a Files dialog: an operator verifying what
        // the GUI is about to do is a real need; showing it to someone who will
        // never open Terminal is noise at the worst moment.
        HStack(spacing: Theme.Space.s) {
          Text(command)
            .font(Theme.Font.mono(.subheadline))
            .foregroundStyle(Theme.muted)
            .textSelection(.enabled)
            .lineLimit(1).truncationMode(.middle)
          CopyGlyphButton(
            value: command,
            help: "Copy as a synch command",
            accessibilityName: "Copy this command line")
        }
      }

      HStack {
        Spacer()
        Button("Cancel", role: .cancel) { dismiss() }
          .keyboardShortcut(.cancelAction)
        Button(request.verb, role: .destructive) {
          request.perform()
          dismiss()
        }
        .disabled(!matches)
      }
    }
    .padding(Theme.Space.xxl)
    .frame(width: 460)
  }
}

#if DEBUG
#Preview("Typed confirmation") {
  TypedConfirmationSheet(
    request: ConfirmationRequest(
      title: "Stop sharing “archive”?",
      consequence: "The files stay exactly where they are on this Mac. Other devices stop being offered them, and this Mac stops answering for them.",
      verb: "Stop Sharing",
      gate: .typed,
      typedPhrase: "archive",
      commandLine: "synch source rm archive",
      perform: {}),
    dismiss: {})
  .environment(NodeStore.preview())
}

#Preview("Typed confirmation, no command") {
  // Without a command line the disclosure has nothing to reveal, which is a
  // different layout and the one most operations get.
  TypedConfirmationSheet(
    request: ConfirmationRequest(
      title: "Retire this device key?",
      consequence: "Peers stop accepting anything this Mac signs with it. Anything already published stays readable.",
      verb: "Retire",
      gate: .typed,
      typedPhrase: "retire",
      perform: {}),
    dismiss: {})
  .environment(NodeStore.preview())
}
#endif
