import SwiftUI

/// The one moment the secret exists outside the daemon.
struct SecretShownOnceSheet: View {
  @Environment(\.dismiss) private var dismiss
  let key: NewAccessKey

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.l) {
      Text("Copy this secret now").font(.title3.weight(.semibold))
      Text("It is stored in the daemon and never shown again. Closing this window is the last chance.")
        .font(.callout).foregroundStyle(Theme.muted)
        .fixedSize(horizontal: false, vertical: true)
      GroupBox {
        VStack(alignment: .leading, spacing: Theme.Space.snug) {
          labelled("Access key id", key.keyID)
          labelled("Secret", key.secret)
        }
        .padding(Theme.Space.snug)
      }
      HStack {
        Button("Copy Secret") {
          NSPasteboard.general.clearContents()
          NSPasteboard.general.setString(key.secret, forType: .string)
        }
        Spacer()
        Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
      }
    }
    .padding(Theme.Space.xxl).frame(width: 480)
  }

  private func labelled(_ title: String, _ value: String) -> some View {
    VStack(alignment: .leading, spacing: Theme.Space.tiny) {
      Text(title).font(.caption.weight(.semibold)).foregroundStyle(Theme.muted)
      Text(value).font(Theme.Font.mono(.subheadline)).textSelection(.enabled)
        .fixedSize(horizontal: false, vertical: true)
    }
  }
}

#if DEBUG
#Preview("The secret, once") {
  SecretShownOnceSheet(key: NewAccessKey(
    keyID: "AKIAPREVIEW00000003",
    secret: "3f0c1d9a7b5e4826aa1c0d5f9e8b7a6c4d3e2f10"))
}
#endif
