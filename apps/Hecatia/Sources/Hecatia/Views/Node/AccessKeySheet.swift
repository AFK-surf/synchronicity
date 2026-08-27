import SwiftUI

/// `AppendConfig` on `s3.keys`.
///
/// The gateway has no way to read a secret back and neither has this app, so
/// the sheet offers to generate one and then shows it exactly once.
struct AccessKeySheet: View {
  @Environment(NodeStore.self) private var node
  @Environment(\.dismiss) private var dismiss
  let generated: (NewAccessKey) -> Void

  @State private var keyID = ""
  @State private var secret = ""
  @State private var wasGenerated = false

  private var isValid: Bool {
    !keyID.isEmpty && !secret.isEmpty
      && !GatewayConfig.containsSeparator(keyID) && !GatewayConfig.containsSeparator(secret)
  }
  private var replaces: Bool { node.s3KeyIDs.contains(keyID) }

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.l) {
      Text("Add an Access Key").font(.title3.weight(.semibold))
      Text("A SigV4 key pair the gateway accepts from S3 clients. It authenticates clients only \u{2014} this Mac\u{2019}s place in the cluster is its device key, not this.")
        .font(.callout).foregroundStyle(Theme.muted)
        .fixedSize(horizontal: false, vertical: true)
      TextField("Access key id", text: $keyID).textFieldStyle(.roundedBorder)
      HStack(spacing: Theme.Space.s) {
        SecureField("Secret", text: $secret).textFieldStyle(.roundedBorder)
        Button("Generate") { generate() }
      }
      if replaces {
        Label(
          "\(keyID) already exists. Adding replaces its secret; the old one stops working.",
          systemImage: "exclamationmark.triangle.fill")
          .font(.caption).foregroundStyle(Theme.warning)
          .fixedSize(horizontal: false, vertical: true)
      }
      Text("The secret is never readable again \u{2014} not by this app, not by the gateway\u{2019}s listing. Copy it when it is shown.")
        .font(.caption).foregroundStyle(Theme.muted)
        .fixedSize(horizontal: false, vertical: true)
      HStack {
        Spacer()
        Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Add") { add() }.keyboardShortcut(.defaultAction).disabled(!isValid)
      }
    }
    .padding(Theme.Space.xxl).frame(width: 480)
  }

  private func generate() {
    if keyID.isEmpty { keyID = "SYNCH" + Self.random(15, from: Self.upperAlphanumeric) }
    secret = Self.random(40, from: Self.secretAlphabet)
    wasGenerated = true
  }

  private func add() {
    let record = GatewayConfig.keyRecord(id: keyID, secret: secret)
    let shown = NewAccessKey(keyID: keyID, secret: secret)
    let wasGenerated = wasGenerated
    Task {
      do {
        try await node.client.appendConfig(key: GatewayConfig.keysKey, record: record)
        await node.refresh([.s3])
        // Only what this app invented is worth showing back. A secret the
        // operator typed, they already have.
        if wasGenerated { generated(shown) }
      } catch {
        node.alert = DaemonFailure.classify(error, operation: "add the access key")
      }
    }
    dismiss()
  }

  private static let upperAlphanumeric = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
  private static let secretAlphabet = Array(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

  /// From the system CSPRNG: a secret is a credential, and `Int.random` is not
  /// documented to be one.
  private static func random(_ count: Int, from alphabet: [Character]) -> String {
    var bytes = [UInt8](repeating: 0, count: count)
    guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else { return "" }
    return String(bytes.map { alphabet[Int($0) % alphabet.count] })
  }
}

#if DEBUG
#Preview("Add an access key") {
  AccessKeySheet(generated: { _ in }).environment(NodeStore.preview())
}
#endif
