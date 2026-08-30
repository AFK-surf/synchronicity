import SwiftUI

/// `AppendConfig` on `s3.buckets`.
struct BucketSheet: View {
  @Environment(NodeStore.self) private var node
  @Environment(\.dismiss) private var dismiss

  @State private var bucket = ""
  @State private var space = ""
  @State private var policy: VersionPolicy = .newest
  @State private var access: GatewayBucket.Access = .readOnly

  private var nameProblem: String? { GatewayConfig.bucketNameProblem(bucket) }
  /// The fold is last-record-wins, so adding a name that already exists
  /// repoints it — silently, where the access-key sheet thirty lines below
  /// warns about exactly the same semantics. Every S3 client aimed at that
  /// bucket serves a different folder from the next request.
  private var replaces: GatewayBucket? {
    node.s3Buckets.first { $0.name == bucket }
  }
  private var isValid: Bool {
    !bucket.isEmpty && !space.isEmpty && nameProblem == nil
      && !GatewayConfig.containsSeparator(bucket) && !GatewayConfig.containsSeparator(space)
      && (access == .readOnly || node.spaces.first(where: { $0.id == space })?.isSource == true)
  }

  private var originChoices: [String] {
    var origins = Set(node.members.compactMap(\.origin).filter(Versions.isActionable))
    if let own = node.origin { origins.insert(own) }
    return origins.sorted()
  }

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.l) {
      Text("Add a Bucket").font(.title3.weight(.semibold))
      Text("Maps an S3 bucket name onto one space, for the separate gateway process.")
        .font(.callout).foregroundStyle(Theme.muted)
      VStack(alignment: .leading, spacing: Theme.Space.xs) {
        TextField("Bucket name", text: $bucket).textFieldStyle(.roundedBorder)
        // The gateway enforces the S3 naming rules when it folds the log, and
        // the daemon does not, so a name refused there would be stored here and
        // then serve nothing. Said before the record is written instead.
        if let nameProblem {
          Text(nameProblem).font(.caption).foregroundStyle(Theme.ink(Theme.danger))
            .fixedSize(horizontal: false, vertical: true)
        } else if let replaces, replaces.space != space {
          Label(
            "\(bucket) already serves \u{201C}\(replaces.space)\u{201D}. Adding this repoints it, and every S3 client using that name starts serving \u{201C}\(space)\u{201D} instead.",
            systemImage: "exclamationmark.triangle.fill")
            .font(.caption).foregroundStyle(Theme.warning)
            .fixedSize(horizontal: false, vertical: true)
        }
      }
      Picker("Space", selection: $space) {
        Text("Choose\u{2026}").tag("")
        ForEach(node.spaces) { Text($0.id).tag($0.id) }
      }
      Picker("Access", selection: $access) {
        Text("Read only").tag(GatewayBucket.Access.readOnly)
        Text("Read and write").tag(GatewayBucket.Access.readWrite)
      }
      if access == .readOnly {
        Picker("Version", selection: $policy) {
          Text("Newest").tag(VersionPolicy.newest)
          Text("Strict").tag(VersionPolicy.strict)
          ForEach(originChoices, id: \.self) { origin in
            Text("From \(origin)").tag(VersionPolicy.origin(origin))
          }
        }
      } else if node.spaces.first(where: { $0.id == space })?.isSource != true {
        Label(
          "Read-write buckets require a source on this Mac.",
          systemImage: "exclamationmark.triangle.fill")
          .font(.caption).foregroundStyle(Theme.warning)
          .fixedSize(horizontal: false, vertical: true)
      }
      HStack {
        Spacer()
        Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Add") { add() }
          .keyboardShortcut(.defaultAction)
          .disabled(!isValid)
      }
    }
    .padding(Theme.Space.xxl).frame(width: 460)
  }

  private func add() {
    let selected = access == .readWrite ? VersionPolicy.origin(node.origin ?? "self") : policy
    let record = GatewayConfig.bucketRecord(
      name: bucket, space: space, access: access, policy: selected)
    Task {
      do {
        try await node.client.appendConfig(key: GatewayConfig.bucketsKey, record: record)
        await node.refresh([.s3])
      } catch {
        node.alert = DaemonFailure.classify(error, operation: "add the bucket")
      }
    }
    dismiss()
  }
}

#if DEBUG
#Preview("Add a bucket") {
  BucketSheet().environment(NodeStore.preview())
}
#endif
