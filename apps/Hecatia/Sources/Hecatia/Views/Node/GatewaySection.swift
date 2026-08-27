import SwiftUI

/// The separate `synch-s3` gateway's buckets and access keys: two tables, each
/// with the ＋ and － that edit it.
///
/// Both lists used to be columns of cards with a － on every row, folded away
/// behind a disclosure. The fold went with the Node window: a settings page is
/// reached by choosing it from a list, and a page that then hides most of
/// itself behind a second choice asks the same question twice.
struct GatewaySection: View {
  @Environment(NodeStore.self) private var node
  @Binding var addingBucket: Bool
  @Binding var addingKey: Bool
  @Binding var confirmation: ConfirmationRequest?
  @State private var selectedBucket: GatewayBucket.ID?
  @State private var selectedKey: AccessKeyRow.ID?

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.section) {
      SettingsSection(
        "S3 Gateway",
        footer: bucketsFooter,
        warnings: node.parseWarnings[.s3] ?? []
      ) {
        VStack(alignment: .leading, spacing: Theme.Space.s) {
          BorderedTable {
            buckets
              // The window is 980 × 660 and never anything else, so both
              // tables take the height that leaves room for the other one
              // rather than a share of a size they will never be asked for.
              .frame(height: 132)
              .overlay { emptyBuckets }
          } actions: {
            TableActionButton(symbol: "plus", name: "Map another bucket") { addingBucket = true }
            TableActionButton(symbol: "minus", name: "Remove the selected bucket") {
              if let bucket = node.s3Buckets.first(where: { $0.id == selectedBucket }) {
                removeBucket(bucket)
              }
            }
            .disabled(selectedBucket == nil)
            Spacer()
            Button("Refresh") { Task { await node.refresh([.s3]) } }
          }
          // The two sentences the row's own warning glyph can only offer as a
          // tooltip. A bucket that serves nothing is worth a line of prose.
          ForEach(node.s3Buckets) { bucket in
            if let caution = warning(for: bucket) {
              Label("\(bucket.name): \(caution)", systemImage: "exclamationmark.triangle.fill")
                .font(.caption).foregroundStyle(Theme.warning)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: Theme.measure, alignment: .leading)
            }
          }
        }
      }

      SettingsSection("Access Keys", footer: keysFooter) {
        BorderedTable {
          keys
            .frame(height: 108)
            .overlay { emptyKeys }
        } actions: {
          TableActionButton(symbol: "plus", name: "Make another access key") { addingKey = true }
          TableActionButton(symbol: "minus", name: "Remove the selected access key") {
            if let id = selectedKey { removeKey(id) }
          }
          .disabled(selectedKey == nil)
        }
      }
    }
  }

  private var buckets: some View {
    Table(node.s3Buckets, selection: $selectedBucket) {
      // The one column with no maximum: a bucket name is a name someone chose
      // and can be as long as they liked, so what the other two leave over
      // belongs here.
      TableColumn("Bucket") { bucket in
        HStack(spacing: Theme.Space.snug) {
          if let caution = warning(for: bucket) {
            Image(systemName: "exclamationmark.triangle.fill")
              .foregroundStyle(Theme.warning).imageScale(.small)
              .help(caution).accessibilityLabel(caution)
          }
          Text(bucket.name)
            .font(Theme.Font.mono(.subheadline)).lineLimit(1).truncationMode(.middle)
            .help(bucket.name).textSelection(.enabled)
        }
      }
      .width(min: 140, ideal: 200)

      TableColumn("Space") { bucket in
        Text(bucket.space)
          .font(.caption).foregroundStyle(Theme.muted)
          .lineLimit(1).truncationMode(.middle)
          .help(bucket.space).textSelection(.enabled)
      }
      .width(min: 100, ideal: 160, max: 260)

      // `From nas@x.example` is a whole origin inside a column label, so this
      // one truncates as readily as the name does.
      TableColumn("Versions") { bucket in
        Text(bucket.policy.label)
          .font(.caption).foregroundStyle(Theme.muted)
          .lineLimit(1).truncationMode(.middle)
          .help(bucket.policy.label).textSelection(.enabled)
      }
      .width(min: 90, ideal: 140, max: 220)
    }
    .contextMenu(forSelectionType: GatewayBucket.ID.self) { ids in
      if let bucket = node.s3Buckets.first(where: { ids.contains($0.id) }) {
        Button("Copy Bucket Name") { copy(bucket.name) }
        Button("Remove\u{2026}", role: .destructive) { removeBucket(bucket) }
      }
    }
  }

  private var keys: some View {
    Table(node.s3KeyIDs.map { AccessKeyRow(id: $0) }, selection: $selectedKey) {
      TableColumn("Access key ID") { row in
        // Only the id half ever reaches this view: the fold drops the secret,
        // so there is no layer here holding one to render.
        Text(row.id)
          .font(Theme.Font.mono(.subheadline)).lineLimit(1).truncationMode(.middle)
          .help(row.id).textSelection(.enabled)
      }
    }
    .contextMenu(forSelectionType: AccessKeyRow.ID.self) { ids in
      if let id = ids.first {
        Button("Copy Access Key ID") { copy(id) }
        Button("Remove\u{2026}", role: .destructive) { removeKey(id) }
      }
    }
  }

  /// What stands in an empty table's rectangle.
  ///
  /// Over the table rather than instead of it, so the action bar does not move
  /// under the pointer when the first record arrives — and it says what the
  /// emptiness costs, which "None" did not.
  @ViewBuilder private var emptyBuckets: some View {
    if node.s3Buckets.isEmpty {
      Text("No buckets mapped. The gateway serves nothing until one is.")
        .font(.callout).foregroundStyle(Theme.muted)
        .multilineTextAlignment(.center)
        .padding(.horizontal, Theme.Space.l)
    }
  }

  @ViewBuilder private var emptyKeys: some View {
    if node.s3KeyIDs.isEmpty {
      Text("No access keys. The gateway refuses to serve without one.")
        .font(.callout).foregroundStyle(Theme.muted)
        .multilineTextAlignment(.center)
        .padding(.horizontal, Theme.Space.l)
    }
  }

  private var bucketsFooter: String {
    let base = "Buckets and access keys the separate `synch-s3` gateway reads, each bucket mapping one S3 name onto one space. Both are append-only logs \u{2014} a change is a new record and nothing is ever rewritten, so two processes editing at once cannot lose each other\u{2019}s work. What is listed here is what the gateway makes of the log, not the log itself."
    guard node.s3RecordCount > 0 else { return base }
    // Removals and replacements are appended too, so the log is longer than
    // the two lists on this page.
    let records = node.s3RecordCount == 1 ? "1 record" : "\(node.s3RecordCount) records"
    return base + " The log holds \(records)."
  }

  private var keysFooter: String {
    "The gateway accepts these. Only the id half ever reaches this app \u{2014} the secret is shown once, when the key is made, and is not stored here. A removal is appended rather than erased, so the secret stays in the config until the whole value is cleared: treat a withdrawn secret as spent, not as private again."
  }

  /// The two things `synch-s3 bucket add` warns about, which the daemon stores
  /// happily either way.
  private func warning(for bucket: GatewayBucket) -> String? {
    if case .origin(let pinned) = bucket.policy, let ours = node.origin, pinned != ours {
      return "Pins \(pinned), so writes here publish this Mac\u{2019}s view and reads keep serving \(pinned)\u{2019}s: effectively read-only."
    }
    if !node.spaces.isEmpty, !node.spaces.contains(where: { $0.id == bucket.space }) {
      return "No space named \(bucket.space) on this Mac, so the bucket serves nothing until one publishes it."
    }
    return nil
  }

  private func copy(_ value: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(value, forType: .string)
  }

  private func removeBucket(_ bucket: GatewayBucket) {
    confirmation = ConfirmationRequest(
      title: "Remove the bucket \u{201c}\(bucket.name)\u{201d}?",
      consequence: "The gateway stops answering for \(bucket.name). The space \(bucket.space) and everything in it is untouched \u{2014} only the S3 name for it goes away.",
      verb: "Remove",
      gate: .confirm,
      perform: { append(GatewayConfig.bucketsKey, GatewayConfig.bucketRemoval(bucket.name), "remove the bucket") }
    )
  }

  private func removeKey(_ id: String) {
    confirmation = ConfirmationRequest(
      title: "Remove the access key \u{201c}\(id)\u{201d}?",
      consequence: "Anything using it stops being served. The removal is appended rather than erased, so the secret stays in the config until the whole value is cleared \u{2014} treat a withdrawn secret as spent, not as private again.",
      verb: "Remove",
      gate: .confirm,
      perform: { append(GatewayConfig.keysKey, GatewayConfig.keyRemoval(id), "remove the access key") }
    )
  }

  private func append(_ key: String, _ record: String, _ what: String) {
    Task {
      do {
        try await node.client.appendConfig(key: key, record: record)
        await node.refresh([.s3])
      } catch {
        node.alert = DaemonFailure.classify(error, operation: what)
      }
    }
  }
}

/// An access key id as a table row.
///
/// `Table` identifies its rows and the daemon gives this list as bare strings,
/// so the identity is the id itself.
struct AccessKeyRow: Identifiable, Hashable {
  let id: String
}

#if DEBUG
#Preview("S3 gateway") {
  // `photos-readonly` pins another node in the fixtures, so the read-only
  // warning is on screen with no arranging.
  GatewaySection(
    addingBucket: .constant(false),
    addingKey: .constant(false),
    confirmation: .constant(nil))
  .environment(NodeStore.preview())
  .padding(Theme.Space.xl)
  .frame(width: 760, height: 560)
}

#Preview("Nothing published") {
  GatewaySection(
    addingBucket: .constant(false),
    addingKey: .constant(false),
    confirmation: .constant(nil))
  .environment(NodeStore.preview(buckets: [], keyIDs: []))
  .padding(Theme.Space.xl)
  .frame(width: 760, height: 560)
}

#Preview("A bucket with no folder") {
  // The other warning, which needs a bucket the fixtures do not carry: the
  // daemon stores a mapping for a folder this Mac does not share, and only
  // this view ever says so.
  GatewaySection(
    addingBucket: .constant(false),
    addingKey: .constant(false),
    confirmation: .constant(nil))
  .environment(NodeStore.preview(
    buckets: [GatewayBucket(name: "scratch", space: "scratch", policy: .newest)]))
  .padding(Theme.Space.xl)
  .frame(width: 760, height: 560)
}

#Preview("Larger text") {
  // Both footers grow and both tables keep their height, which is what this
  // page's scrolling is made of.
  GatewaySection(
    addingBucket: .constant(false),
    addingKey: .constant(false),
    confirmation: .constant(nil))
  .environment(NodeStore.preview())
  .dynamicTypeSize(.accessibility1)
  .padding(Theme.Space.xl)
  .frame(width: 760, height: 560)
}
#endif
