import SwiftUI

/// `compare` — what one device has for this folder that another does not.
///
/// Reads `--json`, which is the only structured output the daemon offers, so
/// this screen is the one place in the app with no parsing risk at all.
struct CompareSheet: View {
  @Environment(NodeStore.self) private var node
  @Environment(\.dismiss) private var dismiss

  let space: String
  let prefix: String

  @State private var to = ""
  @State private var from = ""
  @State private var report: CompareReport?
  @State private var running = false
  @State private var failure: String?

  private var reference: String {
    prefix.isEmpty ? space : "\(space)/\(prefix)"
  }

  private var origins: [String] {
    var found = Set(node.members.compactMap(\.origin))
    // `compactMap { _ in nil as String? }` stood here and returned an empty
    // sequence for every input, so a device this Mac had exchanged with but
    // not statically trusted never reached the list. `PeerInfo.origins` is the
    // field it wanted; `(untrusted)` is the daemon's placeholder for a key it
    // holds no name for, and a placeholder is not a name a command accepts.
    for peer in node.peers where peer.origins != "(untrusted)" {
      // Comma, because that is what the daemon joins them with
      // (server.rs: `names.join(",")`). An origin is `name@zone` or
      // `key:<z-base-32>`, and neither can contain a comma — unlike a
      // delegation's folder list, which is why that one is never split.
      for origin in peer.origins.split(separator: ",").map({
        $0.trimmingCharacters(in: .whitespaces)
      }) where Versions.isActionable(origin) {
        found.insert(origin)
      }
    }
    if let own = node.origin { found.remove(own) }
    return found.sorted()
  }

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.l) {
      Text("Compare “\(reference)”").font(.title3.weight(.semibold))
      Text("Lists what the other device publishes for this space that this one does not, and the other way round. Nothing is changed.")
        .font(.callout).foregroundStyle(Theme.muted)
        .fixedSize(horizontal: false, vertical: true)

      HStack(spacing: Theme.Space.s) {
        Text("With").frame(width: 44, alignment: .trailing)
        if origins.isEmpty {
          TextField("device name, e.g. nas@cluster.example.com", text: $to)
            .textFieldStyle(.roundedBorder).font(Theme.Font.mono(.subheadline))
        } else {
          Picker("", selection: $to) {
            Text("Choose…").tag("")
            // The name is what is read; the raw origin is what is sent.
            ForEach(origins, id: \.self) { Text(node.label(forOrigin: $0)).tag($0) }
          }
          .labelsHidden()
          // `labelsHidden` hides the label from the screen and from VoiceOver
          // with it; the "With" beside it is a sibling, not a label.
          .accessibilityLabel("Compare with which device")
        }
      }

      DisclosureGroup("Compare something other than this Mac") {
        HStack(spacing: Theme.Space.s) {
          Text("From").frame(width: 44, alignment: .trailing)
          TextField(node.origin ?? "this Mac", text: $from)
            .textFieldStyle(.roundedBorder).font(Theme.Font.mono(.subheadline))
        }
        .padding(.top, Theme.Space.snug)
      }
      .font(.callout)

      Divider()

      Group {
        if running {
          HStack(spacing: Theme.Space.s) { ProgressView().controlSize(.small); Text("Comparing…") }
            .foregroundStyle(Theme.muted)
        } else if let failure {
          Text(failure).foregroundStyle(Theme.danger).font(.callout)
            .fixedSize(horizontal: false, vertical: true)
        } else if let report {
          results(report)
        } else {
          Text("Choose a device and compare.").foregroundStyle(Theme.muted).font(.callout)
        }
      }
      .frame(maxWidth: .infinity, minHeight: 200, alignment: .topLeading)

      HStack {
        Spacer()
        Button("Done") { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Compare") { compare() }
          .keyboardShortcut(.defaultAction)
          .disabled(to.trimmingCharacters(in: .whitespaces).isEmpty || running)
      }
    }
    .padding(Theme.Space.xxl)
    .frame(width: 560, height: 520)
    .task { await node.refresh([.members, .peers]) }
  }

  private func results(_ report: CompareReport) -> some View {
    VStack(alignment: .leading, spacing: Theme.Space.s) {
      HStack(spacing: Theme.Space.s) {
        StatusChip(
          text: "\(report.created.count) only on \(node.label(forOrigin: report.to))",
          tint: Theme.online)
        StatusChip(text: "\(report.modified.count) differ", tint: Theme.warning)
        StatusChip(
          text: "\(report.deleted.count) only on \(node.label(forOrigin: report.from))",
          tint: Theme.muted)
      }
      if report.changes.isEmpty {
        Text("The two devices publish exactly the same thing for this space.")
          .foregroundStyle(Theme.muted).font(.callout)
      } else {
        List(report.changes) { change in
          HStack(spacing: Theme.Space.s) {
            Image(systemName: icon(change.status))
              .foregroundStyle(tint(change.status)).frame(width: 16)
            Text(change.path).font(Theme.Font.mono(.subheadline))
              .lineLimit(1).truncationMode(.middle).help(change.path)
            Spacer()
            Text(label(change.status, report)).font(.caption).foregroundStyle(Theme.muted)
          }
        }
        .listStyle(.inset)
      }
    }
  }

  private func icon(_ status: CompareReport.Change.Status) -> String {
    switch status {
    case .created: return "plus.circle"
    case .modified: return "pencil.circle"
    case .deleted: return "minus.circle"
    }
  }

  private func tint(_ status: CompareReport.Change.Status) -> Color {
    switch status {
    case .created: return Theme.online
    case .modified: return Theme.warning
    case .deleted: return Theme.muted
    }
  }

  /// Which side a change is on, named by the devices the report itself
  /// carries.
  ///
  /// These used to be fixed strings — "only on this Mac" — while the sheet's
  /// own "Compare something other than this Mac" field could make the baseline
  /// a different device entirely, so every row was attributed to a machine
  /// that might publish none of those paths.
  private func label(_ status: CompareReport.Change.Status, _ report: CompareReport) -> String {
    switch status {
    case .created: return "only on \(node.label(forOrigin: report.to))"
    case .modified: return "different contents"
    case .deleted: return "only on \(node.label(forOrigin: report.from))"
    }
  }

  private func compare() {
    let target = to.trimmingCharacters(in: .whitespaces)
    let baseline = from.trimmingCharacters(in: .whitespaces)
    running = true
    failure = nil
    report = nil
    Task {
      let output = await node.run(
        Operations.require("compare"),
        Cmd.compare(reference: reference, to: target, from: baseline.isEmpty ? nil : baseline),
        commandLine: "synch compare \(Shell.quote(reference)) --to \(Shell.quote(target)) --json",
        deadline: .long,
        // Listed, but not alerted: the sheet shows the failure itself, and
        // there is nowhere else for it to go. It used to be `quiet: true`,
        // which suppressed the Activity row as well — so the sentence below
        // sent the reader to a window that had no record of the command at
        // all, and the daemon's own message existed nowhere in the app.
        alerts: false)
      running = false
      guard let output else {
        let said = node.lastFailure.map { failure -> String in
          failure.recoverySuggestion.map { "\(failure.detail)\n\n\($0)" } ?? failure.detail
        }
        failure = said ?? "The comparison did not complete."
        return
      }
      guard let decoded = CompareReport.decode(output.lines) else {
        failure = "The daemon answered in a shape this app does not recognise."
        return
      }
      report = decoded
    }
  }
}

#if DEBUG
#Preview("Compare a folder") {
  CompareSheet(space: "notes", prefix: "journal")
    .environment(NodeStore.preview())
}

#Preview("Compare a whole share") {
  CompareSheet(space: "family photos", prefix: "")
    .environment(NodeStore.preview())
}
#endif
