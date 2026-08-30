import SwiftUI

/// What this node is, `doctor`, and the two operations that cannot be undone.
///
/// The block of facts at the top is what Overview opened with. That page went
/// with the Node window: its alarms are the settings window's own banner now
/// and Scan and Sync are on the menu bar under ⌘R and ⇧⌘R, which left one card
/// of what the daemon reports about itself with nowhere to live. It belongs
/// beside the report that examines the same things.
struct DiagnosticsPane: View {
  @Environment(NodeStore.self) private var node
  /// The scene action, which reaches the Activity window from here because the
  /// settings window *is* on the scene's view tree — unlike the browser, whose
  /// contents are hosted by hand and need ``OpenAppWindow`` instead.
  @Environment(\.openWindow) private var openWindow
  @Binding var confirmation: ConfirmationRequest?
  @State private var recovering = false

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: Theme.Space.section) {
        if let status = node.status {
          SettingsSection(
            "This Mac",
            footer: status.trustSummary,
            warnings: node.parseWarnings[.status] ?? []
          ) {
            summary(of: status)
          }

          if status.needsRecovery { publishing }

          if let adoptions = node.identity?.adoptions, !adoptions.isEmpty {
            SettingsSection(
              "Names Adopted From the Zone",
              footer: "Names this Mac answers to because the zone handed them to it, rather than because it was configured with them."
            ) {
              GroupBox { TranscriptView(lines: adoptions).frame(height: 80) }
            }
          }

          if !status.unparsedLines.isEmpty {
            SettingsSection(
              "Also Reported",
              footer: "Lines the status command printed that this version of the app has no field for. Nothing the daemon says is dropped."
            ) {
              GroupBox { TranscriptView(lines: status.unparsedLines).frame(height: 80) }
            }
          }
        }

        report
        unrecoverable
      }
      .padding(Theme.Space.xl)
      .frame(maxWidth: .infinity, alignment: .leading)
    }
    .sheet(isPresented: $recovering) { RecoverSheet() }
  }

  /// `daemon status` and `id`, as the card Overview drew.
  private func summary(of status: NodeStatus) -> some View {
    GroupBox {
      VStack(alignment: .leading, spacing: Theme.Space.s) {
        if case .named(let origin, let signing) = status.naming {
          // The name and the address are the two values long enough to be
          // truncated in the middle of the row, so both carry the whole string
          // in a tooltip as well as on the copy button.
          DetailRow(label: "Name", value: origin, mono: true, copyable: origin)
            .help(origin)
          DetailRow(label: "Signing as", value: signing, mono: true)
        }
        if let address = status.address {
          DetailRow(label: "Address", value: address, mono: true, copyable: address)
            .help(address)
        }
        DetailRow(
          label: "Spaces",
          value: status.spaceNames.isEmpty ? "none" : status.spaceNames.joined(separator: ", "))
        if let sources = status.sourceCount { DetailRow(label: "Sources", value: "\(sources)") }
        if let replicas = status.replicaCount { DetailRow(label: "Replicas", value: "\(replicas)") }
        DetailRow(
          label: "Published",
          value: status.headSeq.map { "seq \($0)" } ?? "nothing published yet")
        if let seen = status.peersSeen {
          DetailRow(label: "Devices seen", value: "\(seen)")
        }
      }
      .padding(Theme.Space.snug)
    }
  }

  /// The recovery control, which exists only while the condition does.
  ///
  /// Absent on a healthy node, and it does not repeat the alarm: that is the
  /// window's banner, above every page including this one.
  private var publishing: some View {
    SettingsSection(
      "Publishing",
      footer: "This Mac cannot publish: a peer advertises a newer published position for it than it holds. Resuming listens for what other devices say they have seen and continues above that."
    ) {
      Button("Resume Publishing…") { recovering = true }
    }
  }

  private var report: some View {
    SettingsSection(
      "Report",
      footer: "The daemon’s own examination, shown exactly as it writes it. It is not run on opening this page — it holds the daemon’s connection for as long as the walk takes."
    ) {
      BorderedTable {
        // Two different constraints, not one. A transcript is a scroll view and
        // wants a fixed height to scroll inside; an empty state is a glyph over
        // two lines of prose and wants a floor it can exceed — given the same
        // fixed height it is centred and then clipped, which takes the glyph
        // off the top. The same rule applies to every table in this pane.
        if node.doctorReport.isEmpty {
          DoctorEmptyState(running: node.doctorRunning)
            .frame(maxWidth: .infinity, minHeight: 200)
        } else {
          TranscriptView(lines: node.doctorReport)
            .frame(height: 200)
        }
      } actions: {
        // The flag is on the store, not here. As this pane's own `@State` it
        // was destroyed by leaving the pane, so coming back re-enabled the
        // button and dropped the spinner while `doctor` was still running —
        // and `enqueue` serialises rather than rejects, so the second one
        // simply queued behind the first. It also never covered the rebuild
        // below, which shares the same operation and ran with no spinner.
        Button("Run Diagnostics") {
          node.enqueue { await node.runDoctor(rebuild: false) }
        }
        .disabled(node.doctorRunning)
        if node.doctorRunning { ProgressView() }
        // `doctor` is what the daemon says about itself when asked; Activity is
        // what it said while doing everything else. The two are read together
        // often enough that the way to one belongs beside the other — and it is
        // a window rather than a page here because a log is read beside the
        // thing it is a log of.
        Button("Open Activity") { openWindow(id: "activity") }
          .help("Every command this app has run, with the daemon’s full output")
        Spacer()
        Button("Copy Report") {
          NSPasteboard.general.clearContents()
          NSPasteboard.general.setString(node.doctorReport.joined(separator: "\n"), forType: .string)
        }
        .disabled(node.doctorReport.isEmpty)
      }
    }
  }

  /// The two operations behind the disclosure.
  ///
  /// Both were on the Node window and both keep the gate they had there: the
  /// checkbox, and then a phrase to type. One disclosure rather than two,
  /// because they now sit on one page and two checkboxes reading the same flag
  /// with the same words is one promise written twice.
  private var unrecoverable: some View {
    SettingsSection(
      "Operations That Cannot Be Undone",
      footer: "Rebuilding re-materialises every record of every device from the authoritative trie, and this Mac answers no reads while it runs. Stopping the background service ends sharing, mirrors and remote browsing — this app cannot start it again over the same socket."
    ) {
      VStack(alignment: .leading, spacing: Theme.Space.m) {
        HStack(spacing: Theme.Space.s) {
          Button("Rebuild Derived Views…", role: .destructive) { requestRebuild() }
            .disabled(!node.advancedUnlocked || node.doctorRunning)
            .help("Re-materialise every record from the authoritative trie")
          Button("Stop the Service…", role: .destructive) { requestStop() }
            .disabled(!node.advancedUnlocked)
            .help("Stop the background daemon on this Mac")
        }
        // Not persisted: a disclosure that survives a relaunch is not one.
        AdvancedToggle()
      }
      .frame(maxWidth: .infinity, alignment: .leading)
    }
  }

  private func requestRebuild() {
    confirmation = ConfirmationRequest(
      title: "Rebuild derived views?",
      consequence: "This re-materialises every record of every device from the authoritative trie. This Mac answers no reads while it runs, and on a large cluster that can take a long time.",
      verb: "Rebuild",
      gate: .typed,
      typedPhrase: "rebuild",
      commandLine: "synch doctor --rebuild",
      perform: { node.enqueue { await node.runDoctor(rebuild: true) } }
    )
  }

  private func requestStop() {
    confirmation = ConfirmationRequest(
      title: "Stop the background service?",
      consequence: "Sharing, mirrors and remote browsing stop immediately. This app loses its connection, and nothing on that socket can start the service again — you will need a terminal.",
      verb: "Stop",
      gate: .typed,
      typedPhrase: "stop",
      commandLine: "synch daemon stop",
      perform: {
        node.enqueue {
          await node.run(Operations.require("daemon.stop"), Cmd.daemonStop, deadline: .fast)
          node.disconnect()
        }
      }
    )
  }
}

/// The report before there is one.
///
/// An empty transcript is this page's ordinary first state, not a failure —
/// `doctor` runs only when asked — and the grey sentence it used to show read
/// as one more line the daemon had printed.
private struct DoctorEmptyState: View {
  var running = false

  var body: some View {
    if running {
      ContentUnavailableView {
        Label("Examining this Mac", systemImage: "stethoscope")
      } description: {
        Text("The daemon is walking its store, comparing its clock against its peers and checking every shared space.")
      }
    } else {
      ContentUnavailableView {
        Label("No report yet", systemImage: "stethoscope")
      } description: {
        Text("Run Diagnostics to have the daemon examine its store, its clock and every shared space, and print what it finds.")
      }
    }
  }
}

#if DEBUG
#Preview("Diagnostics") {
  DiagnosticsPane(confirmation: .constant(nil))
    .environment(NodeStore.preview())
    .frame(width: 760, height: 560)
}

#Preview("Diagnostics, in recovery") {
  // The alarm itself is the window's banner and is not in this preview; what
  // is here is the section that only exists while the alarm does.
  DiagnosticsPane(confirmation: .constant(nil))
    .environment(NodeStore.preview(status: SampleData.alarmedStatus))
    .frame(width: 760, height: 560)
}

#Preview("Operations unlocked") {
  // The only state in which the two destructive buttons can be looked at
  // alive. Seeded by hand, because the flag is deliberately not stored.
  let store = NodeStore.preview()
  store.advancedUnlocked = true
  return DiagnosticsPane(confirmation: .constant(nil))
    .environment(store)
    .frame(width: 760, height: 560)
}

#Preview("The daemon said something new") {
  // Lines the status parser did not recognise get their own section rather
  // than being dropped.
  var status = SampleData.status
  status.unparsedLines = ["ratchet: 4 epochs retained", "gossip: fanout 6, 2 suppressed"]
  return DiagnosticsPane(confirmation: .constant(nil))
    .environment(NodeStore.preview(status: status))
    .frame(width: 760, height: 560)
}

#Preview("Waiting for the report") {
  // The whole page cannot show this state: `NodeStore.preview()` seeds a
  // report, and `doctorReport` is settable only from the store's own file.
  BorderedTable {
    DoctorEmptyState().frame(height: 200)
  } actions: {
    Button("Run Diagnostics") {}
    Spacer()
    Button("Copy Report") {}.disabled(true)
  }
  .padding(Theme.Space.xl)
  .frame(width: 760)
}

#Preview("The report is being written") {
  BorderedTable {
    DoctorEmptyState(running: true).frame(height: 200)
  } actions: {
    Button("Run Diagnostics") {}.disabled(true)
    ProgressView()
    Spacer()
    Button("Copy Report") {}.disabled(true)
  }
  .padding(Theme.Space.xl)
  .frame(width: 760)
}
#endif
