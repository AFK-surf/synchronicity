import SwiftUI

/// Every command the app has run, and everything the daemon said back.
///
/// This is the architectural release valve. Any of the daemon's 42 subcommands
/// can be delivered correctly here with **no parsing at all** — the transcript
/// is the daemon's own words, and success is the stream ending cleanly — which
/// is what makes adding the next operation a registry entry rather than a
/// parser, a table and a redesign.
///
/// A window, and only a window. It was briefly a page of the settings window
/// too, and that is where it belonged least: a log is read beside the thing it
/// is a log of, and a settings window cannot sit beside a browser. Diagnostics
/// carries the button that opens this instead.
struct ActivityWindow: View {
  @Environment(NodeStore.self) private var node
  @State private var selection: ActivityRun.ID?

  var body: some View {
    NavigationSplitView {
      ActivityRuns(selection: $selection)
        .navigationSplitViewColumnWidth(min: 200, ideal: 250, max: 320)
    } detail: {
      ActivityTranscript(run: node.activity.first { $0.id == selection })
        // On the detail, so Clear sits over the transcript it clears rather
        // than over the run list, and so it is the transcript's width that
        // decides when the toolbar runs out of room.
        .toolbar {
          ToolbarItem {
            Button("Clear") { node.clearActivity() }
              .disabled(node.activity.allSatisfy(\.isRunning))
              .help("Remove every finished run from this list")
          }
        }
    }
    .navigationTitle("Activity")
  }
}

/// The runs, newest first, as a selectable list.
struct ActivityRuns: View {
  @Environment(NodeStore.self) private var node
  @Binding var selection: ActivityRun.ID?

  var body: some View {
    List(node.activity, selection: $selection) { run in
      VStack(alignment: .leading, spacing: Theme.Space.xs) {
        HStack(spacing: Theme.Space.snug) {
          icon(run)
          Text(run.title).font(.callout).lineLimit(1)
        }
        Text(subtitle(run)).font(.caption).foregroundStyle(Theme.muted).lineLimit(1)
      }
      .padding(.vertical, Theme.Space.tiny)
      .tag(run.id)
      // Whether a command worked was carried by the colour of a glyph and by
      // nothing else — unspoken by VoiceOver, and invisible to anyone who
      // cannot tell the red circle from the green one.
      .accessibilityElement(children: .combine)
      .accessibilityLabel("\(run.title), \(outcomeLabel(run)). \(subtitle(run))")
    }
    .overlay {
      if node.activity.isEmpty {
        // Not "every command this app sends": the refresh that keeps these
        // windows current sends several every few seconds and is deliberately
        // not listed, because it would bury the ones a person started. The
        // empty state used to promise the opposite and then look broken.
        ContentUnavailableView(
          "Nothing has run yet", systemImage: "list.bullet.rectangle",
          description: Text("Commands you start show up here with the daemon’s full output. The background refresh behind the other windows is not listed."))
      }
    }
  }

  @ViewBuilder private func icon(_ run: ActivityRun) -> some View {
    // The glyph carries the outcome as a shape as well as a colour — a tick, a
    // cross, a dash — and `outcomeLabel` carries it as words.
    switch run.outcome {
    case .running: ProgressView().controlSize(.mini)
    case .succeeded: Image(systemName: "checkmark.circle.fill").foregroundStyle(Theme.online)
    case .failed: Image(systemName: "xmark.circle.fill").foregroundStyle(Theme.danger)
    case .cancelled: Image(systemName: "minus.circle").foregroundStyle(Theme.muted)
    }
  }

  private func outcomeLabel(_ run: ActivityRun) -> String {
    switch run.outcome {
    case .running: return "running"
    case .succeeded: return "succeeded"
    case .failed(let failure): return "failed: \(failure.detail)"
    case .cancelled: return "cancelled"
    }
  }

  private func subtitle(_ run: ActivityRun) -> String {
    if run.isRunning { return run.latestProgress ?? "Running…" }
    if let duration = run.duration {
      return "\(run.startedAt.formatted(date: .omitted, time: .standard)) · \(duration.formatted(.number.precision(.fractionLength(1))))s"
    }
    return run.startedAt.formatted(date: .omitted, time: .standard)
  }
}

/// One run's output, or why there is none to show.
struct ActivityTranscript: View {
  let run: ActivityRun?

  var body: some View {
    if let run {
      ActivityDetail(run: run)
    } else {
      ContentUnavailableView(
        "Select a command", systemImage: "text.alignleft",
        description: Text("Its output is shown exactly as the daemon wrote it."))
    }
  }
}

#if DEBUG
#Preview("Activity") {
  ActivityWindow()
    .environment(NodeStore.preview())
    .frame(width: 820, height: 480)
}

#Preview("Nothing has run") {
  ActivityWindow()
    .environment(NodeStore.preview(activity: []))
    .frame(width: 820, height: 480)
}

#Preview("A run selected") {
  // The transcript half on its own, which is what the window is mostly showing
  // and what the run list exists to choose between.
  ActivityTranscript(run: SampleData.activity.first)
    .environment(NodeStore.preview())
    .frame(width: 560, height: 420)
}
#endif
