import SwiftUI

/// One run: what was asked, what the daemon said, and how it ended.
struct ActivityDetail: View {
  let run: ActivityRun

  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      VStack(alignment: .leading, spacing: Theme.Space.snug) {
        Text(run.title).font(.title3.weight(.semibold))
        HStack(spacing: Theme.Space.s) {
          Text(run.commandLine)
            .font(Theme.Font.mono(.subheadline)).foregroundStyle(Theme.muted)
            .textSelection(.enabled).lineLimit(1).truncationMode(.middle)
          CopyGlyphButton(
            value: run.commandLine,
            help: "Copy as a synch command",
            accessibilityName: "Copy this command line")
        }
        if case .failed(let failure) = run.outcome {
          VStack(alignment: .leading, spacing: Theme.Space.xs) {
            // `Theme.ink`, not the tint itself: this is text on that tint's
            // own wash, which is the pairing `Theme.ink` exists for and which
            // every other tinted ground in the app already routes through.
            Text(failure.detail).font(.callout).foregroundStyle(Theme.ink(Theme.danger))
              .fixedSize(horizontal: false, vertical: true)
            if let suggestion = failure.recoverySuggestion {
              Text(suggestion).font(.caption).foregroundStyle(Theme.muted)
                .fixedSize(horizontal: false, vertical: true)
            }
          }
          .padding(Theme.Space.m)
          .frame(maxWidth: .infinity, alignment: .leading)
          .background(Theme.danger.opacity(0.1), in: .rect(cornerRadius: Theme.Radius.s))
        }
      }
      .padding(Theme.Space.l)

      Divider()

      TranscriptView(
        lines: run.output.transcript,
        emptyMessage: run.isRunning ? "Running…" : "The command produced no output.")

      HStack {
        Spacer()
        Button("Copy Output", action: copyOutput)
          .disabled(run.output.isEmpty)
      }
      .padding(.horizontal, Theme.Space.l).padding(.vertical, Theme.Space.s)
      .overlay(alignment: .top) { Divider() }
    }
  }

  private func copyOutput() {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(
      run.output.transcript.joined(separator: "\n"), forType: .string)
  }
}

#if DEBUG
#Preview("A run that worked") {
  // 560 points is about what the detail column gets in an 820pt Activity
  // window, once the run list has taken its own.
  let run = SampleData.activity.first { $0.outcome == .succeeded }!
  return ActivityDetail(run: run)
    .frame(width: 560, height: 420)
}

#Preview("A run that failed") {
  // The failing line is on screen twice, deliberately: the daemon's own words
  // in the transcript, and the same words with the app's remedy under them in
  // the block above it.
  let run = SampleData.activity.first { if case .failed = $0.outcome { true } else { false } }!
  return ActivityDetail(run: run)
    .frame(width: 560, height: 420)
}

#Preview("Still running") {
  // A run in flight has no outcome and a transcript that is only progress
  // lines — which is output, so Copy Output is already live.
  let run = SampleData.activity.first(where: \.isRunning)!
  return ActivityDetail(run: run)
    .frame(width: 560, height: 420)
}

#Preview("A failure, narrow") {
  // The detail column is the half that shrinks when the window does: the
  // command line truncates in the middle and the failure text wraps rather
  // than either of them setting a floor on the window's width.
  let run = SampleData.activity.first { if case .failed = $0.outcome { true } else { false } }!
  return ActivityDetail(run: run)
    .frame(width: 360, height: 420)
}
#endif
