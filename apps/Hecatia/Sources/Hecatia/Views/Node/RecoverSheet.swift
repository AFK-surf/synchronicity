import SwiftUI

/// `recover [--wait <dur>] [--gap <n>]`.
///
/// Its own sheet rather than a plain confirmation, because both flags are
/// judgement calls the operator has to be able to make: how long to listen
/// before deciding what peers have seen, and how far above that to resume.
struct RecoverSheet: View {
  @Environment(NodeStore.self) private var node
  @Environment(\.dismiss) private var dismiss

  @State private var wait = ""
  @State private var gap = ""
  @State private var typed = ""

  private var observed: String {
    node.alarms.first(where: \.isRecovery)?.text ?? "A peer advertises a newer position than this Mac holds."
  }

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.l) {
      HStack(alignment: .firstTextBaseline, spacing: Theme.Space.m) {
        Image(systemName: "exclamationmark.octagon.fill")
          .font(.title2).foregroundStyle(Theme.danger)
        Text("Resume publishing").font(.title3.weight(.semibold))
      }

      Text(observed).font(.callout).foregroundStyle(Theme.muted)
        .fixedSize(horizontal: false, vertical: true)

      Text("This collects what other devices say they have seen and resumes publishing above it. What they advertise is their **unverified summary**, not a signed record — if the machine holding this Mac’s newest history is merely asleep, wait for it instead of doing this.")
        .font(.callout)
        .fixedSize(horizontal: false, vertical: true)

      HStack(spacing: Theme.Space.s) {
        Text("Listen for").frame(width: 74, alignment: .trailing)
        TextField("the daemon’s default", text: $wait)
          .textFieldStyle(.roundedBorder).frame(width: 120)
          .accessibilityLabel("Listen for")
        Text("e.g. 30s, 2m").font(.caption).foregroundStyle(Theme.muted)
      }
      VStack(alignment: .leading, spacing: Theme.Space.xs) {
        HStack(spacing: Theme.Space.s) {
          Text("Resume").frame(width: 74, alignment: .trailing)
          TextField("default", text: $gap)
            .textFieldStyle(.roundedBorder).frame(width: 120)
            .accessibilityLabel("Resume this far above the highest position seen")
          Text("this far above the highest position seen").font(.caption).foregroundStyle(Theme.muted)
        }
        if gapIsUnreadable {
          // Said here rather than silently dropped: the daemon takes a number
          // and nothing else, and a sheet that quietly discards half of what
          // was typed is worse than one that refuses it.
          Text("A whole number of positions, or leave it empty for the daemon’s default.")
            .font(.caption).foregroundStyle(Theme.danger)
            .padding(.leading, Theme.Space.section)
        }
      }

      VStack(alignment: .leading, spacing: Theme.Space.snug) {
        Text("Type resume to confirm").font(.caption).foregroundStyle(Theme.muted)
        TextField("", text: $typed)
          .textFieldStyle(.roundedBorder).font(Theme.Font.mono(.body))
          // The app's most consequential gate announced itself to VoiceOver as
          // an unnamed text field: the caption above is a sibling, not a label.
          .accessibilityLabel("Type the word resume to confirm")
      }

      CopyableCommand(commandLine)

      HStack {
        Spacer()
        Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Resume", role: .destructive) { recover() }
          .disabled(typed != "resume" || gapIsUnreadable)
      }
    }
    .padding(Theme.Space.xxl).frame(width: 520)
  }

  /// The gap as the daemon will receive it, or nil.
  ///
  /// `UInt64(gap)` is nil for anything non-numeric, so `5x` was dropped from
  /// the request and kept in the command line beside it — the sheet displayed
  /// and offered to copy a command that differed from the one it ran.
  private var gapValue: UInt64? { gap.isEmpty ? nil : UInt64(gap) }

  private var gapIsUnreadable: Bool { !gap.isEmpty && gapValue == nil }

  private var commandLine: String {
    var parts = ["synch recover"]
    if !wait.isEmpty { parts.append("--wait \(wait)") }
    if let gapValue { parts.append("--gap \(gapValue)") }
    return parts.joined(separator: " ")
  }

  private func recover() {
    let waitValue = wait.isEmpty ? nil : wait
    let gapValue = gapValue
    let line = commandLine
    node.enqueue {
      await node.run(
        Operations.require("recover"),
        Cmd.recover(wait: waitValue, gap: gapValue),
        commandLine: line, deadline: .long)
    }
    dismiss()
  }
}

#if DEBUG
#Preview("Recover") {
  RecoverSheet()
    .environment(NodeStore.preview(status: SampleData.alarmedStatus))
}
#endif
