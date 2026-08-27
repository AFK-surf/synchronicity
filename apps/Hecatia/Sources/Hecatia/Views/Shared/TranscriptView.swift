import SwiftUI

/// A monospaced transcript, used for everything the app refuses to parse.
struct TranscriptView: View {
  let lines: [String]
  var emptyMessage = "No output."

  /// The joined text, joined once per change rather than once per body pass.
  ///
  /// One `Text` rather than one per line, because a transcript is copied whole
  /// and per-line `Text`s cannot be selected across. But the join is O(the
  /// whole transcript) and the body runs whenever anything else in the window
  /// publishes, so it is kept here and rebuilt only when the transcript
  /// actually grows.
  @State private var joined = ""

  var body: some View {
    ScrollView([.vertical, .horizontal]) {
      if lines.isEmpty {
        Text(emptyMessage).foregroundStyle(Theme.muted).padding(Theme.Space.m)
      } else {
        Text(joined)
          .font(Theme.Font.mono())
          .textSelection(.enabled)
          .frame(maxWidth: .infinity, alignment: .leading)
          .padding(Theme.Space.m)
      }
    }
    // Keyed on the shape of the transcript rather than on the array, so the
    // check itself is not another O(n) pass over it.
    .task(id: "\(lines.count)|\(lines.last ?? "")") {
      joined = lines.joined(separator: "\n")
    }
  }
}

#if DEBUG
#Preview("Transcript") {
  TranscriptView(lines: SampleData.doctorReport)
    .padding(Theme.Space.xl)
    .frame(width: 520, height: 220)
}

#Preview("Transcript, empty") {
  TranscriptView(lines: [], emptyMessage: "The daemon said nothing.")
    .padding(Theme.Space.xl)
    .frame(width: 520, height: 160)
}
#endif
