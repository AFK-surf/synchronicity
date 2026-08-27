import SwiftUI

/// Shown when a parser met a line it did not recognise.
///
/// The daemon's text formats carry no version signal, so this is the app's only
/// honest answer to one changing: the table renders what it read, and says so.
struct ParseWarningChip: View {
  let lines: [String]
  @State private var showing = false

  var body: some View {
    if !lines.isEmpty {
      Button { showing = true } label: {
        Label("\(lines.count) unread", systemImage: "questionmark.circle")
          .font(.caption)
      }
      .buttonStyle(.borderless)
      .foregroundStyle(Theme.warning)
      .help("The daemon printed lines this version of the app does not recognise")
      .popover(isPresented: $showing) {
        VStack(alignment: .leading, spacing: Theme.Space.s) {
          Text("Lines this app could not read")
            .font(.headline)
          Text("They are shown exactly as the daemon printed them. Nothing was dropped.")
            .font(.caption).foregroundStyle(Theme.muted)
          TranscriptView(lines: lines).frame(width: 460, height: 160)
        }
        .padding(Theme.Space.l)
      }
    }
  }
}

#if DEBUG
#Preview("Chrome") {
  ParseWarningChip(lines: ["a line the daemon added in a later release"])
    .padding(Theme.Space.xl)
    .frame(width: 520)
}
#endif
