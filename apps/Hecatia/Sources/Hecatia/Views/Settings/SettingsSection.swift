import SwiftUI

/// A titled block of a settings page: a name, the content, and the sentence
/// that explains it underneath.
///
/// What replaced `PaneLayout`, the Node window's shared pane chrome. The
/// explanation used to sit at the top of a pane beside its buttons — 30-odd
/// points of height on every page, and the sentence placed where it is read
/// before the thing it describes has been seen. Here it is a footer, the way a
/// `Form` section's is: the content first, the caption under it for whoever
/// wants it.
///
/// The content gets no border of its own. A block of rows wants none and a
/// table wants ``BorderedTable``'s, so the decision belongs to what is inside.
struct SettingsSection<Content: View>: View {
  var title: String?
  var footer: String?
  /// Lines the daemon printed that no parser here recognised. Shown as the
  /// chip that opens them verbatim, so nothing is dropped silently.
  var warnings: [String] = []
  @ViewBuilder var content: Content

  init(
    _ title: String? = nil,
    footer: String? = nil,
    warnings: [String] = [],
    @ViewBuilder content: () -> Content
  ) {
    self.title = title
    self.footer = footer
    self.warnings = warnings
    self.content = content()
  }

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.s) {
      if let title {
        Text(title).font(.headline)
      }
      content
      if let footer {
        Text(footer)
          .font(.callout)
          .foregroundStyle(Theme.muted)
          .fixedSize(horizontal: false, vertical: true)
          // A line of prose stops being readable long before the page stops
          // being wide, and the content above is allowed the whole width.
          .frame(maxWidth: Theme.measure, alignment: .leading)
      }
      if !warnings.isEmpty {
        ParseWarningChip(lines: warnings)
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }
}

#if DEBUG
#Preview("Spaces") {
  SettingsSection(
    "Shared Spaces",
    footer: "Filesystem and API sources this Mac publishes. The space name is shared across every device."
  ) {
    VStack(alignment: .leading, spacing: Theme.Space.xs) {
      DetailRow(label: "Spaces", value: "notes, archive, photos")
      DetailRow(label: "Published", value: "seq 4118")
    }
  }
  .padding(Theme.Space.xl)
  .frame(width: 760)
}

#Preview("No name of its own") {
  // A section that follows one with a title, where a second heading would be
  // the same word twice.
  SettingsSection(footer: "Stopping the service ends sharing, checkout updates and remote browsing.") {
    Toggle("Show advanced operations", isOn: .constant(false))
  }
  .padding(Theme.Space.xl)
  .frame(width: 760)
}

#Preview("The daemon said something new") {
  SettingsSection(
    "Checkouts & Pins",
    footer: "A replica checkout writes the newest view into a normal folder. Pins hold one object even when no role needs it.",
    warnings: ["a line the daemon added in a later release"]
  ) {
    DetailRow(label: "Checkouts", value: "1")
  }
  .padding(Theme.Space.xl)
  .frame(width: 760)
}

#Preview("Larger text") {
  // The footer is the part that grows, and it is the part with a width limit
  // on it: `Theme.measure` caps the line length, never the number of lines.
  SettingsSection(
    "Shared Spaces",
    footer: "Filesystem and API sources this Mac publishes. The space name is shared across every device."
  ) {
    DetailRow(label: "Spaces", value: "notes")
  }
  .dynamicTypeSize(.accessibility1)
  .padding(Theme.Space.xl)
  .frame(width: 760)
}
#endif
