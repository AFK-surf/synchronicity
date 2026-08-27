import SwiftUI

/// The attributes of whatever is selected — and the app's answer to divergence.
///
/// An inspector rather than the old "Get Info" sheet, because a sheet has to be
/// closed before you can look at the next row, and reviewing twelve divergent
/// files is exactly the task that turns into an afternoon when it must be done
/// one modal at a time.
struct FileInspector: View {
  @Bindable var model: FilesModel
  @Binding var confirmation: ConfirmationRequest?

  private var section: InspectorSection { model.inspectorSection }

  var body: some View {
    Group {
      if let entry = model.selectedEntry {
        VStack(spacing: 0) {
          Picker("", selection: $model.inspectorSection) {
            ForEach(InspectorSection.allCases) { Text($0.rawValue).tag($0) }
          }
          .pickerStyle(.segmented)
          // `labelsHidden` hides the label from the screen *and* from
          // VoiceOver, so a hidden label needs a spoken one right here — not
          // twenty lines down on the container, which is where this one had
          // ended up.
          .labelsHidden()
          .accessibilityLabel("Which details to show")
          .padding(Theme.Space.m)

          Divider()

          ScrollView {
            VStack(alignment: .leading, spacing: Theme.Space.l) {
              switch section {
              case .info:
                InspectorInfoTab(entry: entry, model: model, confirmation: $confirmation)
              case .versions:
                InspectorVersionsTab(entry: entry, model: model, confirmation: $confirmation)
              case .history: history(entry)
              }
            }
            .padding(Theme.Space.l)
            .frame(maxWidth: .infinity, alignment: .leading)
          }
        }
        // Keyed on the entry as well as the section. As an `onChange` of the
        // section alone this fired when the tab changed and never when the
        // selected row did, so History kept showing the previous file's log —
        // and it never fired for the panel's first appearance either.
        // Keyed on what the panel's answer depends on, not only on identity.
        // `RemoteEntry.id` is (space, path, kind) and moves with nothing else,
        // so a re-publish left the Versions tab showing the previous contents'
        // version set — and the "Opens now" marker then compared the new
        // root against the old list. Reachable now that a refresh of the
        // folder you are in keeps its rows.
        .task(id: LoadID(entry: entry, section: section)) {
          switch section {
          case .history: await model.loadHistory(for: entry)
          case .versions: await model.loadVersions(for: entry)
          case .info: break
          }
        }
      } else {
        ContentUnavailableView(
          model.selectedEntries.count > 1 ? "\(model.selectedEntries.count) items selected" : "Nothing selected",
          systemImage: "sidebar.trailing",
          description: Text("Select one file to see where its contents came from."))
      }
    }
  }

  /// Reload whenever any transport-backed entry field changes, without
  /// depending on the publishing seq removed from the structured protocol.
  private struct LoadID: Hashable {
    let entry: RemoteEntry
    let section: InspectorSection
  }

  // MARK: - History

  @ViewBuilder private func history(_ entry: RemoteEntry) -> some View {
    if model.historyLoading {
      HStack(spacing: Theme.Space.s) { ProgressView().controlSize(.small); Text("Reading history…") }
        .foregroundStyle(Theme.muted)
    } else if model.historyPath != entry.id {
      // Neither loaded nor empty: this is the gap between the row changing and
      // its log arriving, and claiming "no history" across it was a statement
      // the app could not yet make.
      HStack(spacing: Theme.Space.s) { ProgressView().controlSize(.small); Text("Reading history…") }
        .foregroundStyle(Theme.muted)
    } else if model.history.isEmpty {
      Text("No history recorded for this path.").foregroundStyle(Theme.muted)
    } else {
      // `log` is prose and stays prose. Parsing it into a table would be a
      // guess about a format that carries no version signal.
      Text("What this Mac has published for this path, newest first.")
        .font(.caption).foregroundStyle(Theme.muted)
      Text(model.history.joined(separator: "\n"))
        .font(Theme.Font.mono(.subheadline))
        .textSelection(.enabled)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
  }
}

#if DEBUG
private struct InspectorPreview: View {
  let entry: RemoteEntry
  let versions: PathVersions
  @State private var store = NodeStore.preview()

  var body: some View {
    let model = FilesModel(store: store)
    FileInspector(model: model, confirmation: .constant(nil))
      .environment(store)
      .frame(width: 340, height: 560)
      .task {
        model.select(space: "notes")
        model.selection = [entry.id]
      }
  }
}

#Preview("Divergent") {
  InspectorPreview(entry: SampleData.conflicted, versions: SampleData.versions)
}

#Preview("Nothing selected") {
  let store = NodeStore.preview()
  return FileInspector(
    model: FilesModel.preview(rows: SampleData.rows, space: "notes", store: store),
    confirmation: .constant(nil))
    .environment(store)
    .frame(width: 340, height: 320)
}
#endif
