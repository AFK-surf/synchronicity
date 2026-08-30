import SwiftUI

/// `synch adopt tree` — adopt the cluster's content into a filesystem source.
///
/// The operation someone reaches for after adding an existing shared space to
/// a new Mac. It is not a foreground download or a replica checkout: it writes into the
/// filesystem source this node already publishes, additively. It never removes anything,
/// leaves bytes that already match alone, reports differing ones instead of
/// overwriting them, honours `.syncignore`, and stamps the published mtime so
/// it does not mint a version that looks newer than what it copied.
///
/// The dry run is not a nicety here — under `--dry-run` the daemon decides
/// everything and writes nothing, so its report *is* the answer. This sheet
/// always runs it first and shows it as the confirmation.
struct AdoptTreeSheet: View {
  @Environment(NodeStore.self) private var node
  @Environment(\.dismiss) private var dismiss

  let space: Space

  @State private var preview: [String] = []
  @State private var running = false
  @State private var asked = false
  @State private var force = false
  /// A dry run that did not reach the daemon. Distinct from an empty report,
  /// and it has to be: the report *is* this sheet's confirmation, so the two
  /// used to collapse into one screen that said "The daemon reported nothing."
  /// and armed the write behind it.
  @State private var failure: String?

  var body: some View {
    VStack(alignment: .leading, spacing: Theme.Space.l) {
      Text("Adopt “\(space.id)” From the Cluster").font(.title3.weight(.semibold))
      Text("Writes every file the cluster has for this space into \(space.pathLabel). Files already here with matching content are left alone, and nothing is ever removed.")
        .font(.callout).foregroundStyle(Theme.muted)
        .fixedSize(horizontal: false, vertical: true)

      if running {
        HStack(spacing: Theme.Space.s) {
          ProgressView().controlSize(.small)
          Text("Working out what would change…").font(.callout).foregroundStyle(Theme.muted)
        }
      } else if let failure {
        Text(failure).foregroundStyle(Theme.danger).font(.callout)
          .fixedSize(horizontal: false, vertical: true)
      } else if asked {
        VStack(alignment: .leading, spacing: Theme.Space.xs) {
          Text("What this would do").font(.callout.weight(.semibold))
          TranscriptView(lines: preview)
            .frame(minHeight: 120, maxHeight: 260)
        }
      }

      if asked && !running {
        Toggle(isOn: $force) {
          Text("Replace local files whose content differs")
        }
        Text(force
          ? "Files listed above as differing are overwritten with the cluster’s version. What is on this Mac now is not recoverable from here."
          : "Files whose content differs are reported and left exactly as they are.")
          .font(.caption)
          .foregroundStyle(force ? Theme.ink(Theme.danger) : Theme.muted)
          .fixedSize(horizontal: false, vertical: true)
      }

      HStack {
        Spacer()
        Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
        Button(asked ? "Adopt" : "Preview…") {
          if asked { adopt() } else { dryRun() }
        }
          .keyboardShortcut(.defaultAction)
          .disabled(running || !space.hasFilesystemSource)
      }
    }
    .padding(Theme.Space.xxl).frame(width: 560)
  }

  private func dryRun() {
    running = true
    failure = nil
    Task {
      let lines = await node.adoptTree(reference: space.id, dryRun: true)
      running = false
      // `asked` is what turns the default button from `Preview…` into `Adopt`,
      // and the dry run's report is the only confirmation this sheet raises.
      // So a preview that never reached the daemon must not set it: the
      // alternative, which is what shipped, drew the failure as `The daemon
      // reported nothing.` — indistinguishable from a clean space with nothing
      // to copy — and armed the write anyway.
      guard let lines else {
        let said = node.lastFailure.map { failure -> String in
          failure.recoverySuggestion.map { "\(failure.detail)\n\n\($0)" } ?? failure.detail
        }
        failure = said ?? "The preview did not complete."
        return
      }
      preview = lines.isEmpty ? ["The daemon reported nothing."] : lines
      asked = true
    }
  }

  private func adopt() {
    let reference = space.id
    let overwrite = force
    node.enqueue { _ = await node.adoptTree(reference: reference, replace: overwrite) }
    dismiss()
  }
}

#if DEBUG
#Preview("Adopt Tree") {
  AdoptTreeSheet(space: Space(id: "media", localPath: "/Volumes/Big/Media"))
    .environment(NodeStore.preview())
}
#endif
