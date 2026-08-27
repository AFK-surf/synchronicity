import SwiftUI

/// The rows for the current folder.
///
/// A real `Table`, which is where sorting, column resizing and customisation,
/// type-select, multiple selection and full keyboard navigation come from. The
/// hand-rolled stack it replaces had none of them.
struct EntryTable: View {
  @Environment(NodeStore.self) private var node
  @Bindable var model: FilesModel
  @Environment(\.exportEntry) private var exportEntry
  @State private var confirmation: ConfirmationRequest?
  /// The in-flight delete plan, if one is being worked out, and which press
  /// owns it — a plan cancelled by navigating away still runs its cleanup, and
  /// without the token that cleanup would clear a *newer* press's handle.
  @State private var planning: Task<Void, Never>?
  @State private var planToken = 0
  /// Settings offered this and nothing read it, so turning it off changed
  /// nothing at all. It governs this dialog and only this one: the stronger
  /// gates are chosen by what an operation costs, not by a checkbox.
  @AppStorage("confirmDeletes") private var confirmDeletes = true

  var body: some View {
    VStack(spacing: 0) {
      if let failure = model.loadFailure, !model.rows.isEmpty {
        // These rows are what the folder held when it was last read
        // successfully, so they stay — with the reason they are not newer.
        AlarmBanner(
          text: "This folder could not be re-read: \(failure.detail) What is below is what it held last time.",
          tint: Theme.warning,
          actionTitle: "Try Again",
          action: { Task { await model.reload() } })
      }
      if let withheld = model.withheldSummary {
        // Never silently. The daemon's `List` omits a path its policy refuses
        // rather than reporting the refusal, so choosing Strict used to delete
        // rows from the folder with nothing saying so.
        AlarmBanner(
          text: withheld,
          tint: Theme.warning,
          actionTitle: "Show Newest",
          action: { model.showNewest() })
      }
      if model.wasTruncated {
        // Never silent. The old client capped at 500 rows with no notice, so a
        // large folder simply looked small.
        //
        // And never advice that cannot work: this used to say "narrow it with
        // the search field", but the search filters the rows already loaded and
        // has no way to reach past the cap. Opening a subfolder does — it is a
        // shorter prefix on the daemon's own listing.
        AlarmBanner(
          text: "This folder has more items than the app can show at once. Open a subfolder to narrow the listing — the search field only filters what is already listed.",
          tint: Theme.warning)
      }
      // Rows and the empty area below them both have a menu, and the table
      // decides which by what was clicked. Under SwiftUI this needed a wrapper
      // with its own `contextMenu`, because `contextMenu(forSelectionType:)`
      // is documented to hand the builder an empty set below the last row and
      // did not — right-clicking there produced nothing at all.
      table
      PathBar(model: model)
      EntryStatusBar(model: model, isPlanning: planning != nil)
    }
    .confirmedAction($confirmation)
    // A plan describes the folder it was asked about, so it does not outlive
    // it.
    .onChange(of: model.prefix) { _, _ in cancelPlanning() }
    .onChange(of: model.selectedSpace) { _, _ in cancelPlanning() }

  }

  private var table: some View {
    // An `NSTableView`, not a SwiftUI `Table`. See ``EntryTableView`` for
    // what decided it: a SwiftUI table in this window could be clicked and not
    // take the keyboard, so the caret could get into the browser and never
    // move between its two lists.
    EntryTableView(
      rows: model.visibleRows,
      selection: model.selection,
      sortOrder: model.sortOrder,
      // Left-aligned and inset the way a table cell is. A hosting view fills
      // its cell, and a SwiftUI view centres itself in what it is given — so
      // without this every name sat in the middle of its column.
      cell: { entry, column in
        AnyView(
          cell(entry, column)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Theme.Space.xs))
      },
      onSelect: { model.selection = $0 },
      onSort: { model.sortOrder = $0 },
      onActivate: { activate($0) },
      onDelete: { requestDelete(model.selectedEntries) },
      menu: { ids in
        ids.isEmpty ? emptyAreaMenu : menu(for: entries(ids))
      })
    .overlay {
      if model.isLoading && model.rows.isEmpty {
        ProgressView().controlSize(.small)
      } else if let failure = model.loadFailure, model.rows.isEmpty {
        // A folder that could not be listed is not an empty folder, and the
        // table used to say it was. Only when there is nothing to draw,
        // though: a *refresh* that fails deliberately keeps the rows it has,
        // and an overlay is drawn on top of them — so that case gets the
        // banner above the table instead.
        ContentUnavailableView {
          Label("Could not list this folder", systemImage: "exclamationmark.triangle")
        } description: {
          Text(failure.recoverySuggestion.map { "\(failure.detail)\n\n\($0)" } ?? failure.detail)
        } actions: {
          Button("Try Again") { Task { await model.reload() } }
        }
      } else if model.rows.isEmpty && !model.isLoading {
        ContentUnavailableView {
          Label("Nothing here yet", systemImage: "tray")
        } description: {
          Text("Drop files in, or use the Add button.")
        }
      } else if model.visibleRows.isEmpty && !model.search.isEmpty {
        // An empty folder and a filter that matches nothing are different
        // facts. Sharing one blank table between them left the second with no
        // explanation and no way out of it.
        ContentUnavailableView {
          Label("No matches", systemImage: "line.3.horizontal.decrease.circle")
        } description: {
          Text("Nothing in this folder matches \u{201c}\(model.search)\u{201d}. \(model.rows.count) item\(model.rows.count == 1 ? " is" : "s are") here.")
        } actions: {
          Button("Clear Filter") { model.clearSearch() }
        }
      }
    }
    // Space is Quick Look on a Mac, and the table takes the key first for
    // type-select, so this takes it earlier still.
    .modifier(QuickLookKeyMonitor(model: model))
  }

  /// One cell, still drawn by SwiftUI — only the table around it is AppKit.
  @ViewBuilder private func cell(
    _ entry: RemoteEntry, _ column: EntryTableView.Column
  ) -> some View {
    switch column {
    case .name:
      nameCell(entry)
    case .versions:
      if entry.hasVersions {
        StatusChip(
          text: "\(entry.versions)", tint: Theme.warning, systemImage: "arrow.triangle.branch")
          // Versions, not devices: several devices that agree share one, so
          // "3 devices publish different contents" was a different number.
          .help("\(entry.versions) versions of this file exist across your devices — open Versions to pick one")
      } else if !entry.isSynthesizedDirectory {
        Text("\u{2014}").cellForeground(Theme.muted)
      }
    case .size:
      Text(entry.sizeLabel)
        .font(Theme.Font.mono(.subheadline))
        .cellForeground(Theme.muted)
        .monospacedDigit()
    case .modified:
      Text(entry.modifiedLabel).font(.caption).cellForeground(Theme.muted)
    case .device:
      // The name, not the key. Sorted on the raw value so the column still
      // groups a device's rows together whatever it is called.
      DeviceCell(name: node.label(forOrigin: entry.origin), key: entry.origin)
    }
  }

  private func nameCell(_ entry: RemoteEntry) -> some View {
    EntryNameCell(
      entry: entry, model: model,
      opensUnderPolicy: isOpenedByPolicy(entry),
      withheldChip: withheldChip,
      withheldHelp: withheldHelp,
      spokenLabel: accessibilityLabel(entry))
  }

  private func accessibilityLabel(_ entry: RemoteEntry) -> String {
    var parts = [entry.name, entry.kindLabel]
    if !entry.isDirectory { parts.append(entry.sizeLabel) }
    if !entry.origin.isEmpty { parts.append("from \(node.label(forOrigin: entry.origin))") }
    if entry.hasVersions { parts.append("\(entry.versions) versions") }
    return parts.joined(separator: ", ")
  }

  /// Whether the chosen policy will open this row.
  ///
  /// Asked of the model rather than guessed from `entry.origin`: under a
  /// pinned device the daemon resolves each path *to that device's* entry, so
  /// `entry.origin == pinned` was true of every row that survived and the mark
  /// could never draw. The rows that do not survive are the point, and they
  /// are only in the listing at all because it is folded under Newest.
  private func isOpenedByPolicy(_ entry: RemoteEntry) -> Bool {
    !model.withheldPaths.contains(entry.path)
  }

  /// What the mark says, which depends on why the row is closed.
  ///
  /// Two words. It sits inside the Name column beside the file's own name, and
  /// "not from Unnamed device (ao6bbs…)" left "apple-si…alyze.zip" of a name
  /// that fits comfortably. The sentence is in the banner above the table and
  /// in this row's tooltip; the chip is only the flag.
  private var withheldChip: String {
    if case .origin = model.policy { "other device" } else { "several versions" }
  }

  private var withheldHelp: String {
    if case .origin(let id) = model.policy {
      "\(node.label(forOrigin: id)) does not publish this, so the version policy will not open it."
    } else {
      "More than one device publishes this, and Strict refuses to choose between them."
    }
  }

  /// The named rows, in the order they are on screen.
  ///
  /// `visibleRows`, not `rows`: `rows` comes off the listing fold as
  /// folders-then-files whatever the sort, so `.first` of a selection was the
  /// alphabetically-first folder rather than anything the person was looking
  /// at.
  private func entries(_ ids: Set<RemoteEntry.ID>) -> [RemoteEntry] {
    model.visibleRows.filter { ids.contains($0.id) }
  }

  /// Double-click, and ⌘↓.
  ///
  /// `primaryAction` is handed the whole selection and never says which row
  /// was clicked, so a mixed selection has to be given a rule rather than a
  /// guess. One row does what it says. Several rows means the folders are not
  /// what was meant — navigation has one destination and a selection has many
  /// — so the files are previewed and the folders left alone.
  private func activate(_ ids: Set<RemoteEntry.ID>) {
    let chosen = entries(ids)
    if chosen.count == 1, let only = chosen.first {
      if only.isDirectory { model.open(only) } else { model.requestPreview(only) }
      return
    }
    guard let file = chosen.first(where: \.isFile) else { return }
    model.requestPreview(file)
  }

  private func menu(for entries: [RemoteEntry]) -> MenuPlan {
    var plan: [MenuPlan.Entry] = []
    if entries.count == 1, let entry = entries.first {
      if entry.isDirectory {
        plan.append(.item("Open") { model.open(entry) })
      } else {
        plan.append(.item("Quick Look") { model.requestPreview(entry) })
        plan.append(.item("Download\u{2026}") { exportEntry(entry) })
        plan.append(.separator)
        // Selects the row it was invoked on. It used to open the panel and
        // change nothing else, so the panel was headed by whatever had been
        // selected before — or by "Nothing selected" — while the fetch it
        // started was for a different file.
        plan.append(.item("Show Versions") { model.showVersions(of: entry) })
        // One item, pointing the way this file actually is. Both used to be
        // offered on every file, always enabled, with the state readable
        // nowhere in this window.
        let pinned = model.isPinned(entry)
        plan.append(.item(pinned ? "Stop Keeping Offline" : "Keep Offline") {
          confirmation = model.pinRequest(entry, pinned: !pinned)
        })
      }
      plan.append(.separator)
    }
    if !entries.isEmpty {
      plan.append(.item("Delete", destructive: true) { requestDelete(entries) })
    }
    return MenuPlan(plan)
  }

  /// What can be done here when the click named no file.
  private var emptyAreaMenu: MenuPlan {
    MenuPlan([
      .item("Add Files\u{2026}", enabled: model.selectedSpace != nil) {
        model.importRequested = true
      },
      .item("Refresh", enabled: model.selectedSpace != nil) {
        Task { await model.reload() }
      },
      .separator,
      .item(
        "Scan This Mac\u{2019}s Folders",
        enabled: node.connection.isConnected && !node.houseworkRunning
      ) { node.scanNow() },
      .item(
        "Sync With Other Devices",
        enabled: node.connection.isConnected && !node.houseworkRunning
      ) { node.syncNow() },
      .separator,
      .item(model.inspectorVisible ? "Hide Versions" : "Show Versions") {
        model.toggleVersionsPanel()
      },
    ])
  }

  private func cancelPlanning() {
    planning?.cancel()
    planning = nil
    planToken += 1
  }

  private func requestDelete(_ entries: [RemoteEntry]) {
    guard !entries.isEmpty else { return }
    guard planning == nil else { return }
    // Asking the daemon what a folder holds is a round trip now, so this is a
    // Task. The confirmation still cannot appear before the count it states.
    //
    // Deliberately a different name from the async one it calls: two overloads
    // separated only by `async` resolve by context, and a sync wrapper that
    // picks itself is an infinite loop that compiles.
    // Held, so a second press does not start a second enumeration and so
    // navigating away can drop this one — a folder's plan is up to fifty round
    // trips now, and a confirmation that arrives after the folder has changed
    // describes something nobody is looking at.
    planToken += 1
    let token = planToken
    planning = Task { await confirmDelete(entries, token: token) }
  }

  private func confirmDelete(_ entries: [RemoteEntry], token: Int) async {
    defer { if token == planToken { planning = nil } }
    let plan = await model.deletePlan(for: entries)
    guard !Task.isCancelled else { return }
    guard !plan.paths.isEmpty else {
      // The empty plan has two causes and they are not the same fact: the
      // folder really is empty of anything this Mac publishes, or this Mac
      // could not finish asking. Saying the first when it was the second is
      // how a delete that failed looked like a delete that had nothing to do.
      node.alert = plan.incomplete
        ? DaemonFailure(
            code: .unavailable,
            detail: "This Mac could not list what is inside that folder, so it cannot say what deleting it would remove.",
            operation: "list that folder")
        : DaemonFailure(
            code: .notFound,
            detail: "That folder holds nothing this Mac publishes, so there is nothing here to delete.",
            operation: nil)
      return
    }
    // The consequence is computed, and it corrects the guess: a delete
    // publishes this Mac's tombstone. It does not reach into other machines,
    // and it does not touch the local file that produced the entry.
    var consequence = plan.paths.count == 1
      ? "This publishes a deletion for it from this Mac."
      : "This publishes deletions for \(plan.paths.count) items from this Mac."
    if !plan.folders.isEmpty {
      consequence += " Folders are expanded into the items they contain, because the daemon deletes one path at a time."
    }
    if plan.incomplete {
      consequence += " This Mac could not finish listing one of the folders, so there may be more inside it than this names."
    }
    consequence += " Other devices that publish the same paths keep their own copies, and those paths stay visible."
    guard confirmDeletes else {
      // Turned off in Settings. The transfer of the decision is the whole
      // point of the preference, so it is honoured rather than second-guessed.
      model.delete(plan)
      return
    }
    confirmation = ConfirmationRequest(
      title: plan.summary,
      consequence: consequence,
      verb: "Delete",
      gate: .confirm,
      perform: { model.delete(plan) }
    )
  }
}

#if DEBUG
#Preview("Rows") {
  let store = NodeStore.preview()
  return EntryTable(model: FilesModel.preview(rows: SampleData.rows, space: "notes", store: store))
    .environment(store)
    .frame(width: 760, height: 420)
}

#Preview("Inside a folder") {
  let store = NodeStore.preview()
  let model = FilesModel.preview(
    rows: SampleData.rows, space: "notes", prefix: "journal", store: store)
  return EntryTable(model: model)
    .environment(store)
    .frame(width: 760, height: 420)
}

#Preview("Nothing here yet") {
  let store = NodeStore.preview()
  return EntryTable(model: FilesModel.preview(rows: [], space: "notes", store: store))
    .environment(store)
    .frame(width: 760, height: 300)
}
#endif
