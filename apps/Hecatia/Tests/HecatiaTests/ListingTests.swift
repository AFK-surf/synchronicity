import Foundation
import Testing
@testable import Hecatia

/// What the file list shows, and in what order.
@Suite("Arranging a folder")
struct ArrangeTests {
  private func entry(_ path: String, folder: Bool = false, size: UInt64 = 0) -> RemoteEntry {
    RemoteEntry(
      origin: "a@b", space: "demo", path: path, kind: folder ? .directory : .file,
      size: size, modified: Date(timeIntervalSince1970: 0), versions: 1,
      isSynthesizedDirectory: folder)
  }

  private let byName: [KeyPathComparator<RemoteEntry>] = [.init(\.name, order: .forward)]

  @Test("Folders come first, whatever the sort")
  func foldersFirst() {
    let rows = [entry("beta.txt"), entry("alpha", folder: true), entry("alpha.txt"),
                entry("zulu", folder: true)]
    let arranged = FilesModel.arrange(rows, matching: "", by: byName)
    #expect(arranged.map(\.name) == ["alpha", "zulu", "alpha.txt", "beta.txt"])
  }

  @Test("Folders still come first when the sort is reversed")
  func foldersFirstReversed() {
    let rows = [entry("beta.txt"), entry("alpha", folder: true), entry("alpha.txt"),
                entry("zulu", folder: true)]
    let arranged = FilesModel.arrange(
      rows, matching: "", by: [.init(\.name, order: .reverse)])
    #expect(arranged.map(\.name) == ["zulu", "alpha", "beta.txt", "alpha.txt"])
  }

  /// The bug the single-pass comparator exists to prevent: two `sorted` calls
  /// relied on the first one's order surviving the second, and Swift's sort is
  /// not stable, so the secondary key could come back scrambled.
  @Test("A secondary key is honoured rather than left to luck")
  func secondaryKey() {
    let rows = (0..<40).map { entry("f\(String(format: "%02d", $0)).txt", size: UInt64($0 % 2)) }
    let arranged = FilesModel.arrange(
      rows, matching: "",
      by: [.init(\.size, order: .forward), .init(\.name, order: .forward)])
    let small = arranged.prefix(while: { $0.size == 0 }).map(\.name)
    #expect(small == small.sorted())
    let large = arranged.drop(while: { $0.size == 0 }).map(\.name)
    #expect(large == large.sorted())
  }

  @Test("The filter matches names, not paths, and ignores case")
  func filtering() {
    let rows = [entry("notes/Readme.md"), entry("notes/other.txt"), entry("readme", folder: true)]
    #expect(FilesModel.arrange(rows, matching: "readme", by: byName).map(\.name)
      == ["readme", "Readme.md"])
    #expect(FilesModel.arrange(rows, matching: "notes", by: byName).isEmpty)
  }

  @Test("Identity distinguishes a folder from a file at the same path")
  func identity() {
    #expect(entry("a/b", folder: true).id != entry("a/b").id)
    #expect(entry("a/b").name == "b")
    #expect(entry("b").name == "b")
  }
}

/// The browser's own state transitions, without a daemon.
@Suite("Browser state")
@MainActor
struct BrowserStateTests {
  private func entry(_ path: String, versions: UInt32 = 1) -> RemoteEntry {
    RemoteEntry(
      origin: "a@b", space: "demo", path: path, kind: .file, size: 1,
      modified: Date(timeIntervalSince1970: 0), versions: versions)
  }

  /// The status bar's "N need a decision" used to open the panel and select
  /// nothing, so it landed on "Nothing selected" — a button that named a
  /// number and then showed none of it.
  @Test("Show Versions lands on a row that has versions")
  func showVersionsPicksADivergentRow() {
    let model = FilesModel.preview(rows: [entry("a.txt"), entry("b.txt", versions: 3)])
    model.showVersions()
    #expect(model.inspectorVisible)
    #expect(model.inspectorSection == .versions)
    #expect(model.selection == [model.rows[1].id])
  }

  @Test("Show Versions on a named row selects that row")
  func showVersionsOnARow() {
    let rows = [entry("a.txt"), entry("b.txt", versions: 3)]
    let model = FilesModel.preview(rows: rows)
    model.showVersions(of: rows[0])
    #expect(model.selection == [rows[0].id])
    #expect(model.inspectorSection == .versions)
  }

  @Test("A selection that already has versions is left alone")
  func showVersionsKeepsAGoodSelection() {
    let rows = [entry("a.txt", versions: 2), entry("b.txt", versions: 3)]
    let model = FilesModel.preview(rows: rows)
    model.selection = [rows[1].id]
    model.showVersions()
    #expect(model.selection == [rows[1].id])
  }

  /// Clearing the filter from the empty state or the status bar used to leave
  /// an expanded, empty field in the toolbar, because folding it away was only
  /// ever a reaction to that field losing the focus.
  @Test("Clearing the filter puts the magnifier back")
  func clearingTheFilterFoldsTheField() {
    let model = FilesModel.preview(rows: [entry("a.txt")])
    model.openSearch()
    model.search = "a"
    #expect(model.searchPresented)
    model.clearSearch()
    #expect(model.search.isEmpty)
    #expect(!model.searchPresented)
  }

  /// A Bool cannot express "focus it again": Command-F with the field already
  /// open re-assigns true to a value that is already true.
  @Test("Every request for the caret is distinguishable from the last")
  func focusRequestsAreDistinct() {
    let model = FilesModel.preview(rows: [entry("a.txt")])
    let first = model.searchFocusRequest
    model.openSearch()
    model.openSearch()
    #expect(model.searchFocusRequest == first + 2)
  }

  @Test("The visible rows are recomputed when the filter changes")
  func theCacheIsDroppedWhenItsInputsChange() {
    let model = FilesModel.preview(rows: [entry("alpha.txt"), entry("beta.txt")])
    #expect(model.visibleRows.count == 2)
    model.search = "alpha"
    #expect(model.visibleRows.count == 1)
    model.sortOrder = [.init(\.name, order: .reverse)]
    #expect(model.visibleRows.count == 1)
    model.search = ""
    #expect(model.visibleRows.map(\.name) == ["beta.txt", "alpha.txt"])
  }
}

/// How a device is named where a person is reading.
@Suite("Naming a device")
@MainActor
struct OriginLabelTests {
  private let key = "key:" + String(repeating: "a", count: 52)

  @Test("This Mac is called This Mac")
  func ownOrigin() {
    let store = NodeStore.preview()
    guard let own = store.origin else { return }
    #expect(store.label(forOrigin: own) == "This Mac")
  }

  /// A 52-character z-base-32 key is an identifier, not a name. It wrapped
  /// over three lines in the inspector and named nothing.
  @Test("A device key becomes a short, honest placeholder")
  func keyOrigin() {
    let store = NodeStore.preview()
    let label = store.label(forOrigin: key)
    #expect(label.hasPrefix("Unnamed device ("))
    #expect(label.count < 30)
    #expect(!label.contains(String(repeating: "a", count: 20)))
  }

  @Test("A named device keeps its name")
  func namedOrigin() {
    #expect(NodeStore.preview().label(forOrigin: "nas@cluster.example") == "nas@cluster.example")
  }

  // Not tested here: that `VersionCard`'s confirmation actually composes its
  // sentence from `actionableAttestor` and this labeller. A test that reads
  // the property and then labels it proves only what `keyOrigin` above already
  // proves — `requestAdopt` is private to a `View`, so reverting it to
  // `attestors.first` would leave any such test green. What guards that is
  // `theDeviceACommandReachesIsNotAlwaysTheFirstAttestor` in
  // `OriginRecoveryTests`, which pins the one property both halves now read,
  // and the mixed-attestor `#Preview` on the card itself.

  @Test("The daemon's own placeholder is translated, not printed")
  func untrusted() {
    #expect(NodeStore.preview().label(forOrigin: "(untrusted)") == "An unnamed device")
  }

  @Test("An absent origin is an em dash, not an empty cell")
  func empty() {
    #expect(NodeStore.preview().label(forOrigin: "") == "\u{2014}")
  }
}

/// What a delete would actually do, before it is confirmed.
@Suite("Delete plans")
@MainActor
struct DeletePlanTests {
  private func file(_ path: String) -> RemoteEntry {
    RemoteEntry(
      origin: "a@b", space: "demo", path: path, kind: .file, size: 1,
      modified: Date(timeIntervalSince1970: 0), versions: 1)
  }

  @Test("One file names one path and says its name")
  func oneFile() async {
    let model = FilesModel.preview(rows: [file("a.txt")])
    let plan = await model.deletePlan(for: [file("a.txt")])
    #expect(plan.paths.count == 1)
    #expect(plan.folders.isEmpty)
    #expect(plan.summary.contains("a.txt"))
    #expect(!plan.incomplete)
  }

  @Test("Several files are counted, not named")
  func severalFiles() async {
    let rows = [file("a.txt"), file("b.txt"), file("c.txt")]
    let model = FilesModel.preview(rows: rows)
    let plan = await model.deletePlan(for: rows)
    #expect(plan.paths.count == 3)
    #expect(plan.summary == "Delete 3 items?")
  }

  @Test("Nothing selected plans nothing")
  func nothing() async {
    let model = FilesModel.preview(rows: [])
    let plan = await model.deletePlan(for: [])
    #expect(plan.paths.isEmpty)
  }
}

/// What a successful Delete response is allowed to claim.
@Suite("Delete results")
@MainActor
struct DeleteResultTests {
  @Test("Idempotent success does not become a false missing-copy warning")
  func successfulDeleteIsSilent() {
    #expect(FilesModel.deleteNotice(
      stopped: false, attempted: 1, total: 1, stillPublished: []) == nil)
  }

  @Test("A copy still published elsewhere is explained")
  func stillPublishedIsExplained() {
    let notice = FilesModel.deleteNotice(
      stopped: false, attempted: 1, total: 1, stillPublished: ["notes.txt"])
    #expect(notice?.detail.contains("another device still publishes it") == true)
  }

  @Test("A stopped batch reports its boundary")
  func stoppedBatchReportsProgress() {
    let notice = FilesModel.deleteNotice(
      stopped: true, attempted: 2, total: 5, stillPublished: [])
    #expect(notice?.detail.hasPrefix("Stopped after 2 of 5.") == true)
  }
}

/// The queue's own invariants, which two crashes have already depended on.
@Suite("Transfer queue")
@MainActor
struct TransferQueueTests {
  private func transfer() -> Transfer {
    Transfer(
      id: UUID(), direction: .download, name: "a.bin", space: "demo", path: "a.bin",
      total: 10)
  }

  /// Running a retired runner again is what resumed a `CheckedContinuation`
  /// twice, which is a `fatalError` rather than an error.
  @Test("A retired transfer offers no Retry")
  func retiring() async {
    let queue = TransferQueue()
    let one = transfer()
    queue.add(one) { id in queue.update(id) { $0.state = .failed("no") } }
    try? await Task.sleep(for: .milliseconds(120))
    #expect(queue.canRetry(one.id))
    queue.retire(one.id)
    #expect(!queue.canRetry(one.id))
    // The row itself stays, with its reason on it.
    #expect(queue.transfer(one.id) != nil)
  }

  /// `cancel` writes `.cancelled` and drops the handle while the task is still
  /// unwinding, so for a moment the row looked finished and retryable.
  @Test("A transfer still unwinding is not retryable")
  func notWhileRunning() async {
    let queue = TransferQueue()
    let one = transfer()
    queue.add(one) { _ in try? await Task.sleep(for: .seconds(5)) }
    try? await Task.sleep(for: .milliseconds(120))
    queue.update(one.id) { $0.state = .failed("stalled") }
    #expect(!queue.canRetry(one.id))
  }

  /// Quick Look and a drag fetch through the queue and must not pop the list.
  @Test("Only a transfer a person asked for counts as started")
  func askedFor() async {
    let queue = TransferQueue()
    queue.add(transfer(), asked: false) { _ in }
    #expect(queue.startedCount == 0)
    queue.add(transfer()) { _ in }
    #expect(queue.startedCount == 1)
  }

  /// Quick Look's own download used to delete its row the moment it worked, so
  /// the two commonest ways of getting a file out of a folder left no trace.
  @Test("A transfer that finished keeps its row, dated")
  func historyIsKept() async {
    let queue = TransferQueue()
    let one = transfer()
    queue.add(one, asked: false) { id in queue.update(id) { $0.state = .completed(detail: nil) } }
    try? await Task.sleep(for: .milliseconds(120))
    #expect(queue.transfer(one.id) != nil)
    #expect(queue.transfer(one.id)?.finishedAt != nil)
    queue.clearFinished()
    #expect(queue.transfer(one.id) == nil)
  }

  /// A popover four rows tall put a download you had just started underneath
  /// everything that had ever finished.
  @Test("What is running is listed above the history")
  func runningFirst() async {
    let queue = TransferQueue()
    let old = transfer()
    queue.add(old) { id in queue.update(id) { $0.state = .completed(detail: nil) } }
    try? await Task.sleep(for: .milliseconds(120))
    let running = transfer()
    queue.add(running) { _ in try? await Task.sleep(for: .seconds(5)) }
    try? await Task.sleep(for: .milliseconds(60))
    #expect(queue.listed.map(\.id) == [running.id, old.id])
  }

  /// The history is a record of the session, held in memory, so it has a far
  /// end — and nothing running may fall off it.
  @Test("The history has a limit that running transfers are exempt from")
  func historyIsBounded() async {
    let queue = TransferQueue()
    let running = transfer()
    queue.add(running) { _ in try? await Task.sleep(for: .seconds(30)) }
    for _ in 0...TransferQueue.historyLimit {
      let one = transfer()
      queue.add(one, asked: false) { id in queue.update(id) { $0.state = .cancelled } }
    }
    try? await Task.sleep(for: .milliseconds(300))
    // One more `add` is what trims, so ask for it after they have all finished.
    queue.add(transfer(), asked: false) { id in queue.update(id) { $0.state = .cancelled } }
    try? await Task.sleep(for: .milliseconds(120))
    #expect(queue.transfers.count(where: \.isFinished) <= TransferQueue.historyLimit)
    #expect(queue.transfer(running.id) != nil)
  }
}

/// Which row "the selection" means, when there is more than one.
@Suite("What a preview opens")
@MainActor
struct PreviewableSelectionTests {
  private func file(_ path: String) -> RemoteEntry {
    RemoteEntry(
      origin: "a@b", space: "demo", path: path, kind: .file, size: 1,
      modified: Date(timeIntervalSince1970: 0), versions: 1)
  }

  private func folder(_ path: String) -> RemoteEntry {
    RemoteEntry(
      origin: "", space: "demo", path: path, kind: .directory, size: 0,
      modified: .distantPast, versions: 1, isSynthesizedDirectory: true)
  }

  @Test("One file is the file")
  func oneFile() {
    let rows = [file("b.txt"), file("a.txt")]
    let model = FilesModel.preview(rows: rows)
    model.selection = [rows[0].id]
    #expect(model.previewableSelection?.name == "b.txt")
  }

  @Test("One folder previews nothing")
  func oneFolder() {
    let rows = [folder("docs")]
    let model = FilesModel.preview(rows: rows)
    model.selection = [rows[0].id]
    #expect(model.previewableSelection == nil)
  }

  /// A folder sorts first, so `.first` of the selection used to be the folder
  /// and Quick Look was disabled with a file plainly selected.
  @Test("A folder alongside a file does not disable the preview")
  func mixedSelection() {
    let rows = [folder("docs"), file("a.txt")]
    let model = FilesModel.preview(rows: rows)
    model.selection = Set(rows.map(\.id))
    #expect(model.previewableSelection?.name == "a.txt")
  }

  /// `rows` ends in a dictionary's values, whose order differs per launch;
  /// screen order does not.
  @Test("Several files preview the first one on screen")
  func severalFiles() {
    let rows = [file("zulu.txt"), file("alpha.txt"), file("mike.txt")]
    let model = FilesModel.preview(rows: rows)
    model.selection = Set(rows.map(\.id))
    #expect(model.previewableSelection?.name == "alpha.txt")
  }
}

/// What the strongest confirmation gate asks to be typed.
@Suite("Typed gates")
struct TypedPhraseTests {
  /// A device trusted without a published name is bound under its key, so the
  /// gate asked for `key:` and 52 characters of z-base-32 — which is a copy
  /// and paste, not a deliberate act.
  @Test("A device key is shortened to something typeable")
  func keyOrigin() {
    let key = "key:" + String(repeating: "b", count: 52)
    let phrase = MembersPane.typeablePhrase(for: key)
    #expect(phrase.count == 8)
    #expect(key.hasSuffix(phrase))
  }

  @Test("A name someone could type is asked for in full")
  func namedOrigin() {
    #expect(MembersPane.typeablePhrase(for: "nas@cluster.example") == "nas@cluster.example")
  }
}

/// The command lines the app shows and offers to copy.
@Suite("Shell quoting")
struct ShellQuoteTests {
  /// A space id is allowed to contain a space, so `synch space rm Family
  /// Photos` was a command that means something else, under a button labelled
  /// "Copy as a synch command".
  @Test("A token with a space is quoted")
  func spaces() {
    #expect(Shell.quote("Family Photos") == "'Family Photos'")
    #expect(Shell.quote("/Users/me/My Files") == "'/Users/me/My Files'")
  }

  @Test("An ordinary token is left alone")
  func plain() {
    #expect(Shell.quote("notes") == "notes")
    #expect(Shell.quote("nas@cluster.example.com") == "nas@cluster.example.com")
    #expect(Shell.quote("key:abc/notes.txt") == "key:abc/notes.txt")
  }

  /// The one thing single quotes cannot contain is a single quote.
  @Test("An embedded quote is closed, escaped and reopened")
  func quoted() {
    #expect(Shell.quote("it's") == "'it'\\''s'")
  }

  @Test("Empty is a pair of quotes, not nothing")
  func empty() {
    #expect(Shell.quote("") == "''")
  }

  @Test("Anything a shell would act on is quoted")
  func metacharacters() {
    for token in ["a;b", "a&b", "a|b", "a$b", "a`b", "a>b", "a*b", "a(b)"] {
      #expect(Shell.quote(token).hasPrefix("'"), "\(token) was left bare")
    }
  }
}

/// Which folder the browser is in, as folders come and go.
@Suite("Adopting folders")
@MainActor
struct AdoptSpaceTests {
  private func space(_ id: String) -> Space { Space(id: id, localPath: "/tmp/\(id)") }

  @Test("The first folder is adopted when there is no selection")
  func adopts() {
    let model = FilesModel.preview(rows: [], space: "")
    model.adoptFirstSpaceIfNeeded([space("a"), space("b")])
    #expect(model.selectedSpace == "a")
  }

  /// Removing the folder you are browsing used to leave the title bar, the
  /// path bar and Add Files… all naming a folder the daemon no longer indexes.
  @Test("A folder that is gone is let go of")
  func lettingGo() {
    let model = FilesModel.preview(rows: [], space: "a")
    model.adoptFirstSpaceIfNeeded([space("b")])
    #expect(model.selectedSpace == "b")
  }

  /// `disconnect` empties `spaces`, and the app reconnects on its own — so an
  /// empty list must not be read as "yours is gone".
  @Test("An empty list is not news")
  func emptyIsNotNews() {
    let model = FilesModel.preview(rows: [], space: "a")
    model.adoptFirstSpaceIfNeeded([])
    #expect(model.selectedSpace == "a")
  }

  @Test("A folder that is still there is left alone")
  func stays() {
    let model = FilesModel.preview(rows: [], space: "b")
    model.adoptFirstSpaceIfNeeded([space("a"), space("b")])
    #expect(model.selectedSpace == "b")
  }
}
