import AppKit
import Testing
@testable import Hecatia

/// The coverage audit.
///
/// The daemon exposes 68 addressable operations: 14 typed rpcs and the 54
/// subcommands `Run` carries (proto field numbers 1…55 with 9 reserved).
///
/// These numbers are the app's side of the count only. Asserting them here is
/// what *failed* last time: `space set`, `space sync` and `fill` shipped in the
/// daemon and this test stayed green, because it compared the registry against
/// a literal that was written from the registry. The check that can actually
/// fail lives in `Scripts/audit-coverage.sh`, which counts the oneof in
/// `control.proto` — a file `make check-proto` keeps identical to the
/// daemon's. Keep both: this one localizes a miscount to a test name, that one
/// is the one that notices.
struct CoverageTests {

  @Test func everyOperationIsAccountedFor() {
    #expect(Operations.typed.count == 14)
    #expect(Operations.run.count == 54)
    #expect(Operations.all.count == 68)
  }

  @Test func noOperationIsListedTwice() {
    let ids = Operations.all.map(\.id)
    #expect(Set(ids).count == ids.count)
  }

  @Test func anythingNotSurfacedSaysWhy() {
    for operation in Operations.all where operation.surface == .notSurfaced {
      #expect(
        operation.omission?.isEmpty == false,
        "\(operation.id) is not surfaced and gives no reason")
    }
  }

  @Test func theOmissionsAreExactlyTheOnesWeChose() {
    // Pinned as a whole set rather than a floor, so an operation that *loses*
    // its surface fails here instead of joining the list quietly.
    //
    // `ls`: `Control.List` answers it with a schema, so the text form would
    // add a parser and no capability. `cat` and `get` used to be here on the
    // same reasoning, and the reasoning was wrong — `ReadRequest` carries no
    // content root, so it can only select the *current* version of a path,
    // and everything a superseded version or an `archive` replica holds needs
    // `--root` — which is why they are surfaced now.
    //
    // The nine `socket` subcommands and `rpc.openSocket` are a second kind of
    // omission, and the distinction is the point: `ls` is *replaced*, they are
    // simply *unbuilt*. v3 grew a socket surface — publish, review, arm, run,
    // watch, kill — and this app has none of it. They are registered so the
    // count stays the daemon's, on the reasoning at the bottom of
    // `Operations.run`. Anything else appearing in this list means capability
    // was dropped, not replaced.
    let omitted = Operations.all.filter { $0.surface == .notSurfaced }.map(\.id).sorted()
    #expect(omitted == [
      "ls", "rpc.openSocket", "socket.add", "socket.arm", "socket.disarm",
      "socket.kill", "socket.log", "socket.ls", "socket.ps", "socket.rm",
      "socket.sdk",
    ])
  }

  /// A read that claims to dirty what it fills re-enters its own refresh
  /// forever. That shipped once and pinned a core at 114%, so it is a test now.
  @Test func readsInvalidateNothing() {
    let readOnly: Set<String> = [
      "id", "daemon.status", "key.ls", "trust.ls", "delegate.ls", "domain.ls",
      "peers", "space.ls", "mirror.ls", "pin.ls", "cloud.status", "doctor",
      "status", "log", "compare", "rpc.list", "rpc.resolve", "rpc.read",
      "rpc.getConfig", "rpc.listUploads", "rpc.listParts", "ls", "cat", "get",
    ]
    for operation in Operations.all where readOnly.contains(operation.id) {
      #expect(
        operation.dirties.isEmpty,
        "\(operation.id) is a read but claims to invalidate \(operation.dirties)")
    }
  }

  @Test func everyMutationInvalidatesSomething() {
    // A mutation that dirties nothing leaves a table contradicting the chip
    // beside it, which is exactly the class of bug the registry exists to make
    // impossible to introduce by forgetting.
    let readOnly: Set<String> = [
      "id", "daemon.status", "key.ls", "trust.ls", "delegate.ls", "domain.ls",
      "peers", "space.ls", "mirror.ls", "pin.ls", "cloud.status", "doctor",
      "status", "log", "compare", "rpc.list", "rpc.resolve", "rpc.read",
      "rpc.getConfig", "rpc.listUploads", "rpc.listParts", "ls", "cat", "get",
    ]
    // `.notSurfaced` is exempt, and it is honest rather than convenient to
    // exempt it: nothing can invoke those, so what they would invalidate is a
    // guess, and a guess written as a fact is the exact failure this test
    // exists to prevent. `socket add` and `socket rm` really do change a
    // listing — but the day either gets a button is the day that can be
    // written down from a refresh someone watched happen, and the exemption
    // ends there.
    for operation in Operations.all
    where !readOnly.contains(operation.id) && operation.surface != .notSurfaced {
      #expect(
        !operation.dirties.isEmpty,
        "\(operation.id) changes something but invalidates nothing")
    }
  }

  @Test func dangerousOperationsAreGated() {
    // The seven that cannot be undone, plus the one that only exists when it is
    // the fix. Anything added to this list without a gate fails here.
    let mustBeTyped = [
      "key.retire", "daemon.stop", "trust.rm", "domain.clear", "space.rm",
    ]
    for id in mustBeTyped {
      #expect(Operations.find(id)?.gate == .typed, "\(id) is missing its typed gate")
    }
    #expect(Operations.find("recover")?.gate == .conditional)
  }

  @Test func filesWindowOnlyHoldsOperationsThatNameAFileOrFolder() {
    // The rule that keeps the browser the whole app: if it does not name a file
    // or a folder, it belongs in the Node window.
    let allowed: Set<String> = [
      "rpc.list", "rpc.resolve", "rpc.read", "rpc.put", "rpc.delete",
      "space.ls", "space.add", "status", "take", "log", "compare",
      "pin.add", "pin.rm", "scan",
      // `fill` names a folder and writes into it. `cat` and `get` name one
      // object by its content root, which is a version of a file — the only
      // route to one no path selects any more.
      "fill", "cat", "get",
    ]
    for operation in Operations.all where operation.surface == .files {
      #expect(allowed.contains(operation.id), "\(operation.id) does not belong in the Files window")
    }
  }
}

/// The listing fold, which is where two of the report's browsing bugs lived.
struct ListingTests {

  @Test func aSiblingPrefixIsNotFoldedIntoTheFolder() {
    // The daemon matches a listing prefix as a raw byte range, so asking for
    // `docs` also returns `docs-old/legacy.md` and `docsly.md`. Requesting
    // `docs/` is the first guard; dropping anything that still arrives outside
    // the folder is the second.
    #expect(Listing.remainder(of: "docs/readme.md", under: "docs") == "readme.md")
    #expect(Listing.remainder(of: "docs-old/legacy.md", under: "docs") == nil)
    #expect(Listing.remainder(of: "docsly.md", under: "docs") == nil)
  }

  @Test func aFileAndAFolderAtTheSamePathBothAppear() {
    // Legal in the unified tree: one origin publishes a file at `reports`
    // while another publishes `reports/q1.pdf`. Keying them together let the
    // file win and made the whole subtree unreachable from the app.
    var builder = LevelBuilder(space: "notes", prefix: "")
    builder.add(entry(space: "notes", path: "reports", kind: .file))
    builder.add(entry(space: "notes", path: "reports/q1.pdf", kind: .file))
    let rows = builder.rows()
    #expect(rows.count == 2)
    #expect(rows.contains { $0.isDirectory && $0.path == "reports" })
    #expect(rows.contains { $0.isFile && $0.path == "reports" })
  }

  @Test func synthesisedFoldersCarryNoBorrowedMetadata() {
    // A folder row is a rendering of a prefix, not a published record, so
    // borrowing a random descendant's date, origin and version count — which
    // put phantom conflict badges on folders — is not an option.
    var builder = LevelBuilder(space: "notes", prefix: "")
    builder.add(
      entry(space: "notes", path: "journal/a.md", kind: .file, versions: 4, origin: "nas"))
    let folder = builder.rows()[0]
    #expect(folder.isDirectory)
    #expect(folder.versions == 1)
    #expect(folder.origin.isEmpty)
    #expect(folder.hasVersions == false)
    #expect(folder.modifiedLabel == "—")
  }

  @Test func onlyImmediateChildrenAreKept() {
    var builder = LevelBuilder(space: "notes", prefix: "journal")
    builder.add(entry(space: "notes", path: "journal/2026/01.md", kind: .file))
    builder.add(entry(space: "notes", path: "journal/2026/02.md", kind: .file))
    builder.add(entry(space: "notes", path: "journal/index.md", kind: .file))
    let rows = builder.rows()
    #expect(rows.count == 2)
    #expect(rows[0].path == "journal/2026")
    #expect(rows[1].path == "journal/index.md")
    // Memory is bounded by the level being shown, not by the subtree under it.
    #expect(builder.descendants == 3)
  }

  private func entry(
    space: String, path: String, kind: RemoteEntry.Kind,
    versions: UInt32 = 1, origin: String = "me"
  ) -> RemoteEntry {
    RemoteEntry(
      origin: origin, space: space, path: path, kind: kind,
      size: 0, modified: .distantPast, versions: versions)
  }
}

/// The version-policy grammar, which round-trips losslessly because the daemon
/// renders exactly what it parses.
struct PolicyTests {
  @Test func policiesRoundTrip() {
    for policy: VersionPolicy in [.newest, .strict, .origin("nas@x.example"), .origin("key:abc")] {
      #expect(VersionPolicy(wire: policy.wire) == policy)
    }
  }

  @Test func aMalformedPolicyIsRejectedRatherThanGuessedAt() {
    #expect(VersionPolicy(wire: "origin=") == nil)
    #expect(VersionPolicy(wire: "whatever") == nil)
  }
}

/// Error classification, which is what replaced a single opaque alert string.
struct FailureTests {
  @Test func statusCodesMapBackToTheDaemonsOwnVocabulary() {
    #expect(ControlErrorCode.from(status: .unauthenticated) == .unauthorized)
    #expect(ControlErrorCode.from(status: .notFound) == .notFound)
    #expect(ControlErrorCode.from(status: .aborted) == .divergent)
    #expect(ControlErrorCode.from(status: .unavailable) == .unavailable)
    // FailedPrecondition covers two codes, which is the ambiguity the
    // `x-synch-error-code` trailer exists to resolve.
    #expect(ControlErrorCode.from(status: .failedPrecondition) == .versionMismatch)
  }

  @Test func aStaleTokenIsRecoverableWithoutAskingTheUser() {
    let failure = DaemonFailure(code: .unauthorized, detail: "control token mismatch")
    #expect(failure.isStaleConnection)
    #expect(DaemonFailure(code: .notFound, detail: "x").isStaleConnection == false)
  }
}

/// The optional proto fields that used to be silently never set.
///
/// The report that prompted this rewrite listed them as a class of defect on
/// their own: a field the app can never populate is a capability the daemon
/// offers and the GUI quietly withholds. These assert the builders accept them;
/// the UI that fills them is the sheet named in each comment.
struct OptionalFieldTests {

  @Test func trustAddCarriesEveryOptionalField() {   // TrustDeviceSheet
    let command = Cmd.trustAdd(key: "k", note: "the NAS", addr: "10.0.0.2:4433")
    #expect(command.trustAdd.note == "the NAS")
    #expect(command.trustAdd.addr == "10.0.0.2:4433")
  }

  @Test func emptyOptionalsAreLeftUnsetRatherThanSentBlank() {
    let command = Cmd.trustAdd(key: "k", note: "", addr: nil)
    #expect(command.trustAdd.hasNote == false)
    #expect(command.trustAdd.hasAddr == false)
  }

  @Test func trustRemoveCanDropOneKey() {           // MembersPane ▸ Drop Just This Key
    #expect(Cmd.trustRm(origin: "nas@x.example", key: "abc").trustRm.key == "abc")
    #expect(Cmd.trustRm(origin: "nas@x.example", key: nil).trustRm.hasKey == false)
  }

  @Test func keyActivateCanNameAnAddress() {        // ActivateKeySheet
    #expect(Cmd.keyActivate("k", bind: "0.0.0.0:4433").keyActivate.bind == "0.0.0.0:4433")
    #expect(Cmd.keyActivate("k", bind: nil).keyActivate.hasBind == false)
  }

  @Test func recoverCarriesWaitAndGap() {           // RecoverSheet
    let command = Cmd.recover(wait: "30s", gap: 5)
    #expect(command.recover.wait == "30s")
    #expect(command.recover.gap == 5)
  }

  @Test func delegateAddCarriesEveryScope() {       // GrantAccessSheet
    let command = Cmd.delegateAdd(
      key: "k", spaces: ["photos", "incoming"], until: "7d", note: "for Ada")
    #expect(command.delegateAdd.spaces == ["photos", "incoming"])
    #expect(command.delegateAdd.until == "7d")
  }

  @Test func compareAlwaysAsksForJson() {           // CompareSheet
    // The text form is never rendered, so `json` is not a user-facing option.
    let command = Cmd.compare(reference: "notes", to: "nas@x.example", from: nil)
    #expect(command.compare.json)
    #expect(command.compare.hasFrom == false)
  }

  @Test func mirrorAddCarriesItsPolicy() {          // MirrorSheet
    let command = Cmd.mirrorAdd(space: "notes", path: "/tmp/m", policy: .strict)
    #expect(command.mirrorAdd.policy == "strict")
  }

  @Test func doctorCanRebuild() {                   // DiagnosticsPane
    #expect(Cmd.doctor(rebuild: true).doctor.rebuild)
  }

  @Test func referencesFollowTheDaemonsGrammar() {
    // `[<origin>:]<space>[/<path>]` — the origin goes before the first colon,
    // and a colon after the first `/` is part of the path.
    #expect(Cmd.reference(space: "notes") == "notes")
    #expect(Cmd.reference(space: "notes", path: "a/b.md") == "notes/a/b.md")
    #expect(
      Cmd.reference(origin: "nas@x.example", space: "notes", path: "a.md")
        == "nas@x.example:notes/a.md")
  }
}

/// The one structured output the daemon offers.
struct CompareReportTests {
  @Test func compareJsonDecodes() {
    let line = #"{"space":"notes","from":"me@x","to":"nas@x","changes":[{"status":"created","path":"a.md"},{"status":"modified","path":"b/c.md"},{"status":"deleted","path":"d.md"}]}"#
    let report = CompareReport.decode(["some prose first", line])
    #expect(report?.space == "notes")
    #expect(report?.created.map(\.path) == ["a.md"])
    #expect(report?.modified.map(\.path) == ["b/c.md"])
    #expect(report?.deleted.map(\.path) == ["d.md"])
  }

  @Test func aPathWithQuotesSurvives() {
    let line = #"{"space":"n","from":"a","to":"b","changes":[{"status":"created","path":"he said \"hi\".txt"}]}"#
    #expect(CompareReport.decode([line])?.changes.first?.path == #"he said "hi".txt"#)
  }
}

/// Continuing a download rather than starting it over.
///
/// `ReadRequest.start` is the daemon's own range and was the field this app
/// never set: every download asked for the whole object, so one that failed at
/// 90% threw away the 90%. The partial is named after the content root, which
/// is what makes "the bytes on disk belong to this version" a fact rather than
/// a hope — but how many of them to trust is still a decision, and this is it.
struct ResumeDecisionTests {

  @Test func nothingOnDiskStartsAtZero() {
    #expect(FilesModel.decide(have: 0, total: 4096) == .fromScratch)
  }

  @Test func aPrefixIsContinued() {
    #expect(FilesModel.decide(have: 1024, total: 4096) == .resume(at: 1024))
  }

  @Test func aWholeFileIsNotDownloadedAgain() {
    // The move to its destination is all that is left. Asking the daemon for
    // `start == size` would be a legal empty range, but asking for nothing is
    // clearer than asking for zero bytes.
    #expect(FilesModel.decide(have: 4096, total: 4096) == .alreadyComplete)
  }

  @Test func somethingLongerThanTheObjectIsNotAPrefixOfIt() {
    #expect(FilesModel.decide(have: 8192, total: 4096) == .fromScratch)
  }

  @Test func anEmptyObjectIsStillWritten() {
    // Zero-length files exist and the destination has to be created.
    #expect(FilesModel.decide(have: 0, total: 0) == .fromScratch)
  }
}

/// Whether the space bar is Quick Look.
///
/// `onKeyPress(.space)` never fired — an `NSTableView` takes the key first for
/// type-select — and a menu item with Space as its key equivalent takes it too
/// early, before the search field can type one. The decision therefore lives in
/// a local event monitor, and this is that decision with the AppKit taken out
/// of it.
@MainActor
struct SpaceBarTests {
  private typealias Monitor = QuickLookKeyMonitor

  @Test func aPlainSpaceOnASelectedFilePreviewsIt() {
    let d = Monitor.takesSpace(
      characters: " ", modifiers: [], isKeyWindow: true,
      isEditingText: false, fileListHasTheCaret: true, selectionIsAFile: true)
    #expect(d.yes)
  }

  @Test func anythingElseIsNotTheSpaceBar() {
    #expect(!Monitor.takesSpace(
      characters: "a", modifiers: [], isKeyWindow: true,
      isEditingText: false, fileListHasTheCaret: true, selectionIsAFile: true).yes)
    #expect(!Monitor.takesSpace(
      characters: nil, modifiers: [], isKeyWindow: true,
      isEditingText: false, fileListHasTheCaret: true, selectionIsAFile: true).yes)
  }

  @Test func aTextFieldKeepsItsSpaces() {
    // The reason a menu shortcut could not be used: the search field has to be
    // able to type a space.
    let d = Monitor.takesSpace(
      characters: " ", modifiers: [], isKeyWindow: true,
      isEditingText: true, fileListHasTheCaret: true, selectionIsAFile: true)
    #expect(!d.yes)
    #expect(d.reason.contains("text field"))
  }

  @Test func aModifiedSpaceBelongsToSomethingElse() {
    for modifier: NSEvent.ModifierFlags in [.command, .option, .control, .shift] {
      #expect(!Monitor.takesSpace(
        characters: " ", modifiers: modifier, isKeyWindow: true,
        isEditingText: false, fileListHasTheCaret: true, selectionIsAFile: true).yes)
    }
    // Caps lock and the numeric-pad flag ride along on ordinary keys and must
    // not count as a modifier.
    #expect(Monitor.takesSpace(
      characters: " ", modifiers: [.function], isKeyWindow: true,
      isEditingText: false, fileListHasTheCaret: true, selectionIsAFile: true).yes)
  }

  @Test func aBackgroundWindowDoesNotAnswer() {
    // The monitor is per-window and local monitors see every window's keys.
    #expect(!Monitor.takesSpace(
      characters: " ", modifiers: [], isKeyWindow: false,
      isEditingText: false, fileListHasTheCaret: true, selectionIsAFile: true).yes)
  }

  @Test func aFolderHasNothingToPreview() {
    #expect(!Monitor.takesSpace(
      characters: " ", modifiers: [], isKeyWindow: true,
      isEditingText: false, fileListHasTheCaret: true, selectionIsAFile: false).yes)
  }

  /// The monitor eats the key when it says yes, so anything else holding the
  /// focus never sees it — a focused button could not be pressed with Space
  /// while a file row happened to be selected.
  @Test func somethingElseWithTheFocusKeepsItsSpace() {
    let d = Monitor.takesSpace(
      characters: " ", modifiers: [], isKeyWindow: true,
      isEditingText: false, fileListHasTheCaret: false, selectionIsAFile: true)
    #expect(!d.yes)
    #expect(d.reason.contains("focus"))
  }
}
