import Foundation
import UniformTypeIdentifiers

/// Uploads, downloads and deletes, driven from the browser.
///
/// Every one of these reports: it starts a transfer row or an activity run, it
/// says what the daemon answered, and it can be cancelled. The old versions
/// were silent — a download read a whole file with no indication anything was
/// happening, and a delete that changed nothing looked identical to one that
/// worked.
extension FilesModel {

  // MARK: - Upload

  func upload(urls: [URL]) {
    guard let space = selectedSpace else {
      store.alert = DaemonFailure(
        code: .invalid,
        detail: "Choose a folder in the sidebar before adding files to it.",
        operation: "add these files")
      return
    }
    Task { await enqueueUploads(urls: urls, space: space) }
  }

  private func enqueueUploads(urls: [URL], space: String) async {
    // A dropped directory is expanded rather than refused: the old client fed
    // it straight to a file read, which threw and took the whole batch with it.
    //
    // Off the main actor, all of it: the walk stats every file under the
    // folder and the loop below used to stat each one again for its size, so
    // dropping a folder of a few thousand files froze the window before a
    // single byte moved. `[URL]` goes out and an array of Sendable tuples
    // comes back.
    let files = await Task.detached { urls.flatMap(Self.expand) }.value
    for file in files {
      let destination = prefix.isEmpty ? file.relative : "\(prefix)/\(file.relative)"
      let size = file.size
      let transfer = Transfer(
        id: UUID(), direction: .upload, name: file.relative,
        space: space, path: destination, total: Int64(size))
      store.transfers.add(transfer) { [weak self] id in
        await self?.performUpload(id: id, source: file.source, space: space, path: destination)
      }
    }
  }

  /// Puts a finished download where it was going.
  ///
  /// `nonisolated` so it can be run off the main actor — see the call site.
  nonisolated private static func place(_ partial: URL, at landing: URL) throws {
    try? FileManager.default.removeItem(at: landing)
    try FileManager.default.moveItem(at: partial, to: landing)
  }

  /// `nonisolated`, so the walk below can be sent off the main actor.
  ///
  /// It stats every file under a dropped folder, one at a time, and it used to
  /// do that on the main actor before a single byte was transferred — so
  /// dropping a folder with a few thousand files in it froze the window until
  /// the walk finished.
  nonisolated private static func expand(_ url: URL) -> [(source: URL, relative: String, size: Int)] {
    var isDirectory: ObjCBool = false
    guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) else {
      return []
    }
    guard isDirectory.boolValue else {
      return [(url, url.lastPathComponent, size(of: url))]
    }
    let root = url.lastPathComponent
    guard let walker = FileManager.default.enumerator(
      at: url, includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles])
    else { return [] }
    var found: [(URL, String, Int)] = []
    for case let child as URL in walker {
      // Size and regular-file-ness from the same read, because the loop that
      // consumes this used to ask for the size again, one file at a time, on
      // the main actor.
      let values = try? child.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
      guard values?.isRegularFile == true else { continue }
      let relative = child.path.replacing(url.path + "/", with: "")
      found.append((child, "\(root)/\(relative)", values?.fileSize ?? 0))
    }
    return found
  }

  nonisolated private static func size(of url: URL) -> Int {
    (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
  }

  private func performUpload(id: UUID, source: URL, space: String, path: String) async {
    let scoped = source.startAccessingSecurityScopedResource()
    defer { if scoped { source.stopAccessingSecurityScopedResource() } }

    store.transfers.update(id) { $0.state = .running }
    let size = Int64((try? source.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
    store.transfers.update(id) { $0.total = size }

    let queue = store.transfers
    let onProgress: @Sendable (Int64) -> Void = { sent in
      Task { @MainActor in queue.update(id) { $0.bytes = sent } }
    }

    do {
      if size >= ControlClient.multipartThreshold {
        // Large files go through the multipart calls, so the daemon holds the
        // parts and an interrupted transfer resumes instead of restarting.
        // Matched on the space as well as the path. An upload id names one
        // key, so a path that exists in two folders would otherwise resume
        // into the wrong one.
        let resuming = store.transfers.resumable.first {
          $0.space == space && $0.path == path
        }?.id
        let result = try await store.client.multipartPut(
          space: space, path: path, from: source, totalBytes: size, resuming: resuming,
          onOpen: { uploadID in
            Task { @MainActor in queue.update(id) { $0.uploadID = uploadID } }
          },
          onProgress: onProgress)
        if let uploadID = store.transfers.transfer(id)?.uploadID {
          store.transfers.dropResumable(id: uploadID)
        }
        store.transfers.update(id) {
          $0.bytes = $0.total
          $0.state = .completed(detail: result.replayed ? "Already uploaded" : "Uploaded")
        }
      } else {
        let written = try await store.client.put(
          space: space, path: path, from: source, onProgress: onProgress)
        store.transfers.update(id) {
          $0.bytes = $0.total
          // What the daemon actually published, which the old client drained
          // and discarded.
          $0.state = .completed(detail: written.map { "Published seq \($0.entry.seq)" } ?? "Uploaded")
        }
      }
      // Not `await reload()`: every file in a batch finishes separately, and
      // one listing per file is one listing per file too many.
      scheduleReload()
    } catch is CancellationError {
      store.transfers.update(id) { $0.state = .cancelled }
    } catch {
      let failure = DaemonFailure.classify(error, operation: "upload \(path)")
      // One bad file no longer takes the batch with it: this row fails, the
      // rest keep going, and the queue says which is which.
      store.transfers.update(id) { $0.state = .failed(failure.detail) }
    }
  }

  // There was a stray-file recovery path here — `explainStrayFile`,
  // `StrayFile`, `discardStrayFile` — for DAEMON-ISSUES D2: `Put` committed
  // the bytes into the folder before discovering the scanner would not index
  // them, then answered `not-found`, leaving a file behind under a message
  // saying the write had failed.
  //
  // The daemon fixed it. `Control::put` now opens the adoption *before* the
  // response stream, and `open_adoption` goes through `ensure_adoptable`,
  // which is `ensure_publishable` plus `refuse_if_ignored` — so an ignored
  // path is refused before the first byte, with a message that names the path
  // and the rule. The recovery could no longer fire for the case it was
  // written for, and its comment told the next reader something about the
  // daemon that had stopped being true. Deleted rather than left as a
  // monument; the daemon's own refusal is a better error than the one this
  // synthesised.

  // MARK: - Download

  /// Streams a file to a temporary location, then hands it to the save panel.
  ///
  /// Progress and cancellation come from the transfer row; the panel opens
  /// only once the bytes are on disk, which is also what keeps a multi-gigabyte
  /// file from ever being resident in memory.
  func download(_ entry: RemoteEntry, to destination: URL?) {
    guard entry.isFile else { return }
    let transfer = Transfer(
      id: UUID(), direction: .download, name: entry.name,
      space: entry.space, path: entry.path, total: Int64(entry.size))
    let readPolicy = policy
    store.transfers.add(transfer) { [weak self] id in
      let url = await self?.fetch(
        id: id, entry: entry, policy: readPolicy, destination: destination,
        detail: destination == nil ? "Ready" : "Saved")
      // `fileExporter` writes the document before it hands the URL over, and
      // the document is a placeholder with no bytes in it — so a save panel
      // that has been confirmed leaves a 0-byte file with the real name
      // whether or not the download then works. Cancelling or failing used to
      // leave it there, indistinguishable from a file that had arrived.
      if url == nil, let destination,
         let size = try? destination.resourceValues(forKeys: [.fileSizeKey]).fileSize,
         size == 0 {
        try? FileManager.default.removeItem(at: destination)
      }
    }
  }

  /// Asks the window to preview a file. Folders have nothing to preview.
  func requestPreview(_ entry: RemoteEntry, version: EntryVersion? = nil) {
    guard entry.isFile else { return }
    previewRequest = PreviewRequest(entry: entry, version: version)
  }

  /// Downloads to a temporary file and returns it, for Quick Look and for
  /// dragging a file out to Finder.
  ///
  /// This goes through the transfer queue like every other download, because
  /// previewing a 40 GB file is a 40 GB download: it used to run with no
  /// progress, no cancel and no row anywhere, so the window simply stopped
  /// answering.
  ///
  /// The row stays afterwards, whether it worked or not. It used to be deleted
  /// on success — "a preview that worked is not news" — which made the list a
  /// view of what was happening rather than a record of what had happened, and
  /// left the two biggest ways of getting a file out of a folder, Quick Look
  /// and a drag to Finder, with no trace at all.
  ///
  /// What it does not get is a Retry: the runner is retired before the
  /// continuation is resumed, because running it again would resume the same
  /// continuation a second time, and that is a `fatalError` rather than an
  /// error. Pressing Space on a file whose fetch failed and then Retry killed
  /// the app.
  func materialize(_ entry: RemoteEntry, version: EntryVersion? = nil) async -> URL? {
    guard entry.isFile else { return nil }
    // The same property the confirmation and the fetch read: Preview and adopt
    // ask one question — which origin can this version be named by — and they
    // were two separate answers to it.
    let readPolicy: VersionPolicy = version?.actionableAttestor.map { .origin($0) } ?? policy
    let transfer = Transfer(
      id: UUID(), direction: .download, name: entry.name,
      space: entry.space, path: entry.path, total: Int64(entry.size))
    return await withCheckedContinuation { continuation in
      // `asked: false` — this is Quick Look, a double-click or a drag, and the
      // person did not ask to be shown a transfer list.
      store.transfers.add(transfer, asked: false) { [weak self] id in
        let url = await self?.fetch(
          id: id, entry: entry, policy: readPolicy, destination: nil, detail: nil)
        // Unconditionally, and before the resume: this closure must never run
        // twice, whatever happened inside it.
        self?.store.transfers.retire(id)
        continuation.resume(returning: url)
      }
    }
  }

  /// Streams one version into a local file, continuing a partial download when
  /// the last attempt left one for the same content.
  ///
  /// Returns the finished file, or nil when it was cancelled or failed — the
  /// transfer row carries the reason either way.
  private func fetch(
    id: UUID, entry: RemoteEntry, policy readPolicy: VersionPolicy, destination: URL?,
    detail: String?
  ) async -> URL? {
    store.transfers.update(id) { $0.state = .running }
    let queue = store.transfers
    let onProgress: @Sendable (Int64) -> Void = { got in
      Task { @MainActor in queue.update(id) { $0.bytes = got } }
    }

    do {
      // Resolved first, under the policy this download actually reads: the
      // row's root and size came from the *listing* policy, and a per-version
      // preview reads a different version entirely. It is also what keys the
      // partial file below.
      let resolved = try await store.client.resolve(
        space: entry.space, path: entry.path, policy: readPolicy)
      let total = Int64(resolved.size)
      store.transfers.update(id) { $0.total = total }

      let partial = Self.partialFile(for: resolved, name: entry.name)
      switch Self.decide(have: Self.bytesOnDisk(at: partial), total: total) {
      case .alreadyComplete:
        store.transfers.update(id) { $0.bytes = total }
      case .fromScratch:
        try await store.client.read(
          space: entry.space, path: entry.path, policy: readPolicy,
          into: partial, from: 0, onProgress: onProgress)
      case .resume(let at):
        store.transfers.update(id) { $0.bytes = at; $0.resumedFrom = at }
        try await store.client.read(
          space: entry.space, path: entry.path, policy: readPolicy,
          into: partial, from: at, onProgress: onProgress)
      }

      let landing = destination ?? Self.namedTemporary(for: entry, version: readPolicy)
      // Off the main actor: a move across volumes copies the bytes, so
      // finishing a download of any size held the window for as long as the
      // copy took. There is no suspension between the last `read` above and
      // here, so this was the main actor's own work.
      try await Task.detached { try Self.place(partial, at: landing) }.value
      store.transfers.update(id) { $0.bytes = total; $0.state = .completed(detail: detail) }
      return landing
    } catch is CancellationError {
      // The partial is left where it is. That is the whole point: the next
      // attempt asks the daemon for the bytes after it rather than for the
      // object again.
      store.transfers.update(id) { $0.state = .cancelled }
      return nil
    } catch {
      var failure = DaemonFailure.classify(error, operation: "download \(entry.name)")
      failure = Self.explainMissingContent(failure, entry: entry)
      store.transfers.update(id) { $0.state = .failed(failure.detail) }
      store.alert = failure
      return nil
    }
  }

  /// A better answer than "the daemon failed while serving this" for the one
  /// failure that is not about the daemon's health.
  ///
  /// The daemon lists a file, `status` confirms its version and its size, and
  /// `Read` answers `io: No such file or directory (os error 2)` — a raw
  /// `io::Error` with no path in it. Measured against a real daemon, two files
  /// out of eight in one folder do this while their source files sit in the
  /// shared folder at exactly the size the daemon reports, and `synch get`
  /// fails the same way from the command line, so it is not this app asking
  /// wrongly. Recorded as E10 in docs/DAEMON-ISSUES.md.
  ///
  /// The suggestion names no remedy, because both obvious ones were tried
  /// against the daemon that produces this and neither works. `synch scan`
  /// reports "unchanged 10" and changes nothing — the daemon agrees the folder
  /// and the index match. `synch doctor` reports the head as "servable, 10
  /// entries" and does not mention it. Telling someone to run either would be
  /// sending them somewhere the answer is not.
  private static func explainMissingContent(
    _ failure: DaemonFailure, entry: RemoteEntry
  ) -> DaemonFailure {
    guard failure.detail.contains("No such file or directory") else { return failure }
    return DaemonFailure(
      code: failure.code,
      detail: "The daemon lists \u{201C}\(entry.name)\u{201D} but cannot read its contents.",
      operation: failure.operation,
      suggestion: "The other files in this folder are unaffected, and rescanning does not change it \u{2014} the daemon reports this folder as matching what is on disk. Nothing this app can do reaches it.")
  }

  /// Where a half-finished download waits for its second half.
  ///
  /// Keyed by the content root, so a partial can only ever be continued into
  /// the bytes it came from: if the path has been republished since, the root
  /// differs, this names a file that does not exist, and the download starts
  /// from zero rather than splicing two versions together. An entry with no
  /// root — which a file always has — gets a name nothing will match, so it
  /// simply never resumes.
  private static func partialFile(for entry: Synch_Control_V1_Entry, name: String) -> URL {
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent("partial-downloads", isDirectory: true)
    try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let key = entry.hasContent
      ? entry.content.map { String(format: "%02x", $0) }.joined()
      : UUID().uuidString
    return directory.appendingPathComponent(key)
  }

  /// What the bytes already on disk are worth.
  ///
  /// The partial is named after the content root, so anything found under that
  /// name is a prefix of *this* object — but only a prefix. A file that is
  /// somehow longer than the object it is named for is not one, and the safe
  /// reading of it is that something else wrote there, so it is replaced rather
  /// than trusted. The daemon would refuse an offset past the end anyway; this
  /// is the app not asking.
  enum ResumeDecision: Equatable {
    case fromScratch
    case resume(at: Int64)
    case alreadyComplete
  }

  nonisolated static func decide(have: Int64, total: Int64) -> ResumeDecision {
    guard total > 0 else { return .fromScratch }
    if have <= 0 { return .fromScratch }
    if have < total { return .resume(at: have) }
    if have == total { return .alreadyComplete }
    return .fromScratch
  }

  private static func bytesOnDisk(at url: URL) -> Int64 {
    let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize
    return Int64(size ?? 0)
  }

  /// A temporary file that keeps the entry's name and extension, which is what
  /// Quick Look and a Finder drag both read the type from.
  private static func namedTemporary(for entry: RemoteEntry, version: VersionPolicy) -> URL {
    var suffix = ""
    if case .origin(let origin) = version { suffix = " (\(origin))" }
    let base = (entry.name as NSString).deletingPathExtension + suffix
    let ext = (entry.name as NSString).pathExtension
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return directory.appendingPathComponent(ext.isEmpty ? base : "\(base).\(ext)")
  }

  // MARK: - Delete

  /// How many paths a delete would tombstone, and what the daemon will do.
  struct DeletePlan {
    var paths: [(space: String, path: String)]
    var folders: [String]
    var summary: String
    /// True when a folder could not be fully enumerated, so the plan names
    /// fewer paths than the folder holds. Said out loud rather than deleting a
    /// prefix of what the person pointed at.
    var incomplete = false
  }

  func deletePlan(for entries: [RemoteEntry]) async -> DeletePlan {
    var paths: [(String, String)] = []
    var folders: [String] = []
    var incomplete = false
    for entry in entries {
      if entry.isDirectory {
        folders.append(entry.name)
        // The daemon has no recursive delete — `DeleteRequest` carries exactly
        // one path — so a folder is expanded into its leaves and the count is
        // stated up front.
        let found = await leaves(under: entry)
        paths += found.paths
        incomplete = incomplete || found.incomplete
      } else {
        paths.append((entry.space, entry.path))
      }
    }
    let summary: String
    if entries.count == 1, let only = entries.first, !only.isDirectory {
      summary = "Delete \u{201C}\(only.name)\u{201D}?"
    } else if !folders.isEmpty {
      summary = paths.isEmpty
        ? "Nothing to delete"
        : "Delete \(paths.count) item\(paths.count == 1 ? "" : "s")?"
    } else {
      summary = "Delete \(paths.count) items?"
    }
    return DeletePlan(paths: paths, folders: folders, summary: summary, incomplete: incomplete)
  }

  /// Every path the daemon publishes under a folder row.
  ///
  /// Asked of the daemon rather than read out of `rows`, because `rows` cannot
  /// answer it: `LevelBuilder` keeps only the level being shown and synthesises
  /// a single row for everything below it, so no element of `rows` has a path
  /// *under* a folder row. Filtering it for one matched nothing — in every
  /// folder, always — and the delete then reported "That folder holds nothing
  /// this Mac publishes", which was never true of a folder that was on screen.
  private func leaves(under folder: RemoteEntry) async -> (
    paths: [(String, String)], incomplete: Bool
  ) {
    var found: [(String, String)] = []
    var startAfter: String?
    while true {
      let page: ControlClient.ListPage
      do {
        page = try await store.client.listPage(
          // `.newest`, like the listing itself — see `FilesModel.reload` and
          // E5 in docs/DAEMON-ISSUES.md. A version policy decides which
          // *version* a read opens; `Delete` is addressed by path and has no
          // version in it. Enumerating under the toolbar's policy made Strict
          // and a pinned device silently shrink the plan, and because a
          // refusal is not an enumeration failure the plan still called itself
          // complete — so the dialog stated a count smaller than the folder.
          space: folder.space, prefix: folder.path, policy: .newest,
          startAfter: startAfter, wanted: 2_000)
      } catch {
        // Better to delete nothing than to delete a prefix of what was named.
        return ([], true)
      }
      if page.entries.isEmpty {
        // A page can come back empty while paths remain — see `reload`, which
        // documents why — so the end is confirmed with one unbounded request
        // rather than assumed from a short page.
        do {
          let remainder = try await store.client.listRemainder(
            space: folder.space, prefix: folder.path, policy: .newest,
            startAfter: startAfter)
          found += remainder.map(RemoteEntry.init).filter { !$0.isDirectory }
            .map { ($0.space, $0.path) }
        } catch {
          // `try?` here reported a short plan as a complete one, which is the
          // difference between "this folder holds three files" and "this
          // folder holds at least three files".
          return (found, true)
        }
        break
      }
      found += page.entries.map(RemoteEntry.init).filter { !$0.isDirectory }
        .map { ($0.space, $0.path) }
      startAfter = page.entries.last?.path
      if found.count > 200_000 { return (found, true) }
    }
    return (found, false)
  }

  func delete(_ plan: DeletePlan) {
    guard !plan.paths.isEmpty else { return }
    store.enqueue { [weak self] in
      guard let self else { return }
      var removed = 0
      var stillPublished: [String] = []
      // Said out loud, because it is not quick: the daemon has no bulk delete
      // — `DeleteRequest` carries one path — and it rescans every configured
      // folder and signs a head after each one. A hundred-file delete is a
      // hundred of those, and the window used to sit there saying nothing.
      self.deleteProgress = DeleteProgress(done: 0, total: plan.paths.count)
      // Belt and braces with the `defer` below, which already clears it on
      // every exit — but this is the line that states the contract, and it is
      // also the honest limit of the button: a second plan already queued
      // behind this one is its own `delete(_:)` call and starts fresh here, so
      // a Stop ends the delete that is running, not everything asked for.
      self.stopDeleteRequested = false
      defer {
        self.deleteProgress = nil
        self.stopDeleteRequested = false
      }
      var attempted = 0
      var stopped = false
      for target in plan.paths {
        // Between paths is the only place a stop lands, and that is chosen
        // rather than forced: aborting the request in flight is available —
        // `GRPCAsyncUnaryCall` cancels the RPC when its task is cancelled —
        // and it would leave that path's outcome unknown, which is the one
        // thing a delete must never be. So the wait after a press is one
        // request, bounded by the `.standard` deadline it was sent under and
        // not by the size of the plan — and then the loop's tail, which is a
        // `reload` and a `status` refresh before the row clears. That is the
        // difference between a stop and a hang.
        if self.stopDeleteRequested {
          stopped = true
          break
        }
        // Attempted, not removed: `removed` counts the paths the daemon
        // actually had a local copy of, so deleting content published only by
        // another device read "Deleting 0 of 12…" for the whole run.
        defer {
          attempted += 1
          self.deleteProgress = DeleteProgress(done: attempted, total: plan.paths.count)
        }
        do {
          let response = try await self.store.client.delete(
            space: target.space, path: target.path)
          if response.removed { removed += 1 }
          // The two answers the old client threw away. Without them, deleting a
          // path another machine also publishes looked like the app had simply
          // ignored the request.
          if response.stillPublished { stillPublished.append(target.path) }
        } catch {
          // How far it got, not just where it stopped. A delete that failed
          // half way used to name the failing path and nothing else, so there
          // was no way to know whether the other ninety-nine had gone.
          let done = attempted
          let failure = DaemonFailure.classify(error, operation: "delete \(target.path)")
          self.store.alert = plan.paths.count == 1 ? failure : DaemonFailure(
            code: failure.code,
            detail: "\(failure.detail)\n\n\(done) of \(plan.paths.count) had already been deleted.",
            operation: failure.operation,
            suggestion: failure.recoverySuggestion)
          break
        }
      }
      await self.reload()
      await self.store.refresh([.status])
      if stopped {
        // A stop is not a failure, and it is not silence either. What it
        // leaves behind is a half-deleted folder, and the only way to know
        // which half is to be told how far it got — the same reason the
        // failure branch above counts rather than just naming a path. It also
        // has to come first: without it the `removed == 0` branch below would
        // answer a stop with "There was no copy on this Mac to remove.", which
        // is a statement about the folder rather than about what just
        // happened.
        //
        // Composed rather than chosen, because a stop does not make the other
        // two facts untrue: the paths the loop did reach can still be ones
        // another device publishes, and answering that with the stop sentence
        // alone would leave those rows sitting in the listing with nothing
        // said about why. `attempted` is at least one — the flag is cleared
        // immediately above and the first check runs before any `await`, so a
        // stop cannot land before the first path.
        var detail = "Stopped after \(attempted) of \(plan.paths.count). "
          + "What was already deleted stays deleted."
        if !stillPublished.isEmpty {
          detail += stillPublished.count == 1
            ? " This Mac’s copy of \(stillPublished[0]) is gone, but another device still publishes it, so it stays in the list."
            : " \(stillPublished.count) of them are still published by another device, so they stay in the list."
        }
        self.store.alert = DaemonFailure(code: .invalid, detail: detail, operation: nil)
      } else if !stillPublished.isEmpty {
        self.store.alert = DaemonFailure(
          code: .invalid,
          detail: stillPublished.count == 1
            ? "This Mac’s copy of \(stillPublished[0]) is gone, but another device still publishes it, so it stays in the list."
            : "This Mac’s copies are gone, but \(stillPublished.count) of them are still published by another device, so they stay in the list.",
          operation: nil)
      } else if removed == 0 {
        self.store.alert = DaemonFailure(
          code: .notFound,
          detail: "There was no copy on this Mac to remove.",
          operation: nil)
      }
    }
  }

  // MARK: - Keeping content offline

  /// Whether the daemon is holding this file's bytes.
  ///
  /// Matched on the content root, which is what a pin names. The browser used
  /// to offer "Keep Offline" and "Stop Keeping Offline" side by side on every
  /// file, both always enabled, with the actual state readable nowhere in this
  /// window — so there was no way to tell which of the two would do anything.
  /// Only an operator pin counts. `store.pins` already holds nothing else —
  /// the replica rows are filtered out on the way in — but the test says what
  /// it means rather than relying on that: a replicating folder holds the same
  /// roots, and treating its claim as a pin showed "Keep Offline" as already
  /// on for every file in a replicated folder, then failed on the way back off.
  func isPinned(_ entry: RemoteEntry) -> Bool {
    guard let root = entry.rootHex else { return false }
    return store.pins.contains { $0.root == root && $0.isOperatorPinned }
  }

  /// What removing this pin actually does, which depends on who else holds it.
  ///
  /// A replicating folder holds the same content roots. Where one does, `pin
  /// rm` removes the operator's pin and frees nothing — the daemon says so in
  /// its own reply, `unpinned {root} (still held by …)`. Promising a reclaim
  /// there was promising the opposite of what happens.
  private func unpinConsequence(_ entry: RemoteEntry) -> String {
    let alsoHeld = entry.rootHex.map { root in
      store.pins.contains { $0.root == root && $0.hasOtherHolders }
    } ?? false
    return alsoHeld
      ? "A replicating folder still holds these bytes, so nothing is freed on this Mac yet. They go when that folder releases them."
      : "The bytes may be reclaimed the next time the daemon needs the space. The file stays in the listing and is fetched again when it is opened."
  }

  /// Puts the pin change behind the gate its `Operation` declares.
  ///
  /// `pin.add` is `.consequence` and `pin.rm` is `.confirm`; this call site
  /// applied neither, which is exactly the drift `ConfirmedAction` says a gate
  /// on the operation is meant to prevent.
  func pinRequest(_ entry: RemoteEntry, pinned: Bool) -> ConfirmationRequest {
    let target = entry.rootHex ?? Cmd.reference(space: entry.space, path: entry.path)
    let operation = Operations.require(pinned ? "pin.add" : "pin.rm")
    return ConfirmationRequest(
      title: pinned
        ? "Keep \u{201C}\(entry.name)\u{201D} on this Mac?"
        : "Stop keeping \u{201C}\(entry.name)\u{201D} on this Mac?",
      consequence: pinned
        ? "The daemon holds these bytes here even when nothing else needs them, so the file opens without fetching it. It uses the space until you stop."
        : unpinConsequence(entry),
      verb: pinned ? "Keep Offline" : "Stop Keeping",
      gate: operation.gate,
      commandLine: "synch pin \(pinned ? "add" : "rm") \(Shell.quote(target))",
      isDestructive: !pinned,
      perform: { [weak self] in self?.setPinned(entry, pinned: pinned) }
    )
  }

  func setPinned(_ entry: RemoteEntry, pinned: Bool) {
    let target = entry.rootHex ?? Cmd.reference(space: entry.space, path: entry.path)
    store.enqueue { [weak self] in
      guard let self else { return }
      let operation = Operations.require(pinned ? "pin.add" : "pin.rm")
      await self.store.run(
        operation,
        pinned ? Cmd.pinAdd(target) : Cmd.pinRm(target),
        commandLine: "synch pin \(pinned ? "add" : "rm") \(Shell.quote(target))",
        deadline: .long)
      // So the browser's own toggle knows what happened.
      await self.store.refresh([.pins])
    }
  }
}
