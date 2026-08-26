import Foundation

/// Uploads and downloads in flight.
///
/// Everything here is addressed by `Transfer.id`. The crash this replaces came
/// from a positional index captured when a batch started and written to after
/// an unrelated operation had emptied the array — so no API in this type takes
/// an index, and the queue is never cleared as a side effect of anything else.
@MainActor
@Observable
final class TransferQueue {
  private(set) var transfers: [Transfer] = []
  /// Uploads the daemon still holds parts for, found at launch. Their state
  /// outlives this process, so an interrupted 40 GB file is resumable rather
  /// than lost.
  private(set) var resumable: [ResumableUpload] = []

  private var tasks: [UUID: Task<Void, Never>] = [:]
  /// Which start of a transfer owns ``tasks``'s slot for it.
  private var runTokens: [UUID: Int] = [:]
  private var nextRunToken = 0
  /// The work each transfer is, kept so a finished one can be run again.
  private var runners: [UUID: @MainActor (UUID) async -> Void] = [:]

  var active: [Transfer] { transfers.filter(\.isActive) }
  var hasActive: Bool { !active.isEmpty }

  /// The order the list is read in: whatever is running, then the history
  /// newest first.
  ///
  /// ``transfers`` is held newest-first, so neither half needs sorting — two
  /// passes over an array bounded at ``historyLimit``. Without this, keeping
  /// the history put every new transfer *below* everything that had ever
  /// finished, which in a popover four rows tall meant a download you had just
  /// started was off the bottom of it.
  var listed: [Transfer] { active + transfers.filter(\.isFinished) }

  var summary: String {
    let running = active.count
    if running == 0 {
      let failed = transfers.count(where: { if case .failed = $0.state { true } else { false } })
      if failed > 0 { return failed == 1 ? "1 transfer failed" : "\(failed) transfers failed" }
      // Interrupted uploads are rows in this list, so the heading above them
      // has to count them. It read "No transfers" over three of them — and the
      // same string is the toolbar button's tooltip and its accessible name,
      // so VoiceOver said "Transfers: No transfers" in exactly the state the
      // banner had just sent the person here to look at.
      if !resumable.isEmpty {
        return resumable.count == 1
          ? "1 interrupted upload" : "\(resumable.count) interrupted uploads"
      }
      return transfers.isEmpty ? "No transfers" : "Transfers finished"
    }
    return running == 1 ? "1 transfer" : "\(running) transfers"
  }

  /// Bumped whenever a transfer a *person* asked for begins.
  ///
  /// Settings has offered "Show transfers automatically" since the first
  /// version and nothing ever read it, so the checkbox did nothing whichever
  /// way it was set. This is what it reads.
  ///
  /// Not every transfer counts. Quick Look, a double-click and a drag out to
  /// Finder all fetch the bytes through the same queue — they want the row,
  /// for its progress and its cancel — but nobody who presses Space is asking
  /// to see a transfer list. Worse, a small file finishes before the popover
  /// draws, so the row is already gone: pressing Space popped a panel that
  /// said "Nothing is transferring" and stayed until it was dismissed.
  private(set) var startedCount = 0

  /// How many finished rows the history keeps.
  ///
  /// The list is a record of the session, not of all time, and it is held in
  /// memory. Old rows fall off the far end; running ones never do, however
  /// many there are.
  static let historyLimit = 200

  func add(
    _ transfer: Transfer, asked: Bool = true,
    run: @escaping @MainActor (UUID) async -> Void
  ) {
    // At the front: this list is read newest-first.
    transfers.insert(transfer, at: 0)
    runners[transfer.id] = run
    if asked { startedCount += 1 }
    start(transfer.id)
  }

  /// Drops the oldest finished rows once there are more than the limit.
  /// Called when one finishes, which is the only time the history grows.
  private func trimHistory() {
    let finished = transfers.filter(\.isFinished)
    guard finished.count > Self.historyLimit else { return }
    let stale = Set(finished.suffix(finished.count - Self.historyLimit).map(\.id))
    for id in stale { runners[id] = nil }
    transfers.removeAll { stale.contains($0.id) }
  }

  private func start(_ id: UUID) {
    guard let run = runners[id] else { return }
    // A token, because the finishing task has to be able to tell its own slot
    // from a newer one's. Clearing `tasks[id]` unconditionally let a retry
    // issued while the previous run was still unwinding lose its own cancel
    // handle to the older run finishing a moment later.
    nextRunToken += 1
    let token = nextRunToken
    runTokens[id] = token
    tasks[id] = Task { @MainActor in
      await run(id)
      guard self.runTokens[id] == token else { return }
      self.runTokens[id] = nil
      self.tasks[id] = nil
    }
  }

  /// Whether a finished transfer still knows how to run itself again.
  ///
  /// `tasks[id] == nil` as well, because `cancel` writes `.cancelled` and drops
  /// the handle while the task is still unwinding — so for a moment the row is
  /// "finished" and offering a Retry that would race the run it is replacing.
  func canRetry(_ id: UUID) -> Bool {
    guard let transfer = transfer(id), tasks[id] == nil else { return false }
    if case .completed = transfer.state { return false }
    return transfer.isFinished && runners[id] != nil
  }

  /// Forgets how to run a transfer again, without touching its row.
  ///
  /// For work that can only be done once. `materialize` hands its runner a
  /// `CheckedContinuation`, and running that runner a second time resumes the
  /// same continuation twice — which is not an error but a `fatalError`. The
  /// row stays, with its reason and its Clear; only the Retry goes.
  func retire(_ id: UUID) {
    runners[id] = nil
  }

  /// Runs a failed or cancelled transfer again.
  ///
  /// A download that stopped part-way left its bytes on disk under the content
  /// root it was fetching, so this continues from there rather than starting
  /// over — the same promise the multipart uploads already made, now kept in
  /// both directions.
  func retry(_ id: UUID) {
    guard canRetry(id), let index = transfers.firstIndex(where: { $0.id == id }) else { return }
    transfers[index].state = .waiting
    transfers[index].bytes = 0
    transfers[index].resumedFrom = 0
    transfers[index].startedAt = .now
    transfers[index].finishedAt = nil
    startedCount += 1
    start(id)
  }

  /// The only way progress is written. A transfer that has been removed simply
  /// does not match, which is a no-op rather than a trap.
  ///
  /// Dating a transfer that has just stopped happens here because this is the
  /// one place every state change goes through. Doing it at the call sites
  /// meant five of them, and a sixth added later that forgot.
  func update(_ id: UUID, _ change: (inout Transfer) -> Void) {
    guard let index = transfers.firstIndex(where: { $0.id == id }) else { return }
    change(&transfers[index])
    guard transfers[index].isFinished, transfers[index].finishedAt == nil else { return }
    transfers[index].finishedAt = .now
    // Only on the transition, never on the progress writes: this walks the
    // whole array, and a running download calls `update` once per chunk.
    trimHistory()
  }

  func transfer(_ id: UUID) -> Transfer? { transfers.first { $0.id == id } }

  func cancel(_ id: UUID) {
    tasks[id]?.cancel()
    tasks[id] = nil
    runTokens[id] = nil
    update(id) { transfer in
      if transfer.isActive { transfer.state = .cancelled }
    }
  }

  func cancelAll() {
    for id in tasks.keys { cancel(id) }
  }

  /// Clears finished rows only. Running transfers survive, because the queue
  /// is not scratch space for whatever ran last.
  func clearFinished() {
    for transfer in transfers where transfer.isFinished { runners[transfer.id] = nil }
    transfers.removeAll { $0.isFinished }
  }

  func setResumable(_ uploads: [ResumableUpload]) {
    resumable = uploads
  }

  func dropResumable(id: String) {
    resumable.removeAll { $0.id == id }
  }
}
