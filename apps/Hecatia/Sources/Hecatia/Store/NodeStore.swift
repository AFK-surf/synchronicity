import Foundation
import SwiftUI

/// Everything the app knows about one daemon.
///
/// One per data directory, shared by every window, because there is one daemon
/// behind a global connection mutex and two independent views of it is a
/// coherence hazard rather than a feature. Per-window browsing state lives in
/// ``FilesModel`` instead.
@MainActor
@Observable
final class NodeStore {

  /// The connection, as a state rather than a boolean.
  ///
  /// The boolean it replaces was set before any request had been made and never
  /// reverted, so a dead daemon, a rotated token and a protocol mismatch all
  /// showed a green "DAEMON ONLINE" card with the connect card gone.
  enum Connection: Equatable {
    case idle
    case connecting
    case connected
    case failed(DaemonFailure)
    /// A version mismatch is not an alert: nothing else will work, so it takes
    /// over the window.
    case needsUpdate(DaemonFailure)

    var isConnected: Bool { self == .connected }
  }

  // MARK: - Published state

  private(set) var connection: Connection = .idle
  private(set) var status: NodeStatus?
  private(set) var identity: NodeStatusReader.Identity?

  private(set) var spaces: [Space] = []
  private(set) var members: [Member] = []
  private(set) var domains: [DomainHealth] = []
  private(set) var zonePending: String?
  private(set) var peers: [PeerInfo] = []
  private(set) var deviceKeys: [DeviceKey] = []
  private(set) var keyReport: [String] = []
  private(set) var mirrors: [MirrorEntry] = []
  /// Operator pins only — see the `.pins` refresh for why.
  private(set) var pins: [PinEntry] = []
  /// Objects `pin ls` reported that a replica holds and the operator did not.
  /// Not listed, but worth saying the number of, or a replica's disk use looks
  /// like it comes from nowhere.
  private(set) var heldByReplicas = 0
  /// Per-space replication reports, keyed by space id, for the folders that
  /// replicate. Absent means "not replicated" or "not asked yet".
  private(set) var replicaStatus: [String: ReplicaStatus] = [:]
  private(set) var cloud = CloudState()
  private(set) var doctorReport: [String] = []
  /// The last `mirror sync`, attributed per mirror.
  private(set) var lastMirrorSync: MirrorSyncOutcome?
  /// The gateway's live bucket map and access key ids, folded out of the
  /// append-only logs the two config values actually hold.
  private(set) var s3Buckets: [GatewayBucket] = []
  private(set) var s3KeyIDs: [String] = []
  /// How many records the two logs carry, which is not how many buckets and
  /// keys there are and is worth saying so.
  private(set) var s3RecordCount = 0

  /// Bumped whenever something invalidates what a browser is showing.
  ///
  /// Every open Files window watches it and reloads, so an operation that
  /// changes the tree refreshes the tree wherever it is being looked at,
  /// however it was started.
  private(set) var listingGeneration = 0

  /// Lines a parser did not recognise, per topic. Surfaced as a diagnostics
  /// chip so an unexpected format degrades to a visibly incomplete table
  /// instead of a silently wrong one.
  private(set) var parseWarnings: [Topic: [String]] = [:]
  private(set) var loading: Set<Topic> = []

  private(set) var activity: [ActivityRun] = []
  var alert: DaemonFailure?

  /// The folder given to `synch daemon start`, remembered across launches.
  ///
  /// Read and written straight through `UserDefaults` rather than with
  /// `@AppStorage`, which does not work inside an `@Observable` class: the
  /// wrapper carries its own change tracking, observation never sees the
  /// write, and every view bound to it would quietly stop updating.
  static let dataDirectoryKey = "dataDirectory"

  var dataDirectoryPath = UserDefaults.standard.string(forKey: NodeStore.dataDirectoryKey)
    ?? NodeStore.defaultDataDirectory
  {
    didSet { UserDefaults.standard.set(dataDirectoryPath, forKey: NodeStore.dataDirectoryKey) }
  }
  /// Reset on quit by design: a disclosure that survives a relaunch is not a
  /// disclosure.
  var advancedUnlocked = false

  #if DEBUG
  /// True for a store built by ``preview(_:)``. A preview has no daemon behind
  /// it, so a command must not be *attempted*: the attempt spends its deadline
  /// failing and then overwrites the very fixture the preview was made of.
  fileprivate(set) var isPreview = false
  #endif

  let transfers = TransferQueue()
  /// When this app first saw each tunnel hold its current state. The daemon
  /// records the real instant and never renders it, so this is the closest
  /// available fact — and it is labelled as such wherever it is shown.
  let observed = ObservationLedger()
  let client = ControlClient()

  static let defaultDataDirectory = "~/Library/Application Support/synchronicity"

  private var pollTask: Task<Void, Never>?
  private var commandChain: Task<Void, Never>?
  private var reconnectAttempted = false
  /// The last failure any run produced, alerted or not, so a caller that
  /// suppressed the modal can still say what went wrong.
  private(set) var lastFailure: DaemonFailure?
  /// Consecutive failures of the five-second status probe.
  private var statusProbeFailures = 0
  /// How many of this app's own deadline-less commands are in flight.
  ///
  /// The daemon takes one global mutex for every store read, so a `scan` or a
  /// `doctor --rebuild` of ours can make it stop answering the status probe —
  /// and a probe that cannot tell that apart from a daemon that has died will
  /// eventually declare one that is merely busy on our behalf.
  private var longRunsInFlight = 0
  private var frameBuffer: [UUID: [RunFrame]] = [:]
  private var frameFlush: Task<Void, Never>?

  // MARK: - Derived

  var isWaitingToBeNamed: Bool {
    if case .waitingToBeNamed = status?.naming { return true }
    return false
  }

  var origin: String? { status?.origin }

  /// What to call this node where a person is reading rather than an operator.
  ///
  /// A node named by a membership zone publishes under that name —
  /// `nas@cluster.example` — and the name is the right answer. A node without
  /// one is named by its device key, and `key:` followed by 52 characters of
  /// z-base-32 is an identifier, not a name: the Files window said
  /// `key:ao6bbsx33q…55m1qejcdh3m11o` where it meant "this Mac". The key is
  /// still exactly what the Node window shows, and still one tooltip away.
  var displayName: String {
    guard let origin, !origin.isEmpty else { return "This Mac" }
    return origin.hasPrefix("key:") ? "This Mac" : origin
  }

  /// What to call *any* origin where a person is reading.
  ///
  /// ``displayName`` did this for this Mac and stopped there, so the same
  /// 52-character z-base-32 key it was written to keep out of the Files window
  /// went on being printed in the Device column and in the inspector's Device
  /// row, where it wrapped over three lines and named nothing. A key is an
  /// identifier; the full one is still a tooltip away wherever this is used.
  func label(forOrigin origin: String) -> String {
    guard !origin.isEmpty else { return "\u{2014}" }
    if origin == self.origin { return "This Mac" }
    // The daemon's own placeholder for a key it holds no name for.
    guard origin != "(untrusted)" else { return "An unnamed device" }
    guard origin.hasPrefix("key:") else { return origin }
    let key = origin.dropFirst(4)
    return "Unnamed device (\(key.prefix(6))\u{2026})"
  }

  /// The Files toolbar chip. It is the seam between the two windows: a fact the
  /// user already wanted, sitting where they were already looking, that happens
  /// to be a button into the Node window.
  var nodeSummary: String {
    guard connection.isConnected else { return "Not connected" }
    if isWaitingToBeNamed { return "Waiting to be named" }
    let peerCount = status?.peersSeen ?? peers.count
    let devices = peerCount == 1 ? "1 other device" : "\(peerCount) other devices"
    if let seq = status?.headSeq { return "\(devices) · published seq \(seq)" }
    return devices
  }

  /// The same fact without the operator's half of it.
  ///
  /// ``nodeSummary`` ends in "published seq 23", which is the right answer in
  /// the Node window and the menu bar and means nothing in the Files window.
  /// The seq is still one tooltip away.
  var peerSummary: String {
    guard connection.isConnected else { return "Not connected" }
    if isWaitingToBeNamed { return "Waiting to be named" }
    let count = status?.peersSeen ?? peers.count
    switch count {
    case 0: return "No other devices"
    case 1: return "1 other device"
    default: return "\(count) other devices"
    }
  }

  var alarms: [NodeStatus.Alarm] { status?.alarms ?? [] }

  // MARK: - Lifecycle

  var dataDirectory: URL {
    URL(filePath: (dataDirectoryPath as NSString).expandingTildeInPath)
  }

  /// Connecting is not a user task, so the app does it on launch rather than
  /// making the browser window a form.
  func connectOnLaunch() {
    guard case .idle = connection else { return }
    connect()
  }

  func connect() {
    connection = .connecting
    Task {
      do {
        try await client.connect(dataDirectory: dataDirectory)
        connection = .connected
        statusProbeFailures = 0
        reconnectAttempted = false
        await refresh([.status, .spaces])
        startPolling()
        await loadResumableUploads()
      } catch let failure as DaemonFailure {
        connection = failure.code == .versionMismatch
          ? .needsUpdate(failure)
          : .failed(failure)
      } catch {
        connection = .failed(DaemonFailure.classify(error, operation: "connect"))
      }
    }
  }

  func disconnect() {
    pollTask?.cancel()
    pollTask = nil
    transfers.cancelAll()
    Task {
      await client.disconnect()
      connection = .idle
      status = nil
      spaces = []
      clearCaches()
    }
  }

  private func clearCaches() {
    members = []; domains = []; peers = []; deviceKeys = []; keyReport = []
    mirrors = []; pins = []; cloud = CloudState(); doctorReport = []
    s3Buckets = []; s3KeyIDs = []; s3RecordCount = 0; parseWarnings = [:]
  }

  private func startPolling() {
    pollTask?.cancel()
    pollTask = Task { [weak self] in
      while !Task.isCancelled {
        // Faster once something has gone wrong: the second probe is what turns
        // one slow answer into a diagnosis, and waiting a full five seconds
        // for it doubled how long the app went on claiming to be connected.
        try? await Task.sleep(for: .seconds(self?.statusProbeFailures ?? 0 > 0 ? 1 : 5))
        guard let self, !Task.isCancelled else { return }
        if self.connection.isConnected {
          await self.refresh([.status])
        } else if case .failed = self.connection {
          // A daemon that comes back should be noticed without being asked.
          // `.failed` is the state a daemon that *stopped* leaves behind;
          // `.idle` is the app's own Stop and `.needsUpdate` needs a new
          // binary, and neither is something to keep retrying.
          await self.reconnectQuietly()
        }
      }
    }
  }

  /// Notices a daemon that has stopped answering.
  ///
  /// Nothing else could: `connection` only ever left `.connected` for an
  /// `unauthorized` reply, which is the token a *restarted* daemon mints. A
  /// daemon that simply died answered `unavailable`, the poll swallowed it
  /// because it runs `quiet`, and the app went on showing a green dot, a
  /// device name, a filled menu-bar glyph and two enabled commands — with the
  /// only Retry button sitting in a branch that had become unreachable.
  ///
  /// Two failures, not one, and never a cancelled probe: `daemon.status` runs
  /// on the `.fast` deadline, so one slow answer is a timeout rather than a
  /// death, and `classify` maps `CancellationError` to `unavailable` too, so a
  /// probe cancelled by `disconnect()` would otherwise read as one.
  private func noteStatusProbeFailed(_ failure: DaemonFailure?) {
    guard !Task.isCancelled, connection.isConnected else { return }
    // Only the code that means *gone*. A `.fast` deadline expiry lands on
    // `.internalError`, and the daemon takes one global mutex for every store
    // read — so a `doctor --rebuild` or a `scan` of this app's own, which run
    // with no deadline at all, can hold it past twenty seconds twice running.
    // Counting that as a death was worse than not noticing: it wiped the
    // caches and then reconnected, and reconnecting opens by closing the
    // channel — killing the very command the person had started.
    guard failure?.code == .unavailable else { return }
    // And never while one of this app's own deadline-less commands is in
    // flight, whichever it is.
    guard longRunsInFlight == 0 else { return }
    statusProbeFailures += 1
    guard statusProbeFailures >= 2 else { return }
    // Back to the slow cadence: the fast one exists to reach a *diagnosis*
    // quickly, and once there is one the loop is retrying a connection rather
    // than probing — once a second, for as long as the daemon stays away.
    statusProbeFailures = 0
    connection = .failed(DaemonFailure(
      code: .unavailable,
      detail: "The daemon stopped answering. It may have quit, or been stopped.",
      operation: "check on the daemon",
      suggestion: "This app keeps trying, and reconnects on its own the moment one is listening again."))
    clearCaches()
  }

  /// Tries the socket again without making the window flicker.
  ///
  /// Deliberately not `connect()`: that goes through `.connecting`, which the
  /// browser draws as a spinner, so retrying every five seconds would blink
  /// the whole window at the user. This stays `.failed` until it works.
  private func reconnectQuietly() async {
    do {
      try await openAndAdopt()
      await loadResumableUploads()
    } catch {
      // Still down. The window already says so, and says how to fix it.
    }
  }

  /// Opens the socket and adopts a working connection.
  ///
  /// `startPolling()` is deliberately not in here: `reconnectQuietly` is
  /// called from *inside* the poll task, and starting the poll again would
  /// cancel its own caller. `connect()` starts it straight after this call and
  /// before `loadResumableUploads()`, which is a round of `openUploads` per
  /// space, so the first status tick is not held up behind it.
  private func openAndAdopt() async throws {
    try await client.connect(dataDirectory: dataDirectory)
    connection = .connected
    statusProbeFailures = 0
    reconnectAttempted = false
    await refresh([.status, .spaces])
  }

  /// A token mismatch means the daemon restarted — it mints a new one on every
  /// start — so it is recovered from silently instead of being shown as a
  /// credential error the user cannot act on.
  private func recoverIfStale(_ failure: DaemonFailure) async -> Bool {
    guard failure.isStaleConnection, !reconnectAttempted else { return false }
    reconnectAttempted = true
    do {
      try await client.connect(dataDirectory: dataDirectory)
      connection = .connected
      statusProbeFailures = 0
      reconnectAttempted = false
      return true
    } catch let next as DaemonFailure {
      connection = next.code == .versionMismatch ? .needsUpdate(next) : .failed(next)
      return false
    } catch {
      connection = .failed(DaemonFailure.classify(error, operation: "reconnect"))
      return false
    }
  }

  // MARK: - Running commands

  /// Runs a command, records its transcript, and reports failure once.
  ///
  /// Success is the stream ending cleanly. Nothing here reads the text to
  /// decide whether the command worked.
  @discardableResult
  func run(
    _ operation: Operation,
    _ command: Synch_Control_V1_Command,
    commandLine: String? = nil,
    deadline: ControlClient.Deadline = .standard,
    quiet: Bool = false,
    alerts: Bool? = nil
  ) async -> RunOutput? {
    #if DEBUG
    if isPreview { return nil }
    #endif
    // `quiet` decides whether the run is *listed*; `alerts` whether a failure
    // raises the modal. They were one flag, so a caller that wanted to show a
    // failure in its own sheet had to hide the run from Activity too — and
    // then tell the user to look in Activity for a message that was never
    // recorded anywhere. Defaults to the old meaning.
    let alerts = alerts ?? !quiet
    let runID = UUID()
    if deadline == .long { longRunsInFlight += 1 }
    defer { if deadline == .long { longRunsInFlight -= 1 } }
    if !quiet {
      activity.insert(
        ActivityRun(
          id: runID,
          title: operation.title,
          commandLine: commandLine ?? operation.commandLine,
          startedAt: .now
        ),
        at: 0
      )
    }
    do {
      let output = try await client.runToCompletion(
        command,
        deadline: deadline,
        operation: operation.title.lowercased()
      ) { [weak self] frame in
        Task { @MainActor in self?.bufferFrame(frame, to: runID) }
      }
      finish(runID, output: output, outcome: .succeeded)
      // `quiet` marks the calls a refresh makes for itself. Re-refreshing
      // from inside one is how `load(.status)` came to re-enter itself.
      if !quiet, !operation.dirties.isEmpty { await refresh(Set(operation.dirties)) }
      return output
    } catch let failure as DaemonFailure {
      if await recoverIfStale(failure) {
        // The first attempt was abandoned in favour of the retry on the next
        // line, and `.cancelled` is what that is. Without this it kept the
        // default `.running` outcome for the life of the process, spinning in
        // Activity with Clear refusing to take it — and this is the *intended*
        // recovery path, so a restarted daemon left one behind every time.
        finish(runID, output: nil, outcome: .cancelled)
        return await run(
          operation, command, commandLine: commandLine, deadline: deadline,
          quiet: quiet, alerts: alerts)
      }
      finish(runID, output: nil, outcome: .failed(failure))
      if alerts { alert = failure }
      lastFailure = failure
      return nil
    } catch {
      let failure = DaemonFailure.classify(error, operation: operation.title.lowercased())
      finish(runID, output: nil, outcome: .failed(failure))
      if alerts { alert = failure }
      lastFailure = failure
      return nil
    }
  }

  /// Serialises mutating commands. The daemon takes a global connection mutex
  /// for every store read, and two writes racing through the UI is how the old
  /// model let a stale listing land on top of a fresh one.
  func enqueue(_ work: @escaping @MainActor () async -> Void) {
    let previous = commandChain
    commandChain = Task { @MainActor in
      await previous?.value
      await work()
    }
  }

  /// Collects output frames, and publishes them ten times a second.
  ///
  /// One publish per line was one full re-render of every open window per
  /// line, and `scan` reports every skipped file on a progress frame. With the
  /// Activity window open it was worse: its transcript is one `Text` of the
  /// whole joined output, so the entire transcript was re-joined and re-laid
  /// out for each line that arrived.
  private func bufferFrame(_ frame: RunFrame, to id: UUID) {
    frameBuffer[id, default: []].append(frame)
    guard frameFlush == nil else { return }
    frameFlush = Task { @MainActor [weak self] in
      try? await Task.sleep(for: .milliseconds(100))
      // A cancelled timer declines. Without this it flushed anyway, and
      // `flushFrames` opens by cancelling whatever timer is current — so one
      // stray wake-up cancelled its own successor, and from then on every
      // batch published immediately. Which is the per-line re-render the
      // buffer exists to stop.
      guard !Task.isCancelled else { return }
      self?.flushFrames()
    }
  }

  private func flushFrames() {
    frameFlush?.cancel()
    frameFlush = nil
    let buffered = frameBuffer
    frameBuffer = [:]
    for (id, frames) in buffered {
      guard let index = activity.firstIndex(where: { $0.id == id }) else { continue }
      activity[index].output.append(contentsOf: frames)
    }
  }

  private func finish(_ id: UUID, output: RunOutput?, outcome: ActivityRun.Outcome) {
    // Whatever is still buffered belongs to this run's transcript, in order,
    // before the outcome lands on it.
    flushFrames()
    guard let index = activity.firstIndex(where: { $0.id == id }) else { return }
    if let output { activity[index].output = output }
    activity[index].outcome = outcome
    activity[index].finishedAt = .now
    // The transcript is a log, not a leak: 200 runs is plenty of history and
    // bounds a session that scans on a timer.
    if activity.count > 200 { activity.removeLast(activity.count - 200) }
  }

  func clearActivity() {
    activity.removeAll { !$0.isRunning }
  }

  // MARK: - Refreshing

  func refresh(_ topics: Set<Topic>) async {
    guard connection.isConnected else { return }
    #if DEBUG
    if isPreview { return }
    #endif
    loading.formUnion(topics)
    defer { loading.subtract(topics) }
    for topic in topics {
      #if DEBUG
      MainActorWatchdog.doing = "refresh \(topic)"
      #endif
      await load(topic)
    }
    #if DEBUG
    MainActorWatchdog.doing = "idle"
    #endif
  }

  func refresh(_ topics: [Topic]) async { await refresh(Set(topics)) }

  private func note(_ topic: Topic, _ unrecognized: [String]) {
    // Guarded for the same reason: assigning nil over nil still publishes.
    let wanted: [String]? = unrecognized.isEmpty ? nil : unrecognized
    if parseWarnings[topic] != wanted { parseWarnings[topic] = wanted }
  }

  private func load(_ topic: Topic) async {
    switch topic {
    case .status:
      guard let output = await run(op("daemon.status"), Cmd.daemonStatus, deadline: .fast, quiet: true)
      else {
        // `lastFailure` is set even for a quiet run, and nothing awaits
        // between there and here.
        noteStatusProbeFailed(lastFailure)
        return
      }
      statusProbeFailures = 0
      if let parsed = NodeStatusReader.status(output) {
        // Only when it actually changed. Observation fires on every
        // assignment, equal or not, and this one is assigned by a five-second
        // poll — so an idle app re-ran the body of every view in every window,
        // twelve times a minute, to redraw the same numbers.
        // A head that has moved means this node published something — a file
        // dropped into a shared folder in Finder, say — so the browser is
        // told, rather than waiting for its own slower look.
        if let old = status?.headSeq, let new = parsed.headSeq, old != new {
          listingGeneration += 1
        }
        if status != parsed { status = parsed }
        note(.status, parsed.unparsedLines)
      } else {
        note(.status, output.lines)
      }
    case .spaces:
      // A node the zone has not named yet serves a reduced surface and refuses
      // this, so it is not even asked.
      guard !isWaitingToBeNamed else { spaces = []; return }
      guard let output = await run(op("space.ls"), Cmd.spaceLs(), deadline: .fast, quiet: true)
      else { return }
      let parsed = Listings.spaces(output.lines)
      spaces = parsed.rows
      note(.spaces, parsed.unrecognized)
      // A folder that stopped replicating should not leave its old numbers
      // sitting under it.
      let replicating = Set(parsed.rows.filter(\.isReplicating).map(\.id))
      replicaStatus = replicaStatus.filter { replicating.contains($0.key) }
    case .members:
      // `delegate ls` first, because a delegated device appears in *both*
      // listings: `trust ls` prints every binding including the delegated
      // ones, and only the delegation row carries the scope and the issuer.
      // Concatenating them put the same device on screen twice, once with the
      // folders it was actually granted and once claiming all of them.
      var delegated: [Member] = []
      var trusted: [Member] = []
      var bad: [String] = []
      if let output = await run(op("delegate.ls"), Cmd.delegateLs, deadline: .fast, quiet: true) {
        let parsed = Listings.delegations(output.lines)
        delegated = parsed.rows
        bad += parsed.unrecognized
      }
      if let output = await run(op("trust.ls"), Cmd.trustLs, deadline: .fast, quiet: true) {
        let parsed = Listings.trust(output.lines)
        trusted = parsed.rows
        bad += parsed.unrecognized
      }
      let known = Set(delegated.map(\.key))
      // A delegated binding `delegate ls` did not print is one it no longer
      // considers live, and it keeps its own row so the lapse is visible.
      members = delegated + trusted.filter { !($0.source == .granted && known.contains($0.key)) }
      note(.members, bad)
    case .domains:
      guard let output = await run(op("domain.ls"), Cmd.domainLs, deadline: .fast, quiet: true)
      else { return }
      let parsed = Listings.domains(output.lines)
      domains = parsed.rows
      zonePending = parsed.unrecognized.first { $0.hasPrefix("pending:") }
      note(.domains, parsed.unrecognized.filter { !$0.hasPrefix("pending:") })
    case .peers:
      guard let output = await run(op("peers"), Cmd.peers, deadline: .fast, quiet: true)
      else { return }
      let parsed = Listings.peers(output.lines)
      peers = parsed.rows
      note(.peers, parsed.unrecognized)
    case .keys:
      guard let output = await run(op("id"), Cmd.id, deadline: .fast, quiet: true) else { return }
      let parsed = NodeStatusReader.identity(output)
      identity = parsed
      deviceKeys = parsed.keys
    case .mirrors:
      guard let output = await run(op("mirror.ls"), Cmd.mirrorLs, deadline: .fast, quiet: true)
      else { return }
      let parsed = Listings.mirrors(output.lines)
      mirrors = parsed.rows
      note(.mirrors, parsed.unrecognized)
    case .pins:
      guard let output = await run(op("pin.ls"), Cmd.pinLs, deadline: .fast, quiet: true)
      else { return }
      let parsed = Listings.pins(output.lines)
      // Only the operator's own pins are "Kept offline". `pin ls` reports
      // everything anything holds now, and a replica's claims are rows in the
      // same table — one replicated space can be hundreds of thousands of them.
      // They were never a choice someone made here, `pin rm` refuses them, and
      // listing them buries the handful that were chosen.
      //
      // Filtered here rather than in the view so the rows are not retained at
      // all: the whole point is that there may be 400,000 of them.
      pins = parsed.rows.filter(\.isOperatorPinned)
      heldByReplicas = parsed.rows.count - pins.count
      note(.pins, parsed.unrecognized)
    case .replication:
      // One detail report per replicating folder. Only replicating ones: the
      // daemon answers for the others with a one-line "not replicated" and
      // there is nothing to draw from it.
      var reports: [String: ReplicaStatus] = [:]
      for space in spaces where space.isReplicating {
        guard let output = await run(
          op("space.ls"), Cmd.spaceLs(id: space.id), deadline: .fast, quiet: true)
        else { continue }
        reports[space.id] = Listings.replicaStatus(output.lines)
      }
      replicaStatus = reports
      note(.replication, reports.values.flatMap(\.unrecognized))
    case .cloud:
      guard let output = await run(op("cloud.status"), Cmd.cloudStatus, deadline: .fast, quiet: true)
      else { return }
      cloud = Listings.cloud(output)
      for domain in cloud.domains {
        // Keyed by the row, not by the domain. `cloud status` is one line per
        // *endpoint* now, so an apex with a replica down writes "attached" and
        // "detached" under one key within a single refresh, and the ledger
        // reset its clock on every poll — every row then claimed "unchanged
        // since now", which is the one thing the line exists not to say. It was
        // right only when every endpoint agreed, and wrong exactly when one
        // did not. `CloudState.id` was already defined for this.
        observed.observe(
          "cloud/\(domain.id)",
          value: domain.detail.hasPrefix("attached") ? "attached" : "detached")
      }
    case .uploads:
      await loadResumableUploads()
    case .s3:
      // A read that failed is not a gateway that serves nothing. `try? … ?? []`
      // made a timed-out config read indistinguishable from an empty one, and
      // the pane then asserted "No buckets mapped. The gateway serves nothing
      // until one is." over a configuration that was intact — including in the
      // moment right after adding one, since the sheet refreshes on the way
      // out.
      do {
        let bucketRecords = try await client.config(key: GatewayConfig.bucketsKey)
        let keyRecords = try await client.config(key: GatewayConfig.keysKey)
        s3Buckets = GatewayConfig.buckets(bucketRecords)
        s3KeyIDs = GatewayConfig.accessKeyIDs(keyRecords)
        s3RecordCount = bucketRecords.count + keyRecords.count
        note(.s3, [])
      } catch {
        let failure = DaemonFailure.classify(error, operation: "read the gateway configuration")
        // Through the channel the app already has for a daemon answer it could
        // not use, so the pane shows a warning instead of a false empty state.
        note(.s3, [failure.detail])
      }
    case .listing:
      // Owned by each window's FilesModel, which is why this cannot reload it
      // directly — but it can say that it is stale. Without this the topic was
      // a dead end: `scan` declares `dirties: [.listing]`, and running it from
      // the menu bar or from Command-R left every open browser showing the rows
      // from before the scan.
      listingGeneration &+= 1
    }
  }

  /// `key ls` dials every peer in turn and can take minutes on a cluster with
  /// a machine switched off, so it is never on a refresh path — it is a button
  /// with a spinner and a warning.
  func askPeersAboutKeys() async {
    askingPeersAboutKeys = true
    defer { askingPeersAboutKeys = false }
    guard let output = await run(op("key.ls"), Cmd.keyLs, deadline: .long) else { return }
    let parsed = Listings.deviceKeys(output.lines)
    if !parsed.rows.isEmpty { deviceKeys = parsed.rows }
    keyReport = output.lines
    note(.keys, parsed.unrecognized)
  }

  /// Runs `mirror sync` and works out which mirrors it never reached.
  ///
  /// The command stops at the first failure, so "no error" is the only thing
  /// its exit status distinguishes. This turns a silent partial run into a
  /// precise one.
  /// True while a mirror sync is in flight.
  ///
  /// On the store, because the pane that shows it is destroyed when you leave
  /// it: as the pane's own `@State` the spinner reset and the button became
  /// live again mid-sync, and `enqueue` serialises rather than rejects, so a
  /// second `mirror sync` simply queued up behind the first.
  private(set) var mirrorSyncRunning = false
  /// True while `doctor` is in flight, for the same reason: the pane that
  /// shows it is destroyed when you leave it.
  private(set) var doctorRunning = false
  /// True while `key ls` is dialling every peer, which takes minutes.
  private(set) var askingPeersAboutKeys = false
  /// True while a scan or a sync a person started is running.
  ///
  /// Both are `deadline: .long` and both used to show nothing at all outside
  /// the Activity window — no spinner, no disabled item — so a slow one looked
  /// like nothing had happened, and pressing again queued another whole run
  /// behind the first, since `enqueue` serialises rather than rejects.
  private(set) var houseworkRunning = false

  // MARK: - Housekeeping a person asks for
  //
  // Here rather than in an extension beside the menu that calls them: they set
  // `houseworkRunning`, which is `private(set)`, and a command a person
  // started that shows nothing while it runs is what put that flag there.

  func scanNow() {
    enqueue {
      self.houseworkRunning = true
      defer { self.houseworkRunning = false }
      await self.run(Operations.require("scan"), Cmd.scan, deadline: .long)
    }
  }

  func syncNow() {
    enqueue {
      self.houseworkRunning = true
      defer { self.houseworkRunning = false }
      await self.run(Operations.require("sync"), Cmd.syncNow)
    }
  }

  /// Shares a folder, and indexes what is already in it.
  ///
  /// Both halves, together, because the second was forgotten once: `SpaceAdd`
  /// registers the folder and starts a watcher over it, and a watcher reports
  /// *changes* — it emits nothing for the files already on disk. A folder
  /// added with a thousand files in it listed none of them, under a daemon
  /// message that says "indexing", until the scanner's own interval came
  /// round.
  /// A detached space is the exception: it has no directory, so there is
  /// nothing on disk to index and the scan afterwards would be a long walk over
  /// nothing. That scan used to be unconditional.
  func addSpace(
    id: String, path: String, detached: Bool = false,
    replicate: ReplicaPolicy? = nil, grace: Int64? = nil, budget: UInt64? = nil
  ) async {
    houseworkRunning = true
    defer { houseworkRunning = false }
    var line = "synch space add \(Shell.quote(id))"
    if detached {
      line += " --detached"
    } else {
      line += " \(Shell.quote(path))"
    }
    if let replicate { line += " --replicate=\(replicate.wire)" }
    if let grace { line += " --grace \(grace)s" }
    if let budget { line += " --budget \(budget)" }
    await run(
      Operations.require("space.add"),
      Cmd.spaceAdd(
        id: id, path: detached ? "" : path, detached: detached,
        replicate: replicate, grace: grace, budget: budget),
      commandLine: line)
    guard !detached else { return }
    await run(Operations.require("scan"), Cmd.scan, deadline: .long)
  }

  /// Turns replication on, off, or adjusts it — one call, whatever changed.
  ///
  /// The daemon refuses an empty set rather than treating it as a no-op, so a
  /// caller with nothing to say must not call.
  func setReplication(
    id: String, replicate: ReplicaPolicy? = nil, stop: Bool = false,
    release: Bool = false, grace: Int64? = nil, budget: UInt64? = nil
  ) async {
    guard replicate != nil || stop || release || grace != nil || budget != nil else { return }
    houseworkRunning = true
    defer { houseworkRunning = false }
    var line = "synch space set \(Shell.quote(id))"
    if let replicate { line += " --replicate=\(replicate.wire)" }
    if stop { line += " --no-replicate" }
    if release { line += " --release" }
    if let grace { line += " --grace \(grace)s" }
    if let budget { line += " --budget \(budget)" }
    await run(
      Operations.require("space.set"),
      Cmd.spaceSet(
        id: id, replicate: replicate, noReplicate: stop, release: release,
        grace: grace, budget: budget),
      commandLine: line, deadline: .long)
  }

  /// A reconciling sweep now, instead of at the daemon's next 300-second
  /// interval. `.long`, because the handler blocks on a real fetch pass.
  func replicateNow(id: String? = nil) {
    enqueue {
      self.houseworkRunning = true
      defer { self.houseworkRunning = false }
      await self.run(
        Operations.require("space.sync"), Cmd.spaceSync(id: id),
        commandLine: "synch space sync\(id.map { " " + Shell.quote($0) } ?? "")",
        deadline: .long)
    }
  }

  /// Materializes the cluster's content into a space's own directory.
  ///
  /// Returns the daemon's own lines so the caller can show them: `fill`'s
  /// report *is* the answer, especially under `--dry-run`, where deciding
  /// everything and writing nothing is the entire operation.
  ///
  /// `nil` is a run that failed; `[]` is a run that had nothing to report.
  /// They arrived here as the same empty array, and the sheet that asks for
  /// the dry run drew both as a report — so a preview that never reached the
  /// daemon read as "there is nothing to do" and armed the write behind it.
  func fill(
    reference: String, from: String? = nil, strict: Bool = false,
    force: Bool = false, dryRun: Bool = false
  ) async -> [String]? {
    houseworkRunning = true
    defer { houseworkRunning = false }
    var line = "synch fill \(Shell.quote(reference))"
    if let from, !from.isEmpty { line += " --from \(Shell.quote(from))" }
    if strict { line += " --strict" }
    if force { line += " --force" }
    if dryRun { line += " --dry-run" }
    let output = await run(
      Operations.require("fill"),
      Cmd.fill(reference: reference, from: from, strict: strict, force: force, dryRun: dryRun),
      // The split `compare` already needed (`CompareSheet.swift:183-189`): the
      // dry run is listed in Activity like any other command, and only the
      // modal is suppressed, because `FillSheet` is where the reader is and it
      // shows that failure itself. It used to be `quiet: dryRun`, which hid the
      // Activity row too, so a failed preview left the daemon's message
      // nowhere in the app at all. The price is that a successful dry run now
      // honours the registry's `dirties` and re-reads a listing it did not
      // change; one wasted read is cheaper than an unrecorded command.
      commandLine: line, deadline: .long, alerts: !dryRun)
    return output?.transcript
  }

  func syncMirrors() async {
    mirrorSyncRunning = true
    defer { mirrorSyncRunning = false }
    await refresh([.mirrors])
    let known = mirrors
    let output = await run(
      Operations.require("mirror.sync"), Cmd.mirrorSync, deadline: .long)
    lastMirrorSync = MirrorSyncOutcome.read(
      lines: output?.lines ?? [],
      progress: output?.progress ?? [],
      mirrors: known,
      failed: output == nil)
    await refresh([.mirrors])
  }

  func runDoctor(rebuild: Bool) async {
    doctorRunning = true
    defer { doctorRunning = false }
    guard let output = await run(
      op("doctor"), Cmd.doctor(rebuild: rebuild),
      commandLine: rebuild ? "synch doctor --rebuild" : "synch doctor",
      deadline: .long)
    else { return }
    doctorReport = output.lines
  }

  private func loadResumableUploads() async {
    guard connection.isConnected, !isWaitingToBeNamed else { return }
    // `UploadInfo` does not carry its space and the request does, so the
    // space is kept from the call that found it. Flattening the lists lost
    // that, and every discard then quoted whichever space happened to be
    // first — which the daemon answers as an upload that does not exist,
    // deliberately, since an id is a bearer token for exactly one key.
    var found: [ResumableUpload] = []
    for space in spaces {
      guard let infos = try? await client.openUploads(space: space.id) else { continue }
      found += infos.map { ResumableUpload(space: space.id, info: $0) }
    }
    transfers.setResumable(found)
  }

  private func op(_ id: String) -> Operation {
    Operations.require(id)
  }
}

#if DEBUG
extension NodeStore {
  /// A store seeded for previews, with no daemon behind it.
  ///
  /// State is assigned directly — the properties are `private(set)`, so this
  /// lives in the same file as they do — which is what lets a container view
  /// render without a socket while its buttons still type-check.
  static func preview(
    connection: Connection = .connected,
    status: NodeStatus? = SampleData.status,
    spaces: [Space] = SampleData.spaces,
    members: [Member] = SampleData.members,
    transfers: [Transfer] = [],
    peers: [PeerInfo] = SampleData.peers,
    domains: [DomainHealth] = SampleData.domains,
    pins: [PinEntry] = SampleData.pins,
    buckets: [GatewayBucket] = SampleData.buckets,
    keyIDs: [String] = SampleData.keyIDs,
    cloud: CloudState = SampleData.cloud,
    activity: [ActivityRun] = SampleData.activity,
    resumable: [ResumableUpload] = [],
    // Seeded rather than reached: a preview store never refreshes — see
    // `isPreview` — so the state a view draws *before* the answer arrives has
    // no other way to be looked at.
    loading: Set<Topic> = []
  ) -> NodeStore {
    let store = NodeStore()
    store.isPreview = true
    store.connection = connection
    store.status = status
    store.spaces = spaces
    store.members = members
    store.peers = peers
    store.domains = domains
    store.pins = pins
    store.s3Buckets = buckets
    store.s3KeyIDs = keyIDs
    store.s3RecordCount = buckets.count + keyIDs.count
    store.cloud = cloud
    store.activity = activity
    store.keyReport = SampleData.keyReport
    store.doctorReport = SampleData.doctorReport
    store.deviceKeys = [
      DeviceKey(key: String(repeating: "y", count: 52), state: .active, peersHolding: "3 of 3 reachable peer(s)"),
      DeviceKey(key: String(repeating: "n", count: 52), state: .staged, peersHolding: "1 of 3 reachable peer(s)"),
    ]
    store.mirrors = [
      MirrorEntry(space: "notes", localPath: "/Users/me/Mirrors/notes", policy: "newest")
    ]
    for transfer in transfers {
      store.transfers.add(transfer) { _ in }
    }
    store.transfers.setResumable(resumable)
    store.loading = loading
    return store
  }
}
#endif
