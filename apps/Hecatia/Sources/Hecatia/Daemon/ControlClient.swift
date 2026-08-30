import Foundation
@preconcurrency import GRPC
import NIOCore
import NIOHPACK
import NIOPosix
import SwiftProtobuf

/// The daemon's local control service.
///
/// An `actor`, so nothing here runs on the main actor: chunking a 4 GB upload
/// and accumulating a listing are exactly the work that must not compete with
/// the window's own redraws.
///
/// It owns the transport and nothing else — no browsing state, no caches, no
/// opinions about what a failure means beyond classifying it.
actor ControlClient {
  /// How long a call may take before the deadline fires. There is no
  /// server-side timeout, so a stalled daemon hangs whichever call is in
  /// flight until this expires.
  enum Deadline {
    /// Everything that reads local state and answers immediately.
    case fast
    /// Anything that touches content or a peer on its way to an answer.
    case standard
    /// Scans, mirror passes, recovery, and `key ls`, which dials every peer in
    /// turn and can legitimately take minutes.
    case long

    var limit: TimeLimit {
      switch self {
      case .fast: return .timeout(.seconds(20))
      case .standard: return .timeout(.seconds(120))
      case .long: return .none
      }
    }
  }

  private struct Session {
    let group: MultiThreadedEventLoopGroup
    let channel: GRPCChannel
    let client: Synch_Control_V1_ControlAsyncClient
  }

  /// The version this app speaks. A mismatch is not an alert — nothing else
  /// will work — so it is surfaced as a whole-window state instead
  /// (`NodeStore` turns it into `.needsUpdate` and `FirstRunView` takes the
  /// window).
  ///
  /// Four, because the daemon's interceptor compares this header for
  /// *equality* on every call (`control/server.rs:306`) rather than for a
  /// floor. Announcing "2" to a v3 daemon is therefore not a degraded
  /// connection but no connection at all: even the `daemon status` round trip
  /// below, the one that exists to prove reachability before `connect`
  /// reports success, comes back refused. v3 is the release that added the
  /// socket surface — `OpenSocket` and the nine `socket` subcommands. The
  /// daemon's own note for the bump describes arming by an opaque review
  /// token rather than by content root, which was a change to work in flight
  /// on its side: sockets and v3 landed together, so no shipped version of
  /// this protocol ever had the other kind.
  static let controlVersion = "4"
  /// Identifies this app's multipart uploads so a listing can show only its
  /// own. An upload id is a bearer token; a listing across principals would
  /// make it a public one.
  static let principal = "hecatia"

  private static let chunkSize = 256 * 1024
  /// Above this, an upload goes through the multipart calls so it survives a
  /// crash, a closed lid, or a daemon restart.
  static let multipartThreshold: Int64 = 64 * 1024 * 1024
  private static let partSize: Int64 = 8 * 1024 * 1024

  private var session: Session?
  private(set) var dataDirectory: URL?

  var isConnected: Bool { session != nil }

  // MARK: - Lifecycle

  /// Opens the socket and **proves the connection works** before reporting
  /// success. The old client only stat'd two files, so a dead daemon, a
  /// rotated token and a version mismatch all reported "connected" and then
  /// failed on the next call with the connect card already gone.
  func connect(dataDirectory directory: URL) async throws {
    await disconnect()
    let socket = directory.appending(path: "control.sock")
    let tokenURL = directory.appending(path: "control.token")
    let files = FileManager.default

    guard files.fileExists(atPath: socket.path) else {
      throw DaemonFailure(
        code: .unavailable,
        detail: "No daemon is running for \(directory.path): nothing is listening on control.sock.",
        operation: "connect"
      )
    }
    guard files.fileExists(atPath: tokenURL.path), let token = try? Data(contentsOf: tokenURL) else {
      throw DaemonFailure(
        code: .unauthorized,
        detail: "\(directory.path) has no control.token, so this is not a data directory a daemon is currently serving.",
        operation: "connect"
      )
    }

    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let channel = try GRPCChannelPool.with(
      target: .unixDomainSocket(socket.path),
      transportSecurity: .plaintext,
      eventLoopGroup: group
    ) { configuration in
      // The default is 30s of waiting on a socket that may be orphaned; a
      // local daemon either answers at once or is not there.
      configuration.connectionPool.maxWaitTime = .seconds(5)
    }

    var metadata = HPACKHeaders()
    metadata.add(name: "x-synch-control-version", value: Self.controlVersion)
    metadata.add(name: "x-synch-control-token-bin", value: token.base64EncodedString())
    let options = CallOptions(customMetadata: metadata, timeLimit: Deadline.fast.limit)

    self.session = Session(
      group: group,
      channel: channel,
      client: Synch_Control_V1_ControlAsyncClient(channel: channel, defaultCallOptions: options)
    )
    self.dataDirectory = directory

    do {
      // The round trip. `daemon status` is answered in both of the daemon's
      // states, including the reduced one a node waiting to be named serves,
      // so it proves reachability without assuming the node has an identity.
      _ = try await runToCompletion(.with { $0.daemonStatus = .init() }, deadline: .fast)
    } catch {
      await disconnect()
      throw error
    }
  }

  func disconnect() async {
    guard let session else { return }
    self.session = nil
    try? await session.channel.close().get()
    try? await session.group.shutdownGracefully()
  }

  private func client(_ deadline: Deadline) throws -> Synch_Control_V1_ControlAsyncClient {
    guard let session else {
      throw DaemonFailure(code: .unavailable, detail: "Not connected to a daemon.")
    }
    var client = session.client
    client.defaultCallOptions.timeLimit = deadline.limit
    return client
  }

  // MARK: - Run

  /// Runs one CLI subcommand and collects everything it said.
  ///
  /// Success is the stream ending without a gRPC status — never the text. That
  /// is what lets any of the daemon's 54 subcommands be surfaced correctly
  /// with no parsing at all.
  func runToCompletion(
    _ command: Synch_Control_V1_Command,
    deadline: Deadline = .standard,
    operation: String? = nil,
    onFrame: (@Sendable (RunFrame) -> Void)? = nil
  ) async throws -> RunOutput {
    let call = try client(deadline).makeRunCall(command)
    var output = RunOutput()
    do {
      for try await frame in call.responseStream {
        guard let payload = frame.payload else { continue }
        let item: RunFrame
        switch payload {
        case .line(let text): item = .line(text)
        case .progress(let text): item = .progress(text)
        case .chunk: continue  // byte payloads belong to Read, not to a transcript
        }
        output.append(item)
        onFrame?(item)
      }
      return output
    } catch {
      throw DaemonFailure.classify(
        error,
        trailers: try? await call.trailingMetadata,
        operation: operation
      )
    }
  }

  /// Runs one subcommand and keeps its **bytes**, which `runToCompletion`
  /// deliberately drops.
  ///
  /// Only two commands put bytes on this stream — `cat` and `get` — and they
  /// are the only way to read an object by its content root. `Control.Read`
  /// takes a `<space>/<path>` and a version policy, with no root field at all,
  /// so it can only ever answer with the *current* version of a path; a
  /// superseded one, or anything an `archive` replica is holding, is
  /// unreachable through it.
  ///
  /// `onProgress` is fed the running byte count rather than a fraction: the
  /// daemon does not say how large the object is before it starts sending it.
  func runCollectingChunks(
    _ command: Synch_Control_V1_Command,
    deadline: Deadline = .long,
    operation: String? = nil,
    onProgress: (@Sendable (Int64) -> Void)? = nil
  ) async throws -> (bytes: Data, output: RunOutput) {
    let call = try client(deadline).makeRunCall(command)
    var bytes = Data()
    var output = RunOutput()
    do {
      for try await frame in call.responseStream {
        guard let payload = frame.payload else { continue }
        switch payload {
        case .line(let text): output.append(.line(text))
        case .progress(let text): output.append(.progress(text))
        case .chunk(let data):
          bytes.append(data)
          onProgress?(Int64(bytes.count))
        }
        try Task.checkCancellation()
      }
      return (bytes, output)
    } catch {
      throw DaemonFailure.classify(
        error,
        trailers: try? await call.trailingMetadata,
        operation: operation
      )
    }
  }

  // MARK: - Listing

  /// The namespace and this node's independent source/replica roles.
  func listSpaces() async throws -> [Synch_Control_V1_SpaceInfo] {
    let call = try client(.fast).makeListSpacesCall(.init())
    var spaces: [Synch_Control_V1_SpaceInfo] = []
    do {
      for try await space in call.responseStream { spaces.append(space) }
      return spaces
    } catch {
      throw DaemonFailure.classify(
        error, trailers: try? await call.trailingMetadata, operation: "list spaces")
    }
  }

  /// One page of entries, and deliberately no "is this the end" flag.
  ///
  /// The daemon filters tombstone-only paths out of a page *after* the limit
  /// has already bounded it, so a page can come back short — or empty — with
  /// more paths still beyond it. No row count at any limit can tell that apart
  /// from the end of the listing; only `listRemainder` settles it.
  struct ListPage: Sendable {
    var entries: [Synch_Control_V1_Entry]
  }

  /// One page of the unified tree.
  ///
  /// `limit` is sent as `wanted + 1` and the extra row is the truncation
  /// signal, which is the same thing the S3 gateway does for `IsTruncated`.
  func listPage(
    space: String,
    prefix: String,
    policy: VersionPolicy,
    startAfter: String?,
    wanted: Int
  ) async throws -> ListPage {
    let request = Synch_Control_V1_ListRequest.with {
      $0.space = space
      // The daemon matches `prefix` as a raw byte range, so a directory must
      // be asked for with its separator or the listing also returns every
      // sibling whose name merely starts with the same characters.
      $0.prefix = prefix.isEmpty || prefix.hasSuffix("/") ? prefix : prefix + "/"
      if let startAfter { $0.startAfter = startAfter }
      $0.limit = UInt64(wanted + 1)
      $0.policy = policy.wire
    }
    let call = try client(.standard).makeListCall(request)
    var entries: [Synch_Control_V1_Entry] = []
    do {
      for try await entry in call.responseStream {
        entries.append(entry)
        if entries.count > wanted { break }
      }
    } catch {
      throw DaemonFailure.classify(
        error, trailers: try? await call.trailingMetadata, operation: "list this folder")
    }
    // One over the limit was asked for, so the extra row is the proof there is
    // another page and is not itself part of this one.
    if entries.count > wanted { entries.removeLast() }
    return ListPage(entries: entries)
  }

  func resolve(space: String, path: String, policy: VersionPolicy) async throws
    -> Synch_Control_V1_Entry
  {
    let request = Synch_Control_V1_ResolveRequest.with {
      $0.space = space
      $0.path = path
      $0.policy = policy.wire
    }
    let call = try client(.fast).makeResolveCall(request)
    do {
      return try await call.response
    } catch {
      throw DaemonFailure.classify(
        error, trailers: try? await call.trailingMetadata, operation: "read this file’s details")
    }
  }

  // MARK: - Read

  /// Streams a verified byte range straight to a file handle.
  ///
  /// Nothing accumulates: the old client built the whole object in memory and
  /// only then opened a save panel, which is why a large download looked like
  /// the app had stopped responding and could not be cancelled.
  ///
  /// `from` is the daemon's own range, and the reason it is worth using rather
  /// than always asking for the whole object: `prepare_range` clamps the window
  /// to the entry and refuses an offset past its end, so continuing a download
  /// is asking for the bytes after the ones already on disk instead of
  /// fetching the front of the object again to throw it away.
  ///
  /// The file is the caller's: nothing here removes it on failure, because a
  /// partly-written file is exactly what makes the next attempt a continuation.
  /// `onProgress` reports the absolute byte count, `from` included.
  func read(
    space: String,
    path: String,
    policy: VersionPolicy,
    into destination: URL,
    from start: Int64 = 0,
    onProgress: @escaping @Sendable (Int64) -> Void
  ) async throws {
    let request = Synch_Control_V1_ReadRequest.with {
      $0.space = space
      $0.path = path
      $0.policy = policy.wire
      $0.start = UInt64(max(0, start))
    }
    let call = try client(.standard).makeReadCall(request)
    if start <= 0 || !FileManager.default.fileExists(atPath: destination.path) {
      FileManager.default.createFile(atPath: destination.path, contents: nil)
    }
    let handle = try FileHandle(forWritingTo: destination)
    defer { try? handle.close() }
    if start > 0 {
      try handle.seek(toOffset: UInt64(start))
      // Anything past the resume point is from an attempt that did not finish
      // and must not survive under the bytes about to be written.
      try handle.truncate(atOffset: UInt64(start))
    } else {
      try handle.truncate(atOffset: 0)
    }
    var written = max(0, start)
    do {
      for try await chunk in call.responseStream {
        try Task.checkCancellation()
        try handle.write(contentsOf: chunk.data)
        written += Int64(chunk.data.count)
        onProgress(written)
      }
    } catch {
      try? handle.close()
      throw DaemonFailure.classify(
        error, trailers: try? await call.trailingMetadata, operation: "download \(path)")
    }
  }

  // MARK: - Write

  /// Streams a local file into a space with `Put`.
  ///
  /// Returns what the daemon published, which the old client drained and threw
  /// away, so an upload could not report where it landed.
  @discardableResult
  func put(
    space: String,
    path: String,
    from source: URL,
    onProgress: @escaping @Sendable (Int64) -> Void
  ) async throws -> Synch_Control_V1_Written? {
    let call = try client(.long).makePutCall()
    let handle = try FileHandle(forReadingFrom: source)
    defer { try? handle.close() }
    do {
      try await call.requestStream.send(
        .with { $0.header = .with { $0.space = space; $0.path = path } })
      var sent: Int64 = 0
      while true {
        if Task.isCancelled {
          // An abandoned write must never be indistinguishable from a complete
          // one, so the daemon is told explicitly to keep nothing.
          try? await call.requestStream.send(.with { $0.abort = "cancelled by the user" })
          call.requestStream.finish()
          throw CancellationError()
        }
        let data = try handle.read(upToCount: Self.chunkSize) ?? Data()
        if data.isEmpty { break }
        try await call.requestStream.send(.with { $0.chunk = data })
        sent += Int64(data.count)
        onProgress(sent)
      }
      try await call.requestStream.send(.with { $0.commit = .init() })
      call.requestStream.finish()
      var written: Synch_Control_V1_Written?
      for try await response in call.responseStream { written = response }
      return written
    } catch is CancellationError {
      throw CancellationError()
    } catch {
      call.requestStream.finish()
      throw DaemonFailure.classify(
        error, trailers: try? await call.trailingMetadata, operation: "upload \(path)")
    }
  }

  func delete(space: String, path: String) async throws -> Synch_Control_V1_DeleteResponse {
    let call = try client(.standard).makeDeleteCall(
      .with { $0.space = space; $0.path = path })
    do {
      return try await call.response
    } catch {
      throw DaemonFailure.classify(
        error, trailers: try? await call.trailingMetadata, operation: "delete \(path)")
    }
  }

  // MARK: - Multipart

  /// Every remaining path under a prefix, with **no limit**.
  ///
  /// This is what settles a listing. `limit` bounds the distinct paths the
  /// daemon selects *before* it drops the ones every publisher has tombstoned,
  /// so a bounded page can come back empty while paths remain — and no row
  /// count, at any limit, can tell the two apart. An unbounded request has no
  /// window to be emptied, so a zero-row answer to this one means the listing
  /// really is finished.
  ///
  /// Reserved for that ambiguous case: it costs the daemon a `VersionSet` for
  /// every remaining path at once, which is what `synch ls` already does but
  /// not what a browser should do on every page.
  func listRemainder(
    space: String,
    prefix: String,
    policy: VersionPolicy,
    startAfter: String?
  ) async throws -> [Synch_Control_V1_Entry] {
    let request = Synch_Control_V1_ListRequest.with {
      $0.space = space
      $0.prefix = prefix.isEmpty || prefix.hasSuffix("/") ? prefix : prefix + "/"
      if let startAfter { $0.startAfter = startAfter }
      // No `limit` field at all — the daemon treats it as unbounded.
      $0.policy = policy.wire
    }
    let call = try client(.long).makeListCall(request)
    var entries: [Synch_Control_V1_Entry] = []
    do {
      for try await entry in call.responseStream {
        try Task.checkCancellation()
        entries.append(entry)
      }
    } catch {
      throw DaemonFailure.classify(
        error, trailers: try? await call.trailingMetadata, operation: "finish listing this folder")
    }
    return entries
  }

  private func uploadRef(id: String, space: String, path: String) -> Synch_Control_V1_UploadRef {
    .with {
      $0.uploadID = id
      $0.space = space
      $0.path = path
      $0.principal = Self.principal
    }
  }

  func openUploads(space: String, prefix: String = "") async throws
    -> [Synch_Control_V1_UploadInfo]
  {
    let call = try client(.fast).makeListUploadsCall(
      .with { $0.space = space; $0.prefix = prefix; $0.principal = Self.principal })
    var infos: [Synch_Control_V1_UploadInfo] = []
    do {
      for try await info in call.responseStream { infos.append(info) }
    } catch {
      throw DaemonFailure.classify(
        error, trailers: try? await call.trailingMetadata, operation: "list unfinished uploads")
    }
    return infos
  }

  /// Drops an upload and everything staged for it.
  ///
  /// Returns whether there was one. An id names exactly one key, and the daemon
  /// answers a request that quotes it against a different one as though the
  /// upload did not exist — so `false` is the signal that the space and path
  /// sent with it were not the ones it was opened against, and it is worth
  /// having rather than discarding.
  @discardableResult
  func abortUpload(id: String, space: String, path: String) async throws -> Bool {
    let call = try client(.fast).makeAbortUploadCall(
      .with { $0.upload = uploadRef(id: id, space: space, path: path) })
    do {
      return try await call.response.existed
    } catch {
      throw DaemonFailure.classify(
        error, trailers: try? await call.trailingMetadata, operation: "discard the upload")
    }
  }

  /// Uploads a large file through the multipart calls, resuming any part the
  /// daemon already recorded.
  ///
  /// The daemon holds this state across its own restarts, which is what makes
  /// an interrupted 40 GB transfer resumable rather than lost — the floating
  /// panel it replaces kept the queue in a window that could be closed.
  @discardableResult
  func multipartPut(
    space: String,
    path: String,
    from source: URL,
    totalBytes: Int64,
    resuming existing: String?,
    onOpen: @escaping @Sendable (String) -> Void,
    onProgress: @escaping @Sendable (Int64) -> Void
  ) async throws -> Synch_Control_V1_CompleteUploadResponse {
    let uploadID: String
    if let existing {
      uploadID = existing
    } else {
      let created = try await client(.standard).createUpload(
        .with { $0.space = space; $0.path = path; $0.principal = Self.principal })
      uploadID = created.uploadID
    }
    onOpen(uploadID)
    let ref = uploadRef(id: uploadID, space: space, path: path)

    // Parts the daemon already has survive an interrupted run and are not
    // re-sent.
    var recorded: [UInt32: Synch_Control_V1_PartInfo] = [:]
    if existing != nil {
      let call = try client(.fast).makeListPartsCall(.with { $0.upload = ref })
      for try await part in call.responseStream { recorded[part.number] = part }
    }

    let handle = try FileHandle(forReadingFrom: source)
    defer { try? handle.close() }

    var parts: [Synch_Control_V1_CompletionPart] = []
    var number: UInt32 = 1
    var offset: Int64 = 0
    var reported: Int64 = 0

    while offset < totalBytes {
      let length = min(Self.partSize, totalBytes - offset)
      if let done = recorded[number], Int64(done.size) == length {
        parts.append(.with { $0.number = done.number; $0.root = done.root })
        offset += length
        reported += length
        onProgress(reported)
        number += 1
        continue
      }
      try Task.checkCancellation()
      try handle.seek(toOffset: UInt64(offset))
      let response = try await sendPart(
        ref: ref, number: number, length: length, handle: handle,
        alreadySent: reported, onProgress: onProgress)
      parts.append(.with { $0.number = response.number; $0.root = response.root })
      offset += length
      reported = offset
      onProgress(reported)
      number += 1
    }

    let call = try client(.long).makeCompleteUploadCall(
      .with { $0.upload = ref; $0.parts = parts })
    do {
      return try await call.response
    } catch {
      throw DaemonFailure.classify(
        error, trailers: try? await call.trailingMetadata, operation: "finish uploading \(path)")
    }
  }

  private func sendPart(
    ref: Synch_Control_V1_UploadRef,
    number: UInt32,
    length: Int64,
    handle: FileHandle,
    alreadySent: Int64,
    onProgress: @escaping @Sendable (Int64) -> Void
  ) async throws -> Synch_Control_V1_UploadPartResponse {
    let call = try client(.long).makeUploadPartCall()
    do {
      try await call.requestStream.send(
        .with { $0.header = .with { $0.upload = ref; $0.number = number } })
      var remaining = length
      var sentHere: Int64 = 0
      while remaining > 0 {
        try Task.checkCancellation()
        let want = Int(min(Int64(Self.chunkSize), remaining))
        let data = try handle.read(upToCount: want) ?? Data()
        if data.isEmpty { break }
        try await call.requestStream.send(.with { $0.chunk = data })
        remaining -= Int64(data.count)
        sentHere += Int64(data.count)
        onProgress(alreadySent + sentHere)
      }
      try await call.requestStream.send(.with { $0.commit = .init() })
      call.requestStream.finish()
      var last: Synch_Control_V1_UploadPartResponse?
      for try await response in call.responseStream { last = response }
      guard let last else {
        throw DaemonFailure(code: .internalError, detail: "The daemon recorded no part \(number).")
      }
      return last
    } catch is CancellationError {
      try? await call.requestStream.send(.with { $0.abort = "cancelled" })
      call.requestStream.finish()
      throw CancellationError()
    } catch {
      call.requestStream.finish()
      throw DaemonFailure.classify(
        error, trailers: try? await call.trailingMetadata, operation: "upload part \(number)")
    }
  }

  // MARK: - Config (the s3.* namespace)

  func config(key: String) async throws -> [String] {
    let call = try client(.fast).makeGetConfigCall(.with { $0.key = key })
    do {
      return try await call.response.records
    } catch {
      throw DaemonFailure.classify(
        error, trailers: try? await call.trailingMetadata, operation: "read \(key)")
    }
  }

  func appendConfig(key: String, record: String) async throws {
    let call = try client(.fast).makeAppendConfigCall(
      .with { $0.key = key; $0.record = record })
    do {
      _ = try await call.response
    } catch {
      throw DaemonFailure.classify(
        error, trailers: try? await call.trailingMetadata, operation: "update \(key)")
    }
  }
}
