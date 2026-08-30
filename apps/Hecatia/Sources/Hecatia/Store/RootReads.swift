import AppKit
import Foundation

/// Reading an object by its content root — `cat --root` and `get --root`.
///
/// The rest of the browser reads a `<space>/<path>` through `Control.Read`.
/// That request carries no root, so it can only ever answer with the version
/// the policy selects for a path that still exists. An object no current entry
/// names — which is most of what a `forever` replica holds — is unreachable
/// through it by construction.
///
/// Both `cat` and `get` take a root and stream the bytes back on the `Run`
/// stream as `Frame.chunk`, which is what
/// ``ControlClient/runCollectingChunks`` is for.
///
/// **Where this can be offered, and where it cannot.** The daemon renders a
/// root at full width in exactly one place: `pin ls`. `render::version_lines`
/// (behind `status`, and so behind the Versions inspector) and `render::log`
/// (behind History) both cut it to 16 hex characters, while `parse_root`
/// requires all 64 — so neither of those panels holds a name the daemon would
/// accept back. That is a daemon limitation and it is recorded as D6 in
/// docs/DAEMON-ISSUES.md; the app does not put a button in those two places
/// that could only ever fail. A divergent version *is* still readable, but
/// through the route that already existed — `Control.Read` with
/// `policy: origin=<id>` — because that names a current version of a path.
extension NodeStore {

  /// Whether a root is complete enough to ask the daemon about.
  ///
  /// Guarded rather than attempted: a truncated root comes back as "bad object
  /// root", which reads as though the object were missing rather than as the
  /// app having handed over half of a name.
  static func canReadByRoot(_ root: String) -> Bool { Anchor.isRoot(Substring(root)) }

  /// Fetches an object by root and hands back the file it landed in.
  ///
  /// Through the transfer queue like every other fetch, because an archived
  /// version is exactly as large as the file was: fetching one with no row, no
  /// progress and no cancel is how this window would stop answering.
  ///
  /// `destination == nil` means a temporary file, for Quick Look.
  @discardableResult
  func readByRoot(_ root: String, name: String, to destination: URL? = nil) async -> URL? {
    guard Self.canReadByRoot(root) else { return nil }
    // `cat` to look, `get` to keep — the daemon's own split, and the app keeps
    // it. Over the control socket the two stream identically, so this changes
    // nothing on the wire; what it does is keep the command the app sends the
    // same as the one it shows in the transcript and the same as the one a
    // person would type. A transcript that says `get` for a Quick Look is a
    // transcript that has stopped being a record of what happened.
    let transfer = Transfer(
      id: UUID(), direction: .download, name: name, space: "", path: name, total: 0)
    return await withCheckedContinuation { continuation in
      transfers.add(transfer, asked: destination != nil) { [weak self] id in
        let url = await self?.fetchRoot(id: id, root: root, name: name, destination: destination)
        // Before the resume and unconditionally: this closure must not be able
        // to run twice and resume the same continuation a second time.
        self?.transfers.retire(id)
        continuation.resume(returning: url)
      }
    }
  }

  private func fetchRoot(id: UUID, root: String, name: String, destination: URL?) async -> URL? {
    // `destination == nil` is a Quick Look, which is `cat`; a save is `get`.
    transfers.update(id) { $0.state = .running }
    let queue = transfers
    do {
      let (bytes, _) = try await client.runCollectingChunks(
        destination == nil ? Cmd.cat(root: root) : Cmd.get(root: root),
        operation: "read the object \(root.prefix(12))…",
        onProgress: { count in
          // The daemon does not say how large the object is before it starts
          // sending, so the total tracks the count rather than pretending to a
          // fraction of something unknown.
          Task { @MainActor in queue.update(id) { $0.bytes = count; $0.total = count } }
        })
      let landing = destination
        ?? FileManager.default.temporaryDirectory.appending(path: "\(root.prefix(12))-\(name)")
      try bytes.write(to: landing, options: .atomic)
      transfers.update(id) {
        $0.bytes = Int64(bytes.count)
        $0.total = Int64(bytes.count)
        $0.state = .completed(detail: destination == nil ? "Ready" : "Saved")
      }
      return landing
    } catch is CancellationError {
      transfers.update(id) { $0.state = .cancelled }
      return nil
    } catch {
      let failure = DaemonFailure.classify(error, operation: "read this object")
      transfers.update(id) { $0.state = .failed(failure.detail) }
      alert = failure
      return nil
    }
  }

  /// A save panel, then the bytes.
  func saveByRoot(_ root: String, name: String) {
    let panel = NSSavePanel()
    panel.nameFieldStringValue = name
    panel.prompt = "Save"
    guard panel.runModal() == .OK, let destination = panel.url else { return }
    Task { await readByRoot(root, name: name, to: destination) }
  }
}
