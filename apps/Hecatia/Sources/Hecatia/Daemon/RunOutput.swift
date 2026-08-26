import Foundation

/// One frame of a `Run` command's output, kept apart by kind.
///
/// `Frame.progress` is not noise: `scan` reports every skipped file on it and
/// `mirror ls` puts its empty-state there, so it is retained and rendered
/// rather than dropped the way the CLI drops it.
enum RunFrame: Sendable, Equatable {
  case line(String)
  case progress(String)
}

/// Everything one `Run` command said, in order.
///
/// The success signal is that the stream ended without a gRPC status — never
/// the text. That is what lets a command be surfaced correctly with no parsing
/// at all, which is how every command starts life in this app.
struct RunOutput: Sendable, Equatable {
  private(set) var frames: [RunFrame] = []
  /// The newest progress line, kept as frames arrive rather than searched for.
  ///
  /// The Activity window reads it once per row per body pass while a command
  /// is running, and it used to be `progress.last` — a whole new `[String]`
  /// built by walking every frame, to read one element of it. A long `scan`
  /// emits a frame per skipped file, so the cost grew with the run.
  private(set) var latestProgress: String?

  init(frames: [RunFrame] = []) {
    for frame in frames { append(frame) }
  }

  mutating func append(_ frame: RunFrame) {
    frames.append(frame)
    if case .progress(let text) = frame { latestProgress = text }
  }

  mutating func append(contentsOf newFrames: [RunFrame]) {
    for frame in newFrames { append(frame) }
  }

  var lines: [String] { frames.compactMap { if case .line(let l) = $0 { l } else { nil } } }
  var progress: [String] { frames.compactMap { if case .progress(let p) = $0 { p } else { nil } } }
  /// Everything, in the order the daemon said it, for a transcript.
  var transcript: [String] { frames.map { if case .line(let l) = $0 { l } else if case .progress(let p) = $0 { p } else { "" } } }

  var isEmpty: Bool { frames.isEmpty }
}
