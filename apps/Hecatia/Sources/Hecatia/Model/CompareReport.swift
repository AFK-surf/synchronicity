import Foundation

/// `synch compare --json`, decoded.
///
/// The only machine-readable output on the whole control surface, so it is
/// always asked for with `json: true` and the text form is never rendered.
struct CompareReport: Decodable, Sendable, Equatable {
  struct Change: Decodable, Sendable, Equatable, Identifiable {
    enum Status: String, Decodable, Sendable {
      case created, modified, deleted
    }
    let status: Status
    let path: String
    var id: String { "\(status.rawValue)/\(path)" }
  }

  let space: String
  let from: String
  let to: String
  let changes: [Change]

  var created: [Change] { changes.filter { $0.status == .created } }
  var modified: [Change] { changes.filter { $0.status == .modified } }
  var deleted: [Change] { changes.filter { $0.status == .deleted } }

  /// Read from the single line `compare --json` emits.
  static func decode(_ lines: [String]) -> CompareReport? {
    for line in lines.reversed() {
      guard let data = line.data(using: .utf8),
            let report = try? JSONDecoder().decode(CompareReport.self, from: data)
      else { continue }
      return report
    }
    return nil
  }
}
