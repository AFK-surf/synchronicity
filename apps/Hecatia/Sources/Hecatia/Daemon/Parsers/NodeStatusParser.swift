import Foundation

/// Reads `daemon status` and `id`.
///
/// This is the one thing the app polls forever, and which of four completely
/// different top-level screens renders depends on it, so it is also the one
/// parser whose failure mode matters most: it must never answer "healthy" for
/// a node that is not. Two defences. Every line it does not recognise is kept
/// in `unparsedLines` and shown, and the *naming* discriminator is the first
/// line's prefix, which the daemon writes unconditionally in both of its two
/// incompatible renderings.
enum NodeStatusReader {

  static func status(_ output: RunOutput) -> NodeStatus? {
    let lines = output.lines
    guard let first = lines.first else { return nil }

    // The reduced surface. A node the zone has not named yet serves only `id`,
    // `daemon status`, `domain *` and `daemon stop`; everything else answers
    // `unavailable`, so recognising this state is what stops the app throwing
    // an opaque error at a user whose node is merely waiting.
    if first.hasPrefix("waiting for "),
       let head = Anchor.before(" to name this node", in: first),
       let waiting = Anchor.after("waiting for ", in: head) {
      let txt = lines.first { $0.contains("IN TXT") }?.trimmingCharacters(in: .whitespaces) ?? ""
      let key = Anchor.after("nk=", in: txt)?.split(separator: " ").first.map(String.init) ?? ""
      return NodeStatus(
        naming: .waitingToBeNamed(domain: waiting, deviceKey: key, txtRecord: txt),
        unparsedLines: []
      )
    }

    guard let originLine = Anchor.after("origin ", in: first), first.hasPrefix("origin ") else {
      return nil
    }
    let originParts = originLine.components(separatedBy: " · signing as ")
    var status = NodeStatus(
      naming: .named(
        origin: originParts.first ?? originLine,
        signingAs: originParts.count > 1 ? originParts[1] : ""
      )
    )

    for line in lines.dropFirst() {
      if let address = Anchor.after("address: ", in: line) {
        status.address = address
      } else if line.hasPrefix("spaces: ") {
        status.spaceNames = spaceNames(in: line)
        status.sourceCount = Anchor.after("sources: ", in: line)
          .flatMap { Int($0.prefix(while: \.isNumber)) }
        status.replicaCount = Anchor.after("replicas: ", in: line).flatMap(Int.init)
      } else if line.hasPrefix("head: ") {
        status.headSeq = Anchor.after("head: seq ", in: line)
          .flatMap { UInt64($0.prefix(while: \.isNumber)) }
        status.peersSeen = Anchor.after("peers seen: ", in: line).flatMap(Int.init)
      } else if let trust = Anchor.after("trust: ", in: line) {
        status.trustSummary = trust
      } else if line.hasPrefix("CLOCK UNUSABLE") {
        status.alarms.append(.clockUnusable(line))
      } else if line.hasPrefix("CLOCK STEPPED BACK") {
        status.alarms.append(.clockSteppedBack(line))
      } else if line.hasPrefix("IN RECOVERY") {
        status.alarms.append(.inRecovery(line))
      } else if line.hasPrefix("(`synch doctor`") {
        continue  // a pointer at another command, not a fact about this node
      } else {
        status.unparsedLines.append(line)
      }
    }
    return status
  }

  /// `sources: {n} · replicas: {m}` — read from inside the
  /// parentheses, which bound the list even when an id contains a space.
  private static func spaceNames(in line: String) -> [String] {
    guard let open = line.firstIndex(of: "("), let close = line.lastIndex(of: ")"), open < close
    else { return [] }
    return line[line.index(after: open)..<close]
      .split(separator: ",")
      .map { $0.trimmingCharacters(in: .whitespaces) }
      .filter { !$0.isEmpty }
  }

  /// `id`'s own shape, which repeats the origin and adds the zone that named
  /// this node and every name it has adopted from one.
  struct Identity: Sendable, Equatable {
    var origin: String = ""
    var keys: [DeviceKey] = []
    var namedBy: String?
    var adoptions: [String] = []
    var address: String?
    var isUnnamed: Bool = false
  }

  static func identity(_ output: RunOutput) -> Identity {
    var identity = Identity()
    identity.keys = Listings.identityKeys(output.lines)
    for line in output.lines {
      if let origin = Anchor.after("origin: ", in: line) {
        identity.origin = origin
        identity.isUnnamed = origin.hasPrefix("none")
      } else if let named = Anchor.after("named by: ", in: line) {
        identity.namedBy = named
      } else if let waiting = Anchor.after("waiting on: ", in: line) {
        identity.namedBy = waiting
      } else if let address = Anchor.after("address: ", in: line) {
        identity.address = address
      } else if line.trimmingCharacters(in: .whitespaces).hasPrefix("adopted ") {
        identity.adoptions.append(line.trimmingCharacters(in: .whitespaces))
      }
    }
    return identity
  }
}
