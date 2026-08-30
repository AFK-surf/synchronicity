import Foundation

/// The `s3.*` config values, which are append-only record logs rather than
/// lists.
///
/// `AppendConfig` is the only writer the daemon offers — deliberately, so two
/// gateway processes editing at once cannot lose each other's work — so the
/// stored value keeps every record ever written. What the gateway *serves* is
/// the fold of that log: the last record naming a bucket or a key wins, and a
/// record carrying only the name is a removal. Rendering the raw log instead
/// shows removed buckets as live and every superseded mapping as a duplicate
/// row, which is what this app used to do.
///
/// The two folds below are `synch-s3`'s `buckets::fold` and `auth::fold`,
/// including where they differ. A bucket record whose policy does not parse is
/// skipped *without* disturbing the mapping it would have replaced; a key
/// record's second field being absent is itself the removal.
enum GatewayConfig {
  /// The config key holding the bucket map.
  static let bucketsKey = "s3.buckets"
  /// The config key holding the static access keys.
  static let keysKey = "s3.keys"

  /// The bucket map the gateway reads out of the log.
  static func buckets(_ records: [String]) -> [GatewayBucket] {
    var out: [GatewayBucket] = []
    for record in records {
      let fields = record.components(separatedBy: "\t")
      guard let name = fields.first, !name.isEmpty else { continue }
      let mapping: GatewayBucket?
      switch fields.count {
      case 1:
        // One field alone is a removal.
        mapping = nil
      case 4...:
        // The gateway trims before parsing, so a stored `newest ` is a policy
        // there and must be one here too.
        guard let access = GatewayBucket.Access(rawValue: fields[2]),
              let policy = VersionPolicy(wire: fields[3].trimmingCharacters(in: .whitespaces))
        else { continue }
        mapping = GatewayBucket(name: name, space: fields[1], access: access, policy: policy)
      default:
        // Two fields is neither an add nor a removal, and is skipped whole.
        continue
      }
      out.removeAll { $0.name == name }
      if let mapping { out.append(mapping) }
    }
    return out.sorted { $0.name < $1.name }
  }

  /// The access key ids the gateway will accept.
  ///
  /// The secrets are dropped here rather than at the view, so there is no
  /// layer of this app holding one where it could be rendered by accident.
  /// `auth::fold` leaves them in log order; they are sorted here because the
  /// gateway dedupes by id and the order carries nothing, while a list that
  /// reorders itself after every edit costs the reader their place.
  static func accessKeyIDs(_ records: [String]) -> [String] {
    var out: [String] = []
    for record in records {
      let fields = record.components(separatedBy: "\t")
      guard let id = fields.first, !id.isEmpty else { continue }
      out.removeAll { $0 == id }
      if fields.count >= 2 { out.append(id) }
    }
    return out.sorted()
  }

  // MARK: - The records that change them

  static func bucketRecord(
    name: String, space: String, access: GatewayBucket.Access, policy: VersionPolicy
  ) -> String {
    "\(name)\t\(space)\t\(access.rawValue)\t\(policy.wire)"
  }

  static func bucketRemoval(_ name: String) -> String { name }

  static func keyRecord(id: String, secret: String) -> String { "\(id)\t\(secret)" }

  static func keyRemoval(_ id: String) -> String { id }

  // MARK: - What the gateway will accept

  /// `synch-s3`'s `validate_name`.
  ///
  /// The daemon stores whatever it is handed, so a name the gateway refuses is
  /// accepted by `AppendConfig` and then silently skipped when the gateway
  /// folds the log — a bucket that exists in the config and serves nothing.
  /// Checking here is what turns that into a message.
  static func isValidBucketName(_ name: String) -> Bool {
    let bytes = Array(name.utf8)
    guard (3...63).contains(bytes.count) else { return false }
    let allowed = bytes.allSatisfy { byte in
      (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte)
        || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
        || byte == UInt8(ascii: "-") || byte == UInt8(ascii: ".")
    }
    guard allowed else { return false }
    let edges: Set<UInt8> = [UInt8(ascii: "-"), UInt8(ascii: ".")]
    return !edges.contains(bytes[0]) && !edges.contains(bytes[bytes.count - 1])
  }

  /// Why the bucket name is not one, in the words the gateway would use.
  static func bucketNameProblem(_ name: String) -> String? {
    if name.isEmpty { return nil }
    return isValidBucketName(name)
      ? nil
      : "3–63 characters of a–z, 0–9, dot or dash, not starting or ending with a dot or dash."
  }

  /// A tab would split one field into two and turn an add into something else,
  /// so it is the one character no field may carry.
  static func containsSeparator(_ text: String) -> Bool { text.contains("\t") }
}
