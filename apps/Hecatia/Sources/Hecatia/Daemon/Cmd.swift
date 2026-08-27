import Foundation

/// Builders for 44 of the 54 subcommands `Run` carries.
///
/// Fewer builders than subcommands, and the gap is exact rather than
/// accidental: `ls` and the nine `socket` commands are registered in
/// ``Operations`` and surfaced nowhere, so building one would be a call site
/// that does not exist — which `Scripts/audit-coverage.sh` reports as an
/// unreachable builder, not as coverage.
///
/// Kept together so the proto's oneof and the app's operation ids line up in
/// one readable place, and so a new command is one line here and one row in
/// ``Operations``.
enum Cmd {
  typealias Command = Synch_Control_V1_Command

  static func make(_ build: (inout Command) -> Void) -> Command {
    var command = Command()
    build(&command)
    return command
  }

  // Identity and lifecycle
  static var id: Command { make { $0.id = .init() } }
  static var daemonStatus: Command { make { $0.daemonStatus = .init() } }
  static var daemonStop: Command { make { $0.daemonStop = .init() } }

  // Device keys
  static var keyLs: Command { make { $0.keyLs = .init() } }
  static var keyRotate: Command { make { $0.keyRotate = .init() } }
  static func keyActivate(_ key: String, bind: String?) -> Command {
    make { $0.keyActivate = .with { $0.key = key; if let bind, !bind.isEmpty { $0.bind = bind } } }
  }
  static func keyRetire(_ key: String) -> Command {
    make { $0.keyRetire = .with { $0.key = key } }
  }

  // Members
  static var trustLs: Command { make { $0.trustLs = .init() } }
  /// No `asOrigin`. Field 6 named a member by hand; the daemon deleted it in
  /// #64, which split "belongs to a zone" from "is named by one" (DESIGN.md
  /// 3.2). A name now comes from a zone and only from a zone. The app went on
  /// setting the field for three releases — prost drops an unknown tag, so
  /// every Trust reported success and showed the raw key.
  static func trustAdd(key: String, note: String?, addr: String?) -> Command {
    make {
      $0.trustAdd = .with {
        $0.key = key
        if let note, !note.isEmpty { $0.note = note }
        if let addr, !addr.isEmpty { $0.addr = addr }
      }
    }
  }
  static func trustRm(origin: String, key: String?) -> Command {
    make {
      $0.trustRm = .with {
        $0.origin = origin
        if let key, !key.isEmpty { $0.key = key }
      }
    }
  }
  static var delegateLs: Command { make { $0.delegateLs = .init() } }
  static func delegateAdd(key: String, spaces: [String], until: String?, note: String?) -> Command {
    make {
      $0.delegateAdd = .with {
        $0.key = key
        $0.spaces = spaces
        if let until, !until.isEmpty { $0.until = until }
        if let note, !note.isEmpty { $0.note = note }
      }
    }
  }
  static func delegateRm(key: String) -> Command {
    make { $0.delegateRm = .with { $0.key = key } }
  }

  // Zone
  static var domainLs: Command { make { $0.domainLs = .init() } }
  /// `delegate` is not optional and it is not cosmetic.
  ///
  /// The daemon writes `set_membership_expects_name(!delegate)` unconditionally
  /// on every `domain set`, and a proto `bool` has no presence — so omitting it
  /// is indistinguishable from sending `false`, which tells the node to expect
  /// the zone to name it. On a delegate that is a demotion: the next start
  /// finds no record for its key, refuses an identity, and comes up on the
  /// reduced control socket with the app stuck at "Waiting to be named". The
  /// app shipped without this field, so pressing Change… on a delegate — even
  /// with the same zone typed back in — stranded it.
  static func domainSet(_ domain: String, delegate: Bool = false) -> Command {
    make { $0.domainSet = .with { $0.domain = domain; $0.delegate = delegate } }
  }
  static var domainClear: Command { make { $0.domainClear = .init() } }
  static var domainRefresh: Command { make { $0.domainRefresh = .init() } }
  static var peers: Command { make { $0.peers = .init() } }

  // Folders
  /// Every space, or one space's detailed replication report.
  ///
  /// The same call answers two very different things: with no id it is the
  /// three-column table, and with one it is the `held`/`releasing`/`wanted`/
  /// `unreachable` report. Two readers, one command — see ``Listings/spaces``
  /// and ``Listings/replicaStatus``.
  static func spaceLs(id: String? = nil) -> Command {
    make { $0.spaceLs = .with { if let id, !id.isEmpty { $0.id = id } } }
  }
  /// `path` is empty for a detached space, which is legal exactly when
  /// something else gives the space a reason to exist — the daemon requires
  /// `--detached` or `--replicate` in that case and refuses a bare empty path.
  static func spaceAdd(
    id: String, path: String, detached: Bool = false,
    replicate: ReplicaPolicy? = nil, grace: Int64? = nil, budget: UInt64? = nil
  ) -> Command {
    make {
      $0.spaceAdd = .with {
        $0.id = id
        $0.path = path
        $0.detached = detached
        if let replicate { $0.replicate = replicate.wire }
        if let grace { $0.grace = grace }
        if let budget { $0.budget = budget }
      }
    }
  }
  /// Changes one half of a space's configuration and leaves the other alone.
  ///
  /// The daemon rejects an empty set rather than treating it as a no-op, so a
  /// caller with nothing to change must not call — see
  /// ``NodeStore/setReplication(id:replicate:stop:release:grace:budget:)``,
  /// which guards on exactly that.
  static func spaceSet(
    id: String, replicate: ReplicaPolicy? = nil, noReplicate: Bool = false,
    release: Bool = false, grace: Int64? = nil, budget: UInt64? = nil
  ) -> Command {
    make {
      $0.spaceSet = .with {
        $0.id = id
        if let replicate { $0.replicate = replicate.wire }
        $0.noReplicate = noReplicate
        $0.release = release
        if let grace { $0.grace = grace }
        if let budget { $0.budget = budget }
      }
    }
  }
  /// Runs a reconciling replication sweep now, rather than at the daemon's next
  /// 300-second interval. Empty id sweeps every replicated space.
  static func spaceSync(id: String? = nil) -> Command {
    make { $0.spaceSync = .with { if let id, !id.isEmpty { $0.id = id } } }
  }
  /// `release` drops the pins this space's replication holds — potentially
  /// terabytes. The daemon defaults it to false on purpose: releasing that much
  /// should not follow from typing the opposite of `add`.
  static func spaceRm(id: String, release: Bool = false) -> Command {
    make { $0.spaceRm = .with { $0.id = id; $0.release = release } }
  }
  /// `[<origin>:]<space>[/<dir>]` — materialize the cluster's content into the
  /// space's own directory. Additive: it never removes, leaves matching bytes
  /// alone, and reports differing ones instead of overwriting unless forced.
  static func fill(
    reference: String, from: String? = nil, strict: Bool = false,
    force: Bool = false, dryRun: Bool = false
  ) -> Command {
    make {
      $0.fill = .with {
        $0.reference = reference
        if let from, !from.isEmpty { $0.from = from }
        $0.strict = strict
        $0.force = force
        $0.dryRun = dryRun
      }
    }
  }

  // Reading by content root
  //
  // `Control.Read` answers a `<space>/<path>` at whatever version the policy
  // selects, which is the current one. It has no root field, so a superseded
  // version — the one you want back after a bad `take`, and everything an
  // `archive` replica is holding — cannot be asked for through it at all.
  // These two can. Both stream the bytes back as `Frame.chunk`, so both need
  // `ControlClient.runCollectingChunks`.

  /// A byte range of an object named by its content root. Backs Quick Look.
  static func cat(root: String, range: String? = nil) -> Command {
    make {
      $0.cat = .with {
        $0.root = root
        if let range, !range.isEmpty { $0.range = range }
      }
    }
  }

  /// A whole object named by its content root. Backs Download.
  ///
  /// The CLI's `--output` is not on the wire: over the control socket this
  /// streams the bytes back like `cat` does, and where they land is the
  /// client's business.
  static func get(root: String) -> Command {
    make { $0.get = .with { $0.root = root } }
  }

  // Versions
  static func status(_ reference: String?) -> Command {
    make { $0.status = .with { if let reference { $0.reference = reference } } }
  }
  static func take(_ reference: String) -> Command {
    make { $0.take = .with { $0.reference = reference } }
  }
  static func log(_ reference: String) -> Command {
    make { $0.log = .with { $0.reference = reference } }
  }
  static func compare(reference: String, to: String, from: String?) -> Command {
    make {
      $0.compare = .with {
        $0.reference = reference
        $0.to = to
        if let from, !from.isEmpty { $0.from = from }
        // The only machine-readable output on the whole surface, so it is
        // always asked for and the text form is never rendered.
        $0.json = true
      }
    }
  }

  // Replication
  static var mirrorLs: Command { make { $0.mirrorLs = .init() } }
  static func mirrorAdd(space: String, path: String, policy: VersionPolicy?) -> Command {
    make {
      $0.mirrorAdd = .with {
        $0.space = space
        $0.path = path
        if let policy { $0.policy = policy.wire }
      }
    }
  }
  static func mirrorRm(path: String) -> Command {
    make { $0.mirrorRm = .with { $0.path = path } }
  }
  static var mirrorSync: Command { make { $0.mirrorSync = .init() } }
  static var pinLs: Command { make { $0.pinLs = .init() } }
  static func pinAdd(_ target: String) -> Command {
    make { $0.pinAdd = .with { $0.target = target } }
  }
  static func pinRm(_ target: String) -> Command {
    make { $0.pinRm = .with { $0.target = target } }
  }

  // Upkeep
  static var scan: Command { make { $0.scan = .init() } }
  static var syncNow: Command { make { $0.syncNow = .init() } }
  static func recover(wait: String?, gap: UInt64?) -> Command {
    make {
      $0.recover = .with {
        if let wait, !wait.isEmpty { $0.wait = wait }
        if let gap { $0.gap = gap }
      }
    }
  }
  static func doctor(rebuild: Bool) -> Command {
    make { $0.doctor = .with { $0.rebuild = rebuild } }
  }

  // Remote access
  static var cloudStatus: Command { make { $0.cloudStatus = .init() } }
  static var cloudEnable: Command { make { $0.cloudEnable = .init() } }
  static var cloudDisable: Command { make { $0.cloudDisable = .init() } }

  /// `[<origin>:]<space>/<path>` — the daemon's reference grammar. The origin
  /// goes before the first colon, and a colon after the first `/` is part of
  /// the path, so only an origin-qualified reference needs the prefix.
  static func reference(origin: String? = nil, space: String, path: String? = nil) -> String {
    var text = space
    if let path, !path.isEmpty { text += "/\(path)" }
    if let origin, !origin.isEmpty { text = "\(origin):\(text)" }
    return text
  }
}
