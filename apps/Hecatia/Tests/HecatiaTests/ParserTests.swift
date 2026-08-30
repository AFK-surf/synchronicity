import Testing
@testable import Hecatia

/// Golden fixtures for every line format the app reads.
///
/// The daemon's text carries no schema and no version signal — `CONTROL_VERSION`
/// is bumped only when a *call* is added, so a reworded line ships under the
/// same version. These fixtures are copied from the `format!` literals in
/// `crates/synch-cli/src/{control/server.rs,render.rs}` and are the only thing
/// standing between a reworded line and a silently wrong table.
///
/// Each case deliberately includes the shape that breaks a column-based parse:
/// an id that overruns its `{:<20}` padding, one that contains a space, a
/// `key:<52-char>` origin that is longer than its `{:<32}` field.
struct ParserTests {

  @Test func replicaStatusFromALiveDaemon() {
    let key = "key:ao6bbsx33qwbyets4qzmxzhumx8tmtnq9m93e55m1qejcdh3m11o"
    let status = Listings.replicaStatus([
      "probe-replica   indexed /private/tmp/hecatia-replica-check   current retention   grace 30d",
      "  held                  0 objects               0 B",
      "  view          complete — releases are running",
      "  claim   \(key) says it holds 0 objects (0 B, still fetching, tree, grace 30d)",
    ])
    #expect(status.isReplicating)
    #expect(status.held == 0)
    #expect(status.heldBytes == 0)
    #expect(status.pausedReason == nil)
    #expect(status.claims.count == 1)
    #expect(!status.isAlarming)
    #expect(status.unrecognized.isEmpty)
  }

  /// From a live daemon, with a budget set — the two-byte-count line.
  @Test func replicaStatusBudgetFromALiveDaemon() {
    let status = Listings.replicaStatus([
      "probe-replica   indexed /private/tmp/hecatia-replica-check   forever retention",
      "  held                  0 objects               0 B",
      "  budget        500000000 B, 0 B of it used",
      "  view          complete — releases are running",
    ])
    #expect(status.budgetBytes == 500_000_000)
    #expect(status.heldBytes == 0)
    #expect(!status.budgetReached)
    #expect(status.unrecognized.isEmpty)
  }

  @Test func replicaStatusFromALiveDaemonForAnUnreplicatedSpace() {
    let status = Listings.replicaStatus([
      "demo   indexed /private/tmp/synch-desktop-demo/Dropbox   not replicated"
    ])
    #expect(!status.isReplicating)
    #expect(status.unrecognized.isEmpty)
  }

  // MARK: - replica ls <id> · render::replica_status

  @Test func replicaStatusReadsItsLabelsNotItsColumns() {
    let status = Listings.replicaStatus([
      "media   indexed /srv/media   current retention   grace 7d",
      "  held               4096 objects       4096000 B",
      "  releasing            12 objects         91000 B   (soonest leaves in 3d)",
      "  wanted                2 objects          2400 B   (oldest 6m ago)",
      "  unreachable           1 objects           800 B   <- no provider has answered for these",
      "  held back             3 objects                     too few peers advertise these to let them go",
      "  budget        1000000 B, 4096000 B of it used",
      "  view          complete — releases are running",
      "  from nas@x.example                      3100000 B",
      "  claim   laptop@x.example says it holds 4108 objects (4098000 B, nothing outstanding, tree)",
    ])
    #expect(status.isReplicating)
    #expect(status.held == 4096)
    #expect(status.heldBytes == 4_096_000)
    #expect(status.releasing == 12)
    #expect(status.soonestRelease == "3d")
    // The daemon has already subtracted `unreachable` from this, and the app
    // must not add it back: they are not a backlog.
    #expect(status.wanted == 2)
    #expect(status.oldestWant == "6m ago")
    #expect(status.unreachable == 1)
    #expect(status.heldBack == 3)
    // The ceiling, not the amount used. The line carries two byte counts and
    // the first one is written `B,` with the comma attached, so a reader that
    // scans for a standalone `B` finds the second and reports the budget as
    // however much has been used — which renders as permanently full.
    #expect(status.budgetBytes == 1_000_000)
    #expect(!status.budgetReached)
    #expect(status.pausedReason == nil)
    #expect(status.byOrigin.first?.origin == "nas@x.example")
    #expect(status.byOrigin.first?.bytes == 3_100_000)
    #expect(status.claims.count == 1)
    #expect(status.isAlarming)  // one unreachable object
    #expect(status.unrecognized.isEmpty)
  }

  /// A nine-figure count overruns `{:>9}`, which is exactly the report someone
  /// is reading because something is wrong.
  @Test func replicaStatusSurvivesCountsThatOverrunTheirColumn() {
    let status = Listings.replicaStatus([
      "photos   indexed —   forever retention",
      "  held          412880123 objects  944892805120 B",
      "  view          incomplete, releases paused: 3 of 5 devices have not answered",
    ])
    #expect(status.held == 412_880_123)
    #expect(status.heldBytes == 944_892_805_120)
    #expect(status.pausedReason == "3 of 5 devices have not answered")
    #expect(status.isAlarming)
  }

  @Test func aSpaceThatDoesNotReplicateSaysSoRatherThanReadingAsEmpty() {
    let status = Listings.replicaStatus(["notes   indexed /Users/me/notes   not replicated"])
    #expect(!status.isReplicating)
    #expect(status.held == 0)
  }

  // MARK: - pin ls · "{root}  {size}  {holders}  {paths}"

  @Test func pinListSplitsHoldersFromPaths() {
    let root = String(repeating: "a1b2c3d4", count: 8)
    let result = Listings.pins([
      "\(root)  4096 B  operator  notes/journal.md",
      "\(root.dropLast() + "e")  512 B  replica:media (leaving in 3d)  (no current entry names it)",
    ])
    #expect(result.isClean)
    #expect(result.rows[0].isOperatorPinned)
    #expect(!result.rows[0].hasOtherHolders)
    #expect(result.rows[0].paths == "notes/journal.md")
    // A replica's claim: `pin rm` refuses it, so the app must not offer to.
    #expect(!result.rows[1].isOperatorPinned)
    #expect(result.rows[1].hasOtherHolders)
  }

  @Test func anObjectBothPinnedAndReplicatedIsBoth() {
    let root = String(repeating: "9f8e7d6c", count: 8)
    let result = Listings.pins(["\(root)  4096 B  operator, replica:media  archive/2019.tar"])
    #expect(result.rows[0].isOperatorPinned)
    #expect(result.rows[0].hasOtherHolders)
  }

  // MARK: - trust ls · "{:<32} {} {:<7} {}{}"

  @Test func trustListAnchorsOnTheDeviceKey() {
    let key = String(repeating: "y", count: 52)
    let result = Listings.trust([
      "nas@cluster.example.com          \(key) static  live  \"the NAS\""
    ])
    #expect(result.isClean)
    #expect(result.rows[0].key == key)
    #expect(result.rows[0].origin == "nas@cluster.example.com")
    #expect(result.rows[0].source == .staticTrust)
  }

  @Test func aKeyIdentifiedOriginOverrunsItsColumnAndStillParses() {
    // `key:<52 chars>` is 56 characters against a 32-wide field, so the row is
    // misaligned in the CLI's own output — the most common row shape there is.
    let origin = "key:" + String(repeating: "b", count: 52)
    let key = String(repeating: "n", count: 52)
    let result = Listings.trust(["\(origin) \(key) dns     live"])
    #expect(result.isClean)
    #expect(result.rows[0].origin == origin)
    #expect(result.rows[0].key == key)
    #expect(result.rows[0].source == .zone)
  }

  // MARK: - delegate ls · "{} {:<28} {:<10} ← {issuer}"

  @Test func delegationKeepsTheScopeUnsplit() {
    let key = String(repeating: "e", count: 52)
    let result = Listings.delegations(["\(key) photos,incoming             7d         ← this node"])
    #expect(result.isClean)
    let row = result.rows[0]
    #expect(row.key == key)
    // Never split on the comma: a folder id may contain one, and splitting
    // would invent scopes that do not exist on a security surface.
    #expect(row.scope == "photos,incoming")
    #expect(row.expiry == "7d")
    #expect(row.issuer == "this node")
    #expect(row.source == .granted)
  }

  @Test func delegationHandlesTheTwoWordExpiry() {
    let key = String(repeating: "j", count: 52)
    let result = Listings.delegations(["\(key) photos                      cut off    ← nas@x.example"])
    #expect(result.isClean)
    #expect(result.rows[0].expiry == "cut off")
    #expect(result.rows[0].scope == "photos")
  }

  @Test func delegationHandlesAScopeContainingASpace() {
    let key = String(repeating: "k", count: 52)
    let result = Listings.delegations(["\(key) family photos,work           never      ← this node"])
    #expect(result.isClean)
    #expect(result.rows[0].scope == "family photos,work")
    #expect(result.rows[0].expiry == "never")
  }

  @Test func noDelegationsIsNotARow() {
    let result = Listings.delegations(["no delegations"])
    #expect(result.rows.isEmpty)
    #expect(result.isClean)
  }

  // MARK: - pin ls · "{root}  {size}  {paths}"

  @Test func pinListRequiresA64CharacterRoot() {
    let root = String(repeating: "a1", count: 32)
    let result = Listings.pins(["\(root)  4218 B  notes/README.md"])
    #expect(result.isClean)
    #expect(result.rows[0].root == root)
    #expect(result.rows[0].detail == "4218 B  notes/README.md")

    let bad = Listings.pins(["deadbeef  4218 B  x"])
    #expect(bad.rows.isEmpty)
    #expect(bad.unrecognized.count == 1)
  }

  // MARK: - peers

  @Test func peerRowKeepsItsDurationsVerbatim() {
    let key = String(repeating: "r", count: 52)
    let result = Listings.peers(["\(key)  nas@x.example  last-seen 3m ago  last-sync 12s ago  rtt 812µs"])
    #expect(result.isClean)
    #expect(result.rows[0].key == key)
    // "3m ago" is the daemon's rendering of its own clock. It is shown, not
    // re-parsed into a Date the app would then be guessing at.
    #expect(result.rows[0].detail.contains("last-seen 3m ago"))
  }

  // MARK: - daemon status

  @Test func namedStatusReadsEveryField() {
    let output = RunOutput(frames: [
      .line("origin nas@cluster.example.com · signing as a1b2c3d4e5"),
      .line("address: ybndrfg8ej via 192.168.1.10:4433"),
      .line("spaces: 2 (media, notes) · sources: 1 · replicas: 1"),
      .line("head: seq 88 · peers seen: 3"),
      .line("trust: rekor require · doh https://1.1.1.1/dns-query"),
      .line("(`synch doctor` for the full examination)"),
    ])
    let status = NodeStatusReader.status(output)
    #expect(status?.origin == "nas@cluster.example.com")
    #expect(status?.spaceNames == ["media", "notes"])
    #expect(status?.sourceCount == 1)
    #expect(status?.replicaCount == 1)
    #expect(status?.headSeq == 88)
    #expect(status?.peersSeen == 3)
    #expect(status?.alarms.isEmpty == true)
    // The pointer at another command is not a fact about this node and is not
    // reported as an unread line.
    #expect(status?.unparsedLines.isEmpty == true)
  }

  @Test func alarmsAreRecognised() {
    let output = RunOutput(frames: [
      .line("origin nas@x.example · signing as aaaa"),
      .line("IN RECOVERY: a peer advertises seq 90 for nas@x.example; run `synch recover`"),
      .line("CLOCK STEPPED BACK: trust decisions are dated by the highest reading"),
    ])
    let status = NodeStatusReader.status(output)
    #expect(status?.alarms.count == 2)
    #expect(status?.needsRecovery == true)
  }

  @Test func aNodeWaitingToBeNamedIsItsOwnState() {
    // The reduced surface: only `id`, `daemon status`, `domain *` and
    // `daemon stop` are served here, so recognising it is what stops the app
    // throwing an opaque error at a user whose node is merely waiting.
    let key = String(repeating: "y", count: 52)
    let output = RunOutput(frames: [
      .line("waiting for cluster.example.com to name this node"),
      .line("  _synchronicity.cluster.example.com. IN TXT \"v=sync1 id=<name> nk=\(key) apex=<apex>\""),
      .line("or `synch domain set <domain>` to wait on another zone"),
    ])
    let status = NodeStatusReader.status(output)
    guard case .waitingToBeNamed(let domain, let deviceKey, _)? = status?.naming else {
      Issue.record("expected the waiting state")
      return
    }
    #expect(domain == "cluster.example.com")
    #expect(deviceKey == key)
    #expect(status?.isNamed == false)
  }

  @Test func anUnknownStatusLineIsKept() {
    let output = RunOutput(frames: [
      .line("origin nas@x.example · signing as aaaa"),
      .line("something the daemon added in a later release"),
    ])
    let status = NodeStatusReader.status(output)
    #expect(status?.unparsedLines == ["something the daemon added in a later release"])
  }

  // MARK: - versions

  @Test func strictRefusalIsReadLosslessly() {
    // `Resolve` under `strict` refuses a divergent path with the full version
    // list: canonical origins, untruncated roots, raw sizes and seqs. It is the
    // best structured source of versions the daemon has.
    let rootA = String(repeating: "a", count: 64)
    let rootB = String(repeating: "b", count: 64)
    let message = """
      notes/roadmap.pdf has 2 versions and the policy is strict:
        \(rootA) size 1482311 mtime 1768470060000000000 seq 88 asserted by nas@x.example
        \(rootB) size 1482990 mtime 1768470070000000000 seq 12 asserted by laptop@x.example, phone@x.example
      """
    let set = Versions.fromStrictRefusal(message, space: "notes", path: "roadmap.pdf")
    #expect(set?.versions.count == 2)
    #expect(set?.versions[0].identity == rootA)
    #expect(set?.versions[0].size == 1_482_311)
    #expect(set?.versions[0].seq == 88)
    #expect(set?.versions[1].attestors == ["laptop@x.example", "phone@x.example"])
    #expect(set?.isDivergent == true)
  }

  @Test func aSymlinkIdentityContainingSpacesStillParses() {
    let message = """
      notes/link has 1 versions and the policy is strict:
        -> /Volumes/Big Disk/target size 24 mtime 1 seq 3 asserted by nas@x.example
      """
    let set = Versions.fromStrictRefusal(message, space: "notes", path: "link")
    #expect(set?.versions[0].identity == "-> /Volumes/Big Disk/target")
    #expect(set?.versions[0].kind == .symlink)
  }

  @Test func statusVersionLinesGiveTheAttestors() {
    let lines = [
      "notes/roadmap.pdf  2 version(s)  ⑂2",
      "    a1b2c3d4e5f60718 file             1482311  seq 88     nas, laptop",
      "    (deleted)        deleted                0  seq 12     phone",
    ]
    let result = Versions.fromStatus(lines)
    #expect(result.isClean)
    let set = result.rows[0]
    #expect(set.space == "notes")
    #expect(set.path == "roadmap.pdf")
    #expect(set.versions.count == 2)
    #expect(set.versions[0].attestors == ["nas", "laptop"])
    #expect(set.versions[1].kind == .tombstone)
  }

  @Test func aSocketVersionLineIsReadRatherThanDiscarded() {
    // v3 added `socket` to the daemon's `kind_name`, and `Versions.kinds` is a
    // lookup inside a `guard` — an unmapped token does not produce a wrong
    // kind, it fails the whole line into `unrecognized`. So before the token
    // was added this row's attestors vanished from the inspector with nothing
    // said, which is why the assertion below is about `isClean` as much as
    // about the kind.
    let lines = [
      "tools/echo.o  1 version(s)",
      "    a1b2c3d4e5f60718 socket            4096  seq 7      nas, laptop",
    ]
    let result = Versions.fromStatus(lines)
    #expect(result.isClean)
    #expect(result.rows[0].versions[0].kind == .socket)
    #expect(result.rows[0].versions[0].attestors == ["nas", "laptop"])
  }

  @Test func attestorsAreMergedOntoTheLosslessVersions() {
    let root = String(repeating: "c", count: 64)
    let lossless = PathVersions(
      space: "notes", path: "a",
      versions: [EntryVersion(identity: root, kind: .file, size: 10, seq: 4, attestors: [])])
    let human = PathVersions(
      space: "notes", path: "a",
      versions: [EntryVersion(identity: "cccccccccccccccc", kind: .file, size: 10, seq: 4,
                              attestors: ["nas", "laptop"])])
    let merged = Versions.merge(lossless: lossless, attestorsFrom: human)
    // The full root survives; only the attestor list is taken from the lossy
    // rendering.
    #expect(merged.versions[0].identity == root)
    #expect(merged.versions[0].attestors == ["nas", "laptop"])
  }

  // MARK: - cloud status

  @Test func cloudStatusReadsTheProgressChannelToo() {
    let output = RunOutput(frames: [
      .line("cloud: enabled"),
      // The only status in this family whose empty state is a progress frame
      // rather than a line. Reading only `lines` loses it entirely.
      .progress("(no attach attempts yet)"),
    ])
    let state = Listings.cloud(output)
    #expect(state.enabled == true)
    #expect(state.notes == ["(no attach attempts yet)"])
  }

  @Test func cloudEndpointErrorIsSeparated() {
    let output = RunOutput(frames: [
      .line("cloud: enabled"),
      .line("cluster.example.com              detached   https://cp.example  last error: connection refused"),
    ])
    let state = Listings.cloud(output)
    #expect(state.domains[0].domain == "cluster.example.com")
    #expect(state.domains[0].lastError == "connection refused")
  }
}

/// The peer row's origin field, which the Compare sheet reads to offer devices.
///
/// `server.rs` builds it as `names.join(",")` and substitutes `(untrusted)`
/// when it holds no name for the key. The sheet used to union an empty
/// sequence here, so no peer ever reached its device list.
struct PeerOriginTests {

  @Test func aPeerRowCarriesItsOriginsCommaSeparated() {
    let key = String(repeating: "a", count: 52)
    let line = "\(key)  nas@cluster.example,laptop@cluster.example  last-seen 3m ago  last-sync 3m ago  rtt 812µs"
    let parsed = Listings.peers([line])
    #expect(parsed.unrecognized.isEmpty)
    #expect(parsed.rows.count == 1)
    #expect(parsed.rows[0].origins == "nas@cluster.example,laptop@cluster.example")
    let names = parsed.rows[0].origins.split(separator: ",").map(String.init)
    #expect(names == ["nas@cluster.example", "laptop@cluster.example"])
    #expect(names.allSatisfy(Versions.isActionable))
  }

  @Test func anUnnamedPeerIsNotADeviceName() {
    let key = String(repeating: "b", count: 52)
    let line = "\(key)  (untrusted)  last-seen just now  last-sync never  rtt 0µs"
    let parsed = Listings.peers([line])
    #expect(parsed.rows[0].origins == "(untrusted)")
    // The placeholder is not a name any command accepts, so it must never be
    // offered as one.
    #expect(!Versions.isActionable("(untrusted)"))
  }
}

/// The third value of `trust ls`'s source column.
///
/// `BindingSource::as_str` returns "static", "dns" *or* "delegated", and the
/// parser knew two of them — so every device that had been granted access to
/// some folders was also listed as an unrestricted zone member.
@Suite("trust ls sources")
struct TrustSourceTests {
  private let key = String(repeating: "y", count: 52)

  @Test("A delegated binding is a grant, not a zone membership")
  func delegated() {
    let result = Listings.trust(["laptop@zone \(key) delegated live"])
    #expect(result.rows.count == 1)
    #expect(result.rows[0].source == .granted)
    #expect(result.unrecognized.isEmpty)
  }

  @Test("The three the daemon writes are the three that parse")
  func allThree() {
    for (text, expected) in [
      ("static", Member.Source.staticTrust), ("dns", .zone), ("delegated", .granted),
    ] {
      let result = Listings.trust(["a@b \(key) \(text) live"])
      #expect(result.rows.first?.source == expected)
    }
  }

  /// A fourth value must reach the parser-drift channel rather than be called
  /// something it is not — the daemon's text carries no version signal.
  @Test("An unknown source is reported, not guessed at")
  func unknown() {
    let result = Listings.trust(["a@b \(key) quantum live"])
    #expect(result.rows.isEmpty)
    #expect(result.unrecognized.count == 1)
  }
}

/// The column two listings share.
@Suite("Member state")
struct MemberStateTests {
  private func member(_ expiry: String?) -> Member {
    Member(
      key: String(repeating: "z", count: 52), origin: "a@b", source: .staticTrust,
      scope: nil, expiry: expiry, issuer: nil, note: nil)
  }

  @Test("Every word for gone counts as gone")
  func dead() {
    #expect(member("expired").isDead)
    #expect(member("cut off").isDead)
    // `trust ls`'s own word, which used to render as a healthy binding.
    #expect(member("lapsed").isDead)
  }

  @Test("A live or unexpired binding is not")
  func alive() {
    #expect(!member("live").isDead)
    #expect(!member("7d").isDead)
    #expect(!member(nil).isDead)
  }
}

/// The number in front of a unit.
@Suite("Trailing counts")
struct TrailingIntTests {
  /// `render.rs:162` writes `"{}  {} binding(s)"`, and reading backwards from
  /// the unit hit the separating space and gave up — so the zone's device
  /// count was parsed on every refresh and was always nil.
  @Test("A separator between the number and the unit is stepped over")
  func spaced() {
    #expect(Anchor.trailingInt(in: "cluster.example.com  3 binding(s)", unit: "binding(s)") == 3)
    #expect(Anchor.trailingInt(in: "12 binding(s)", unit: "binding(s)") == 12)
  }

  @Test("No number is nil, not zero")
  func absent() {
    #expect(Anchor.trailingInt(in: "some binding(s)", unit: "binding(s)") == nil)
    #expect(Anchor.trailingInt(in: "nothing here", unit: "binding(s)") == nil)
  }
}
