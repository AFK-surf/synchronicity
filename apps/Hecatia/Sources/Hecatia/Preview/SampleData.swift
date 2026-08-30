#if DEBUG
import Foundation

/// Fixed data for SwiftUI previews.
///
/// Dates are absolute so a preview never renders differently over time, and
/// the paths are exactly what the daemon publishes — leaves only, with the
/// folder rows left to ``LevelBuilder`` in previews as in the app.
enum SampleData {
  static let spaces: [Space] = [
    Space(id: "notes", localPath: "/Users/me/Documents/notes"),
    Space(id: "family photos", localPath: "/Volumes/Big/Family Photos"),
    Space(
      id: "archive", localPath: "/Users/me/Archive",
      replicationSummary: "current retention · grace 7d · 4096 B held · 2 wanted",
      replicate: .current),
    // A dedicated replica: no local checkout at all. The row every preview
    // was missing, and the row the old parser dropped on the floor.
    Space(
      id: "media", localPath: nil,
      replicationSummary: "forever retention · 880 GiB held", replicate: .forever),
  ]

  static let replicaStatus: [String: ReplicaStatus] = [
    "archive": ReplicaStatus(
      held: 4096, heldBytes: 4_096_000_000, releasing: 12, releasingBytes: 91_000_000,
      wanted: 2, wantedBytes: 2_400_000, unreachable: 1, unreachableBytes: 800_000,
      soonestRelease: "3d", oldestWant: "6m ago",
      byOrigin: [
        .init(origin: "nas@x.example", bytes: 3_100_000_000),
        .init(origin: "laptop@x.example", bytes: 996_000_000),
      ],
      claims: ["nas@x.example says it holds 4108 objects (4098000000 B, nothing outstanding, tree, grace 7d)"]),
    "media": ReplicaStatus(
      held: 412_880, heldBytes: 944_892_805_120, budgetBytes: 1_000_000_000_000,
      pausedReason: "3 of 5 devices have not answered since yesterday"),
  ]

  static func day(_ offset: Int) -> Date {
    Date(timeIntervalSince1970: 1_768_470_060 + Double(offset) * 86_400)
  }

  static func entry(
    space: String = "notes", path: String, kind: RemoteEntry.Kind = .file,
    size: UInt64 = 0, modified: Date = day(0), versions: UInt32 = 1,
    origin: String = "laptop@x.example"
  ) -> RemoteEntry {
    RemoteEntry(
      origin: origin, space: space, path: path, kind: kind, size: size,
      modified: modified, versions: versions,
      contentRoot: Data(repeating: 0xa1, count: 32))
  }

  static let readme = entry(path: "README.md", size: 4_218, modified: day(-1))
  static let conflicted = entry(path: "roadmap.pdf", size: 1_482_311, modified: day(-2), versions: 3)
  static let folder = RemoteEntry(
    origin: "", space: "notes", path: "journal", kind: .directory,
    size: 0, modified: .distantPast, versions: 1, isSynthesizedDirectory: true)

  static let published: [RemoteEntry] = [
    readme,
    conflicted,
    entry(path: "screenshot.png", size: 812_004, modified: day(-6)),
    entry(path: "journal/2026-01-14.md", size: 1_902, modified: day(-1)),
    entry(path: "journal/2026-01-15.md", size: 2_344, modified: day(0)),
    entry(path: "receipts/2026/january.pdf", size: 220_418, modified: day(-3)),
  ]

  static var rows: [RemoteEntry] {
    var builder = LevelBuilder(space: "notes", prefix: "")
    for entry in published { builder.add(entry) }
    return builder.rows()
  }

  static let versions = PathVersions(
    space: "notes", path: "roadmap.pdf",
    versions: [
      EntryVersion(
        identity: String(repeating: "a1", count: 32), kind: .file, size: 1_482_311, seq: 88,
        attestors: ["nas@x.example"]),
      EntryVersion(
        identity: String(repeating: "b2", count: 32), kind: .file, size: 1_482_990, seq: 12,
        attestors: ["laptop@x.example", "phone@x.example"]),
    ])

  static let unanimous = PathVersions(
    space: "notes", path: "README.md",
    versions: [
      EntryVersion(
        identity: String(repeating: "c3", count: 32), kind: .file, size: 4_218, seq: 44,
        attestors: ["this Mac", "nas@x.example", "laptop@x.example"])
    ])

  static let members: [Member] = [
    Member(key: String(repeating: "y", count: 52), origin: "nas@x.example",
           source: .staticTrust, scope: nil, expiry: nil, issuer: nil, note: "the NAS"),
    Member(key: String(repeating: "b", count: 52), origin: "laptop@x.example",
           source: .zone, scope: nil, expiry: nil, issuer: nil, note: nil),
    Member(key: String(repeating: "e", count: 52), origin: nil,
           source: .granted, scope: "family photos,incoming", expiry: "7d",
           issuer: "this node", note: nil),
  ]

  static let transfers: [Transfer] = [
    {
      var t = Transfer(id: UUID(), direction: .upload, name: "holiday.mov",
                       space: "archive", path: "holiday.mov", total: 4_200_000_000)
      t.bytes = 1_800_000_000
      t.state = .running
      t.uploadID = "ab12"
      return t
    }(),
    {
      var t = Transfer(id: UUID(), direction: .download, name: "roadmap.pdf",
                       space: "notes", path: "roadmap.pdf", total: 1_482_311)
      t.bytes = 1_482_311
      t.state = .completed(detail: "Saved")
      return t
    }(),
    {
      var t = Transfer(id: UUID(), direction: .upload, name: "notes.zip",
                       space: "notes", path: "notes.zip", total: 24_000)
      t.state = .failed("no space `notes`: not a local space")
      return t
    }(),
  ]

  static let status = NodeStatus(
    naming: .named(origin: "laptop@cluster.example.com", signingAs: "a1b2c3d4e5"),
    address: "ybndrfg8ejkmcpqxot via 192.168.1.10:4433",
    spaceNames: ["notes", "family photos", "archive"],
    sourceCount: 2,
    replicaCount: 1,
    headSeq: 88,
    peersSeen: 3,
    trustSummary: "rekor require · doh https://1.1.1.1/dns-query · anchor icann-root")

  // MARK: - The slices a pane reads

  /// An age the daemon could have written, with the interval it implies.
  ///
  /// Built here rather than through ``Anchor/age(_:)`` so a fixture never
  /// depends on the parser it is used to look at.
  private static func age(_ seconds: TimeInterval, _ text: String) -> Age {
    Age(lower: seconds, upper: seconds * 2, isNever: false, text: text)
  }

  private static let never = Age(lower: 0, upper: nil, isNever: true, text: "never")

  static let peers: [PeerInfo] = [
    PeerInfo(
      key: String(repeating: "y", count: 52), origins: "nas@x.example",
      detail: "seen 2m ago, synced 2m ago, 192.168.1.11:4433",
      lastSeen: age(120, "2m ago"), lastSync: age(120, "2m ago")),
    // Stale, deliberately: over an hour trips `isStale`, and how a row wears
    // that is the thing this pane exists to show.
    PeerInfo(
      key: String(repeating: "b", count: 52), origins: "laptop@x.example,phone@x.example",
      detail: "seen 3h ago, synced 3h ago, 100.71.4.9:4433",
      lastSeen: age(10_800, "3h ago"), lastSync: age(10_800, "3h ago")),
    PeerInfo(
      key: String(repeating: "q", count: 52), origins: "(untrusted)",
      detail: "seen just now, never synced",
      lastSeen: age(0, "just now"), lastSync: never),
  ]

  static let domains: [DomainHealth] = [
    DomainHealth(
      domain: "cluster.example.com", bindingCount: 3,
      detail: "refreshed 4m ago, next in 56m", lastError: nil),
    DomainHealth(
      domain: "old.example.net", bindingCount: nil,
      detail: "refreshed never", lastError: "NXDOMAIN for _synchronicity.old.example.net"),
  ]

  /// Operator pins, which is all "Kept offline" ever shows. The replica rows
  /// `pin ls` also returns are filtered out in ``NodeStore`` before they reach
  /// a view, so a preview that carried them would be showing something the app
  /// cannot show.
  static let pins: [PinEntry] = [
    PinEntry(
      root: String(repeating: "a1b2c3d4", count: 8), size: "18874368 B",
      holders: "operator", paths: "notes/journal/2026-01.md"),
    PinEntry(
      root: String(repeating: "9f8e7d6c", count: 8), size: "4404019200 B",
      holders: "operator, replica:archive (leaving in 3d)", paths: "archive/2019.tar"),
  ]

  static let buckets: [GatewayBucket] = [
    GatewayBucket(name: "notes", space: "notes", access: .readWrite, policy: .newest),
    GatewayBucket(name: "photos-readonly", space: "family photos", access: .readOnly, policy: .origin("nas@x.example")),
  ]

  static let keyIDs = ["AKIAPREVIEW00000001", "AKIAPREVIEW00000002"]

  static let cloud = CloudState(
    enabled: true,
    domains: [
      CloudState.DomainAttach(
        domain: "cluster.example.com", detail: "attached via edge-1, 12ms", lastError: nil),
      CloudState.DomainAttach(
        domain: "cluster.example.com", detail: "edge-2", lastError: "connection refused"),
    ],
    notes: ["The gateway serves 2 buckets from 1 folder."])

  static let keyReport = [
    "active key held by 3 of 3 reachable peer(s)",
    "staged key held by 1 of 3 reachable peer(s) — nas@x.example has it, laptop@x.example does not",
  ]

  static let doctorReport = [
    "store: 88 heads, no gaps",
    "clock: within 40ms of 3 peers",
    "WARNING: 1 folder has been unreachable since 2026-01-14",
  ]

  static let activity: [ActivityRun] = [
    {
      var run = ActivityRun(
        id: UUID(uuidString: "00000000-0000-0000-0000-00000000a001")!,
        title: "Sync replicas", commandLine: "synch replica sync",
        startedAt: day(0))
      run.output = RunOutput(frames: [
        .line("notes -> /Users/me/Checkouts/notes: 3 written, 1 unchanged"),
        .progress("family photos: up to date"),
      ])
      run.finishedAt = day(0).addingTimeInterval(4.2)
      run.outcome = .succeeded
      return run
    }(),
    {
      var run = ActivityRun(
        id: UUID(uuidString: "00000000-0000-0000-0000-00000000a002")!,
        title: "Share folder “archive”", commandLine: "synch source add archive /Users/me/Archive",
        startedAt: day(0).addingTimeInterval(-90))
      run.output = RunOutput(frames: [.progress("scanning /Users/me/Archive… 4,118 files")])
      return run
    }(),
    {
      var run = ActivityRun(
        id: UUID(uuidString: "00000000-0000-0000-0000-00000000a003")!,
        title: "Upload notes.zip", commandLine: "synch put notes notes.zip",
        startedAt: day(-1))
      run.output = RunOutput(frames: [.line("no space `notes`: not a local space")])
      run.finishedAt = day(-1).addingTimeInterval(0.3)
      run.outcome = .failed(
        DaemonFailure(code: .notFound, detail: "no space `notes`: not a local space"))
      return run
    }(),
  ]

  static let resumable: [ResumableUpload] = [
    {
      var info = Synch_Control_V1_UploadInfo()
      info.uploadID = "ab12cd34"
      info.path = "holiday.mov"
      info.createdNs = Int64(day(-1).timeIntervalSince1970) * 1_000_000_000
      return ResumableUpload(space: "archive", info: info)
    }()
  ]

  /// The same node, shouting. Both alarms at once, because the two are drawn
  /// in different places and each has hidden the other before.
  static let alarmedStatus: NodeStatus = {
    var alarmed = status
    alarmed.alarms = [
      .inRecovery("A PEER ADVERTISES A NEWER PUBLISHED POSITION FOR THIS NODE THAN IT HOLDS."),
      .clockSteppedBack("THE CLOCK STEPPED BACK 4s SINCE THE LAST PUBLISH."),
    ]
    return alarmed
  }()
}
#endif
