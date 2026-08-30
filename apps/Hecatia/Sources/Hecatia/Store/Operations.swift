import Foundation

/// Every operation the control service exposes: 14 typed rpcs and the 54
/// subcommands `Run` carries, all 68 accounted for.
///
/// `OperationsTests` asserts the count and that nothing is listed twice, so a
/// missing placement is a failing test rather than a review question.
///
/// The count is checked against `control.proto` itself by
/// `Scripts/audit-coverage.sh`, not against a number written here. A literal
/// count once let new daemon operations ship with no home because the array
/// and its comment agreed with each other instead of with the daemon.
///
/// What is deliberately **not** here: `init`, `daemon run`, `daemon start`,
/// `cas migrate` and `socket build`. All five are dispatched by the CLI before
/// it opens a control connection (`commands.rs`), so they have no oneof tag and
/// are not operations this app could invoke over the socket even in principle —
/// `socket build` most plainly of all, since it compiles a C file and needs no
/// node, no daemon and no data directory. `daemon start` is still the command
/// the app should be *naming* to a person who has no daemon running, which is
/// a copy problem, not a coverage one.
enum Operations {
  static let all: [Operation] = typed + run

  static let typed: [Operation] = [
    .init("rpc.listSpaces", "Spaces", "synch ls", surface: .files, provides: [.spaces]),
    .init("rpc.list", "Browse", "synch ls <space>", surface: .files, provides: [.listing]),
    .init("rpc.resolve", "Inspect", "synch status <space>/<path>", surface: .files),
    .init("rpc.read", "Download", "synch get <space>/<path>", surface: .files),
    .init("rpc.put", "Upload", "synch put", gate: .none, surface: .files, dirties: [.listing, .status]),
    .init("rpc.delete", "Delete", "synch rm <space>/<path>", gate: .confirm, surface: .files, dirties: [.listing, .status]),
    .init("rpc.getConfig", "Read gateway settings", "synch-s3 bucket ls", surface: .node, provides: [.s3]),
    .init("rpc.appendConfig", "Add a bucket or key", "synch-s3 bucket add", gate: .consequence, surface: .node, dirties: [.s3]),
    .init("rpc.createUpload", "Begin a large upload", "—", surface: .machinery, dirties: [.uploads]),
    .init("rpc.uploadPart", "Send a part", "—", surface: .machinery, dirties: [.uploads]),
    .init("rpc.completeUpload", "Finish a large upload", "—", surface: .machinery, dirties: [.uploads, .listing]),
    .init("rpc.abortUpload", "Cancel a large upload", "—", gate: .confirm, surface: .machinery, dirties: [.uploads]),
    // Reads, so they *provide* the slice rather than dirtying it.
    .init("rpc.listUploads", "Unfinished uploads", "—", surface: .machinery, provides: [.uploads]),
    .init("rpc.listParts", "Parts already sent", "—", surface: .machinery, provides: [.uploads]),
    // v3's socket bridge. Deliberately not `.machinery`: the multipart calls
    // earn that name because the app drives them, and this one the app does
    // not drive at all. The daemon owns the only iroh endpoint, so a client
    // that wants to talk to a program running on another node opens one of
    // these and the daemon bridges it to a QUIC stream. Listed so the registry
    // keeps counting the daemon rather than counting itself; see the `socket`
    // block in `run` for why none of the surface exists yet.
    .init("rpc.openSocket", "—", "synch socket connect <origin>:<space>/<path>", surface: .notSurfaced,
          omission: "A bidirectional byte pipe carrying somebody else's protocol; this app has no terminal, no listener and nothing to pipe it to."),
  ]

  static let run: [Operation] = [
    // Identity and lifecycle
    .init("id", "This Mac", "synch id", surface: .node, provides: [.status]),
    .init("daemon.status", "Overview", "synch daemon status", surface: .node, provides: [.status]),
    .init("daemon.stop", "Stop Background Service…", "synch daemon stop", gate: .typed, surface: .node, dirties: [.status]),
    // Device keys
    .init("key.ls", "Ask the Other Devices…", "synch key ls", surface: .node, provides: [.keys]),
    .init("key.rotate", "Replace This Mac’s Key…", "synch key rotate", gate: .consequence, surface: .node, dirties: [.keys, .status]),
    .init("key.activate", "Switch Signing to the New Key", "synch key activate <key>", gate: .consequence, surface: .node, dirties: [.keys, .status]),
    .init("key.retire", "Retire the Old Key…", "synch key retire <key>", gate: .typed, surface: .node, dirties: [.keys, .status]),
    // Members
    .init("trust.ls", "Devices", "synch trust ls", surface: .node, provides: [.members]),
    .init("trust.add", "Trust a Device…", "synch trust add <key>", gate: .consequence, surface: .node, dirties: [.members, .peers]),
    .init("trust.rm", "Stop Trusting…", "synch trust rm <origin>", gate: .typed, surface: .node, dirties: [.members, .peers]),
    .init("delegate.ls", "Granted access", "synch delegate ls", surface: .node, provides: [.members]),
    .init("delegate.add", "Grant Access…", "synch delegate add <key> --space <id>", gate: .consequence, surface: .node, dirties: [.members]),
    .init("delegate.rm", "Revoke Access…", "synch delegate rm <key>", gate: .confirm, surface: .node, dirties: [.members]),
    // Zone
    .init("domain.ls", "Membership zone", "synch domain ls", surface: .node, provides: [.domains]),
    .init("domain.set", "Use a Membership Zone…", "synch domain set <domain>", gate: .consequence, surface: .node, dirties: [.domains, .members, .status]),
    .init("domain.clear", "Stop Using the Zone…", "synch domain clear", gate: .typed, surface: .node, dirties: [.domains, .members, .status]),
    .init("domain.refresh", "Check Now", "synch domain refresh", surface: .node, dirties: [.domains, .members]),
    .init("peer.ls", "Network", "synch peer ls", surface: .node, provides: [.peers]),
    // Independent local roles. Namespace discovery itself uses ListSpaces.
    .init("source.ls", "—", "synch source ls [<id>]", surface: .notSurfaced,
          omission: "The typed ListSpaces call supplies the same role records without parsing text."),
    .init("source.add", "Publish a Source…", "synch source add <id> <path>", gate: .consequence, surface: .files, dirties: [.spaces, .status, .listing]),
    .init("source.rm", "Stop Publishing…", "synch source rm <id>", gate: .typed, surface: .node, dirties: [.spaces, .status, .listing]),
    .init("source.scan", "Scan Sources Now", "synch source scan [<id>]", surface: .files, dirties: [.listing, .status]),
    .init("replica.ls", "Replicas", "synch replica ls [<id>]", surface: .node, provides: [.spaces, .replication]),
    .init("replica.add", "Add a Replica…", "synch replica add <id>", gate: .consequence, surface: .node, dirties: [.spaces, .replication, .pins]),
    .init("replica.set", "Configure Replica…", "synch replica set <id>", gate: .consequence, surface: .node, dirties: [.spaces, .replication, .pins]),
    .init("replica.rm", "Remove Replica…", "synch replica rm <id>", gate: .confirm, surface: .node, dirties: [.spaces, .replication, .pins]),
    .init("replica.sync", "Sync Replica Now", "synch replica sync [<id>]", surface: .node, dirties: [.replication, .pins, .status]),
    // `.consequence` here is satisfied by the sheet, not by a
    // `ConfirmationRequest`, and that is deliberate rather than an omission —
    // written down because two audits have now read the gap as a missing
    // confirmation. ``AdoptTreeSheet`` cannot reach its Adopt button until a
    // `--dry-run` has come back and been drawn, and under `--dry-run` the
    // daemon decides everything and writes nothing, so that report *is* the
    // consequence, itemised, rather than a sentence predicting it. Overwriting
    // is a second opt-in on top: a toggle that defaults off, with the
    // unrecoverable part named in the danger colour beside it.
    .init("adopt.tree", "Adopt a Tree…", "synch adopt tree <space> --dry-run", gate: .consequence, surface: .files, dirties: [.listing, .status]),
    // Browsing, covered by typed rpcs
    .init("ls", "—", "synch ls", surface: .notSurfaced,
          omission: "Control.List answers the same thing with a schema; the text form would add a parser and no capability."),
    // `cat` and `get` are surfaced now, and only in their `--root` form.
    // The omission note that used to sit here claimed `Control.Read` was
    // equivalent. It is not: `ReadRequest` has no root field, so it can only
    // ever select a *current* version, and a superseded one — the thing you
    // want back after an unwanted adoption, and everything a `forever` replica holds —
    // was unreachable by any route.
    .init("cat", "Quick Look an Old Version", "synch cat --root <hex>", surface: .files),
    .init("get", "Download an Old Version…", "synch get --root <hex>", surface: .files),
    // Versions
    .init("status", "Versions", "synch status <space>/<path>", surface: .files),
    .init("adopt.path", "Use This Version", "synch adopt path <origin>:<space>/<path>", gate: .consequence, surface: .files, dirties: [.listing, .status]),
    .init("log", "History", "synch log <space>/<path>", surface: .files),
    .init("compare", "Compare With…", "synch compare <space> --to <origin> --json", surface: .files),
    // Explicit pins
    .init("pin.ls", "Kept offline", "synch pin ls", surface: .node, provides: [.pins]),
    .init("pin.add", "Keep Offline", "synch pin add <target>", gate: .consequence, surface: .files, dirties: [.pins]),
    .init("pin.rm", "Stop Keeping Offline", "synch pin rm <target>", gate: .confirm, surface: .files, dirties: [.pins]),
    // Upkeep
    .init("peer.sync", "Sync Now", "synch peer sync", surface: .ambient, // `.listing` too: peer sync pulls a peer's entries into this node's store, so
    // it changes what the browser is showing and used not to refresh it.
    dirties: [.peers, .status, .listing]),
    .init("recover", "Resume Publishing…", "synch recover", gate: .conditional, surface: .node, dirties: [.status]),
    .init("doctor", "Run Diagnostics", "synch doctor", surface: .node, dirties: []),
    .init("repair.rebuildViews", "Rebuild Derived Views", "synch repair rebuild-views", gate: .typed, surface: .node, dirties: [.status, .spaces, .listing]),
    // Remote access
    .init("control-plane.status", "Remote access", "synch control-plane status", surface: .node, provides: [.cloud]),
    .init("control-plane.enable", "Allow remote browsing", "synch control-plane enable", gate: .confirm, surface: .node, dirties: [.cloud]),
    .init("control-plane.disable", "Stop remote browsing", "synch control-plane disable", gate: .confirm, surface: .node, dirties: [.cloud]),
    // Sockets (oneof 47…55), none of them surfaced.
    //
    // v3 publishes a socket as an entry of its own kind, arms it against a
    // reviewed content root, and runs it for a peer that connects. That is a
    // whole surface — an object to review, an armed/disarmed state, a list of
    // running invocations, a log — and this app has not one piece of it. They
    // are listed anyway, because the registry is the count the daemon is
    // checked against: leaving an operation out is not neutrality. A new
    // operation once stayed invisible for three releases.
    // `surface: .notSurfaced` is the same admission `ls` makes at
    // the top of this section, and each row says what building it would take.
    //
    // None declares `dirties`. A row nothing can invoke has no table to
    // contradict, so a `dirties` list here would be a guess written as a fact;
    // `CoverageTests.everyMutationInvalidatesSomething` exempts `.notSurfaced`
    // for exactly that reason, and the exemption ends the moment one gets a
    // button.
    .init("socket.declare", "—", "synch socket declare <space>/<path>", surface: .notSurfaced,
          omission: "Publishes an eBPF object as a runnable entry; nothing in this app builds, inspects or reviews one."),
    .init("socket.arm", "—", "synch socket arm <space>/<path>", surface: .notSurfaced,
          omission: "Approves one review token to execute, which is a review decision — a button without the review it approves is the wrong half of the feature."),
    .init("socket.disarm", "—", "synch socket disarm <space>/<path>", surface: .notSurfaced,
          omission: "Stops a socket serving, and there is no armed state shown anywhere for a person to want stopped."),
    .init("socket.undeclare", "—", "synch socket undeclare <space>/<path>", surface: .notSurfaced,
          omission: "Withdraws the socket entry; the browser can name a socket row now but offers it only `rpc.delete`, which is a different question from retiring a published program."),
    .init("socket.ls", "—", "synch socket ls [<space>]", surface: .notSurfaced,
          omission: "The sockets of a space, with no pane to list them in and no Topic for them to fill."),
    .init("socket.sdk", "—", "synch socket sdk", surface: .notSurfaced,
          omission: "Prints the C header a socket program is compiled against, which belongs to a toolchain and not to a Mac app."),
    .init("socket.ps", "—", "synch socket ps [<space>/<path>]", surface: .notSurfaced,
          omission: "Invocations running on another node; Activity shows this app's own transfers and has no vocabulary for someone else's processes."),
    .init("socket.kill", "—", "synch socket kill <invocation>", surface: .notSurfaced,
          omission: "Ends one invocation named by an id only `socket ps` prints, and `socket ps` is not surfaced either."),
    .init("socket.log", "—", "synch socket log <space>/<path>", surface: .notSurfaced,
          omission: "The program's own output, with no log view to put it in."),
  ]

  static func find(_ id: String) -> Operation? { all.first { $0.id == id } }

  /// The operation with this id, or a stand-in built from it.
  ///
  /// Every call site used `find(…)!`, so a typo in a registry id was a crash
  /// in a button's action rather than a command with a plain title. The
  /// stand-in carries no `dirties`, so a mistake degrades one command instead
  /// of taking the app down. `CoverageTests` pins the registry's size and the
  /// uniqueness of its ids, but nothing checks the ids spelled at call sites —
  /// which is exactly why one being wrong should not be fatal. `NodeStore.op`
  /// and `FilesModel` already did this privately; this is the one copy.
  static func require(_ id: String) -> Operation { find(id) ?? Operation(id, id, id) }
}
