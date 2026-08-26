import Foundation

/// Every operation the control service exposes: 14 typed rpcs and the 54
/// subcommands `Run` carries, all 68 accounted for.
///
/// `OperationsTests` asserts the count and that nothing is listed twice, so a
/// missing placement is a failing test rather than a review question.
///
/// The count is checked against `control.proto` itself by
/// `Scripts/audit-coverage.sh`, not against a number written here. It used to
/// be a literal, and it said 55 for three daemon releases while `space set`,
/// `space sync` and `fill` had no home — the test that existed to catch exactly
/// that counted this array against a number in a comment, so the two agreed
/// with each other and neither agreed with the daemon.
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
    .init("rpc.openSocket", "—", "synch connect <origin>:<space>/<path>", surface: .notSurfaced,
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
    .init("peers", "Network", "synch peers", surface: .node, provides: [.peers]),
    // Spaces
    // Provides two slices because it answers two questions: bare, it is the
    // space table; with an id, it is that space's replication report. One
    // oneof tag, so one row here — a second row would put the registry three
    // ahead of the daemon in the same way it was three behind.
    .init("space.ls", "Spaces", "synch space ls [<id>]", surface: .files, provides: [.spaces, .replication]),
    .init("space.add", "Add a Space…", "synch space add <id> <path>", gate: .consequence, surface: .files, dirties: [.spaces, .status, .listing]),
    .init("space.rm", "Stop Sharing a Space…", "synch space rm <id>", gate: .typed, surface: .node, dirties: [.spaces, .status, .listing, .pins, .replication]),
    // Replicating a space — the daemon put this on the command that already
    // names spaces rather than inventing a noun, and so does the app: it is a
    // property of a space, shown where the space is.
    .init("space.set", "Replicate This Space…", "synch space set <id> --replicate", gate: .consequence, surface: .node, dirties: [.spaces, .replication, .pins]),
    .init("space.sync", "Replicate Now", "synch space sync <id>", surface: .node, dirties: [.replication, .pins, .status]),
    // `.consequence` here is satisfied by the sheet, not by a
    // `ConfirmationRequest`, and that is deliberate rather than an omission —
    // written down because two audits have now read the gap as a missing
    // confirmation. ``FillSheet`` cannot reach its Fill button until a
    // `--dry-run` has come back and been drawn, and under `--dry-run` the
    // daemon decides everything and writes nothing, so that report *is* the
    // consequence, itemised, rather than a sentence predicting it. Overwriting
    // is a second opt-in on top: a toggle that defaults off, with the
    // unrecoverable part named in the danger colour beside it.
    .init("fill", "Fill From the Cluster…", "synch fill <space> --dry-run", gate: .consequence, surface: .files, dirties: [.listing, .status]),
    // Browsing, covered by typed rpcs
    .init("ls", "—", "synch ls", surface: .notSurfaced,
          omission: "Control.List answers the same thing with a schema; the text form would add a parser and no capability."),
    // `cat` and `get` are surfaced now, and only in their `--root` form.
    // The omission note that used to sit here claimed `Control.Read` was
    // equivalent. It is not: `ReadRequest` has no root field, so it can only
    // ever select a *current* version, and a superseded one — the thing you
    // want back after a bad `take`, and everything an `archive` replica holds —
    // was unreachable by any route.
    .init("cat", "Quick Look an Old Version", "synch cat --root <hex>", surface: .files),
    .init("get", "Download an Old Version…", "synch get --root <hex>", surface: .files),
    // Versions
    .init("status", "Versions", "synch status <space>/<path>", surface: .files),
    .init("take", "Use This Version", "synch take <origin>:<space>/<path>", gate: .consequence, surface: .files, dirties: [.listing, .status]),
    .init("log", "History", "synch log <space>/<path>", surface: .files),
    .init("compare", "Compare With…", "synch compare <space> --to <origin> --json", surface: .files),
    // Replication
    .init("mirror.ls", "Mirrors", "synch mirror ls", surface: .node, provides: [.mirrors]),
    .init("mirror.add", "Mirror a Space…", "synch mirror add <space> <dir>", gate: .consequence, surface: .node, dirties: [.mirrors]),
    .init("mirror.rm", "Stop Mirroring…", "synch mirror rm <dir>", gate: .confirm, surface: .node, dirties: [.mirrors]),
    .init("mirror.sync", "Sync Mirrored Spaces Now", "synch mirror sync", surface: .node, dirties: [.mirrors]),
    .init("pin.ls", "Kept offline", "synch pin ls", surface: .node, provides: [.pins]),
    .init("pin.add", "Keep Offline", "synch pin add <target>", gate: .consequence, surface: .files, dirties: [.pins]),
    .init("pin.rm", "Stop Keeping Offline", "synch pin rm <target>", gate: .confirm, surface: .files, dirties: [.pins]),
    // Upkeep
    .init("scan", "Scan Now", "synch scan", surface: .files, dirties: [.listing, .status]),
    .init("sync", "Sync Now", "synch sync", surface: .ambient, // `.listing` too: `SyncNow` pulls a peer's entries into this node's store, so
    // it changes what the browser is showing and used not to refresh it.
    dirties: [.peers, .status, .listing]),
    .init("recover", "Resume Publishing…", "synch recover", gate: .conditional, surface: .node, dirties: [.status]),
    .init("doctor", "Run Diagnostics", "synch doctor", surface: .node, dirties: []),
    // Remote access
    .init("cloud.status", "Remote access", "synch cloud status", surface: .node, provides: [.cloud]),
    .init("cloud.enable", "Allow remote browsing", "synch cloud enable", gate: .confirm, surface: .node, dirties: [.cloud]),
    .init("cloud.disable", "Stop remote browsing", "synch cloud disable", gate: .confirm, surface: .node, dirties: [.cloud]),
    // Sockets (oneof 47…55), none of them surfaced.
    //
    // v3 publishes a socket as an entry of its own kind, arms it against a
    // reviewed content root, and runs it for a peer that connects. That is a
    // whole surface — an object to review, an armed/disarmed state, a list of
    // running invocations, a log — and this app has not one piece of it. They
    // are listed anyway, because the registry is the count the daemon is
    // checked against: leaving an operation out is not neutrality, it is how
    // `space set`, `space sync` and `fill` stayed invisible for three
    // releases. `surface: .notSurfaced` is the same admission `ls` makes at
    // the top of this section, and each row says what building it would take.
    //
    // None declares `dirties`. A row nothing can invoke has no table to
    // contradict, so a `dirties` list here would be a guess written as a fact;
    // `CoverageTests.everyMutationInvalidatesSomething` exempts `.notSurfaced`
    // for exactly that reason, and the exemption ends the moment one gets a
    // button.
    .init("socket.add", "—", "synch socket add <space>/<path>", surface: .notSurfaced,
          omission: "Publishes an eBPF object as a runnable entry; nothing in this app builds, inspects or reviews one."),
    .init("socket.arm", "—", "synch socket arm <space>/<path>", surface: .notSurfaced,
          omission: "Approves one review token to execute, which is a review decision — a button without the review it approves is the wrong half of the feature."),
    .init("socket.disarm", "—", "synch socket disarm <space>/<path>", surface: .notSurfaced,
          omission: "Stops a socket serving, and there is no armed state shown anywhere for a person to want stopped."),
    .init("socket.rm", "—", "synch socket rm <space>/<path>", surface: .notSurfaced,
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
