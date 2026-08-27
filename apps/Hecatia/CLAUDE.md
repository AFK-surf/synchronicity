# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Hecatia is the codename; the app is **Synchronicity**, the macOS client for the
`synch` peer-to-peer file store. `README.md` explains what the app is and why it
is shaped the way it is — read it once. This file is what you need on top of it.

## How I want you to work

- Every component/view must have a proper `#Preview`.
- Use responsive layout; avoid elements that end up too wide or too narrow.
- The body of the app is SwiftUI. Use AppKit where SwiftUI causes UI problems
  that are hard to fix, or where the SwiftUI API is limited.
- You have read and edit tools and can also drive the CLI directly. Choose
  sensibly between them.
- Match macOS native / first-party apps as closely as possible — but confirm
  the details with me before committing to them.
- To test UI: build, run, and let me test it by hand.

### Editing

- Always use the Edit tool to modify source. **Never** use `sed`, `awk`,
  heredocs or shell redirection to rewrite a file — these have caused silent
  regressions in this repository.

### Diagnose before fixing

- Before asserting that a configuration or build problem is fine, reproduce it
  and read the real Xcode/compiler error output. Ask me to paste the error
  rather than inferring it from the source.
- When a SwiftUI `#Preview` will not render, check the Debug build settings
  first (`SWIFT_COMPILATION_MODE`, optimization level).

### Reproductions and test data

- A reproduction must actually have been run, with its output shown. Never
  leave it at the theoretical level.
- A reproduction must match my real scenario. Do not introduce artificial steps
  such as deleting a CAS payload by hand unless I ask for them.
- `SampleData` for SwiftUI previews may only contain rows the daemon really
  emits — no directory rows — and its prefix filters and dates must match a
  real payload.

### Scope

- Do not run automatic screenshot, probe or verification flows, and do not run
  background builds, unless I ask.
- UI polish must be surgical: change only the property I named. Do not touch
  sidebar icons, toolbar wording or unrelated layout in the same edit.

## Commands

`Scripts/env.sh` discovers the toolchain and is sourced by everything else. It
exports `DEVELOPER_DIR` (a full Xcode — the Command Line Tools SDK has no
SwiftUI) and `PROTOC_PATH` (the protobuf plugins cannot search `PATH`
themselves). Any bare `swift` command must be preceded by it.

```sh
make run              # debug build → bundle → launch
make build            # bundle to dist/Hecatia.app without launching
make release          # same, release configuration
make test             # swift test, proto check, coverage audit, design audit
make check            # make test + `swift build -c release`
make audit            # just the two audits
make design-audit     # just the design one
make clean            # rm -rf .build dist XcodeGenerated
```

Run a single test or suite — `--filter` matches the Swift type and function
name, never a `@Suite` display string:

```sh
. Scripts/env.sh && swift test --filter 'CoverageTests/everyOperationIsAccountedFor'
. Scripts/env.sh && swift test --filter ParserTests
```

`make check` is the only thing that compiles the release configuration. The
`#if DEBUG` preview harnesses have broken `swift build -c release` while
`make test` stayed green, so run it before calling something done.

**Always test through the bundle, never `.build/debug/Hecatia`.** The bare
SwiftPM executable has no `Info.plist` and no bundle identity, so macOS gives it
a different appearance and activation story — four rounds of focus checks passed
against the bare binary while the fault was plain in the bundled app.

`make snapshots` and `make probe` exist but are covered by the scope rule above:
do not run them unprompted. `probe`'s `upload`/`add`/`external`/`connection`
suites mutate a real daemon and a real shared folder, and the driver terminates
the app when it finishes.

### The proto copy

`Sources/Hecatia/control.proto` is a copy of the daemon's
`crates/synch-cli/proto/control.proto`. The script resolves that canonical file
from the monorepo by default:

```sh
Scripts/sync-proto.sh check
Scripts/sync-proto.sh update
```

`Scripts/test-proto-sync.sh` verifies the default path and proves missing and
drifting repositories fail closed. `make test` runs it before the Swift suite.
When the daemon reserves a field, update the copy and adapt Hecatia in the same
change; do not preserve a client-only compatibility field.

## Architecture

**`Store/Operations.swift` is the spine, not a catalogue.** One `Operation` row
— id, title, `commandLine`, `gate`, `surface`, `dirties`, `provides`,
`omission` — is simultaneously the menu item, its confirmation strength, its
disabled-with-a-reason state, the `synch` line an operator can check, and its
cache invalidation. Call sites never pick a gate and never refresh by hand:
`NodeStore.run` calls `refresh(Set(operation.dirties))` after any successful
non-quiet run. Adding a button means adding a row, not adding logic.

**`Topic` (13 cases) is the entire invalidation vocabulary**, and
`NodeStore.load(_:)` is the single switch that fills each slice. `.listing` is a
token rather than data — `NodeStore` holds no listing, each window's
`FilesModel` does — so `load(.listing)` only bumps `listingGeneration`, which
every browser window watches. That counter is the only cross-window refresh
channel, with a 12s `ListingWatch` fallback for changes nothing announces.

**Concurrency is two-level on purpose.** `ControlClient` is a bare (non-main)
actor owning the gRPC transport and nothing else. Ordering comes from
`NodeStore.enqueue`, a serial chain of Tasks, because the daemon takes a
*global connection mutex* on every store read. `NodeStore`, `FilesModel` and
`TransferQueue` are `@MainActor @Observable`; streamed frames hop back to the
main actor and are buffered, flushed at most every 100ms, because `scan` emits a
progress frame per skipped file.

**Success is "the response stream ended without a gRPC status" — never the
text.** Roughly 25 operations are Tier 0 and correct precisely because nothing
parses their output. The other tiers exist because half the daemon's surface
renders human prose with no schema and no version signal: Tier 1 is
machine-readable by construction (`compare --json`, the strict-`Resolve`
refusal, the tab-separated `s3.*` records); Tier 2 is positional tables parsed
only through self-identifying anchors in `Daemon/Parsers/Anchors.swift`.

**Every Tier-2 parser is total.** `ParseResult<Row>` carries rows plus
`unrecognized` lines; `NodeStore` funnels those into `parseWarnings[Topic]` and
the affected pane renders a diagnostics chip. An unexpected daemon format
degrades to a visibly incomplete table, never a silently wrong one.

**The auth and version contract lives only in Swift, not in the proto:**
`x-synch-control-version` (the daemon's interceptor compares it for *equality*,
not as a floor), `x-synch-control-token-bin`, and the `x-synch-error-code`
trailer. `ControlClient.controlVersion` is the single bump point. A mismatch is
a total outage — even the `daemon status` reachability probe is refused — so
`NodeStore` turns it into a whole-window `needsUpdate` state rather than an
alert.

**The server sets no deadline on anything**, so deadlines are a hand-classified
client concern: `.fast` 20s, `.standard` 120s, `.long` none (scans,
`listRemainder`, `Put`/`UploadPart`/`CompleteUpload`). Dead-daemon detection
depends on the exact error classification in `Daemon/DaemonFailure.swift` plus
two consecutive failures and `longRunsInFlight == 0`.

**The unified tree publishes leaves only — there is no directory record.**
`Store/LevelBuilder.swift` synthesises every folder row from a streamed
recursive prefix listing, so `rows` never contains anything *under* a folder.
Any feature needing descendants (delete plan, versions, history) must ask the
daemon again or bail out on a synthesised row.

**The file browser is an AppKit island.** `Views/Files/BrowserSplit.swift` hosts
an `NSSplitViewController` (SwiftUI's `.inspector` animated the browser 165pt;
`inspectorWithViewController:` is what grants full-height layout), and the
eleven AppKit bridges around it each exist for a measured SwiftUI defect.
Everything inside it is off the scene's view tree, so `openWindow`,
`openSettings` and the environment resolve to empty defaults — the app re-plumbs
them as `\.openAppWindow`, `SettingsRoute`, `\.exportEntry` and an explicit
`.environment(node)` at the boundary.

**SwiftPM is authoritative; the Xcode project does not run the protoc plugins.**
A script phase shells out to `swift build` and copies the plugin output into a
gitignored `XcodeGenerated/`. Both targets glob sources, so adding a `.swift`
file needs no project edit — only `control.proto` changes need regeneration.

## Invariants a change can silently break

1. **Registry vs proto.** `Scripts/audit-coverage.sh` counts the `oneof` of
   `message Command` and the `rpc`s of `service Control` against the row counts
   of `Operations.typed`/`run`. It parses `Operations.swift` by exact text shape
   — one `.init(` per line at exactly four spaces of indent — so wrapping a row
   onto a continuation line changes the count the audit believes. The script is
   the authority; `CoverageTests`' literals only localize a miscount.
2. **Reachability.** Every `Cmd.<name>` builder must be called from outside
   `Cmd.swift`, every non-private `ControlClient` method must have a caller, and
   every `Topic` case must appear in some operation's `provides:`. An
   unreachable builder is reported as a defect, not as coverage.
3. **Reads declare `provides:` and never `dirties:`** — a read that dirties what
   it fills re-enters its own refresh forever (it once pinned a core at 114%).
   Every non-`.notSurfaced` mutation must dirty something; every `.notSurfaced`
   row needs a non-empty `omission`. The omitted-id list is pinned as a whole
   set, not a floor, so an operation that *loses* its surface fails the test
   instead of quietly joining the list. The read-only id set is duplicated
   verbatim in two tests — edit both.
4. **Gates are pinned.** `key.retire`, `daemon.stop`, `trust.rm`,
   `domain.clear` and `space.rm` must be `.typed`; `recover` must be
   `.conditional`; every `surface == .files` operation must be on the allowlist
   of ids that name a file or folder.
5. **`design-audit.sh` hard-fails** (in `Views/` and `App/` only) on `.shadow(`,
   anything matching `gradient`, `.system(size:`, `design: .rounded/.serif/
   custom(`, `.weight(.medium)`, literal colours, and — outside `Theme.swift` —
   `cornerRadius: N`, `spacing: N`, `.padding(N)`. `spacing: 0` and bare
   `.padding()` are deliberately legal. Any `labelsHidden()` needs an
   `accessibilityLabel` within −3/+6 lines, checked by proximity.
6. **proto3 presence is load-bearing in `Cmd.swift`.** Optional strings are set
   only when non-nil *and* non-empty; `domainSet` must always send `delegate` (a
   bool has no presence, and omitting it strands a delegate node at "Waiting to
   be named"); `spaceSet` must never be called with nothing to change. A removed
   field is silently dropped by prost, so a stale field reports success and does
   nothing — this shipped for three releases.
7. **Never split daemon text on fixed columns or single spaces.** The `{:<20}`
   widths are minimums, and values contain single spaces (`3m ago`, `cut off`).
   `Anchor.splitAtFirstPath` is legal only when the path is the last field. An
   unknown token must fail the whole line into `unrecognized`, never be coerced
   to a default — collapsing a non-`static` trust source to `.zone` once listed
   delegated devices as unrestricted zone members.
8. **Listing.** Every prefix is sent with a trailing `/` (the daemon matches raw
   byte ranges, so `docs` also returns `docs-old/a`). A short or empty page does
   *not* mean the end — tombstone-only paths are dropped after the limit bounds
   the page, so only an unbounded `listRemainder` proves it. The delete plan must
   enumerate with `policy: .newest` regardless of the toolbar's version policy,
   or it silently shrinks while reporting complete.
9. **Observation hygiene.** Assignment fires observation whether or not the
   value changed, and a 5s poll assigns constantly — guard every write
   (`if status != parsed`, …). Every async landing must re-check its generation
   token (`generation`, `versionGeneration`, `historyGeneration`, `reloadToken`,
   `runTokens`) and a superseded fold must change nothing. `@AppStorage` does
   **not** work inside an `@Observable` class — use `UserDefaults` with a
   `didSet`.
10. **`quiet:` and `alerts:` are different switches.** `quiet` suppresses the
    Activity row *and* the automatic `dirties` refresh, so a caller that only
    wants its own error UI must pass `alerts: false`, not `quiet: true`.
    Separately: every `NSHostingController`/`NSHostingView` must set
    `sizingOptions = []`; `EntryNSTableView.mouseDown` must keep its do-nothing
    `super` override (deleting it makes the file list unclickable); and no
    `InspectorCommands()` may be added, because the versions panel is an
    `NSSplitViewItem`, not SwiftUI's `.inspector`.

## When you add…

- **A daemon operation.** `Scripts/sync-proto.sh update <daemon-repo>`; add one
  `.init(...)` row to `Operations.typed` or `.run` (one line, four-space
  indent); bump the three literals in
  `CoverageTests.everyOperationIsAccountedFor`; satisfy whichever pinned set
  applies; give it a `Cmd.<name>` builder called from outside `Cmd.swift`.
- **Behaviour for a new operation.** Start at Tier 0 — an `Operation` row plus
  `NodeStore.run`, and Activity already renders it correctly. Do not write a
  parser until a pane needs structured rows, and never add
  `if output.contains("ERROR")` logic.
- **A parser.** Build on `Anchors`/`Durations`, return `ParseResult<Row>`, route
  `unrecognized` into `parseWarnings[topic]`, and add a golden fixture to
  `ParserTests` copied verbatim from the daemon's `format!` literals in
  `crates/synch-cli/src/render.rs` and `control/server.rs` — including a shape
  that defeats a column parse.
- **A state slice.** Add a `Topic` case, fill it in exactly one place
  (`NodeStore.load`), and make some operation `provides:` it. An unfilled
  `Topic` fails `audit-coverage.sh`.
- **A view.** A named `#Preview` inside `#if DEBUG` with an explicit
  `.frame(width:height:)`, seeded by `NodeStore.preview()` + `SampleData`
  (preview stores short-circuit `run`/`refresh`, so they must be seeded, and the
  view and its `FilesModel` must share **one** store). Keep the harness and any
  extension it needs inside the `#if DEBUG`.
- **A keyboard shortcut.** Declare it in `AppCommands` only, never on a Scene —
  declaring it in both put ⇧⌘A on two different menu items. Reach the frontmost
  browser through `@FocusedValue(\.filesModel)`.
- **Anything inside `BrowserSplit`.** Use `\.openAppWindow`,
  `SettingsRoute.open(_:)`, `\.exportEntry`, and re-apply `.environment(node)`.
  A plain `openWindow` button compiles and does nothing.
- **Ordering or sorting.** `LevelBuilder.rows()` is intentionally unsorted (a
  50k-entry `localizedStandardCompare` measured 2.02s on the main actor).
  Ordering lives in `FilesModel.visibleRows`, whose cache is invalidated only by
  `didSet` on `rows`/`sortOrder`/`search` — a fourth input without a matching
  `didSet` yields a silently stale table.

## Gotchas

- **Two different files are called `DESIGN.md`.** `docs/DESIGN.md` is this app's
  visual design system, enforced by `design-audit.sh`. But `DESIGN.md 3.2` and
  `DESIGN.md 8` in Swift and proto comments mean the **daemon's**
  `/Users/cirno/workspace/synchronicity/DESIGN.md`. `Model/ReplicaStatus.swift`
  and `Views/Node/ReplicationInspector.swift` cite `docs/REPLICATION.md`, which
  does not exist — that content is §8 of the daemon's `DESIGN.md`.
- **`docs/` is gitignored.** Nothing under it is version-controlled, so a
  deletion there is unrecoverable, and a fresh clone gets `design-audit.sh` and
  none of the reasoning it enforces. Treat the `Theme.swift` and
  `DesignTokens.swift` comments as the surviving copy.
- The daemon exposes **68** addressable operations: **14** typed rpcs and the
  **54** subcommands `Run` carries (`Command` field numbers 1…55, 9 reserved).
  `service Control` declares 15 rpcs, but `Run` is the carrier for the oneof,
  not a fifteenth operation.
