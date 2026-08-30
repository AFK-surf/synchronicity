# Hecatia

**Hecatia** is the codename of this project. The app it builds is called
**Synchronicity** — that is what the window title, the menu bar and Finder say,
and it is what `CFBundleName` carries. The codename names the repository, the
Xcode project, the Swift module and the build product (`dist/Hecatia.app`);
nothing a user sees.

It is the macOS client for [Synchronicity](https://github.com/), a peer-to-peer
file store. It browses the unified tree, and it is honest about the thing that
makes the unified tree interesting: a path can carry more than one version, the
system never merges them, and you decide.

## Requirements

- macOS 14 or newer
- A full Xcode (the Command Line Tools SDK has no SwiftUI)
- `protoc` on `PATH` — `brew install protobuf`
- A running `synch` daemon
- For the proto check: the `synchronicity` checkout this repo now lives inside,
  passed explicitly — see [The protocol copy](#the-protocol-copy). Without a
  path that check says SKIPPED and the rest of the suite still runs.

## Build and run

```sh
make run           # debug build, bundled, launched
make release       # release build at dist/Hecatia.app
make test          # the suites, the proto check, the reachability audit, the design audit
make audit         # just the audits, without the suites
make design-audit  # just the design one
make snapshots     # render every surface to build/snapshots, to look at
make check-proto   # is our control.proto still the daemon's?
```

`Scripts/env.sh` finds Xcode and `protoc` rather than hardcoding paths. Set
`DEVELOPER_DIR` or `PROTOC_PATH` to override either.

The app connects on launch to `~/Library/Application Support/synchronicity`;
change the data folder in Settings (⌘,). Connecting is not a user task, so it
is not a form — the sidebar says what happened and offers the one action that
helps.

## The protocol copy

`Sources/Hecatia/control.proto` is a copy of the daemon's
`crates/synch-cli/proto/control.proto`. The daemon owns it; Hecatia keeps a
copy so SwiftPM can build without generating sources from another package.
The default check resolves both files from this monorepo:

```sh
Scripts/sync-proto.sh check
Scripts/sync-proto.sh update
```

Pass a repository path explicitly when checking against another checkout.
Missing repositories and drift are hard failures. `make test` first exercises
those failure modes and then checks the real copy, so the gate cannot silently
turn into a skip again.

## What it covers

The daemon exposes 68 addressable operations: 14 typed rpcs, and the 54
subcommands `Run` carries. `service Control` declares 15 rpcs, but `Run` is the
carrier for that oneof rather than a fifteenth operation, which is why the count
is 14 — `Scripts/audit-coverage.sh` computes it as `rpc_count - 1`.
`Tests/HecatiaTests/CoverageTests.swift` asserts that every one of them is
accounted for, so a new daemon operation cannot be quietly forgotten here.

Eleven are deliberately not surfaced, and they are two different kinds of
omission. `ls` is *replaced*: the typed `List` answers the same question with a
schema and a cancel. The other ten — `OpenSocket` and the nine `socket`
subcommands — are simply *unbuilt*: v3 grew a socket surface and this app has
none of it. They are registered anyway so the count stays the daemon's.

`cat` and `get` used to be omitted on the same reasoning as `ls`, and the
reasoning was wrong: `ReadRequest` carries no content root, so it can only
select the *current* version of a path, and everything a superseded version or
a `forever` replica holds needs `--root`. Both are surfaced now.

A registry row is a claim, though, not a wire: an operation can be listed,
titled and gated and still be reachable from nothing. `make audit` checks the
other half — that every command builder and every client method is called from
somewhere — and `make test` runs it.

One field is deliberately never sent: `ReadRequest.len`. Nothing here wants a
bounded read, and half a file previews as a broken one.

## The windows

**Files** is the product, and `⌘N` opens another one. A `NavigationSplitView`
over a real `Table`, with an inspector that turns the version count from a badge
into a decision: who has which contents, what each one looks like, and one
button to adopt one. Nothing that does not name a file or a folder is allowed in
this window.

**Settings** (⌘,) is the operator console. It was a separate Node window once;
its panes are pages of Settings now, in a source list rather than a tab bar,
because a tab bar stops scaling at about six items and there are eight. Two
groups: *General* (General, About) and *Node* (Identity & Keys, Members,
Network, Sources & Replicas, Pins, Remote Access, Diagnostics). Overview dissolved
into the pages that own its parts, and per-space replication lives in Spaces,
where the daemon put it.

Beside them: **Activity** (⇧⌘A), which shows every command and the daemon's full
output, and a menu bar item that answers "is it working right now" without
launching anything. Activity is deliberately not a settings page — a live log is
read beside the thing it is a log of, which a settings window cannot be — and
Diagnostics carries the way in.

## How it reads the daemon

Half the daemon's surface answers in rendered human text with no schema and no
version signal. The rule this app follows:

> Parse text whose fields identify themselves. Where the fields are only
> positional, the rendering is lossy, or a misparse would be a security fault,
> ask for a typed RPC instead.

Three tiers, in `Sources/Hecatia/Daemon/`:

- **Tier 0 — no parsing.** Run the command, collect the frames, and treat *the
  stream ending without a gRPC status* as success — never the text. Roughly 25
  operations are correct this way and cannot rot. This is where a new operation
  starts: one `Operation` value, and Activity already renders it properly.
- **Tier 1 — machine-readable by construction.** `compare --json`, the version
  policy grammar, the version list inside a strict `Resolve`'s refusal, and the
  tab-separated `s3.*` records.
- **Tier 2 — positional tables, parsed under rules.** Never split on a column:
  the daemon's `{:<20}` widths are minimums, not truncations, so a 63-byte
  folder id or a `key:<52-char>` origin runs straight through them. Anchor on a
  field that identifies itself — a 52-character z-base-32 key, a 64-character
  hex root, the first `/` of an absolute path. Every parser is total: what it
  cannot read is shown, not dropped, behind a diagnostics chip.

`Tests/HecatiaTests/ParserTests.swift` holds a golden fixture for every
format, copied from the `format!` literals in the daemon's `server.rs` and
`render.rs`, including the shapes that break a column-based parse.

## How it looks

`docs/DESIGN.md` is the design system: which rules this app takes from the
reference it was given, and which it rejects because they are rules for a web
page and would break a macOS convention — the system appearance, the system
text sizes, the platform's own button shapes.

The short version: one accent colour carries every interactive signal and
nothing else does; state colours say what state a thing is in and never make a
thing look clickable; there are no shadows on chrome and no gradients anywhere;
radii come from a four-step ladder and spacing from an 8pt one; and no font is
configured at all, because on this platform the system font is SF and the
system text styles are what respects Larger Text.

`make design-audit` decides the half of that a grep can decide, and `make
snapshots` renders every surface so the other half can be looked at — including
in dark mode, which the reference system does not document.

## Danger

Four strengths of confirmation, and which one an operation gets is a field on
its `Operation` value:

1. A plain confirmation naming the object — and correcting the guess.
   *"Remove this replica? Its checkout files stay where they are."*
2. A confirmation whose consequence the app computes — adoption, `trust add`,
   and `source add`.
3. A typed confirmation behind a disclosure that resets on quit. Five:
   `key retire`, `daemon stop`, `trust rm`, `domain clear`, `source rm`, plus
   `repair rebuild-views`.
4. No control at all until the condition exists — `recover` appears only when
   the daemon reports being in recovery.

`key rotate` and `key activate` get none of these. They are not destructive,
they are *ordered*, so they get a four-step procedure that only enables retiring
the old key once every device has the new one.

## Project layout

```
Hecatia.xcodeproj      the Xcode project; `xcodebuild -scheme Hecatia`
Package.swift          the same target, built by SwiftPM — both are supported
App/Info.plist         bundle metadata; the product name lives here
Scripts/               toolchain discovery, bundling, proto sync
Sources/Hecatia/
  App/       the four scenes and the menu bar commands
  Daemon/    the gRPC actor, error classification, and Parsers/
  Model/     domain types, all Sendable
  Store/     NodeStore (one daemon), FilesModel (one window), transfers
  Views/     Files/, Node/, Activity/, Settings/, Shared/
  Preview/   sample data, DEBUG only
```

`NodeStore` is shared by every window because there is one daemon behind a
global connection mutex. `FilesModel` is per-window, so ⌘N gives a second
browser that navigates independently.
