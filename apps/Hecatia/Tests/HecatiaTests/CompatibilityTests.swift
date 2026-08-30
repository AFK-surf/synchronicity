import Foundation
import Testing
import GRPC
@testable import Hecatia

/// Client-side compensation for what the daemon's rendering destroys.
///
/// Each suite here corresponds to an item in `docs/DAEMON-ISSUES.md` that a
/// first reading called impossible to work around, and is the proof it is not.
struct DurationRecoveryTests {

  /// `render::ago` buckets with truncating integer division, so `3m ago` means
  /// the interval [180, 240). Recovering the interval is what lets a column of
  /// these be ordered at all.
  @Test func agoBucketsBecomeIntervals() {
    #expect(Anchor.age("45s ago") == Age(lower: 45, upper: 46, isNever: false, text: "45s ago"))
    #expect(Anchor.age("3m ago") == Age(lower: 180, upper: 240, isNever: false, text: "3m ago"))
    #expect(Anchor.age("2h ago") == Age(lower: 7200, upper: 10800, isNever: false, text: "2h ago"))
    // Days are open-ended: there is no larger unit to roll into.
    #expect(Anchor.age("5d ago")?.upper == nil)
    #expect(Anchor.age("5d ago")?.lower == 432_000)
  }

  @Test func neverIsNotAnAge() {
    // `never` renders a zero timestamp — "has not happened", which must not be
    // ordered among things that have.
    let never = Anchor.age("never")
    #expect(never?.isNever == true)
    #expect(never?.sortKey == .greatestFiniteMagnitude)
    #expect(Anchor.age("just now")?.lower == 0)
  }

  @Test func ordersCorrectlyAcrossBuckets() {
    // The whole point: these three sort right by interval and wrong by string.
    let texts = ["2d ago", "12s ago", "3m ago"]
    let sorted = texts.compactMap(Anchor.age).sorted { $0.sortKey < $1.sortKey }
    #expect(sorted.map(\.text) == ["12s ago", "3m ago", "2d ago"])
    #expect(texts.sorted() != ["12s ago", "3m ago", "2d ago"])
  }

  @Test func thresholdsAreConservative() {
    // A bucket that straddles the threshold must not trip an alert.
    #expect(Anchor.age("2h ago")?.isAtLeast(3600) == true)
    #expect(Anchor.age("59m ago")?.isAtLeast(3600) == false)
    // 1h ago is [3600, 7200) — entirely at or past the hour, so it does trip.
    #expect(Anchor.age("1h ago")?.isAtLeast(3600) == true)
    #expect(Anchor.age("never")?.isAtLeast(1) == false)
  }

  @Test func remainingUsesItsOwnVocabulary() {
    #expect(Anchor.remainingAge("7d")?.lower == 604_800)
    #expect(Anchor.remainingAge("expired")?.lower == 0)
    #expect(Anchor.remainingAge("cut off")?.lower == 0)
    #expect(Anchor.remainingAge("never")?.isNever == true)
    #expect(Anchor.remainingAge("nonsense") == nil)
  }

  @Test func peerRowYieldsBothAges() {
    let key = String(repeating: "r", count: 52)
    let row = "\(key)  nas@x.example  last-seen 3m ago  last-sync 12s ago  rtt 812µs"
    let peer = Listings.peers([row]).rows[0]
    #expect(peer.origins == "nas@x.example")
    #expect(peer.lastSeen?.lower == 180)
    #expect(peer.lastSync?.lower == 12)
    // The daemon's own words are still what gets displayed.
    #expect(peer.lastSeenText == "3m ago")
    #expect(peer.isStale == false)
  }

  @Test func aDurationContainingASpaceSurvivesTheFieldSplit() {
    // "just now" has a space in it, and the row's field separator is two
    // spaces — a single-space split cuts it in half.
    let key = String(repeating: "r", count: 52)
    let row = "\(key)  (untrusted)  last-seen just now  last-sync never  rtt 90µs"
    let peer = Listings.peers([row]).rows[0]
    #expect(peer.lastSeenText == "just now")
    #expect(peer.lastSync?.isNever == true)
  }

  @Test func anHourOldPeerIsFlaggedStale() {
    let key = String(repeating: "r", count: 52)
    let row = "\(key)  nas@x  last-seen 4h ago  last-sync 4h ago  rtt 1µs"
    #expect(Listings.peers([row]).rows[0].isStale)
  }
}

/// `OriginId::short()` truncates to 10 of 52 characters, which is not a
/// reference any command accepts. It is a prefix, so it is invertible.
struct OriginRecoveryTests {
  private let full = "key:" + String(repeating: "y", count: 52)
  private var truncated: String { "key:" + String(repeating: "y", count: 10) }

  @Test func shortMatchesTheDaemonsRendering() {
    #expect(Versions.short(full) == truncated)
    // A named origin is rendered whole and must not be touched.
    #expect(Versions.short("nas@cluster.example.com") == "nas@cluster.example.com")
  }

  @Test func aTruncatedOriginIsRestoredFromWhatTheNodeKnows() {
    let set = PathVersions(
      space: "notes", path: "a.md",
      versions: [EntryVersion(
        identity: "abc", kind: .file, size: 1, seq: 4, attestors: [truncated])])
    let restored = Versions.restoreOrigins(set, knownOrigins: [full, "nas@x.example"])
    #expect(restored.set.versions[0].attestors == [full])
    #expect(restored.unresolved.isEmpty)
  }

  @Test func anAmbiguousPrefixIsLeftAloneRatherThanGuessed() {
    // Two known origins sharing a 10-character prefix is vanishingly unlikely
    // and must still not be resolved by picking one.
    let other = "key:" + String(repeating: "y", count: 10) + String(repeating: "b", count: 42)
    let set = PathVersions(
      space: "notes", path: "a.md",
      versions: [EntryVersion(
        identity: "abc", kind: .file, size: 1, seq: 4, attestors: [truncated])])
    let restored = Versions.restoreOrigins(set, knownOrigins: [full, other])
    #expect(restored.set.versions[0].attestors == [truncated])
    #expect(restored.unresolved == [truncated])
  }

  @Test func anUnknownPrefixIsReportedNotInvented() {
    let set = PathVersions(
      space: "notes", path: "a.md",
      versions: [EntryVersion(
        identity: "abc", kind: .file, size: 1, seq: 4, attestors: [truncated])])
    let restored = Versions.restoreOrigins(set, knownOrigins: ["nas@x.example"])
    #expect(restored.unresolved == [truncated])
  }

  @Test func onlyAWholeOriginIsActionable() {
    // The adopt button is gated on this: a truncated origin would build a
    // reference the daemon refuses.
    #expect(Versions.isActionable(full))
    #expect(Versions.isActionable(truncated) == false)
    #expect(Versions.isActionable("nas@cluster.example.com"))
    #expect(Versions.isActionable("") == false)
  }

  @Test func theDeviceACommandReachesIsNotAlwaysTheFirstAttestor() {
    // The exact list `restoreOrigins` leaves behind when one attestor was
    // rendered short and no membership name could restore it. On this input
    // the two derivations disagreed: the confirmation named `attestors.first`
    // — the truncated key — and the fetch took the first *actionable* one, so
    // the dialog asked about one device and the command contacted another.
    // There was no single value to assert on before, because the two answers
    // lived in two files.
    let mixed = EntryVersion(
      identity: String(repeating: "e5", count: 32), kind: .file, size: 1,
      seq: 91, attestors: [truncated, "nas@cluster.example.com"])
    #expect(mixed.attestors.first == truncated)
    #expect(mixed.actionableAttestor == "nas@cluster.example.com")

    // And when nothing in the list is a reference the daemon accepts, there is
    // no device to name — which is what disables the buttons.
    let unreachable = EntryVersion(
      identity: String(repeating: "e5", count: 32), kind: .file, size: 1,
      seq: 91, attestors: [truncated])
    #expect(unreachable.actionableAttestor == nil)
  }

  @Test func aResolvedEntryMatchesAStatusVersionWithoutATransportSeq() {
    let root = Data(repeating: 0xab, count: 32)
    let entry = RemoteEntry(
      origin: full, space: "notes", path: "a.md", kind: .file, size: 42,
      modified: .distantPast, versions: 1, contentRoot: root)
    let rendered = EntryVersion(
      identity: String(repeating: "ab", count: 8), kind: .file, size: 42,
      seq: 91, attestors: [truncated])
    #expect(Versions.matches(entry, version: rendered))
  }

  @Test func identityMatchingStillRejectsADifferentVersion() {
    let entry = RemoteEntry(
      origin: full, space: "notes", path: "a.md", kind: .file, size: 42,
      modified: .distantPast, versions: 1, contentRoot: Data(repeating: 0xab, count: 32))
    let wrongRoot = EntryVersion(
      identity: String(repeating: "cd", count: 8), kind: .file, size: 42,
      seq: 91, attestors: [truncated])
    let wrongSize = EntryVersion(
      identity: String(repeating: "ab", count: 8), kind: .file, size: 43,
      seq: 91, attestors: [truncated])
    #expect(!Versions.matches(entry, version: wrongRoot))
    #expect(!Versions.matches(entry, version: wrongSize))
  }
}

/// The daemon records when a tunnel's state last changed and never renders it.
struct ObservationLedgerTests {
  @MainActor
  @Test func anUnchangedValueKeepsItsFirstTimestamp() {
    let ledger = ObservationLedger()
    let start = Date(timeIntervalSince1970: 1_000)
    ledger.observe("cloud/x", value: "attached", now: start)
    let again = ledger.observe("cloud/x", value: "attached", now: start.addingTimeInterval(600))
    #expect(again == start)
  }

  @MainActor
  @Test func aChangedValueRestartsTheClock() {
    let ledger = ObservationLedger()
    let start = Date(timeIntervalSince1970: 1_000)
    ledger.observe("cloud/x", value: "attached", now: start)
    let flipped = start.addingTimeInterval(600)
    #expect(ledger.observe("cloud/x", value: "detached", now: flipped) == flipped)
  }
}

/// Telling a daemon that has stopped from one that is merely slow.
@Suite("Transport failures")
struct TransportClassificationTests {
  // A dead control socket surfaces as a `GRPCConnectionPoolError`, which has
  // no public initialiser, so that arm cannot be constructed here. It is
  // covered end to end instead: `make probe PROBE=connection` kills a real
  // daemon and watches the app notice — measured, "unavailable / Nothing is
  // listening on the control socket" six seconds after the kill, `.failed`
  // six seconds after that, and connected again a second after it came back.

  /// A deadline is the daemon being slow, which is a different thing.
  @Test("A deadline stays an internal failure")
  func deadline() {
    let failure = DaemonFailure.classify(
      GRPCStatus(code: .deadlineExceeded, message: "took too long"), operation: "look")
    #expect(failure.code == .internalError)
  }

  @Test("A cancelled call is not a failure to report")
  func cancelled() {
    #expect(DaemonFailure.classify(CancellationError()).detail == "Cancelled.")
  }
}
