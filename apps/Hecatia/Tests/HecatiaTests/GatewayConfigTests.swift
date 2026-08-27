import Foundation
import Testing
@testable import Hecatia

/// The `s3.*` config values are append-only logs, and what the gateway serves
/// is the fold of one — not the records.
///
/// Every case below is `synch-s3`'s own: `buckets::fold`, `auth::fold` and
/// `validate_name`, including the two places the bucket fold and the key fold
/// deliberately disagree.
struct GatewayConfigTests {

  @Test func laterRecordsWin() {
    let folded = GatewayConfig.buckets([
      "photos\tmedia\tnewest",
      "photos\tmedia\tstrict",
    ])
    #expect(folded.count == 1)
    #expect(folded[0].policy == .strict)
  }

  @Test func oneFieldIsARemoval() {
    #expect(GatewayConfig.buckets(["photos\tmedia\tnewest", "photos"]).isEmpty)
    #expect(GatewayConfig.accessKeyIDs(["AKIA\tsecret", "AKIA"]).isEmpty)
  }

  @Test func aRemovedBucketCanComeBack() {
    let folded = GatewayConfig.buckets([
      "docs\tpapers\tnewest", "docs", "docs\tpapers\tstrict",
    ])
    #expect(folded.map(\.name) == ["docs"])
    #expect(folded[0].policy == .strict)
  }

  /// The asymmetry worth a test of its own. A bucket record whose policy does
  /// not parse is skipped *before* the retain, so it leaves the mapping it
  /// would have replaced standing; a key record's missing second field *is*
  /// the removal.
  @Test func anUnreadableRecordDoesNotRemoveWhatItNames() {
    let folded = GatewayConfig.buckets([
      "photos\tmedia\tnewest",
      "photos\tmedia\tnonsense",
    ])
    #expect(folded.count == 1)
    #expect(folded[0].policy == .newest)
  }

  @Test func twoFieldsIsNeitherAnAddNorARemoval() {
    // `(Some(space), None)` falls to `_ => continue` in the daemon: the record
    // is skipped whole and the previous mapping stands.
    let folded = GatewayConfig.buckets(["photos\tmedia\tnewest", "photos\tmedia"])
    #expect(folded.count == 1)
    #expect(folded[0].space == "media")
  }

  @Test func originPinsSurviveTheRoundTrip() {
    let record = GatewayConfig.bucketRecord(
      name: "archive", space: "media", policy: .origin("nas@cluster.example"))
    #expect(record == "archive\tmedia\torigin=nas@cluster.example")
    #expect(GatewayConfig.buckets([record])[0].policy == .origin("nas@cluster.example"))
  }

  @Test func theGatewayTrimsBeforeParsingAPolicy() {
    // A stored `newest ` is a policy on the daemon side, so it has to be one
    // here or the app would show a bucket the gateway serves as unreadable.
    #expect(GatewayConfig.buckets(["photos\tmedia\tnewest "]).count == 1)
  }

  @Test func secretsNeverLeaveTheFold() {
    let ids = GatewayConfig.accessKeyIDs(["AKIA\ts3cr3t", "AKIB\tother"])
    #expect(ids == ["AKIA", "AKIB"])
    // The only thing a caller can obtain is an id: there is no accessor that
    // would hand a view the secret half.
    #expect(!ids.contains { $0.contains("s3cr3t") })
  }

  @Test func aReplacedKeyIsListedOnce() {
    #expect(GatewayConfig.accessKeyIDs(["AKIA\tone", "AKIA\ttwo"]) == ["AKIA"])
  }

  @Test func emptyNamesAreSkipped() {
    #expect(GatewayConfig.buckets(["", "\tmedia\tnewest"]).isEmpty)
    #expect(GatewayConfig.accessKeyIDs(["", "\tsecret"]).isEmpty)
  }

  @Test func bucketNamesFollowTheGatewaysRule() {
    #expect(GatewayConfig.isValidBucketName("photos"))
    #expect(GatewayConfig.isValidBucketName("my-bucket.one"))
    #expect(!GatewayConfig.isValidBucketName("ab"))
    #expect(!GatewayConfig.isValidBucketName(String(repeating: "a", count: 64)))
    #expect(!GatewayConfig.isValidBucketName("Photos"))
    #expect(!GatewayConfig.isValidBucketName("-photos"))
    #expect(!GatewayConfig.isValidBucketName("photos."))
    #expect(!GatewayConfig.isValidBucketName("photos_1"))
  }

  @Test func aTabWouldSplitTheFieldItIsIn() {
    #expect(GatewayConfig.containsSeparator("two\tfields"))
    #expect(!GatewayConfig.containsSeparator("one field"))
  }

  /// The log a live daemon actually held after six bucket edits and three key
  /// edits, and what `synch-s3 bucket ls` / `key ls` printed from it. The app
  /// has to agree with the gateway about the same bytes, or the two disagree
  /// about what is configured.
  @Test func agreesWithTheGatewayOnALiveLog() {
    let bucketLog = [
      "photos\tdemo\tnewest",
      "photos\tdemo\tstrict",
      "scratch\tdemo\tnewest",
      "scratch",
    ]
    let folded = GatewayConfig.buckets(bucketLog)
    #expect(folded.count == 1)
    #expect(folded[0].name == "photos")
    #expect(folded[0].space == "demo")
    #expect(folded[0].policy == .strict)

    let keyLog = ["AKIAOLD\tsekrit", "AKIAOLD", "AKIALIVE\tstillgood"]
    #expect(GatewayConfig.accessKeyIDs(keyLog) == ["AKIALIVE"])
  }
}
