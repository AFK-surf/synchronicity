//// `controlplane rekor-publish`: put the zone key on the public record.
////
//// Separate from `keygen` on purpose (§5.2): key generation stays runnable
//// on an offline host, and this step — the one that needs egress — is
//// explicit and idempotent. Re-running refreshes the stored checkpoint and
//// audit path against a grown tree without minting a second entry, because
//// two entries would be two public claims about one key.
////
//// **The ordering is inverted from the original ceremony.** A `create` or
//// `rollover` entry must carry a DNSSEC chain, and a chain can only be built
//// once the **DS is live in the parent** — so the sequence is now: generate
//// the key, publish the DNSKEY in the zone, get the DS into the parent,
//// *then* log. The existing two-key rollover window covers the gap: the old
//// key keeps signing until the new one is logged (§5.4). The chain is not
//// for this service's benefit or the client's — both already know the
//// delegation is real — it is what makes the entry classifiable by a
//// monitor, and the client refuses an entry without one for exactly that
//// reason.
////
//// A `retire` is the one exception: a zone being retired may have no DS left
//// to build a chain from, so a chainless retire is allowed and marked as
//// such. Clients never treat a retire as authorization (they refuse the
//// action outright), so the exception cannot be turned into an evasion.
////
//// What this module does *not* do is touch a single byte of any of those
//// formats. Minting the certificate, rendering the Statement, signing,
//// DER-encoding the two extensions, and verifying what the log returned all
//// happen in `rekor/port` — one implementation, the client's own
//// (crates/synch-net), in a separate OS process. This module is the
//// ceremony: what the action is, which key it replaces, what to reuse, what
//// to store, and what to tell the operator.
////
//// Nothing is stored that has not been verified first, by the rules
//// crates/synch-net's verifier applies — because it *is* that verifier:
//// possession, the certificate's key and name bindings, inclusion, the log's
//// signature on the checkpoint, and the DNSSEC chain walk this side could
//// never run before. A row in `rekor_records` means a client would accept
//// this proof. If the port program is missing or fails, the publish fails:
//// there is no path here that stores an unverified record.

import dns/name.{type Name}
import dnssec/keys.{type Csk}
import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import rekor/chain
import rekor/client.{type Log, Submission}
import rekor/port.{type Session}
import rekor/store
import store/sqlite.{type Connection}

pub type PublishError {
  Db(sqlite.Error)
  /// The log refused, or could not be reached.
  LogUnavailable(String)
  /// The entry was not verified — never stored. Covers a verification
  /// failure and an unusable port program alike: both mean this service
  /// cannot say a client would accept the record, and both must stop the
  /// publish.
  Unverified(port.Failure)
  /// The DNSSEC chain could not be collected. Almost always one thing: the
  /// DS is not live in the parent yet, and logging comes after that now.
  NoChain(String)
}

/// One sentence for an operator, who wants to know what to do next.
pub fn describe(error: PublishError) -> String {
  case error {
    Db(e) -> "the database refused: " <> string.inspect(e)
    LogUnavailable(why) -> why
    Unverified(failure) -> port.describe(failure)
    NoChain(why) -> why
  }
}

pub type Outcome {
  Outcome(
    key_tag: Int,
    action: String,
    log_index: Int,
    /// True when the entry was already in the log and only its checkpoint
    /// and audit path were refreshed.
    refreshed: Bool,
    /// True when this entry carries no DNSSEC chain — only ever a `retire`.
    chainless: Bool,
    /// The predecessor key tag this entry's succession countersignature
    /// names, if it carries one.
    countersigned_by: Option(Int),
  )
}

/// Collects the DNSSEC chain a fresh entry will carry.
///
/// A `retire` collects nothing: a retired zone may have no DS left, and
/// clients refuse a retire as authorization outright, so the exception cannot
/// be turned into an evasion. For everything else, failing here is the point
/// — an entry without a chain is refused by every client, so discovering it
/// now, with an operator standing at the terminal reading "is the DS live in
/// the parent yet?", beats discovering it later from a cluster that will not
/// resolve.
///
/// Nothing is validated here. The bytes go to the port program, which walks
/// them cryptographically against the trust anchor *before* the certificate
/// is built, so a chain no reader could anchor never reaches the log.
pub fn collect_links(
  resolver: chain.Resolver,
  apex: Name,
  action: String,
) -> Result(List(port.ChainLink), PublishError) {
  case action {
    "retire" -> Ok([])
    _ -> chain.collect(resolver, apex) |> result.map_error(NoChain)
  }
}

/// Publishes (or refreshes) the record for `csk` at `apex`.
///
/// The action follows the ceremony (§5.4): the first key logged for a zone
/// is a `create`; a key logged while another already has a record is a
/// `rollover` naming the tag it replaces. `predecessor_key_file` is the
/// *previous* zone key's file, given only when the operator still holds it —
/// which is what turns a monitor's tier B into a tier A. The key files are
/// passed by path and opened by the port program: the zone's whole secret
/// never enters argv, and stays in one process rather than two.
pub fn run(
  conn: Connection,
  session: Session,
  apex: Name,
  csk: Csk,
  key_file: String,
  log: Log,
  log_spki: BitArray,
  now: Int,
  action: String,
  predecessor_key_file: String,
  links: List(port.ChainLink),
  anchor_file: String,
) -> Result(Outcome, PublishError) {
  let apex_text = name.to_string(apex)
  let key_tag = keys.key_tag(keys.dnskey_rdata(csk))
  use replaces <- result.try(previous_key_tag(conn, key_tag))

  // What a prior run logged for this key and action, if anything. The port
  // program decides whether it is reusable: the Statement has to be
  // byte-identical *and* the stored certificate has to already carry the
  // countersignature this run was asked for. Statement equality alone is a
  // key identity test — the Statement names the key by the SHA-256 of its
  // DNSKEY rdata — so a row belonging to another key that happens to share
  // this 16-bit tag can never be mistaken for this key's.
  use stored <- result.try(
    store.for_key_tag(conn, key_tag) |> result.map_error(Db),
  )
  let priors =
    stored
    |> list.filter(fn(record) { record.action == action })
    |> list.map(fn(record) { #(record.statement, record.canonicalized_body) })

  use minted <- result.try(
    port.mint(
      session,
      apex: apex_text,
      key_file: key_file,
      action: action,
      now: now,
      replaces: replaces,
      predecessor_key_file: predecessor_key_file,
      anchor_file: anchor_file,
      links: links,
      priors: priors,
    )
    |> result.map_error(Unverified),
  )

  // The submission is a hashedrekord over the DSSE PAE: its digest, the DER
  // signature, and the certificate that names this key and this zone.
  use logged <- result.try(
    log.submit(Submission(minted.digest, minted.signature, minted.certificate))
    |> result.map_error(LogUnavailable),
  )

  // Verify what came back the way a client will, before a row exists. This
  // is the client's own verifier over the log's own bytes: if it refuses, the
  // publish fails and nothing is written.
  use verified <- result.try(
    port.verify(
      session,
      apex: apex_text,
      public: csk.public,
      key_tag: key_tag,
      log_index: logged.log_index,
      statement: minted.statement,
      canonicalized_body: logged.canonicalized_body,
      checkpoint: logged.checkpoint,
      inclusion_path: logged.inclusion_path,
      log_spki: log_spki,
      action: action,
      anchor_file: anchor_file,
    )
    |> result.map_error(Unverified),
  )

  use Nil <- result.try(
    store.put(
      conn,
      store.Record(
        spki_sha256: minted.key_id,
        key_tag: key_tag,
        apex: apex_text,
        action: action,
        statement: minted.statement,
        canonicalized_body: logged.canonicalized_body,
        log_id: verified.log_id,
        log_index: logged.log_index,
        checkpoint: logged.checkpoint,
        // The stored audit path is the hashes, concatenated.
        inclusion_path: bit_array.concat(logged.inclusion_path),
        // Stored rather than re-encoded on the way out: the bytes a zone
        // serves are then exactly the bytes that verified, and the serving
        // path — which runs on every mutation, and on replicas — needs no
        // port program at all.
        proof_txt: verified.proof_txt,
        chainless: verified.chainless,
        integrated_at: logged.integrated_at,
        verified_at: now,
      ),
    )
    |> result.map_error(Db),
  )
  Ok(Outcome(
    key_tag,
    action,
    logged.log_index,
    minted.reused,
    verified.chainless,
    verified.countersigned_by,
  ))
}

/// The action for a fresh publish: a zone's first logged key is a `create`,
/// any later one is a `rollover` naming the tag it replaces.
pub fn action_for(
  conn: Connection,
  key_tag: Int,
) -> Result(String, PublishError) {
  use replaces <- result.try(previous_key_tag(conn, key_tag))
  Ok(case replaces {
    Some(_) -> "rollover"
    None -> "create"
  })
}

/// The already-logged key this one replaces, if any.
fn previous_key_tag(
  conn: Connection,
  key_tag: Int,
) -> Result(Option(Int), PublishError) {
  use tags <- result.try(store.verified_key_tags(conn) |> result.map_error(Db))
  case list_first_other(tags, key_tag) {
    Ok(tag) -> Ok(Some(tag))
    Error(Nil) -> Ok(None)
  }
}

fn list_first_other(tags: List(Int), key_tag: Int) -> Result(Int, Nil) {
  case tags {
    [] -> Error(Nil)
    [first, ..rest] ->
      case first == key_tag {
        True -> list_first_other(rest, key_tag)
        False -> Ok(first)
      }
  }
}
