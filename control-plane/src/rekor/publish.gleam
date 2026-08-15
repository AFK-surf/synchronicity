//// `controlplane rekor-publish`: put the zone key on the public record.
////
//// Separate from `keygen` on purpose (§5.2): key generation stays runnable
//// on an offline host, and this step — the one that needs egress — is
//// explicit and idempotent. Re-running refreshes the stored checkpoint and
//// audit path against a grown tree without minting a second entry, because
//// two entries would be two public claims about one key.
////
//// Nothing is stored that has not been verified here first, by the same
//// rules crates/synch-net's verifier applies: possession (the DSSE
//// signature is the zone key's), binding (the Statement names this key and
//// this apex), inclusion, and the log's signature on the checkpoint. A row
//// in `rekor_records` means *this service checked it*.

import dns/name.{type Name}
import dnssec/keys.{type Csk}
import gleam/option.{type Option, None, Some}
import gleam/result
import rekor/client.{type Log}
import rekor/proof.{type Proof, Proof}
import rekor/statement
import rekor/store
import store/sqlite.{type Connection}

pub type PublishError {
  Db(sqlite.Error)
  /// The log refused, or could not be reached.
  LogUnavailable(String)
  /// The proof did not verify locally — never stored.
  Unverified(proof.ProofError)
  /// The DSSE signature is not this key's, which can only mean the key
  /// file and the statement disagree about who is signing.
  NotOurSignature
}

pub type Outcome {
  Outcome(
    key_tag: Int,
    action: String,
    log_index: Int,
    /// True when the entry was already in the log and only its checkpoint
    /// and audit path were refreshed.
    refreshed: Bool,
  )
}

/// Publishes (or refreshes) the record for `csk` at `apex`.
///
/// The action follows the ceremony (§5.4): the first key logged for a zone
/// is a `create`; a key logged while another already has a record is a
/// `rollover` naming the tag it replaces.
pub fn run(
  conn: Connection,
  apex: Name,
  csk: Csk,
  log: Log,
  log_key: #(BitArray, BitArray),
  now: Int,
) -> Result(Outcome, PublishError) {
  let key_tag = keys.key_tag(keys.dnskey_rdata(csk))
  use replaces <- result.try(previous_key_tag(conn, key_tag))
  let action = case replaces {
    Some(_) -> "rollover"
    None -> "create"
  }
  let payload =
    statement.to_json(statement.for_key(apex, csk.public, action, replaces))

  // Reuse the stored entry when it is byte-identical: the signature is what
  // the log indexed, so re-signing would mint a new entry for the same
  // claim.
  use stored <- result.try(
    store.get(conn, key_tag, action) |> result.map_error(Db),
  )
  let signature = case stored {
    Ok(record) if record.dsse_payload == payload -> record.dsse_signature
    _ -> statement.sign(csk, payload)
  }
  use Nil <- result.try(case statement.verify(csk.public, payload, signature) {
    True -> Ok(Nil)
    False -> Error(NotOurSignature)
  })

  let entry =
    proof.entry_bytes(
      Proof(
        key_tag: key_tag,
        log_id: <<>>,
        log_index: 0,
        dsse_payload: payload,
        dsse_signature: signature,
        checkpoint: <<>>,
        inclusion_path: [],
      ),
    )
  use #(logged, refreshed) <- result.try(fetch_or_submit(log, entry))

  let record =
    Proof(
      key_tag: key_tag,
      log_id: logged.log_id,
      log_index: logged.log_index,
      dsse_payload: payload,
      dsse_signature: signature,
      checkpoint: logged.checkpoint,
      inclusion_path: logged.inclusion_path,
    )
  use _ <- result.try(
    proof.verify_against_log(record, log_key.0, log_key.1)
    |> result.map_error(Unverified),
  )
  use Nil <- result.try(
    store.put(
      conn,
      store.Record(
        key_tag: key_tag,
        apex: name.to_string(apex),
        action: action,
        dsse_payload: payload,
        dsse_signature: signature,
        log_id: logged.log_id,
        log_index: logged.log_index,
        checkpoint: logged.checkpoint,
        inclusion_path: proof.join_path(logged.inclusion_path),
        integrated_at: logged.integrated_at,
        verified_at: now,
      ),
    )
    |> result.map_error(Db),
  )
  Ok(Outcome(key_tag, action, logged.log_index, refreshed))
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

/// Search the log before writing to it, so a republish costs a lookup and
/// not a duplicate entry.
fn fetch_or_submit(
  log: Log,
  entry: BitArray,
) -> Result(#(client.Entry, Bool), PublishError) {
  case log.lookup(entry) {
    Ok(Some(found)) -> Ok(#(found, True))
    Ok(None) ->
      log.submit(entry)
      |> result.map(fn(added) { #(added, False) })
      |> result.map_error(LogUnavailable)
    Error(why) -> Error(LogUnavailable(why))
  }
}

/// The proof a served TXT record carries, rebuilt from a stored row.
pub fn to_proof(record: store.Record) -> Result(Proof, proof.ProofError) {
  use path <- result.try(proof.split_path(record.inclusion_path))
  Ok(Proof(
    key_tag: record.key_tag,
    log_id: record.log_id,
    log_index: record.log_index,
    dsse_payload: record.dsse_payload,
    dsse_signature: record.dsse_signature,
    checkpoint: record.checkpoint,
    inclusion_path: path,
  ))
}
