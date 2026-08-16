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
import gleam/crypto
import gleam/option.{type Option, None, Some}
import gleam/result
import rekor/client.{type Log, Submission}
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
  /// The entry the log returned does not carry this key's signature, which
  /// can only mean the key file and the statement disagree about who signs.
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
  let statement_bytes =
    statement.to_json(statement.for_key(apex, csk.public, action, replaces))

  // Reuse the exact signature a prior run already logged when the Statement
  // is byte-identical: ECDSA signing is randomized, so a fresh signature is
  // a fresh entry, and one key deserves one claim. The signature lives inside
  // the stored `canonicalizedBody`, so a republish reads it back out.
  use stored <- result.try(
    store.get(conn, key_tag, action) |> result.map_error(Db),
  )
  let refreshed = case stored {
    Ok(_) -> True
    Error(Nil) -> False
  }
  let signature = reusable_signature(stored, statement_bytes, csk)
  use Nil <- result.try(
    case statement.verify(csk.public, statement_bytes, signature) {
      True -> Ok(Nil)
      False -> Error(NotOurSignature)
    },
  )

  // The submission is a hashedrekord over the DSSE PAE: its digest, the DER
  // signature, and this key's DER SubjectPublicKeyInfo as the verifier.
  let digest =
    crypto.hash(
      crypto.Sha256,
      statement.pae(statement.dsse_payload_type, statement_bytes),
    )
  let submission = Submission(digest, signature, proof.p256_spki(csk.public))
  use logged <- result.try(
    log.submit(submission) |> result.map_error(LogUnavailable),
  )

  let record =
    Proof(
      key_tag: key_tag,
      // Our log-id convention is SHA-256 of the DER SPKI; the server's own
      // keyId is derived differently, so name the log by our pinned key.
      log_id: proof.log_id(log_key.0),
      log_index: logged.log_index,
      statement: statement_bytes,
      canonicalized_body: logged.canonicalized_body,
      checkpoint: logged.checkpoint,
      inclusion_path: logged.inclusion_path,
    )

  // Verify the returned proof by the same rules the client applies, before a
  // row exists: the body's digest is this Statement's PAE, the entry
  // signature is this key's, the verifier the log recorded is this key, and
  // the entry is in the tree the checkpoint commits to.
  use _ <- result.try(
    verify_entry(record, csk, log_key) |> result.map_error(Unverified),
  )
  use Nil <- result.try(
    store.put(
      conn,
      store.Record(
        key_tag: key_tag,
        apex: name.to_string(apex),
        action: action,
        statement: statement_bytes,
        canonicalized_body: logged.canonicalized_body,
        log_id: record.log_id,
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

/// The signature to submit: a prior run's, reused verbatim when the Statement
/// has not changed, else a fresh DER signature over the PAE.
fn reusable_signature(
  stored: Result(store.Record, Nil),
  statement_bytes: BitArray,
  csk: Csk,
) -> BitArray {
  case stored {
    Ok(record) if record.statement == statement_bytes ->
      case proof.parse_body(record.canonicalized_body) {
        Ok(#(_digest, signature, _verifier)) -> signature
        Error(_) -> statement.sign(csk, statement_bytes)
      }
    _ -> statement.sign(csk, statement_bytes)
  }
}

/// The client's whole verification, run before storing: possession, the
/// verifier binding, and inclusion under the log's signed checkpoint.
fn verify_entry(
  record: Proof,
  csk: Csk,
  log_key: #(BitArray, BitArray),
) -> Result(Nil, proof.ProofError) {
  use #(digest, signature, verifier) <- result.try(proof.parse_body(
    record.canonicalized_body,
  ))
  use Nil <- result.try(
    case
      digest
      == crypto.hash(
        crypto.Sha256,
        statement.pae(statement.dsse_payload_type, record.statement),
      )
    {
      True -> Ok(Nil)
      False ->
        Error(proof.Binding(
          "the logged entry's digest is not this statement's DSSE PAE",
        ))
    },
  )
  use Nil <- result.try(case verifier == proof.p256_spki(csk.public) {
    True -> Ok(Nil)
    False ->
      Error(proof.Binding("the logged verifier key is not this zone's DNSKEY"))
  })
  use Nil <- result.try(
    case statement.verify(csk.public, record.statement, signature) {
      True -> Ok(Nil)
      False ->
        Error(proof.Possession("the entry signature is not this zone key's"))
    },
  )
  use _ <- result.try(verify_against_log_wrap(record, log_key))
  Ok(Nil)
}

fn verify_against_log_wrap(
  record: Proof,
  log_key: #(BitArray, BitArray),
) -> Result(Nil, proof.ProofError) {
  proof.verify_against_log(record, log_key.0, log_key.1)
  |> result.map(fn(_) { Nil })
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

/// The proof a served TXT record carries, rebuilt from a stored row.
pub fn to_proof(record: store.Record) -> Result(Proof, proof.ProofError) {
  use path <- result.try(proof.split_path(record.inclusion_path))
  Ok(Proof(
    key_tag: record.key_tag,
    log_id: record.log_id,
    log_index: record.log_index,
    statement: record.statement,
    canonicalized_body: record.canonicalized_body,
    checkpoint: record.checkpoint,
    inclusion_path: path,
  ))
}
