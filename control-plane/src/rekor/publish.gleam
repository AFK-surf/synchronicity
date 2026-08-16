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
//// Nothing is stored that has not been verified here first, by the rules
//// crates/synch-net's verifier applies: possession (the DSSE signature is
//// the zone key's), binding (the certificate names this key and this apex),
//// inclusion, and the log's signature on the checkpoint. A row in
//// `rekor_records` means *this service checked it*. The one rule this side
//// cannot re-run is the cryptographic chain walk — that lives in the Rust
//// verifier, and the e2e crossval is what keeps this side honest about it.

import dns/name.{type Name}
import dnssec/keys.{type Csk}
import gleam/crypto
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import rekor/cert
import rekor/chain
import rekor/client.{type Log, Submission}
import rekor/proof.{type Proof, Proof}
import rekor/statement
import rekor/store
import store/sqlite.{type Connection}

/// How long a zone-key certificate claims to be valid.
///
/// A century. The window is **semantically meaningless** — nothing in Rekor,
/// in the client or in the monitor reads it, because the certificate is a key
/// envelope and not a trust assertion — but X.509 has a mandatory field
/// there, so it is filled in with something honest rather than something
/// that looks like a policy.
const certificate_lifetime_seconds = 3_155_760_000

pub type PublishError {
  Db(sqlite.Error)
  /// The log refused, or could not be reached.
  LogUnavailable(String)
  /// The proof did not verify locally — never stored.
  Unverified(proof.ProofError)
  /// The entry the log returned does not carry this key's signature, which
  /// can only mean the key file and the statement disagree about who signs.
  NotOurSignature
  /// The DNSSEC chain could not be collected. Almost always one thing: the
  /// DS is not live in the parent yet, and logging comes after that now.
  NoChain(String)
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
  )
}

/// Publishes (or refreshes) the record for `csk` at `apex`.
///
/// The action follows the ceremony (§5.4): the first key logged for a zone
/// is a `create`; a key logged while another already has a record is a
/// `rollover` naming the tag it replaces. `replacesKeyTag` in the Statement
/// is rollover *metadata* — it says which key this one supersedes — and it
/// is not evidence of anything: nothing signs it but the new key itself.
pub fn run(
  conn: Connection,
  apex: Name,
  csk: Csk,
  log: Log,
  log_key: #(BitArray, BitArray),
  now: Int,
  resolver: chain.Resolver,
  action: String,
) -> Result(Outcome, PublishError) {
  let key_tag = keys.key_tag(keys.dnskey_rdata(csk))
  let spki_sha256 = crypto.hash(crypto.Sha256, proof.p256_spki(csk.public))
  use replaces <- result.try(previous_key_tag(conn, key_tag))
  let statement_bytes =
    statement.to_json(statement.for_key(apex, csk.public, action, replaces))

  // Reuse the exact bytes a prior run already logged when the Statement is
  // byte-identical. ECDSA signing is randomized *and* a freshly collected
  // chain carries fresh RRSIGs, so rebuilding either would mint a second
  // leaf for one claim — Rekor is content-addressed, so reusing them is what
  // makes a republish a refresh.
  use stored <- result.try(
    store.get(conn, spki_sha256, key_tag, action) |> result.map_error(Db),
  )
  use #(signature, certificate, refreshed) <- result.try(
    case reusable(stored, statement_bytes) {
      Ok(#(signature, certificate)) -> Ok(#(signature, certificate, True))
      Error(Nil) -> {
        use certificate <- result.try(mint_certificate(
          apex,
          csk,
          action,
          now,
          resolver,
        ))
        Ok(#(statement.sign(csk, statement_bytes), certificate, False))
      }
    },
  )

  use Nil <- result.try(
    case statement.verify(csk.public, statement_bytes, signature) {
      True -> Ok(Nil)
      False -> Error(NotOurSignature)
    },
  )

  // The submission is a hashedrekord over the DSSE PAE: its digest, the DER
  // signature, and the certificate that names this key and this zone.
  let digest =
    crypto.hash(
      crypto.Sha256,
      statement.pae(statement.dsse_payload_type, statement_bytes),
    )
  let submission = Submission(digest, signature, certificate)
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

  // Verify the returned proof by the rules the client applies, before a row
  // exists: the body's digest is this Statement's PAE, the entry signature is
  // this key's, the certificate the log recorded names this key and this
  // apex, and the entry is in the tree the checkpoint commits to.
  use verified <- result.try(
    verify_entry(record, apex, csk) |> result.map_error(Unverified),
  )
  use _ <- result.try(
    proof.verify_against_log(record, log_key.0, log_key.1)
    |> result.map_error(Unverified),
  )
  use Nil <- result.try(
    store.put(
      conn,
      store.Record(
        spki_sha256: spki_sha256,
        key_tag: key_tag,
        apex: name.to_string(apex),
        action: action,
        statement: statement_bytes,
        canonicalized_body: logged.canonicalized_body,
        log_id: record.log_id,
        log_index: logged.log_index,
        checkpoint: logged.checkpoint,
        inclusion_path: proof.join_path(logged.inclusion_path),
        chainless: verified.chainless,
        integrated_at: logged.integrated_at,
        verified_at: now,
      ),
    )
    |> result.map_error(Db),
  )
  Ok(Outcome(key_tag, action, logged.log_index, refreshed, verified.chainless))
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

/// The signature and certificate a prior run logged, when the Statement is
/// unchanged and the stored body still parses.
///
/// Reuse is what makes a republish a *refresh*. ECDSA signing is randomized
/// and a freshly collected chain carries fresh RRSIGs, so rebuilding either
/// would mint a second Merkle leaf for one claim — two public claims about
/// one key, where the operator asked for one.
///
/// The Statement is now the whole test. It did not used to be: a run that
/// named a predecessor keyfile had something to add that lived in the
/// *certificate* rather than the Statement, so Statement equality alone
/// would have thrown the new countersignature away and reported success.
/// With the countersignature gone the certificate carries nothing the
/// Statement does not imply, and the extra condition went with it.
fn reusable(
  stored: Result(store.Record, Nil),
  statement_bytes: BitArray,
) -> Result(#(BitArray, BitArray), Nil) {
  use record <- result.try(case stored {
    Ok(record) if record.statement == statement_bytes -> Ok(record)
    _ -> Error(Nil)
  })
  use #(_digest, signature, certificate) <- result.try(
    proof.parse_body(record.canonicalized_body) |> result.replace_error(Nil),
  )
  Ok(#(signature, certificate))
}

/// Builds the certificate a fresh entry carries.
///
/// `create` and `rollover` must carry a chain, and failing here is the point:
/// an entry without one is refused by every client, so discovering it now —
/// with an operator standing at the terminal reading "is the DS live in the
/// parent yet?" — beats discovering it later from a cluster that will not
/// resolve. There is deliberately no escape hatch: with logging moved to
/// after the DS is live, every key this service logs has one — a zone's
/// genesis key included.
fn mint_certificate(
  apex: Name,
  csk: Csk,
  action: String,
  now: Int,
  resolver: chain.Resolver,
) -> Result(BitArray, PublishError) {
  let apex_text = name.to_string(apex)
  use links <- result.try(case action {
    // A retired zone may have no DS left to build a chain from. Clients
    // refuse a retire as authorization outright, so this cannot be turned
    // into an evasion — it is a breadcrumb for monitors and nothing else.
    "retire" -> Ok(None)
    _ ->
      case chain.collect(resolver, apex) {
        Error(why) -> Error(NoChain(why))
        Ok(links) ->
          // Walk what was just collected before it goes anywhere. This side
          // cannot check the signatures — that is the client's and the
          // monitor's job — but it can check the chain reaches the root, and
          // a chain that does not is one every reader refuses.
          case chain.check_shape(links, apex) {
            Error(why) -> Error(NoChain(why))
            Ok(Nil) ->
              Ok(
                Some(
                  list.map(links, fn(link) { cert.Link(link.zone, link.rrs) }),
                ),
              )
          }
      }
  })
  Ok(cert.build(
    apex_text,
    csk.public,
    csk.private,
    now,
    now + certificate_lifetime_seconds,
    links,
  ))
}

/// What verifying a returned entry established, beyond "it is sound".
type Verified {
  Verified(chainless: Bool)
}

@external(erlang, "cp_crypto_ffi", "cert_spki_and_san")
fn cert_spki_and_san(der: BitArray) -> Result(#(BitArray, String), Nil)

/// The client's verification, run before storing: the digest, possession,
/// and the certificate's two bindings — its key and its name.
fn verify_entry(
  record: Proof,
  apex: Name,
  csk: Csk,
) -> Result(Verified, proof.ProofError) {
  use #(digest, signature, certificate) <- result.try(proof.parse_body(
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
  use #(spki, san) <- result.try(
    cert_spki_and_san(certificate)
    |> result.replace_error(proof.Malformed(
      "the logged certificate does not decode, or has no single dNSName SAN",
    )),
  )
  use Nil <- result.try(case spki == proof.p256_spki(csk.public) {
    True -> Ok(Nil)
    False ->
      Error(proof.Binding(
        "the logged certificate's key is not this zone's DNSKEY",
      ))
  })
  use Nil <- result.try(case san == cert.san_name(name.to_string(apex)) {
    True -> Ok(Nil)
    False ->
      Error(proof.Binding(
        "the logged certificate names " <> san <> ", not this apex",
      ))
  })
  use Nil <- result.try(
    case statement.verify(csk.public, record.statement, signature) {
      True -> Ok(Nil)
      False ->
        Error(proof.Possession("the entry signature is not this zone key's"))
    },
  )
  Ok(Verified(
    chainless: !cert_has_extension(certificate, cert.oid_dnssec_chain),
  ))
}

@external(erlang, "cp_crypto_ffi", "cert_extension")
fn cert_extension(der: BitArray, oid: #(Int, Int, Int)) -> Result(BitArray, Nil)

fn cert_has_extension(der: BitArray, oid: #(Int, Int, Int)) -> Bool {
  case cert_extension(der, oid) {
    Ok(_) -> True
    Error(Nil) -> False
  }
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
