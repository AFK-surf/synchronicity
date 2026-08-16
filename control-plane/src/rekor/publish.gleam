//// `controlplane rekor-publish`: put the zone's key set on the public
//// record.
////
//// Separate from `keygen` on purpose (§5.2): key generation stays runnable
//// on an offline host, and this step — the one that needs egress — is
//// explicit and idempotent. Re-running refreshes the stored checkpoint and
//// audit path against a grown tree without minting a second entry, because
//// two entries would be two public claims about one key set.
////
//// **What an entry claims is the apex DNSKEY RRset the chain proves** — the
//// key set observed on the live wire at publish time, not a key named from
//// memory. The sequence is: get the DS live in the parent, publish the
//// DNSKEY RRset in the zone, *then* log; collection reads the RRset and the
//// chain in one pass, so the claim and its proof cannot disagree. The DSSE
//// signature is attribution — it names the `signer` (the CSK in serve mode,
//// an operational key when the zone is provider-hosted) via the entry's
//// certificate, and authorizes nothing. Authorization is the chain.
////
//// A `retire` is the one exception: a zone being retired may have no DS
//// left to build a chain from, so a chainless retire is allowed and marked
//// as such, and the caller names the keys being retired. Clients never
//// treat a retire as authorization (they refuse the action outright), so
//// the exception cannot be turned into an evasion.
////
//// Nothing is stored that has not been verified here first, by the rules
//// crates/synch-net's verifier applies: attribution (the DSSE signature is
//// the certificate's key's), binding (the certificate names this apex and
//// this signer), inclusion, and the log's signature on the checkpoint. A
//// row in `rekor_records` means *this service checked it*. The one rule
//// this side cannot re-run is the cryptographic chain walk — that lives in
//// the Rust verifier, and the e2e crossval is what keeps this side honest
//// about it.

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

/// What to log.
pub type Claim {
  /// The key set the live chain proves right now — a `create` for a zone's
  /// first record, a `rollover` for any later set.
  Current
  /// A retirement breadcrumb for these DNSKEY rdatas; chainless allowed.
  Retire(subjects: List(BitArray))
}

pub type PublishError {
  Db(sqlite.Error)
  /// The log refused, or could not be reached.
  LogUnavailable(String)
  /// The proof did not verify locally — never stored.
  Unverified(proof.ProofError)
  /// The entry the log returned does not carry the signer's signature, which
  /// can only mean the key file and the statement disagree about who signs.
  NotOurSignature
  /// The DNSSEC chain could not be collected. Almost always one thing: the
  /// DS is not live in the parent yet, and logging comes after that now.
  NoChain(String)
}

pub type Outcome {
  Outcome(
    key_tags: List(Int),
    action: String,
    log_index: Int,
    /// True when the entry was already in the log and only its checkpoint
    /// and audit path were refreshed.
    refreshed: Bool,
    /// True when this entry carries no DNSSEC chain — only ever a `retire`.
    chainless: Bool,
  )
}

/// Publishes (or refreshes) the record for the claimed set at `apex`, DSSE-
/// signed by `signer`.
pub fn run(
  conn: Connection,
  apex: Name,
  signer: Csk,
  log: Log,
  log_key: #(BitArray, BitArray),
  now: Int,
  resolver: chain.Resolver,
  claim: Claim,
) -> Result(Outcome, PublishError) {
  // The subject set and the chain come out of one collection pass, so the
  // claim and its proof cannot disagree about what the zone's keys are.
  use #(links, subjects) <- result.try(case claim {
    Retire(subjects) -> Ok(#(None, subjects))
    Current ->
      case chain.collect(resolver, apex) {
        Error(why) -> Error(NoChain(why))
        Ok(#(links, rdatas)) ->
          case chain.check_shape(links, apex), rdatas {
            Error(why), _ -> Error(NoChain(why))
            Ok(Nil), [] ->
              Error(NoChain("the apex answered no DNSKEY RRset to claim"))
            Ok(Nil), rdatas ->
              Ok(#(
                Some(
                  list.map(links, fn(link) { cert.Link(link.zone, link.rrs) }),
                ),
                rdatas,
              ))
          }
      }
  })

  use #(action, stored) <- result.try(action_and_stored(
    conn,
    apex,
    subjects,
    claim,
  ))
  let claimed = statement.for_keys(apex, subjects, action)
  let statement_bytes = statement.to_json(claimed)
  let keyset_sha256 = statement.keyset_sha256(claimed)

  // Reuse the exact bytes a prior run already logged when the Statement is
  // byte-identical. ECDSA signing is randomized *and* a freshly collected
  // chain carries fresh RRSIGs, so rebuilding either would mint a second
  // leaf for one claim — Rekor is content-addressed, so reusing them is what
  // makes a republish a refresh.
  use #(signature, certificate, refreshed) <- result.try(
    case reusable(stored, statement_bytes) {
      Ok(#(signature, certificate)) -> Ok(#(signature, certificate, True))
      Error(Nil) -> {
        let certificate =
          cert.build(
            name.to_string(apex),
            signer.public,
            signer.private,
            now,
            now + certificate_lifetime_seconds,
            links,
          )
        Ok(#(statement.sign(signer, statement_bytes), certificate, False))
      }
    },
  )

  use Nil <- result.try(
    case statement.verify(signer.public, statement_bytes, signature) {
      True -> Ok(Nil)
      False -> Error(NotOurSignature)
    },
  )

  // The submission is a hashedrekord over the DSSE PAE: its digest, the DER
  // signature, and the certificate that names the signer and this zone.
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
  // the signer's, the certificate the log recorded names this signer and
  // this apex, and the entry is in the tree the checkpoint commits to.
  use verified <- result.try(
    verify_entry(record, apex, signer) |> result.map_error(Unverified),
  )
  use _ <- result.try(
    proof.verify_against_log(record, log_key.0, log_key.1)
    |> result.map_error(Unverified),
  )
  use Nil <- result.try(
    store.put(
      conn,
      store.Record(
        keyset_sha256: keyset_sha256,
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
        keys: list.map(subjects, fn(rdata) {
          #(crypto.hash(crypto.Sha256, rdata), keys.key_tag(rdata))
        }),
      ),
    )
    |> result.map_error(Db),
  )
  Ok(Outcome(
    list.map(claimed.keys, fn(key) { key.key_tag }),
    action,
    logged.log_index,
    refreshed,
    verified.chainless,
  ))
}

/// The action for this claim, and the stored row it refreshes if one exists.
///
/// A set already logged keeps its action — re-running is a refresh, never a
/// second claim. A new set is a `create` when the zone has no record yet and
/// a `rollover` after that; a retire is a retire.
fn action_and_stored(
  conn: Connection,
  apex: Name,
  subjects: List(BitArray),
  claim: Claim,
) -> Result(#(String, Result(store.Record, Nil)), PublishError) {
  let keyset = fn(action) {
    statement.keyset_sha256(statement.for_keys(apex, subjects, action))
  }
  case claim {
    Retire(_) -> {
      use stored <- result.try(
        store.get(conn, keyset("retire"), "retire") |> result.map_error(Db),
      )
      Ok(#("retire", stored))
    }
    Current -> {
      use created <- result.try(
        store.get(conn, keyset("create"), "create") |> result.map_error(Db),
      )
      use rolled <- result.try(
        store.get(conn, keyset("rollover"), "rollover") |> result.map_error(Db),
      )
      case created, rolled {
        Ok(record), _ -> Ok(#("create", Ok(record)))
        _, Ok(record) -> Ok(#("rollover", Ok(record)))
        Error(Nil), Error(Nil) -> {
          use any <- result.try(
            store.any_verified(conn) |> result.map_error(Db),
          )
          Ok(#(
            case any {
              True -> "rollover"
              False -> "create"
            },
            Error(Nil),
          ))
        }
      }
    }
  }
}

/// The signature and certificate a prior run logged, when the Statement is
/// unchanged and the stored body still parses.
///
/// Reuse is what makes a republish a *refresh*. ECDSA signing is randomized
/// and a freshly collected chain carries fresh RRSIGs, so rebuilding either
/// would mint a second Merkle leaf for one claim — two public claims about
/// one key set, where the operator asked for one.
///
/// The Statement is the whole test, and that is sound only because the
/// certificate carries nothing the Statement does not already imply: same
/// set, same apex, same action means same certificate. Anything added to the
/// certificate that is *not* implied by the Statement has to be compared
/// here too, or a rerun would silently reuse a stale one.
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

/// What verifying a returned entry established, beyond "it is sound".
type Verified {
  Verified(chainless: Bool)
}

@external(erlang, "cp_crypto_ffi", "cert_spki_and_san")
fn cert_spki_and_san(der: BitArray) -> Result(#(BitArray, String), Nil)

/// The client's verification, run before storing: the digest, attribution,
/// and the certificate's two bindings — its signer and its name.
fn verify_entry(
  record: Proof,
  apex: Name,
  signer: Csk,
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
  use Nil <- result.try(case spki == proof.p256_spki(signer.public) {
    True -> Ok(Nil)
    False ->
      Error(proof.Binding("the logged certificate's key is not this signer's"))
  })
  use Nil <- result.try(case san == cert.san_name(name.to_string(apex)) {
    True -> Ok(Nil)
    False ->
      Error(proof.Binding(
        "the logged certificate names " <> san <> ", not this apex",
      ))
  })
  use Nil <- result.try(
    case statement.verify(signer.public, record.statement, signature) {
      True -> Ok(Nil)
      False ->
        Error(proof.Attribution("the entry signature is not this signer's"))
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

/// The proof a served TXT record carries, rebuilt from a stored row.
pub fn to_proof(record: store.Record) -> Result(Proof, proof.ProofError) {
  use path <- result.try(proof.split_path(record.inclusion_path))
  Ok(Proof(
    log_id: record.log_id,
    log_index: record.log_index,
    statement: record.statement,
    canonicalized_body: record.canonicalized_body,
    checkpoint: record.checkpoint,
    inclusion_path: path,
  ))
}
