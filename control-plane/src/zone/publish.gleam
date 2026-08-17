//// The one write path for zone contents: bump the serial, rebuild and
//// re-sign the whole zone, replace the presigned RRsets and NSEC chain —
//// all inside one transaction with whatever product mutation triggered
//// it. The zone is small; a full re-sign is sub-second and leaves no
//// partial-invalidation logic to get wrong.

import dns/name.{type Name}
import dns/rdata
import dnssec/keys.{type Csk}
import dnssec/sign
import gleam/bit_array
import gleam/crypto
import gleam/int
import gleam/list
import gleam/result
import rekor/gate
import store/sqlite.{type Connection, Blob, Int as VInt, Text}
import zone/build.{type Rrset}
import zone/model
import zone/render_external

pub type PublishError {
  Db(sqlite.Error)
  Model(model.ModelError)
  Build(build.BuildError)
  /// The key file's public half does not match zone_meta — wrong key file.
  KeyMismatch
  /// The active zone key has no verified transparency-log record and this
  /// emission would widen what the zone claims (docs/REKOR-ZONE-KEY.md §5.3).
  /// Refusing to publish is the same stance as the §3.2 build-time checks:
  /// never emit a zone clients are going to reject.
  NoRekorRecord(key_tag: Int)
  /// `zone-key stage` was handed the key already in service.
  IncomingIsActive
  /// `zone-key promote` was run with no rollover in flight.
  NoIncomingKey
}

/// What an emission does to what the zone claims — the whole of the publish
/// gate's question.
///
/// Chosen by the call site, because only the call site knows: a handler that
/// inserts a device or a key, or promotes a zone key, is `Widening`; one that
/// deletes rows or moves a key to `revoked` is `Narrowing`. Anything unsure of
/// itself is `Widening`.
pub type Change {
  /// The zone will claim something it has not claimed before. Gated: an
  /// unlogged key must not put new content on the wire.
  Widening
  /// The zone will claim strictly less than it did — a revoked key, a deleted
  /// device, an unassigned network member.
  ///
  /// Never gated, for the reason `publish_resign` is not: refusing a removal
  /// cannot withhold an unlogged key from anybody, because that key is already
  /// serving. It leaves the key live in the database *and* leaves the hourly
  /// re-sign renewing the RRSIGs over it, so the one thing a gap must never do
  /// — keep a revoked key resolvable — is exactly what refusing would do.
  Narrowing
}

/// A signed RRset ready to store and serve.
pub type Signed {
  Signed(
    owner: Name,
    rtype: Int,
    ttl: Int,
    rrset_wire: BitArray,
    rrsig_wire: BitArray,
  )
}

/// Signs every RRset. Pure; shared with tests, which point the actual
/// validators at its output.
pub fn sign_rrsets(
  rrsets: List(Rrset),
  csk: Csk,
  key_tag: Int,
  apex: Name,
  inception: Int,
  expiration: Int,
) -> List(Signed) {
  list.map(rrsets, fn(rrset) {
    let sorted = list.sort(rrset.rdatas, bit_array.compare)
    let rrset_wire =
      sorted
      |> list.map(fn(rd) { rdata.rr(rrset.owner, rrset.rtype, rrset.ttl, rd) })
      |> bit_array.concat
    let rrsig_wire =
      sign.sign_rrset(
        csk,
        key_tag,
        apex,
        rrset.owner,
        rrset.rtype,
        rrset.ttl,
        sorted,
        inception,
        expiration,
      )
    Signed(rrset.owner, rrset.rtype, rrset.ttl, rrset_wire, rrsig_wire)
  })
}

/// Publishes the zone: serial+1, rebuild, re-sign, replace. Runs in its
/// own transaction; call `publish_in_tx` instead when a product mutation
/// already holds one. Returns the new serial.
pub fn publish(
  conn: Connection,
  csk: Csk,
  now: Int,
  actor: String,
) -> Result(Int, PublishError) {
  sqlite.transaction(conn, Db, fn() {
    publish_in_tx(conn, csk, now, actor, Widening)
  })
}

/// Re-emits the zone unchanged because its signatures are aging out.
///
/// Ungated, and the reason is that a re-sign says nothing new. It emits the
/// same records clients have already been accepting, with fresh RRSIG windows;
/// refusing it does not withhold an unlogged key from anybody, because that
/// key is already serving. What refusing it does is let the zone's signatures
/// expire — `sig_validity` defaults to 14 days — at which point every
/// client fails closed on *DNSSEC*, not on transparency, and the whole zone
/// goes bogus. A transparency gap should not become a DNS outage.
///
/// `Widening` emissions are the gated ones. So the gate keeps doing its job —
/// no new content is emitted under an unlogged key — while the hourly job
/// keeps the zone resolvable long enough for an operator to run
/// `rekor-publish`.
pub fn publish_resign(
  conn: Connection,
  csk: Csk,
  now: Int,
  actor: String,
) -> Result(Int, PublishError) {
  sqlite.transaction(conn, Db, fn() { emit(conn, csk, now, actor, False) })
}

/// The publish body, for callers that already opened the transaction.
/// `change` decides whether the gate applies — see `Change`.
pub fn publish_in_tx(
  conn: Connection,
  csk: Csk,
  now: Int,
  actor: String,
  change: Change,
) -> Result(Int, PublishError) {
  emit(conn, csk, now, actor, case change {
    Widening -> True
    Narrowing -> False
  })
}

/// The publish body proper. `gated` says whether the transparency gate
/// applies to this emission.
fn emit(
  conn: Connection,
  csk: Csk,
  now: Int,
  actor: String,
  gated: Bool,
) -> Result(Int, PublishError) {
  use _ <- result.try(exec(
    conn,
    "UPDATE zone_meta SET soa_serial = soa_serial + 1 WHERE id = 1",
  ))
  use input <- result.try(model.read(conn) |> result.map_error(Model))
  let meta = input.meta
  use Nil <- result.try(case meta.dnskey_public == csk.public {
    True -> Ok(Nil)
    False -> Error(KeyMismatch)
  })
  use Nil <- result.try(case gated {
    False -> Ok(Nil)
    True ->
      gate.check(
        conn,
        meta.key_tag,
        crypto.hash(crypto.Sha256, keys.dnskey_rdata(csk)),
      )
      |> result.map_error(fn(e) {
        case e {
          gate.NoRecord(key_tag) -> NoRekorRecord(key_tag)
          gate.Db(error) -> Db(error)
        }
      })
  })
  use rrsets <- result.try(build.build(input) |> result.map_error(Build))
  let inception = now - meta.sig_inception_skew
  let expiration = now + meta.sig_validity
  let signed =
    sign_rrsets(
      build.sort_rrsets(rrsets),
      csk,
      meta.key_tag,
      meta.apex,
      inception,
      expiration,
    )

  use _ <- result.try(exec(conn, "DELETE FROM presigned_rrsets"))
  use Nil <- result.try(
    list.try_fold(signed, Nil, fn(_, s) {
      sqlite.exec(
        conn,
        "INSERT INTO presigned_rrsets VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
          Text(name.to_string(s.owner)),
          VInt(s.rtype),
          VInt(s.ttl),
          Blob(s.rrset_wire),
          Blob(s.rrsig_wire),
          VInt(expiration),
          VInt(meta.soa_serial),
          VInt(now),
          Blob(name.sort_key(s.owner)),
        ],
      )
      |> result.map_error(Db)
      |> result.replace(Nil)
    }),
  )

  use _ <- result.try(
    sqlite.exec(
      conn,
      "INSERT INTO audit_log (at, actor, org_id, action, detail)
       VALUES (?, ?, NULL, 'zone.publish', ?)",
      [
        VInt(now),
        Text(actor),
        Text(
          "{\"serial\":"
          <> int.to_string(meta.soa_serial)
          <> ",\"rrsets\":"
          <> int.to_string(list.length(signed))
          <> "}",
        ),
      ],
    )
    |> result.map_error(Db),
  )
  Ok(meta.soa_serial)
}

/// The external-mode publish: serial+1 and validation, in its own
/// transaction. Returns the new serial.
pub fn publish_external(
  conn: Connection,
  now: Int,
  actor: String,
) -> Result(Int, PublishError) {
  sqlite.transaction(conn, Db, fn() { publish_external_in_tx(conn, now, actor) })
}

/// The external-mode publish body (docs/EXTERNAL-DNS-PROVIDER.md): bump the
/// serial — still the generation counter the reconciler tracks — and
/// re-validate the product invariants through the renderer, refusing the
/// whole mutation on a violation exactly as the serving builder would.
/// Nothing is signed and nothing is presigned; commit marks "the database
/// changed", and the reconciler's next pass makes the wire follow.
pub fn publish_external_in_tx(
  conn: Connection,
  now: Int,
  actor: String,
) -> Result(Int, PublishError) {
  use _ <- result.try(exec(
    conn,
    "UPDATE zone_meta SET soa_serial = soa_serial + 1 WHERE id = 1",
  ))
  use input <- result.try(model.read(conn) |> result.map_error(Model))
  use records <- result.try(
    render_external.render(input) |> result.map_error(Build),
  )
  use _ <- result.try(
    sqlite.exec(
      conn,
      "INSERT INTO audit_log (at, actor, org_id, action, detail)
       VALUES (?, ?, NULL, 'zone.publish', ?)",
      [
        VInt(now),
        Text(actor),
        Text(
          "{\"serial\":"
          <> int.to_string(input.meta.soa_serial)
          <> ",\"records\":"
          <> int.to_string(list.length(records))
          <> ",\"mode\":\"external\"}",
        ),
      ],
    )
    |> result.map_error(Db),
  )
  Ok(input.meta.soa_serial)
}

/// Bootstraps zone_meta for external mode: there is no zone key — the
/// provider signs — so the key columns hold an empty key and tag 0, and on
/// later boots only the domain is verified. A database that carries a real
/// key was a serve-mode zone; refusing is what stops a mode flip from
/// quietly abandoning a served zone.
pub fn ensure_meta_external(
  conn: Connection,
  base_domain: String,
) -> Result(Nil, String) {
  case model.read_meta(conn) {
    Ok(meta) -> {
      let same_domain = name.to_string(meta.apex) == base_domain <> "."
      case same_domain, meta.dnskey_public == <<>> {
        True, True -> Ok(Nil)
        False, _ ->
          Error(
            "zone_meta base domain "
            <> name.to_string(meta.apex)
            <> " does not match configured "
            <> base_domain,
          )
        _, False ->
          Error(
            "this database belongs to a serve-mode zone (it has a zone key); "
            <> "refusing to run CP_DNS_MODE=external against it",
          )
      }
    }
    Error(model.NoZoneMeta) ->
      sqlite.exec(
        conn,
        "INSERT INTO zone_meta
           (id, base_domain, soa_serial, dnskey_public, key_tag,
            sig_inception_skew, sig_validity, sig_refresh_before)
         VALUES (1, ?, 0, ?, 0, 3600, 1209600, 604800)",
        [Text(base_domain), Blob(<<>>)],
      )
      |> result.replace(Nil)
      |> result.map_error(fn(_) { "could not initialize zone_meta" })
    Error(_) -> Error("could not read zone_meta")
  }
}

/// Bootstraps zone_meta on first start; on later starts verifies the
/// stored zone identity against the configuration. A mismatch is refused —
/// pointing a primary at the wrong database or key must not "fix" itself.
pub fn ensure_meta(
  conn: Connection,
  base_domain: String,
  csk: Csk,
) -> Result(Nil, String) {
  let dnskey_rd = keys.dnskey_rdata(csk)
  let tag = keys.key_tag(dnskey_rd)
  case model.read_meta(conn) {
    Ok(meta) -> {
      let same_domain = name.to_string(meta.apex) == base_domain <> "."
      case same_domain, meta.dnskey_public == csk.public {
        True, True -> Ok(Nil)
        False, _ ->
          Error(
            "zone_meta base domain "
            <> name.to_string(meta.apex)
            <> " does not match configured "
            <> base_domain,
          )
        // A key file that matches the *staged* key is the second half of a
        // rollover: the operator has swapped in the incoming key and this
        // boot is meant to promote it. Say exactly that, because the
        // generic message sends them looking for the wrong key file.
        _, False ->
          case meta.dnskey_incoming == csk.public {
            True ->
              Error(
                "this key file is the staged incoming key (tag "
                <> int.to_string(meta.key_tag_incoming)
                <> "), which is published but not yet promoted; run "
                <> "`controlplane zone-key promote` before serving with it",
              )
            False ->
              Error(
                "zone key file does not match the key this zone was created with",
              )
          }
      }
    }
    Error(model.NoZoneMeta) ->
      sqlite.exec(
        conn,
        "INSERT INTO zone_meta
           (id, base_domain, soa_serial, dnskey_public, key_tag,
            sig_inception_skew, sig_validity, sig_refresh_before)
         VALUES (1, ?, 0, ?, ?, 3600, 1209600, 604800)",
        [Text(base_domain), Blob(csk.public), VInt(tag)],
      )
      |> result.replace(Nil)
      |> result.map_error(fn(_) { "could not initialize zone_meta" })
    Error(_) -> Error("could not read zone_meta")
  }
}

/// Replaces the nameserver set (operator configuration, applied at boot)
/// — atomically, so a crash mid-boot can't leave a half-written NS set.
pub fn set_ns_hosts(
  conn: Connection,
  hosts: List(#(String, String, String)),
) -> Result(Nil, sqlite.Error) {
  sqlite.transaction(conn, fn(e) { e }, fn() {
    use _ <- result.try(sqlite.exec(conn, "DELETE FROM zone_ns", []))
    list.try_fold(hosts, Nil, fn(_, host) {
      let #(hostname, ipv4, ipv6) = host
      sqlite.exec(conn, "INSERT INTO zone_ns VALUES (?, ?, ?)", [
        Text(hostname),
        sqlite.text_or_null(ipv4),
        sqlite.text_or_null(ipv6),
      ])
      |> result.replace(Nil)
    })
  })
}

fn exec(conn: Connection, sql: String) -> Result(Nil, PublishError) {
  exec_with(conn, sql, [])
}

fn exec_with(
  conn: Connection,
  sql: String,
  params: List(sqlite.Value),
) -> Result(Nil, PublishError) {
  sqlite.exec(conn, sql, params)
  |> result.map_error(Db)
  |> result.replace(Nil)
}

/// Stages the key a rollover is bringing in.
///
/// Public half only — the incoming key never signs while it is staged, it
/// only rides in the DNSKEY RRset so the parent can be handed its DS and
/// `rekor-publish` can claim a key set that already contains it. The
/// republish this does is *not* gated: the signing key is unchanged and
/// already on the record, so nothing here is a claim the gate exists to
/// hold back.
pub fn stage_incoming(
  conn: Connection,
  csk: Csk,
  incoming_public: BitArray,
  now: Int,
  actor: String,
) -> Result(Int, PublishError) {
  sqlite.transaction(conn, Db, fn() {
    stage_incoming_in_tx(conn, csk, incoming_public, now, actor)
  })
}

fn stage_incoming_in_tx(
  conn: Connection,
  csk: Csk,
  incoming_public: BitArray,
  now: Int,
  actor: String,
) -> Result(Int, PublishError) {
  use meta <- result.try(model.read_meta(conn) |> result.map_error(Model))
  use Nil <- result.try(case incoming_public == meta.dnskey_public {
    True -> Error(IncomingIsActive)
    False -> Ok(Nil)
  })
  let tag =
    keys.key_tag(rdata.dnskey(keys.flags, keys.algorithm, incoming_public))
  use _ <- result.try(
    exec_with(
      conn,
      "UPDATE zone_meta SET dnskey_incoming = ?, key_tag_incoming = ? WHERE id = 1",
      [Blob(incoming_public), VInt(tag)],
    ),
  )
  emit(conn, csk, now, actor, False)
}

/// Promotes the staged key: it becomes the signer, and the outgoing key
/// leaves the RRset.
///
/// `csk` must be the incoming key's own file — this is the boot where the
/// operator has swapped it in. Gated, because after this the zone is signed
/// by a key that had better already be on the public record; that is the
/// whole point of having published and logged it while it was staged.
pub fn promote_incoming(
  conn: Connection,
  csk: Csk,
  now: Int,
  actor: String,
) -> Result(Int, PublishError) {
  sqlite.transaction(conn, Db, fn() {
    promote_incoming_in_tx(conn, csk, now, actor)
  })
}

fn promote_incoming_in_tx(
  conn: Connection,
  csk: Csk,
  now: Int,
  actor: String,
) -> Result(Int, PublishError) {
  use meta <- result.try(model.read_meta(conn) |> result.map_error(Model))
  use Nil <- result.try(case meta.dnskey_incoming {
    <<>> -> Error(NoIncomingKey)
    incoming ->
      case incoming == csk.public {
        True -> Ok(Nil)
        False -> Error(KeyMismatch)
      }
  })
  let tag = keys.key_tag(keys.dnskey_rdata(csk))
  use _ <- result.try(
    exec_with(
      conn,
      "UPDATE zone_meta
        SET dnskey_public = ?, key_tag = ?,
            dnskey_incoming = ?, key_tag_incoming = 0
      WHERE id = 1",
      [Blob(csk.public), VInt(tag), Blob(<<>>)],
    ),
  )
  emit(conn, csk, now, actor, True)
}
