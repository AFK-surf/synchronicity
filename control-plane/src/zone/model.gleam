//// Reads the database into a pure description of the zone: who the
//// nameservers are and which membership records each network publishes.
//// Everything downstream (build, sign, serve) is pure functions of this.

import config
import dns/name.{type Name}
import dns/rdata
import dnssec/keys
import gleam/bit_array
import gleam/crypto
import gleam/list
import gleam/result
import gleam/string
import provider/state as provider_state
import rekor/proof
import rekor/publish as rekor_publish
import rekor/store as rekor_store
import store/sqlite.{type Connection, Text}
import thirtytwo

pub type ZoneMeta {
  ZoneMeta(
    apex: Name,
    soa_serial: Int,
    dnskey_public: BitArray,
    key_tag: Int,
    /// The key a rollover is bringing in: published in the DNSKEY RRset so
    /// the parent can be given its DS and `rekor-publish` can claim it, but
    /// never a signer until `zone-key promote` makes it `dnskey_public`.
    /// Empty when no rollover is in flight.
    dnskey_incoming: BitArray,
    key_tag_incoming: Int,
    sig_inception_skew: Int,
    sig_validity: Int,
    sig_refresh_before: Int,
  )
}

pub type NsHost {
  NsHost(host: Name, ipv4: String, ipv6: String)
}

/// One published member: a device's label and one of its live keys.
pub type Member {
  Member(label: String, nk_z32: String, relay: String, addr: String)
}

/// One `_synchronicity.<network>.<org>.<apex>` owner and its members.
pub type TxtName {
  TxtName(owner: Name, members: List(Member))
}

pub type ZoneInput {
  ZoneInput(
    meta: ZoneMeta,
    ns_hosts: List(NsHost),
    txt_names: List(TxtName),
    /// Zone-key transparency proofs for the key the zone publishes, in the
    /// base64url form one TXT record carries. Empty until `rekor-publish`
    /// has run — phase 0 of the rollout serves a zone without them.
    /// The proof records, each with the part number that decides its owner
    /// name: part 1 at `_synchronicity-rekor`, part n at
    /// `_synchronicity-rekor-<n>`.
    rekor_proofs: List(#(Int, String)),
    /// How many servable proofs the byte budget dropped (§4.2 of
    /// docs/EXTERNAL-APEX-OWNERSHIP.md). Normally zero — the serving filter
    /// keeps the set small enough that the budget is unreachable — and
    /// reported rather than silent when it is not, because a cap nobody is
    /// told about is how a zone quietly stops covering a live key.
    rekor_shed: Int,
    /// The control-plane endpoints the apex publishes
    /// (`_synchronicity-cp`), one record each.
    ///
    /// A deployment fact and not a policy: it says *this base's control plane
    /// answers here*, never which network may be browsed. Which network may
    /// is `networks.browse_enabled`, enforced at each endpoint.
    ///
    /// A list because the control plane is a fleet: the registry of attached
    /// daemons is one node's memory, so a node nobody has a tunnel to can
    /// answer no browse question, and every node that may be asked has to be
    /// named. `config.endpoints` builds it — this node's own URL, then
    /// `CP_ENDPOINTS`.
    cp_endpoints: List(String),
  )
}

pub type ModelError {
  NoZoneMeta
  BadStoredName(String)
  Db(sqlite.Error)
  /// A stored proof row cannot be turned back into servable TXT records.
  /// `rekor/publish` refuses to store a record that does not render, so this
  /// is a row that has been damaged since — reported rather than skipped,
  /// because a skipped proof is a zone quietly not covering a live key.
  UnservableProof(String)
}

/// Validates an nk in z-base-32: exactly a 32-byte key. Curve-point
/// validity is not checked — byte identity is what the record grammar
/// operates on, and the client re-parses fail-closed.
pub fn validate_nk(nk_z32: String) -> Result(BitArray, Nil) {
  use bytes <- result.try(thirtytwo.z_base_32_decode(nk_z32))
  case bit_array.byte_size(bytes) == 32 && string.length(nk_z32) == 52 {
    True -> Ok(bytes)
    False -> Error(Nil)
  }
}

pub fn read(conn: Connection) -> Result(ZoneInput, ModelError) {
  use meta <- result.try(read_meta(conn))
  use ns_hosts <- result.try(read_ns(conn, meta.apex))
  use txt_names <- result.try(read_txt_names(conn, meta.apex))
  use live_keys <- result.try(live_keys(conn, meta))
  use #(rekor_proofs, shed) <- result.try(read_rekor_proofs(conn, live_keys))
  Ok(ZoneInput(
    meta,
    ns_hosts,
    txt_names,
    rekor_proofs,
    shed,
    config.endpoints(),
  ))
}

/// The digests of the DNSKEY rdata this zone currently publishes — what the
/// serving filter holds proofs to (`rekor/store.servable`).
///
/// Each mode already knows its own key set, and the branch is the mode: a
/// zone key of its own means this service signs, so the set is what
/// `zone/build` puts in the DNSKEY RRset — the active key, plus the incoming
/// one while a rollover stages it. No key means external mode, where the
/// provider holds the keys and the watcher's `observed_zone_keys` is the
/// record of what it saw on the validated wire.
fn live_keys(
  conn: Connection,
  meta: ZoneMeta,
) -> Result(List(BitArray), ModelError) {
  case meta.dnskey_public {
    <<>> ->
      provider_state.observed_keys(conn)
      |> result.map_error(Db)
      |> result.map(list.map(_, fn(key) { key.key_sha256 }))
    public -> {
      let rdatas = case meta.dnskey_incoming {
        <<>> -> [rdata.dnskey(keys.flags, keys.algorithm, public)]
        incoming -> [
          rdata.dnskey(keys.flags, keys.algorithm, public),
          rdata.dnskey(keys.flags, keys.algorithm, incoming),
        ]
      }
      Ok(list.map(rdatas, crypto.hash(crypto.Sha256, _)))
    }
  }
}

/// The proof records this zone serves, and how many the budget dropped.
///
/// With key-set claims there is no per-tag selection — a client tries each
/// proof it can reassemble and membership in a verified set decides — so
/// what this has to get right is *which* claims are worth serving at all.
/// `servable` answers that: the ones covering a key the zone publishes.
///
/// A stored row that cannot be turned back into servable records fails the
/// read, rather than being skipped. Skipping it would make the publish gate's
/// question ("is there a row for this key?") a different question from the
/// serving one ("is there a proof at the proof name?"), and the gate would pass
/// while every client failed closed. `rekor/publish` refuses to store a record
/// it cannot render, so a row that will not render is damage — and damage is
/// worth a loud refusal, where the zone already published keeps serving and
/// somebody reads the error.
fn read_rekor_proofs(
  conn: Connection,
  live_keys: List(BitArray),
) -> Result(#(List(#(Int, String)), Int), ModelError) {
  use records <- result.try(
    rekor_store.servable(conn, live_keys) |> result.map_error(Db),
  )
  use encoded <- result.try(
    records
    |> list.try_map(fn(record) {
      case rekor_publish.to_proof(record) {
        Ok(built) ->
          proof.to_txt(built)
          |> result.map_error(fn(why) {
            UnservableProof("a stored proof does not render: " <> why)
          })
        Error(_) ->
          Error(UnservableProof(
            "a stored proof's audit path is not a run of 32-byte hashes",
          ))
      }
    }),
  )
  // `servable` returns newest first, so taking a prefix sheds the oldest
  // claims — the ones least likely to still be covering a key on the wire.
  let #(kept, shed) = proofs_within_budget(encoded)
  Ok(#(
    kept
      // One proof is several records, and they go to *different* owner names:
      // part 1 at the base, part n one label along. Providers cap the
      // combined content of a single name, and it is the base name that
      // fills up, because every proof has a part 1 and they all share it.
      |> list.flatten
      |> list.map(fn(text) { #(proof.part_index_of(text), text) }),
    shed,
  ))
}

/// The room a proof's part 1 has at the shared base name.
///
/// Cloudflare refuses more than 8192 wire-format bytes of combined content
/// at one name and type, the tightest cap among the providers this supports,
/// and the budget holds back one part's worth of that so a chain that grows
/// a delegation level does not tip the zone over. The serving filter is what
/// keeps the served set to two or three proofs in the first place; this is
/// the guard that makes a pathological set shed history instead of handing a
/// provider a write it will refuse.
const part_one_budget = 6144

/// The proofs that fit at the shared base name, newest first, and how many
/// older ones were dropped. Exposed so a table test can hold the budget
/// still without standing up a log.
pub fn proofs_within_budget(
  proofs: List(List(String)),
) -> #(List(List(String)), Int) {
  within_budget(proofs, 0, [], 0)
}

fn within_budget(
  proofs: List(List(String)),
  used: Int,
  kept: List(List(String)),
  shed: Int,
) -> #(List(List(String)), Int) {
  case proofs {
    [] -> #(list.reverse(kept), shed)
    [proof_parts, ..rest] -> {
      let cost = part_one_bytes(proof_parts)
      case used + cost > part_one_budget {
        // Everything behind this one is older, so it is shed too.
        True -> #(list.reverse(kept), shed + 1 + list.length(rest))
        False -> within_budget(rest, used + cost, [proof_parts, ..kept], shed)
      }
    }
  }
}

/// One part's wire cost: its characters plus the one length byte each
/// 255-byte character-string carries.
fn part_one_bytes(parts: List(String)) -> Int {
  parts
  |> list.filter(fn(text) { proof.part_index_of(text) == 1 })
  |> list.fold(0, fn(total, text) {
    let length = string.length(text)
    total + length + { length / 255 } + 1
  })
}

/// The health probe's view of the zone: current serial and the soonest
/// RRSIG expiry. Error(Nil) covers every unhealthy shape — no zone_meta,
/// nothing presigned, database unavailable.
pub fn health(conn: Connection) -> Result(#(Int, Int), Nil) {
  case
    sqlite.query(
      conn,
      "SELECT m.soa_serial, min(p.sig_expires_at)
       FROM zone_meta m, presigned_rrsets p",
      [],
    )
  {
    Ok([[sqlite.Int(serial), sqlite.Int(expires)]]) -> Ok(#(serial, expires))
    _ -> Error(Nil)
  }
}

pub fn read_meta(conn: Connection) -> Result(ZoneMeta, ModelError) {
  let sql =
    "SELECT base_domain, soa_serial, dnskey_public, key_tag,
            dnskey_incoming, key_tag_incoming,
            sig_inception_skew, sig_validity, sig_refresh_before
     FROM zone_meta WHERE id = 1"
  case sqlite.query(conn, sql, []) {
    Ok([
      [
        Text(base),
        sqlite.Int(serial),
        sqlite.Blob(dnskey),
        sqlite.Int(tag),
        sqlite.Blob(incoming),
        sqlite.Int(incoming_tag),
        sqlite.Int(skew),
        sqlite.Int(validity),
        sqlite.Int(refresh),
      ],
    ]) ->
      case name.parse(base) {
        Ok(apex) ->
          Ok(ZoneMeta(
            apex,
            serial,
            dnskey,
            tag,
            incoming,
            incoming_tag,
            skew,
            validity,
            refresh,
          ))
        Error(Nil) -> Error(BadStoredName(base))
      }
    Ok([]) -> Error(NoZoneMeta)
    Ok(_) -> Error(Db(sqlite.Protocol))
    Error(e) -> Error(Db(e))
  }
}

fn read_ns(conn: Connection, apex: Name) -> Result(List(NsHost), ModelError) {
  let sql =
    "SELECT hostname, coalesce(ipv4, ''), coalesce(ipv6, '')
             FROM zone_ns ORDER BY hostname"
  use rows <- result.try(sqlite.query(conn, sql, []) |> result.map_error(Db))
  list.try_map(rows, fn(row) {
    case row {
      [Text(hostname), Text(ipv4), Text(ipv6)] -> {
        // A bare label is relative to the apex; dots make it absolute.
        let full = case string.contains(hostname, ".") {
          True -> hostname
          False -> hostname <> "." <> name.to_string(apex)
        }
        case name.parse(full) {
          Ok(host) -> Ok(NsHost(host, ipv4, ipv6))
          Error(Nil) -> Error(BadStoredName(hostname))
        }
      }
      _ -> Error(Db(sqlite.Protocol))
    }
  })
}

fn read_txt_names(
  conn: Connection,
  apex: Name,
) -> Result(List(TxtName), ModelError) {
  let sql =
    "SELECT n.name, o.slug, d.label, k.nk_z32,
            coalesce(d.relay, ''), coalesce(d.addr, '')
     FROM networks n
     JOIN orgs o ON o.id = n.org_id
     JOIN network_devices nd ON nd.network_id = n.id
     JOIN devices d ON d.id = nd.device_id
     JOIN device_keys k ON k.device_id = d.id
     WHERE k.state != 'revoked'
     ORDER BY o.slug, n.name, d.label, k.added_at"
  use rows <- result.try(sqlite.query(conn, sql, []) |> result.map_error(Db))
  use flat <- result.try(
    list.try_map(rows, fn(row) {
      case row {
        [
          Text(network),
          Text(slug),
          Text(label),
          Text(nk),
          Text(relay),
          Text(addr),
        ] -> {
          let full =
            "_synchronicity."
            <> network
            <> "."
            <> slug
            <> "."
            <> name.to_string(apex)
          case name.parse(full) {
            Ok(owner) -> Ok(#(owner, Member(label, nk, relay, addr)))
            Error(Nil) -> Error(BadStoredName(full))
          }
        }
        _ -> Error(Db(sqlite.Protocol))
      }
    }),
  )
  // Group members per owner, preserving order.
  let owners =
    list.fold(flat, [], fn(acc, pair) {
      let #(owner, member) = pair
      case list.key_find(acc, owner) {
        Ok(members) -> list.key_set(acc, owner, [member, ..members])
        Error(Nil) -> [#(owner, [member]), ..acc]
      }
    })
  Ok(
    owners
    |> list.reverse
    |> list.map(fn(pair) { TxtName(pair.0, list.reverse(pair.1)) }),
  )
}
