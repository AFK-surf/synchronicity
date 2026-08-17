//// The external-mode renderer: the same `ZoneInput` the serving builder
//// consumes, rendered down to only the records that are ours to publish
//// through a provider.
////
//// SOA, NS, DNSKEY, negative proofs and every RRSIG are the provider's
//// business in external mode; what this deployment owns is the data —
//// membership TXT and the transparency proofs — plus the ownership marker
//// the reconciler's refusal rule turns on. The product
//// invariants are re-checked with `build.validate`, the exact rule set the
//// serving builder applies: they protect clients, not the wire format, and
//// they hold in either mode.
////
//// Pure, deterministic and canonically ordered, so that a SHA-256 over the
//// rendered set is a stable identity: the reconciler's cheap "already in
//// sync" answer, computed with no provider round-trip.

import dns/name
import dns/rdata
import gleam/crypto
import gleam/list
import gleam/order
import gleam/result
import gleam/string
import provider/diff
import provider/provider.{type Record, Record}
import zone/build
import zone/model.{type ZoneInput}

/// TTLs mirror the serving builder's: data churns, infrastructure doesn't.
pub const ttl_data = 300

/// The proof records' TTL, and the reason it is as short as the data it
/// guards.
///
/// A client caches nothing itself, so the only thing this number controls is
/// how long the recursive resolver a client asks will keep serving the proof
/// set from before a provider rotated. That interval is the tail of the
/// window in which a `Require` client fails closed, and it has to fit —
/// together with the watch cadence — inside the lifetime of the membership a
/// client is already holding, or a routine rotation costs member bindings
/// rather than a few refreshes:
///
///     watch cadence + publish + ttl_proof  <  ttl_data + client trust grace
///     300          + 60      + 300         <  300      + 600
pub const ttl_proof = 300

/// The declaration's TTL. Its content is fixed forever — the same twenty
/// bytes every zone publishes — so there is nothing for a short TTL to buy.
pub const ttl_declaration = 86_400

/// Renders the desired record set, canonically sorted.
///
/// Every name is under the **apex**, never the signing zone. The apex is a
/// name this deployment owns outright, so everything below it is ours to
/// publish and — by the same rule — ours to remove when we stop rendering it.
/// The client finds these names from the `apex=` field of the membership
/// record it has already validated.
pub fn render(input: ZoneInput) -> Result(List(Record), build.BuildError) {
  render_gated(input, False)
}

/// `omit_members` is the already-computed external require-gate: armed, and
/// no verified record exists. Membership TXT is dropped so device bindings
/// never go out before a key is logged; the declaration, owner marker and
/// any proofs still render so the watcher can collect a chain.
pub fn render_gated(
  input: ZoneInput,
  omit_members: Bool,
) -> Result(List(Record), build.BuildError) {
  use Nil <- result.try(build.validate(input))
  let apex = apex_name(input)
  let members = case omit_members {
    True -> []
    False ->
      input.txt_names
      |> list.flat_map(fn(txt_name) {
        let owner = strip_dot(name.to_string(txt_name.owner))
        list.map(txt_name.members, fn(m) {
          Record(
            owner,
            provider.Txt,
            ttl_data,
            rdata.sync1_text(m.label, m.nk_z32, m.relay, m.addr, apex),
          )
        })
      })
  }
  // Each part at its own name: a provider caps the combined content of one
  // name and type (Cloudflare at 8192 wire bytes), which a single
  // ICANN-rooted proof exceeds on its own.
  let rekor =
    list.map(input.rekor_proofs, fn(pair) {
      let #(index, text) = pair
      Record(
        build.rekor_part_label(index) <> "." <> apex,
        provider.Txt,
        ttl_proof,
        text,
      )
    })
  // Unconditional, exactly as in serve mode: the declaration is what makes
  // every logged entry the zone's own statement, so a zone without one has
  // no working transparency at all.
  let transparency =
    Record(
      rdata.transparency_label <> "." <> apex,
      provider.Txt,
      ttl_declaration,
      rdata.transparency_text,
    )
  Ok(sort(
    [diff.owner_record(apex), transparency, ..members]
    |> list.append(rekor),
  ))
}

/// SHA-256 over the canonically rendered set: the reconciler's stored
/// "what I last applied" identity.
pub fn desired_hash(records: List(Record)) -> BitArray {
  records
  |> list.map(fn(record) {
    record.name
    <> "\n"
    <> string.inspect(record.ttl)
    <> "\n"
    <> record.value
    <> "\n"
  })
  |> string.join("")
  |> fn(text) { crypto.hash(crypto.Sha256, <<text:utf8>>) }
}

fn sort(records: List(Record)) -> List(Record) {
  list.sort(records, fn(a, b) {
    case string.compare(a.name, b.name) {
      order.Eq -> string.compare(a.value, b.value)
      other -> other
    }
  })
}

fn apex_name(input: ZoneInput) -> String {
  strip_dot(name.to_string(input.meta.apex))
}

/// Provider APIs spell names without the root dot.
fn strip_dot(text: String) -> String {
  case string.ends_with(text, ".") {
    True -> string.drop_end(text, 1)
    False -> text
  }
}
