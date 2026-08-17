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

pub const ttl_rekor = 86_400

/// Renders the desired record set, canonically sorted.
///
/// Every name is under the **apex**, never the signing zone. Two control
/// planes may share one provider-hosted zone, and if they shared a record
/// name each reconciler would see the other's records as strays at a name it
/// manages and delete them — forever, on every sweep. Scoping to the apex
/// makes that collision unrepresentable rather than merely unlikely. The
/// client finds these names from the `apex=` field of the membership record
/// it has already validated.
pub fn render(input: ZoneInput) -> Result(List(Record), build.BuildError) {
  use Nil <- result.try(build.validate(input))
  let apex = apex_name(input)
  let members =
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
  // Each part at its own name: a provider caps the combined content of one
  // name and type (Cloudflare at 8192 wire bytes), which a single
  // ICANN-rooted proof exceeds on its own.
  let rekor =
    list.map(input.rekor_proofs, fn(pair) {
      let #(index, text) = pair
      Record(
        build.rekor_part_label(index) <> "." <> apex,
        provider.Txt,
        ttl_rekor,
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
      ttl_rekor,
      rdata.transparency_text,
    )
  Ok(sort(
    [diff.owner_record(apex), transparency, ..members]
    |> list.append(rekor),
  ))
}

/// Every name the rendered set can ever occupy — what the reconciler asks
/// the provider to list. Includes the empty-set names (`_rekor`, each
/// network owner) so records we *stopped* rendering still get found and
/// deleted.
pub fn managed_names(input: ZoneInput) -> List(String) {
  let apex = apex_name(input)
  let owners =
    list.map(input.txt_names, fn(txt_name) {
      strip_dot(name.to_string(txt_name.owner))
    })
  [diff.owner_label <> "." <> apex, ..rekor_part_names(input, apex)]
  |> list.append([rdata.transparency_label <> "." <> apex, ..owners])
  |> list.unique
}

/// Every proof-part name the rendered set can occupy, so a part we stopped
/// rendering is still found and deleted.
fn rekor_part_names(input: ZoneInput, apex: String) -> List(String) {
  input.rekor_proofs
  |> list.map(fn(pair) { build.rekor_part_label(pair.0) <> "." <> apex })
  |> list.unique
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
