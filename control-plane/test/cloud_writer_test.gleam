//// The write tunnel's pure edges (docs/CLOUD-WRITES.md §5): the proof it
//// verifies, the URL it is signed over, the registry's slot cap, and which
//// attached session a write goes to. The lookup against the directory is in
//// `api_test`, where the harness that can register a hosted device lives.

import api/agent
import api/cloud_writer
import gleam/bit_array
import gleam/erlang/process
import util/id

/// A write proof and a browse proof over the same URL and nonce differ, so
/// neither endpoint accepts the other's signature — a statement about the
/// signature, not about two URLs happening to differ.
pub fn the_write_attach_proof_is_domain_separated_test() {
  let nonce = <<7:size(256)>>
  let url = "https://sync.example/dp/v1/attach"
  let covered = cloud_writer.signing_input(url, nonce)
  assert covered == <<"synch-cloud-write-v1":utf8, url:utf8, nonce:bits>>
  assert bit_array.starts_with(covered, <<"synch-cloud-write-v1":utf8>>)
  assert covered != agent.signing_input(url, nonce)
  // And the URL is part of what is signed, as on the browse tunnel.
  assert covered
    != cloud_writer.signing_input("https://other.example/dp/v1/attach", nonce)
}

pub fn the_write_attach_url_is_derived_not_configured_test() {
  assert cloud_writer.attach_url("https://sync.example")
    == "https://sync.example/dp/v1/attach"
  assert cloud_writer.attach_url("https://sync.example//")
    == "https://sync.example/dp/v1/attach"
}

/// One credential may hold a bounded number of writes open, and a released
/// slot is a slot again.
pub fn write_slots_are_capped_per_credential_test() {
  let name = process.new_name("cp_writers_slots_" <> id.new())
  let assert Ok(_) = cloud_writer.start(name)
  let registry = process.named_subject(name)
  let cap = cloud_writer.writes_per_user()
  let claimed =
    list_range(cap)
    |> count(fn(_) { cloud_writer.claim_slot(registry, "key:a") })
  assert claimed == cap
  assert cloud_writer.claim_slot(registry, "key:a") == False
  // Another credential is not spending this one's budget.
  assert cloud_writer.claim_slot(registry, "key:b") == True
  cloud_writer.release_slot(registry, "key:a")
  assert cloud_writer.claim_slot(registry, "key:a") == True
}

/// A write goes to the session serving slot 1, the only slot v1 hosts.
pub fn a_write_goes_to_slot_one_test() {
  let two = session("two", 2)
  let one = session("one", 1)
  assert cloud_writer.pick([two, one]) == Ok(one)
  assert cloud_writer.pick([two]) == Error(Nil)
  assert cloud_writer.pick([]) == Error(Nil)
}

/// Sessions are filed by network, and hosting off takes them out at once.
pub fn hosting_off_drops_a_networks_write_sessions_test() {
  let name = process.new_name("cp_writers_drop_" <> id.new())
  let assert Ok(_) = cloud_writer.start(name)
  let registry = process.named_subject(name)
  process.send(registry, cloud_writer.Join(session("s1", 1)))
  process.send(
    registry,
    cloud_writer.Join(
      cloud_writer.Session(..session("s2", 1), network_id: "other"),
    ),
  )
  assert cloud_writer.sessions_for(registry, "n1") |> length == 1
  cloud_writer.drop_network(registry, "n1")
  assert cloud_writer.sessions_for(registry, "n1") == []
  assert cloud_writer.sessions_for(registry, "other") |> length == 1
}

fn session(id: String, slot: Int) -> cloud_writer.Session {
  cloud_writer.Session(
    id: id,
    network_id: "n1",
    org_id: "o1",
    label: "cloud-" <> int_to_string(slot),
    origin: "cloud-" <> int_to_string(slot) <> "@prod.acme.sync.test",
    key_id: "k-" <> id,
    dp: "dp-1",
    slot: slot,
    version: cloud_writer.protocol_version,
    attached_at: 0,
    inbox: process.new_subject(),
  )
}

@external(erlang, "erlang", "integer_to_binary")
fn int_to_string(n: Int) -> String

@external(erlang, "erlang", "length")
fn length(list: List(a)) -> Int

@external(erlang, "lists", "seq")
fn seq(from: Int, to: Int) -> List(Int)

fn list_range(n: Int) -> List(Int) {
  case n {
    0 -> []
    _ -> seq(1, n)
  }
}

fn count(items: List(a), keep: fn(a) -> Bool) -> Int {
  case items {
    [] -> 0
    [first, ..rest] ->
      case keep(first) {
        True -> 1 + count(rest, keep)
        False -> count(rest, keep)
      }
  }
}
