import api/agent
import api/browse_api
import config
import dns/name
import dns/wire
import dnssec/keys
import envoy
import fixtures.{nk}
import gleam/bit_array
import gleam/erlang/process
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import provider/provider
import store/db
import store/migrate
import store/sqlite.{Int as VInt}
import zone/build
import zone/model.{type ZoneInput, Member, NsHost, TxtName, ZoneInput, ZoneMeta}
import zone/render_external

fn input(browse_url: String) -> ZoneInput {
  case browse_url {
    "" -> fleet([])
    url -> fleet([url])
  }
}

fn fleet(browse_urls: List(String)) -> ZoneInput {
  let assert Ok(apex) = name.parse("sync.test.")
  let assert Ok(ns1) = name.parse("ns1.sync.test.")
  let assert Ok(owner) = name.parse("_synchronicity.prod.acme.sync.test.")
  let csk = keys.generate()
  ZoneInput(
    ZoneMeta(
      apex,
      7,
      csk.public,
      keys.key_tag(keys.dnskey_rdata(csk)),
      <<>>,
      0,
      3600,
      1_209_600,
      604_800,
    ),
    [NsHost(ns1, "127.0.0.1", "")],
    [TxtName(owner, [Member("nas", nk(), "", "")])],
    [],
    0,
    browse_urls,
  )
}

fn browse_env() -> Nil {
  envoy.set("CP_ROLE", "primary")
  envoy.set("CP_BASE_DOMAIN", "sync.test")
  envoy.set("CP_DB_PATH", "/var/lib/cp/db/cp.db")
  envoy.set("CP_KEY_FILE", "/var/lib/cp/csk.key")
  envoy.set("CP_SESSION_SECRET", "0123456789abcdef0123456789abcdef")
  envoy.unset("CP_DNS_MODE")
  envoy.unset("CP_HTTP_LISTEN")
  envoy.unset("CP_DNS_LISTEN")
  envoy.unset("CP_NS_HOSTS")
  envoy.set("CP_PUBLIC_URL", "https://sync.example")
  envoy.unset("CP_ENTRY_URL")
  envoy.unset("CP_ENDPOINTS")
  envoy.unset("CP_PRIMARY_URL")
}

// -- the apex record ---------------------------------------------------------

/// One record, at the apex, naming the deployment's endpoint and nothing
/// about which network may be browsed.
pub fn the_attach_record_sits_at_the_apex_test() {
  let assert Ok(rrsets) = build.build(input("https://sync.example"))
  let assert Ok(owner) = name.parse("_synchronicity-cp.sync.test.")
  let assert Ok(rrset) =
    list.find(rrsets, fn(r) { r.owner == owner && r.rtype == wire.type_txt })
  let assert [rd] = rrset.rdatas
  let assert Ok(text) = txt_text(rd)
  assert text == "v=synccp1 url=https://sync.example"
  // In the NSEC chain like any other owner: a name that is not in it cannot
  // be proven absent, and this one is proven present.
  assert list.contains(build.owners_in_order(rrsets), owner)
}

/// A fleet is named one record per node, at the one apex name.
///
/// Every node holds its own registry of attached daemons, so a node nobody
/// has a tunnel to answers no browse question — which is why the record has
/// to name them all, and why the daemon opens one tunnel per record rather
/// than picking one. Separate records rather than several `url=` fields in
/// one is what keeps a daemon built before the fleet existed working: it
/// reads the first record it can parse and reaches one node of the fleet,
/// where a second `url=` in one record is a duplicate field it refuses.
pub fn the_attach_record_names_every_node_of_the_fleet_test() {
  let urls = ["https://sync.example", "https://cp1.sync.example"]
  let assert Ok(rrsets) = build.build(fleet(urls))
  let assert Ok(owner) = name.parse("_synchronicity-cp.sync.test.")
  let assert Ok(rrset) =
    list.find(rrsets, fn(r) { r.owner == owner && r.rtype == wire.type_txt })
  // One RRset, one rdata each, in publication order — no precedence is
  // implied and none is read.
  let texts = list.filter_map(rrset.rdatas, txt_text)
  assert texts
    == [
      "v=synccp1 url=https://sync.example",
      "v=synccp1 url=https://cp1.sync.example",
    ]
  // Still one owner name in the chain, however many records hang off it.
  assert list.length(
      list.filter(build.owners_in_order(rrsets), fn(o) { o == owner }),
    )
    == 1

  // External mode says the same thing to a provider: several values at one
  // name, which is how the reconciler already carries a multi-member
  // membership name.
  let assert Ok(records) = render_external.render(fleet(urls))
  let attach =
    list.filter(records, fn(r) { r.name == "_synchronicity-cp.sync.test" })
  assert list.map(attach, fn(r) { r.value })
    == [
      "v=synccp1 url=https://cp1.sync.example",
      "v=synccp1 url=https://sync.example",
    ]
}

/// The primary names the deployment; each node names only itself.
pub fn the_endpoints_come_from_the_primarys_environment_test() {
  browse_env()
  envoy.set("CP_PUBLIC_URL", "https://sync.example/")
  envoy.set(
    "CP_ENDPOINTS",
    "https://cp1.sync.example, https://cp2.sync.example/;https://cp3.sync.example",
  )
  let assert Ok(cfg) = config.load()
  // This node first, then the rest, each with its trailing slash trimmed to
  // the origin the daemon signs its attach proof over.
  assert cfg.endpoints
    == [
      "https://sync.example",
      "https://cp1.sync.example",
      "https://cp2.sync.example",
      "https://cp3.sync.example",
    ]

  // The same rules as CP_PUBLIC_URL, applied where the operator can still
  // read the message: a value the daemon would reject never reaches a signed
  // record that is cached for its TTL.
  envoy.set("CP_ENDPOINTS", "cp1.sync.example")
  let assert Error(why) = config.load()
  assert string.contains(why, "origin")

  // An RRset is a set, and RFC 4034 §6.3 has a signer drop duplicate RRs
  // before signing: two identical rdatas would be signed as two and
  // canonicalized to one by a validator, which is an RRSIG mismatch and the
  // whole zone failing closed. Listing your own CP_PUBLIC_URL among the
  // others is an ordinary mistake, so it collapses rather than refusing.
  envoy.set("CP_ENDPOINTS", "https://sync.example")
  let assert Ok(cfg) = config.load()
  assert cfg.endpoints == ["https://sync.example"]
  // And the zone builder reads the same deduplicated list — this is the
  // path that actually reaches an RRSIG, and it does not go through the
  // boot-time validator above.
  assert config.endpoints() == ["https://sync.example"]
  let assert Ok(rrsets) = build.build(fleet(config.endpoints()))
  let assert Ok(owner) = name.parse("_synchronicity-cp.sync.test.")
  let assert Ok(rrset) =
    list.find(rrsets, fn(r) { r.owner == owner && r.rtype == wire.type_txt })
  assert list.length(rrset.rdatas) == 1

  // Every entry costs every daemon in every network a standing tunnel, so
  // the zone does not get to decide that number freely.
  envoy.set(
    "CP_ENDPOINTS",
    list.repeat(Nil, config.max_endpoints)
      |> list.index_map(fn(_, i) {
        "https://cp" <> int.to_string(i) <> ".sync.example"
      })
      |> string.join(","),
  )
  let assert Error(why) = config.load()
  assert string.contains(why, "names more than")

  // And it is the primary's list: a replica publishes no zone, so one that
  // set this would be describing a record it does not write.
  browse_env()
  envoy.set("CP_ROLE", "replica")
  envoy.unset("CP_KEY_FILE")
  envoy.unset("CP_SESSION_SECRET")
  envoy.set("CP_SESSION_SECRET", "0123456789abcdef0123456789abcdef")
  envoy.set("CP_PRIMARY_URL", "https://sync.example")
  envoy.set("CP_PUBLIC_URL", "https://cp1.sync.example")
  envoy.set("CP_ENDPOINTS", "https://cp2.sync.example")
  let assert Error(why) = config.load()
  assert string.contains(why, "primary-only")
  browse_env()
}

/// External mode publishes the same one record through the provider, and
/// drops it again when the feature goes off.
pub fn external_mode_reconciles_the_attach_record_test() {
  let assert Ok(records) = render_external.render(input("https://sync.example"))
  let assert Ok(record) =
    list.find(records, fn(r) { r.name == "_synchronicity-cp.sync.test" })
  assert record.value == "v=synccp1 url=https://sync.example"
  assert record.rtype == provider.Txt

  let assert Ok(without) = render_external.render(input(""))
  assert list.all(without, fn(r) { r.name != "_synchronicity-cp.sync.test" })
}

// -- the endpoints -----------------------------------------------------------

/// A node names itself, always. There is no deployment-level switch: the
/// apex says where this base's control plane answers, and a node that
/// answers nowhere is not a node of it. What a *network* may be browsed is
/// the org admin's switch, which is a different question asked at the
/// endpoint.
pub fn a_node_always_names_its_own_endpoint_test() {
  browse_env()
  let assert Ok(cfg) = config.load()
  assert cfg.endpoints == ["https://sync.example"]
  assert config.browse_endpoint() == "https://sync.example"
  browse_env()
}

/// The record publishes the public URL and a daemon signs its proof over it,
/// so a node that has not been told its own URL cannot start: a loopback
/// default published into DNS would send every node in every network
/// nowhere.
pub fn a_node_needs_its_own_url_and_a_replica_needs_the_primarys_test() {
  browse_env()
  envoy.unset("CP_PUBLIC_URL")
  let assert Error(why) = config.load()
  assert string.contains(why, "CP_PUBLIC_URL")

  // A replica offers the surface too: the tunnel is a read, and the tables
  // its attach resolves against are replicated.
  envoy.set("CP_PUBLIC_URL", "https://cp1.sync.example")
  envoy.set("CP_ROLE", "replica")
  envoy.unset("CP_KEY_FILE")

  // It still needs the primary's URL, which is the one fact a read-only node
  // cannot derive from a database that records the deployment's zone rather
  // than which of its nodes holds the pen.
  let assert Error(why) = config.load()
  assert string.contains(why, "CP_PRIMARY_URL")

  envoy.set("CP_PRIMARY_URL", "https://cp0.sync.example")
  let assert Ok(cfg) = config.load()
  assert cfg.primary_url == "https://cp0.sync.example"
  // Its own endpoint and nobody else's: the deployment's list is the
  // primary's to publish.
  assert cfg.endpoints == ["https://cp1.sync.example"]
  browse_env()
}

/// The two names a load-balanced deployment has, and which use falls on
/// which side.
///
/// `CP_PUBLIC_URL` is this node's own — daemons dial it directly and sign
/// their attach proof over it, so the apex publishes it verbatim.
/// `CP_ENTRY_URL` is where a browser reaches the deployment, so it is what a
/// magic link, an OAuth callback and an invitation come back to: a sign-in
/// completed on one node's own name sets its cookie there, and the browser
/// returns to the entry name without it.
pub fn a_deployment_behind_a_balancer_has_two_names_test() {
  browse_env()
  // One node: they are the same name, and nothing has to be told twice.
  let assert Ok(cfg) = config.load()
  assert cfg.public_url == "https://sync.example"
  assert cfg.entry_url == cfg.public_url

  envoy.set("CP_PUBLIC_URL", "https://cp0.sync.example")
  envoy.set("CP_ENTRY_URL", "https://sync.example")
  let assert Ok(cfg) = config.load()
  // The record still names this node, not the balancer: a tunnel relayed
  // from the entry name would carry a proof signed over the wrong URL.
  assert cfg.endpoints == ["https://cp0.sync.example"]
  assert cfg.entry_url == "https://sync.example"

  // Same origin rule as the rest, and a trailing slash trimmed the same way.
  envoy.set("CP_ENTRY_URL", "https://sync.example/")
  let assert Ok(cfg) = config.load()
  assert cfg.entry_url == "https://sync.example"
  envoy.set("CP_ENTRY_URL", "sync.example")
  let assert Error(why) = config.load()
  assert string.contains(why, "origin")

  envoy.unset("CP_ENTRY_URL")
  browse_env()
}

/// A `CP_PUBLIC_URL` the *client* would reject is refused here, where the
/// operator can still read the message.
///
/// The value is rendered straight into a signed apex TXT record and parsed by
/// `parse_control_plane_record`, which reads whitespace-separated `key=value`
/// pairs and requires an origin. A bad one is signed, cached for its TTL, and
/// fails in every daemon rather than at the boot that produced it.
///
/// Both accepted schemes are asserted, including the one-character `http://`
/// origin: the two prefixes are different lengths, so a single shared length
/// bound is off by one for whichever scheme it was not written for.
pub fn a_public_url_the_client_would_reject_is_refused_at_boot_test() {
  let with_url = fn(url) {
    browse_env()
    envoy.set("CP_PUBLIC_URL", url)
    config.load()
  }

  let assert Ok(_) = with_url("https://sync.example")
  let assert Ok(_) = with_url("http://sync.example")
  // Eight characters, and an origin — the length `https://` alone occupies.
  let assert Ok(_) = with_url("http://x")

  let assert Error(why) = with_url("sync.example")
  assert string.contains(why, "origin")
  let assert Error(why) = with_url("ftp://sync.example")
  assert string.contains(why, "origin")
  // A scheme and nothing after it names no host.
  let assert Error(_) = with_url("https://")
  // The record's own grammar: a space ends the field.
  let assert Error(why) = with_url("https://sync.example /x")
  assert string.contains(why, "whitespace")
  browse_env()
}

// -- the switch --------------------------------------------------------------

/// Every network starts unbrowsable, including every network that already
/// existed when the column arrived: browsing is the org's call, and this is
/// the switch it is made with.
pub fn browsing_is_off_for_every_network_by_default_test() {
  let assert Ok(conn) = db.open_primary(":memory:")
  let assert Ok(_) = migrate.migrate(conn)
  let assert Ok(_) =
    sqlite.script(
      conn,
      "INSERT INTO orgs VALUES ('o1', 'acme', 'Acme', 0);
       INSERT INTO networks (id, org_id, name, created_at)
         VALUES ('n1', 'o1', 'prod', 0);",
    )
  let assert Ok([[VInt(enabled)]]) =
    sqlite.query(
      conn,
      "SELECT browse_enabled FROM networks WHERE id = 'n1'",
      [],
    )
  assert enabled == 0
  sqlite.close(conn)
}

// -- the attach proof --------------------------------------------------------

/// Byte-for-byte what `crates/synch-engine/src/cloud/frame.rs` signs. The two
/// halves of this handshake are in different languages and different
/// repositories' worth of code; if they disagree about one byte, no daemon
/// ever attaches, and the failure looks like a bad key rather than a bad
/// string.
pub fn the_signing_input_is_the_daemons_test() {
  let nonce = <<7:size(256)>>
  let covered =
    agent.signing_input("https://sync.example/agent/v1/attach", nonce)
  assert covered
    == <<
      "synch-cloud-attach-v1":utf8,
      "https://sync.example/agent/v1/attach":utf8,
      7:size(256),
    >>
  // Domain-separated: nothing that starts with the head tag can be read as an
  // attach proof, and nothing here starts with the head tag.
  assert bit_array.starts_with(covered, <<"synch-cloud-attach-v1":utf8>>)
  assert !bit_array.starts_with(covered, <<"sync-head/1":utf8>>)
  // Bound to the endpoint: a proof minted for one control plane is not the
  // proof another one would accept.
  assert covered
    != agent.signing_input("https://other.example/agent/v1/attach", nonce)
}

/// The URL both ends sign over is derived from the public URL the same way,
/// however the operator spelled it.
pub fn the_attach_url_is_derived_not_configured_test() {
  assert agent.attach_url("https://sync.example")
    == "https://sync.example/agent/v1/attach"
  assert agent.attach_url("https://sync.example/")
    == "https://sync.example/agent/v1/attach"
  assert agent.attach_url("  https://sync.example//  ")
    == "https://sync.example/agent/v1/attach"
}

// -- routing -----------------------------------------------------------------

fn session(id: String, origin: String) -> agent.Session {
  agent.Session(
    id: id,
    network_id: "n1",
    org_id: "o1",
    label: id,
    origin: origin,
    key_id: "k-" <> id,
    spaces: ["media"],
    version: agent.protocol_version,
    attached_at: 0,
    inbox: process.new_subject(),
  )
}

/// A holder serves best — the bytes cross the operator's network once instead
/// of hopping peer, serving node, cloud — but any attached daemon serves
/// correctly, so the hint may be stale without consequence.
pub fn a_read_prefers_a_daemon_that_holds_the_blob_test() {
  let nas = session("nas", "nas@x.example")
  let laptop = session("laptop", "laptop@x.example")
  assert agent.route([nas, laptop], ["laptop@x.example"]) == Some(laptop)
  assert agent.route([nas, laptop], []) == Some(nas)
  // A holder nobody has attached is no reason to refuse the read.
  assert agent.route([nas], ["studio@x.example"]) == Some(nas)
  assert agent.route([], ["nas@x.example"]) == None
}

/// A session's spaces are a routing fact, not a boundary: they say which
/// daemon can answer for a space, nothing about what may be asked.
pub fn a_session_holds_only_the_spaces_it_claimed_test() {
  let nas = session("nas", "nas@x.example")
  assert agent.holds(nas, "media")
  assert !agent.holds(nas, "private")
}

/// A request may name the node that serves it. Unnamed, any holder; named,
/// that node and no other — and a node that is not attached, and one that is
/// attached but does not hold the space, are different facts with different
/// messages.
pub fn a_request_may_name_its_node_test() {
  let nas = session("nas", "nas@x.example")
  let laptop = session("laptop", "laptop@x.example")
  let vault =
    agent.Session(..nas, origin: "vault@x.example", spaces: ["secrets"])

  // Unnamed: the first holder answers, as it always has.
  assert browse_api.pick("media", [nas, laptop], "") == Ok(nas)
  // Named: the node asked for, not the first in the list.
  assert browse_api.pick("media", [nas, laptop], "laptop@x.example")
    == Ok(laptop)

  // Attached, but holding nothing of this space.
  assert browse_api.pick("media", [nas, vault], "vault@x.example")
    == Error("vault@x.example does not hold media")
  // Not attached at all.
  assert browse_api.pick("media", [nas, laptop], "ghost@x.example")
    == Error("ghost@x.example is not attached")
  // And nobody holding the space is nobody to ask, however named.
  assert browse_api.pick("media", [vault], "")
    == Error("no attached daemon holds media")
}

/// Reads are same-origin GETs with cookies and no CSRF token, so a hostile
/// page can start one with an `img` tag. The cap is what bounds how many.
pub fn one_user_may_not_open_unbounded_downloads_test() {
  let name = process.new_name("cp_agents_cap_test")
  let assert Ok(started) = agent.start(name)
  let registry = started.data
  let taken =
    list.repeat(Nil, agent.streams_per_user())
    |> list.map(fn(_) { agent.claim_stream(registry, "u1") })
  assert list.all(taken, fn(ok) { ok })
  assert !agent.claim_stream(registry, "u1")
  // The cap is per user, not global: one greedy tab does not stop everybody.
  assert agent.claim_stream(registry, "u2")
  // And a finished download gives its slot back.
  agent.release_stream(registry, "u1")
  assert agent.claim_stream(registry, "u1")
}

fn txt_text(rd: BitArray) -> Result(String, Nil) {
  case rd {
    <<len:size(8), rest:bits>> -> {
      let want = len * 8
      case rest {
        <<text:size(want)-bits, _:bits>> -> bit_array.to_string(text)
        _ -> Error(Nil)
      }
    }
    _ -> Error(Nil)
  }
}
