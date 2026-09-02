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
/// than picking one. Each record carries one `url=` field.
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

/// Sources and replicas change without taking the long-lived tunnel down. A
/// replacement claim must become the registry's routing answer immediately,
/// including removals.
pub fn a_live_session_refreshes_its_spaces_test() {
  let name = process.new_name("cp_agents_spaces_test")
  let assert Ok(started) = agent.start(name)
  let registry = started.data
  let nas = session("nas", "nas@x.example")
  process.send(registry, agent.Join(nas))

  process.send(registry, agent.UpdateSpaces(nas.id, ["docs", "photos"]))
  let assert [updated] = agent.sessions_for(registry, "n1")
  assert updated.spaces == ["docs", "photos"]

  process.send(registry, agent.UpdateSpaces(nas.id, []))
  let assert [updated] = agent.sessions_for(registry, "n1")
  assert updated.spaces == []
}

/// v4 is the first version allowed to send the replacement frame, and its
/// JSON shape matches the independently serialized Rust frame.
pub fn a_space_refresh_is_versioned_and_decoded_test() {
  let nas = session("nas", "nas@x.example")
  assert agent.accepts_space_updates(nas)
  assert !agent.accepts_space_updates(agent.Session(..nas, version: 3))
  assert agent.decode_space_update(
      "{\"t\":\"spaces\",\"spaces\":[\"docs\",\"photos\"]}",
    )
    == Ok(["docs", "photos"])
  assert agent.decode_space_update("{\"t\":\"spaces\",\"spaces\":42}")
    == Error(Nil)
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

fn replicates(spaces: List(String)) -> List(agent.ReplicaSpace) {
  list.map(spaces, fn(space) {
    agent.ReplicaSpace(
      space: space,
      policy: "current",
      grace_secs: 2_592_000,
      budget: 0,
      held: 1,
      held_bytes: 10,
      releasing: 0,
      releasing_bytes: 0,
      wanted: 0,
      wanted_bytes: 0,
      unreachable: 0,
      unreachable_bytes: 0,
      held_back: 0,
      oldest_want: 0,
      next_release: 0,
      view_complete: True,
      view_reason: "",
    )
  })
}

/// How many nodes hold a space is the one fact reading each node on its own
/// cannot show: a space one node replicates keeps every superseded version in
/// exactly one place, and looks identical, node by node, to one that three
/// nodes hold.
pub fn a_space_is_counted_once_per_node_that_replicates_it_test() {
  let nas =
    browse_api.NodeReplication(
      "nas",
      "nas@x.example",
      replicates(["media", "docs"]),
      "",
      "",
    )
  let laptop =
    browse_api.NodeReplication(
      "laptop",
      "laptop@x.example",
      replicates(["media"]),
      "",
      "",
    )
  // First-seen order, so the listing does not reshuffle between polls.
  assert browse_api.replica_counts([nas, laptop])
    == [#("media", 2), #("docs", 1)]
}

/// A daemon that could not be asked contributes nothing — not a zero.
///
/// Silence is not evidence that a node does not replicate a space. Counting it
/// as though it were would report the fleet as thinner than it is, which is
/// the direction that has somebody acting on a number nobody measured.
pub fn a_node_that_refused_is_not_counted_as_replicating_nothing_test() {
  let answered =
    browse_api.NodeReplication(
      "nas",
      "nas@x.example",
      replicates(["media"]),
      "",
      "",
    )
  let silent =
    browse_api.NodeReplication(
      "laptop",
      "laptop@x.example",
      [],
      "unavailable",
      "the attached daemon did not answer in time",
    )
  assert browse_api.replica_counts([answered, silent]) == [#("media", 1)]
  // And a fleet where nobody answered reports no coverage at all rather than
  // a row saying zero.
  assert browse_api.replica_counts([silent]) == []
}

/// A daemon older than a question is never sent it.
///
/// The frame would not decode, and a frame that does not decode ends the
/// tunnel — so asking an old node one new question would cost its operator the
/// whole browse surface. Its version is what says which questions it can take,
/// which is the only reason the number is bumped at all.
pub fn an_old_daemon_is_asked_only_what_its_version_defines_test() {
  let current = session("nas", "nas@x.example")
  let old = agent.Session(..current, version: 2)

  assert agent.speaks(current, agent.Replication)
  assert !agent.speaks(old, agent.Replication)
  // And it keeps everything its own version defines, which is the point of
  // admitting it rather than refusing the attach.
  assert agent.speaks(old, agent.Delegations)
  assert agent.speaks(old, agent.Ls("media", "", "", False))

  // The table is per question, so a version this build has never issued is
  // still ordered against the questions correctly.
  assert agent.introduced_in(agent.Replication)
    > agent.introduced_in(agent.Delegations)
  assert agent.introduced_in(agent.Delegations)
    > agent.introduced_in(agent.Stat("media", "a"))

  // A daemon *newer* than this build settles here rather than being refused,
  // and is asked everything this build knows how to ask. The refusal in that
  // direction is the one that cannot be caught by testing today's fleet: it
  // does not fire until the next bump ships to nodes first, which is the
  // ordinary case, since nodes belong to their operators.
  assert agent.settled_version(agent.protocol_version + 4)
    == agent.protocol_version
  let newer =
    agent.Session(
      ..current,
      version: agent.settled_version(agent.protocol_version + 4),
    )
  assert agent.speaks(newer, agent.Replication)

  // Settling never invents a version either end lacks: at or below this
  // build, the daemon's own number stands.
  assert agent.settled_version(agent.protocol_version) == agent.protocol_version
  assert agent.settled_version(agent.min_protocol_version)
    == agent.min_protocol_version
}

/// Asking every daemon must not cost a full timeout per daemon.
///
/// The bound has to be measured on a real fanout rather than asserted about an
/// arithmetic helper. A per-node budget passes any test of its own arithmetic
/// and still spends N budgets in sequence, because each is handed to its own
/// wait — which is a fact about the loop, not about the number, and only a
/// clock around the whole call can see it.
///
/// Sessions built here have an inbox nobody serves, so every one of them is a
/// daemon that never answers: the worst case, and the one that decides whether
/// a dashboard panel returns or hangs.
pub fn asking_a_fleet_does_not_multiply_the_wait_test() {
  let budget = 400
  let fleet =
    list.index_map(list.repeat(Nil, 40), fn(_, n) {
      session("node-" <> int.to_string(n), "n" <> int.to_string(n) <> "@x")
    })

  let started = monotonic_ms()
  let answers = agent.ask_all_within(fleet, agent.Replication, budget)
  let elapsed = monotonic_ms() - started

  assert list.length(answers) == 40
  // Laid end to end this would be 16 seconds. The deadline is what makes the
  // fleet size stop mattering; the generous ceiling here is scheduling slack,
  // not room for a second budget.
  assert elapsed < budget * 2
}

/// A daemon that costs nothing must not take a share of the window.
///
/// This is the rollout the version range exists for: one upgraded node among
/// many old ones. The old ones are answered locally without a frame, so if the
/// window were divided by the session count the single node that *can* answer
/// would get a hundredth of it and time out — and the panel would report the
/// one node that was working as the one that failed.
pub fn an_outdated_fleet_does_not_eat_the_asked_nodes_window_test() {
  let budget = 400
  let old =
    list.index_map(list.repeat(Nil, 99), fn(_, n) {
      let current =
        session("old-" <> int.to_string(n), "o" <> int.to_string(n) <> "@x")
      agent.Session(..current, version: 2)
    })
  let fleet = list.append(old, [session("new", "new@x")])

  let started = monotonic_ms()
  let answers = agent.ask_all_within(fleet, agent.Replication, budget)
  let elapsed = monotonic_ms() - started

  // The 99 are refused without a frame, and the one that was asked is wedged
  // — so the call spends essentially the whole window on that one node.
  assert elapsed >= budget * 3 / 4
  let outdated =
    list.filter(answers, fn(entry) {
      case entry.1 {
        Error(agent.Refusal("outdated", _)) -> True
        _ -> False
      }
    })
  assert list.length(outdated) == 99
}

@external(erlang, "cp_sys_ffi", "monotonic_ms")
fn monotonic_ms() -> Int

@external(erlang, "cp_sys_ffi", "mailbox_len")
fn mailbox_len() -> Int

/// A daemon that answers, but only after the caller has given up on it.
///
/// The inbox is created *inside* the spawned process, because a subject is
/// received on by whoever made it — which is what makes this a real session
/// rather than a subject nobody serves.
fn late_answering_session(id: String, delay: Int) -> agent.Session {
  let ready = process.new_subject()
  process.spawn_unlinked(fn() {
    let inbox = process.new_subject()
    process.send(ready, inbox)
    let assert Ok(agent.Query(_, reply)) = process.receive(inbox, 5000)
    process.sleep(delay)
    process.send(reply, Ok(agent.Replicating([])))
  })
  let assert Ok(inbox) = process.receive(ready, 1000)
  agent.Session(..session(id, id <> "@x.example"), inbox: inbox)
}

/// A question the caller gave up on must not leave its answer behind.
///
/// The answer still arrives — the session is holding the request and will
/// either answer it or have `sweep_waiting` refuse it at the lease — and
/// nothing receives it, because `process.receive` matches one subject's ref
/// and the caller has moved on. Under `mist` the caller is the connection
/// actor, which the dashboard's poll keeps alive for the life of a tab, so
/// every abandoned question used to leave a message in a mailbox that only
/// grew, and every later selective receive in that process scanned the pile.
///
/// Invisible to every other test: the counts are right, the panel renders,
/// and the only symptom is a process getting slower the longer somebody
/// watches it. So it is asserted directly.
pub fn a_question_the_caller_abandons_leaves_nothing_behind_test() {
  let before = mailbox_len()
  let fleet =
    list.index_map(list.repeat(Nil, 5), fn(_, n) {
      late_answering_session("late-" <> int.to_string(n), 400)
    })

  // Every daemon answers at 400ms; the call gives up at 100ms.
  let answers = agent.ask_all_within(fleet, agent.Replication, 100)
  assert list.length(answers) == 5
  assert list.all(answers, fn(entry) {
    case entry.1 {
      Error(agent.Refusal("unavailable", _)) -> True
      _ -> False
    }
  })

  // Well past every answer, so a leak would have landed by now.
  process.sleep(900)
  assert mailbox_len() == before
}

/// One node attached twice is still one node.
///
/// A daemon that redials after a blip joins before the registry reaps the
/// half-open session, so for up to a minute the fleet holds two sessions for
/// one origin. Counting both inflates the replica count in the direction that
/// hides the warning — a single-copy space reads as two copies and the amber
/// badge goes quiet — so the collapse happens before anything counts.
pub fn one_node_attached_twice_counts_once_test() {
  let stale =
    browse_api.NodeReplication("nas", "nas@x.example", [], "unavailable", "…")
  let live =
    browse_api.NodeReplication(
      "nas",
      "nas@x.example",
      replicates(["media"]),
      "",
      "",
    )
  let other =
    browse_api.NodeReplication(
      "laptop",
      "laptop@x.example",
      replicates(["media"]),
      "",
      "",
    )

  // The answer wins over the refusal whichever order they arrive in: a node
  // one of whose sessions answered is a node that answered.
  let assert [kept, _] = browse_api.one_row_per_node([stale, live, other])
  assert kept.error == ""
  let assert [kept, _] = browse_api.one_row_per_node([live, stale, other])
  assert kept.error == ""

  // The double-count that matters is two tunnels that both answer, which is
  // what a redial during a poll looks like. One node, one replica.
  let both = [live, live, other]
  assert browse_api.replica_counts(browse_api.one_row_per_node(both))
    == [#("media", 2)]
  // Without the collapse this is the wrong number, and wrong the quiet way:
  // `media` reads as three copies when two nodes hold it, so the amber
  // single-copy badge would stay silent on a fleet of one replica plus a
  // reconnect.
  assert browse_api.replica_counts(both) == [#("media", 3)]
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
