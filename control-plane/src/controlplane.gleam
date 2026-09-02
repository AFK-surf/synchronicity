//// Entry point for the synchronicity control plane: CLI dispatch and the
//// two supervision trees (primary, replica).
////
//// Subcommands:
////   serve                 run the service (configuration from CP_* env)
////   keygen <apex> <file>  generate the zone CSK; print DNSKEY / DS / anchor
////   ds <apex> <file>      print DS + anchor material for an existing key
////   rekor-publish <file>  log the zone key in the transparency log, verify
////                         the proof locally, store and serve it. Run this
////                         *after* the DS is live in the parent — the entry
////                         carries a DNSSEC chain, and there is no chain to
////                         build before then (§5.2). The apex is this
////                         deployment's own, from `CP_BASE_DOMAIN`.
////   rekor-retire <file>   log a retirement breadcrumb for a key. Allowed to
////                         be chainless: a retired zone may have no DS left,
////                         and clients never treat a retire as authorization.
////   seed                  create a demo org/network/devices and publish
////   seed-admin <email>    first-user bootstrap: print a one-time magic link
////   dataplane-key mint <name> [--expires-in <secs>]
////                         mint the cloud data plane's credential and print
////                         the token once. Deliberately a subcommand and not
////                         a route: this is the one key that can see every
////                         org, so it is never mintable through the API it
////                         authorizes (docs/CLOUD-DATAPLANE.md §3.2).
////   migrate-check         replay the migration chain against a scratch DB

import api/agent
import api/auth_api
import api/browse_api
import api/cloud_writer
import api/edge
import api/reads
import api/router
import auth/dataplane_key
import auth/github
import auth/google
import auth/magic
import cloud/dataplane
import config.{type Config, Primary, Replica}
import dns/name
import dns/serve as dns_serve
import dns/server_tcp
import dns/server_udp
import dnssec/keys
import email/mailer
import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/json
import gleam/list
import gleam/option
import gleam/otp/static_supervisor as sup
import gleam/result
import gleam/string
import jobs/provider_sync
import jobs/resign
import jobs/zonekey_watch
import mist
import provider/bunny
import provider/cloudflare
import provider/provider
import rekor/chain
import rekor/client
import rekor/publish as rekor
import store/db
import store/migrate
import store/pool
import store/sqlite
import tools/seed
import util/id
import wisp/wisp_mist
import zone/model
import zone/publish

@external(erlang, "cp_sys_ffi", "argv")
fn argv() -> List(String)

@external(erlang, "cp_sys_ffi", "now_unix")
fn now_unix() -> Int

@external(erlang, "erlang", "halt")
fn halt(code: Int) -> Nil

pub fn main() {
  case argv() {
    ["keygen", apex, key_file] -> keygen(apex, key_file)
    ["ds", apex, key_file] -> print_key_material(apex, key_file)
    ["rekor-publish", key_file] ->
      run_or_die(fn() { rekor_publish(key_file, "") })
    ["rekor-retire", key_file] ->
      run_or_die(fn() { rekor_publish(key_file, "retire") })
    ["zone-key", "stage", apex, key_file, incoming_key_file] ->
      run_or_die(fn() { zone_key_stage(apex, key_file, incoming_key_file) })
    ["zone-key", "promote", apex, key_file] ->
      run_or_die(fn() { zone_key_promote(apex, key_file) })
    ["provider-sync"] -> run_or_die(provider_sync_once)
    ["migrate-check"] -> migrate_check()
    ["seed"] -> run_or_die(run_seed)
    ["seed-admin", email] -> run_or_die(fn() { seed_admin(email) })
    // `key_name` rather than `name`: this module imports `dns/name`, and a
    // binding of that name would shadow the module for the rest of the clause.
    // The data plane a key is minted for is required, not optional. A key
    // that named no data plane is one `/dp/v1` has to refuse, so accepting
    // the mint and failing at the poll would move the error away from the
    // person who can fix it (docs/CLOUD-DATAPLANE.md §7.2).
    ["dataplane-key", "mint", key_name, "--dp", dp_id] ->
      run_or_die(fn() { dataplane_key_mint(key_name, dp_id, "") })
    ["dataplane-key", "mint", key_name, "--dp", dp_id, "--expires-in", seconds] ->
      run_or_die(fn() { dataplane_key_mint(key_name, dp_id, seconds) })
    ["dataplane", "register", dp_id] ->
      run_or_die(fn() { dataplane_register(dp_id) })
    ["dataplane", "list"] -> run_or_die(dataplane_list)
    ["dataplane", "assign", org_slug, network_name, dp_id] ->
      run_or_die(fn() { dataplane_assign(org_slug, network_name, dp_id) })
    ["serve"] -> run_or_die(serve)
    _ -> {
      io.println_error(
        "usage: controlplane serve | keygen <apex> <keyfile> | ds <apex> <keyfile> | rekor-publish <keyfile> | rekor-retire <keyfile> | zone-key stage <apex> <keyfile> <incoming-keyfile> | zone-key promote <apex> <keyfile> | provider-sync | seed | seed-admin <email> | dataplane register <dp-id> | dataplane list | dataplane assign <org> <network> <dp-id> | dataplane-key mint <name> --dp <dp-id> [--expires-in <secs>] | migrate-check",
      )
      halt(2)
    }
  }
}

fn run_or_die(run: fn() -> Result(Nil, String)) -> Nil {
  case run() {
    Ok(Nil) -> Nil
    Error(message) -> {
      io.println_error("error: " <> message)
      halt(1)
    }
  }
}

fn keygen(apex_text: String, key_file: String) -> Nil {
  run_or_die(fn() {
    use apex <- result.try(
      name.parse(apex_text) |> result.replace_error("invalid apex domain"),
    )
    let csk = keys.generate()
    use Nil <- result.try(keys.save(key_file, csk))
    io.println("; zone key written to " <> key_file <> " — back it up offline.")
    print_material(apex, csk)
    Ok(Nil)
  })
}

fn print_key_material(apex_text: String, key_file: String) -> Nil {
  run_or_die(fn() {
    use apex <- result.try(
      name.parse(apex_text) |> result.replace_error("invalid apex domain"),
    )
    use csk <- result.try(keys.load(key_file))
    print_material(apex, csk)
    Ok(Nil)
  })
}

fn print_material(apex: name.Name, csk: keys.Csk) -> Nil {
  let rd = keys.dnskey_rdata(csk)
  io.println("; key tag " <> int.to_string(keys.key_tag(rd)))
  io.println("; DS record for the parent zone:")
  io.println(keys.ds_line(apex, csk.public))
  io.println("; trust-anchor line for synch --dnssec-anchor:")
  io.println(keys.anchor_line(apex, csk.public))
}

/// The DNS zone that actually holds and signs the apex's records.
///
/// The apex itself whenever the control plane runs a delegated zone of its
/// own — always the case in serve mode, where this service *is* the
/// authoritative nameserver for the apex. In external mode a provider may
/// host a zone above the apex instead, and `CP_SIGNING_ZONE` names it.
fn signing_zone_of(
  cfg: config.Config,
  apex: name.Name,
) -> Result(name.Name, String) {
  case cfg.dns_mode {
    config.Serve -> Ok(apex)
    config.External(_, zone) ->
      name.parse(zone)
      |> result.replace_error("invalid CP_SIGNING_ZONE " <> zone)
  }
}

/// The apex and signing zone a ceremony command operates on.
///
/// Both come from configuration, and the apex cannot be given on the command
/// line: allowing an override could put an entry naming somebody else's apex
/// into the public log. Public so the suite can assert this without a database
/// or log.
pub fn ceremony_zones(
  cfg: config.Config,
) -> Result(#(name.Name, name.Name), String) {
  use apex <- result.try(
    name.parse(cfg.base_domain)
    |> result.replace_error("invalid CP_BASE_DOMAIN " <> cfg.base_domain),
  )
  use signing_zone <- result.try(signing_zone_of(cfg, apex))
  Ok(#(apex, signing_zone))
}

/// Puts the zone key set on the public record and republishes, so the proof
/// record is served beside the key it is about (§5.2, §5.3).
///
/// Idempotent: re-running refreshes the stored checkpoint against a grown
/// tree without minting a second entry, and republishes either way — which is
/// how a control plane whose key was not yet logged gets past the publish
/// gate.
fn rekor_publish(
  key_file: String,
  forced_action: String,
) -> Result(Nil, String) {
  use cfg <- result.try(config.load())
  use #(apex, signing_zone) <- result.try(ceremony_zones(cfg))
  use csk <- result.try(keys.load(key_file))
  use conn <- result.try(open_primary_db(cfg))
  let now = now_unix()
  // Which shard to submit to comes out of the trusted root this build ships.
  // A ceremony run after Sigstore opens the next shard needs a deploy — or
  // CP_REKOR_URL and CP_REKOR_KEY, which name a log outright — and says so
  // rather than submitting into a closed one.
  use target <- result.try(client.discover(now))
  let claim = case forced_action {
    // The retiring subject is the CSK being taken out of service — the one
    // key this deployment ever put in the zone.
    "retire" -> rekor.Retire([keys.dnskey_rdata(csk)])
    _ -> rekor.Current
  }
  use outcome <- result.try(
    rekor.run(
      conn,
      apex,
      signing_zone,
      client.http(target.url),
      target.key,
      now,
      chain.doh(chain.resolver_url()),
      claim,
    )
    |> result.map_error(fn(e) { "logging the zone key: " <> string.inspect(e) }),
  )
  use _ <- result.try(
    publish.publish(conn, csk, now, "system:rekor-publish")
    |> result.map_error(fn(e) { "republishing zone: " <> string.inspect(e) }),
  )
  sqlite.close(conn)
  io.println(
    "zone key set "
    <> string.join(list.map(outcome.key_tags, int.to_string), ",")
    <> " "
    <> outcome.action
    <> ": "
    <> target.url
    <> " log index "
    <> int.to_string(outcome.log_index)
    <> case outcome.refreshed {
      True -> " (proof refreshed, no new entry)"
      False -> " (entry added)"
    }
    <> case outcome.chainless {
      True -> ", no DNSSEC chain (retire breadcrumb)"
      // Every monitor watching this apex will report this key the first time
      // it sees it — that is what publishing to a transparency log now
      // means, and an operator who is surprised by the report is an operator
      // who did not publish this key.
      False -> ", DNSSEC chain carried (monitors will report this key)"
    },
  )
  Ok(Nil)
}

fn migrate_check() -> Nil {
  run_or_die(fn() {
    use conn <- result.try(
      db.open_primary(":memory:")
      |> result.map_error(fn(_) { "could not open scratch database" }),
    )
    use version <- result.try(
      migrate.migrate(conn)
      |> result.map_error(fn(e) { "migration failed: " <> string.inspect(e) }),
    )
    io.println("migration chain ok, version " <> int.to_string(version))
    Ok(Nil)
  })
}

fn open_primary_db(cfg: Config) -> Result(sqlite.Connection, String) {
  use conn <- result.try(
    db.open_primary(cfg.db_path)
    |> result.map_error(fn(e) {
      "opening " <> cfg.db_path <> ": " <> string.inspect(e)
    }),
  )
  use _ <- result.try(
    migrate.migrate(conn)
    |> result.map_error(fn(e) { "migrating: " <> string.inspect(e) }),
  )
  Ok(conn)
}

fn prepare_primary(cfg: Config) -> Result(keys.Csk, String) {
  use conn <- result.try(open_primary_db(cfg))
  use csk <- result.try(keys.load(cfg.key_file))
  use Nil <- result.try(publish.ensure_meta(conn, cfg.base_domain, csk))
  use _ <- result.try(
    publish.set_ns_hosts(conn, cfg.ns_hosts)
    |> result.map_error(fn(e) { "setting ns hosts: " <> string.inspect(e) }),
  )
  // Ungated, for exactly the reason `publish_resign` is ungated: a boot
  // emission says nothing new. It re-emits the records already in the
  // database — the ones clients have been accepting — with fresh RRSIG
  // windows, so refusing it withholds no unlogged key from anybody.
  //
  // Gating it instead made a transparency gap a *total DNS outage*, which is
  // the one outcome `publish_resign`'s own reasoning rules out. The failure
  // reaches `run_or_die` and halts the process, so with `CP_REKOR_REQUIRE`
  // armed the nameserver never starts — and the hourly resign job that exists
  // to keep the zone resolvable while an operator runs `rekor-publish` never
  // runs either, because there is no process for it to run in. It also left a
  // greenfield zone unbootable: the gate wants a logged key, logging wants a
  // live DS, and nothing can serve the zone in between.
  //
  // The gate is unaffected where it matters. Every `Widening` emission — a
  // device added, a network created, a key promoted — still goes through
  // `publish_in_tx` and is still refused under an unlogged key.
  use _ <- result.try(
    publish.publish_resign(conn, csk, now_unix(), "system:boot")
    |> result.map_error(fn(e) { "publishing zone: " <> string.inspect(e) }),
  )
  sqlite.close(conn)
  Ok(csk)
}

/// The browse surface this node offers.
///
/// Every node offers one: the apex names it, and a daemon opens a tunnel to
/// each name. What a *network* may be browsed is the org admin's switch
/// (`networks.browse_enabled`), enforced at the endpoint, where a change
/// takes effect at once rather than a TTL away.
fn browse_surface(
  cfg: Config,
  agents: process.Name(agent.Msg),
  writers: process.Name(cloud_writer.Msg),
) -> browse_api.Browse {
  browse_api.Browse(
    agents,
    agent.attach_url(cfg.public_url),
    writers,
    cloud_writer.attach_url(cfg.public_url),
  )
}

fn serve() -> Result(Nil, String) {
  use cfg <- result.try(config.load())
  case cfg.role, cfg.dns_mode {
    Primary, config.Serve -> serve_primary(cfg)
    Primary, config.External(provider_cfg, signing_zone) ->
      serve_external(cfg, provider_cfg, signing_zone)
    // config.load refuses external on a replica, so this arm is serve mode.
    Replica, _ -> serve_replica(cfg)
  }
}

/// A replica serves DNS/DoH from a database an external process refreshes
/// (atomic rename); it holds no key material and takes no writes.
/// No reload signal exists or is needed: every pooled checkout reopens
/// the database file, so a swapped replacement is seen on the next query.
///
/// It also serves the dashboard and the read half of the product API off
/// that same copy, and the browse surface too — daemons attach *here*, to
/// this node's own `CP_PUBLIC_URL`,
/// because the registry of attached sessions is one process's memory and a
/// node with no tunnel of its own can answer no browse question however
/// faithfully the database replicated. The primary lists the fleet's
/// endpoints in the apex record with `CP_ENDPOINTS`, and every daemon
/// opens one tunnel per endpoint.
fn serve_replica(cfg: Config) -> Result(Nil, String) {
  // Anchor/DS come from the replicated public key material; this also
  // verifies the database is readable and not from a newer build.
  use meta <- result.try({
    use conn <- result.try(
      db.open_read(cfg.db_path)
      |> result.map_error(fn(e) { "opening db: " <> string.inspect(e) }),
    )
    use version <- result.try(
      migrate.current_version(conn)
      |> result.map_error(fn(e) {
        "reading schema version: " <> string.inspect(e)
      }),
    )
    use Nil <- result.try(case version > migrate.build_version() {
      True -> Error("database is from a newer build — refusing")
      False -> Ok(Nil)
    })
    let meta =
      model.read_meta(conn)
      |> result.map_error(fn(e) { "reading zone_meta: " <> string.inspect(e) })
    sqlite.close(conn)
    meta
  })
  let dns_name = process.new_name("cp_dns_pool")
  let udp_name = process.new_name("cp_udp_server")
  let agents_name = process.new_name("cp_agents")
  let writers_name = process.new_name("cp_writers")
  let dns_pool = pool.handle(dns_name, db.read_pragmas)
  let serving = dns_serve.Serving(dns_pool, meta.apex)
  // The dashboard reads the same pool the nameserver does: both are
  // read-only against the same replicated file, and a second pool would only
  // double the workers competing for it.
  let api = router.ReadOnly(reads.Reads(dns_pool), cfg.primary_url)
  let browse = browse_surface(cfg, agents_name, writers_name)
  let ctx =
    router.Context(
      keys.anchor_line(meta.apex, meta.dnskey_public),
      keys.ds_line(meta.apex, meta.dnskey_public),
      api,
      router.ServingZone(serving),
      browse,
    )
  let handler = fn(req) { router.handle(req, ctx) }
  // The secret is the primary's, byte for byte (`CP_SESSION_SECRET`), or no
  // cookie the primary minted verifies here.
  let http =
    wisp_mist.handler(handler, cfg.session_secret)
    |> edge.handler(edge.Surface(browse, dns_pool, cfg.session_secret))
    |> mist.new
    |> mist.bind(cfg.http_listen.address)
    |> mist.port(cfg.http_listen.port)
  let tree =
    sup.new(sup.OneForOne)
    |> sup.restart_tolerance(intensity: 60, period: 10)
    |> sup.add(pool.supervised(
      dns_name,
      cfg.db_path,
      sqlite.ReadOnly,
      db.read_pragmas,
      replica_pool_size,
    ))
    |> sup.add(server_udp.supervised(
      udp_name,
      cfg.dns_listen.address,
      cfg.dns_listen.port,
      serving,
    ))
    |> sup.add(server_tcp.supervised(
      cfg.dns_listen.address,
      cfg.dns_listen.port,
      serving,
    ))
  // The registry before the listener, as on the primary: `sup` starts
  // children in order, so mounting HTTP first would open a window where an
  // attach or a browse call reaches a `cp_agents` name nothing has
  // registered yet, and the request kills its connection handler instead of
  // being answered.
  use _ <- result.try(
    tree
    |> sup.add(agent.supervised(agents_name))
    |> sup.add(cloud_writer.supervised(writers_name))
    |> sup.add(mist.supervised(http))
    |> sup.start
    |> result.map_error(fn(_) { "could not start supervision tree" }),
  )
  io.println(
    "replica serving "
    <> cfg.base_domain
    <> " — dns "
    <> endpoint(cfg.dns_listen)
    <> " http "
    <> endpoint(cfg.http_listen)
    <> " — read-only dashboard, writes at "
    <> cfg.primary_url
    <> " — attach at "
    <> agent.attach_url(cfg.public_url),
  )
  process.sleep_forever()
  Ok(Nil)
}

/// How many pooled readers a replica runs.
///
/// The primary's eight rather than the four a nameserver alone would need. A
/// DNS answer is one short read out of a pre-signed table, but a replica also
/// serves the dashboard: a browse call resolves its org on a connection, and
/// `router.with_session` borrows one to check the cookie before the handler
/// borrows its own. At four, a handful of dashboard tabs would queue DNS
/// answers behind them.
const replica_pool_size = 8

fn serve_primary(cfg: Config) -> Result(Nil, String) {
  use csk <- result.try(prepare_primary(cfg))
  use apex <- result.try(
    name.parse(cfg.base_domain) |> result.replace_error("bad base domain"),
  )
  let mail = case cfg.smtp {
    option.Some(#(host, port, user, pass, from)) ->
      mailer.Smtp(host, port, user, pass, from)
    option.None -> mailer.LogOnly
  }
  io.println("mailer: " <> mailer.describe(mail))
  let api_name = process.new_name("cp_api_pool")
  let dns_name = process.new_name("cp_dns_pool")
  let udp_name = process.new_name("cp_udp_server")
  let agents_name = process.new_name("cp_agents")
  let writers_name = process.new_name("cp_writers")
  let api_pool = pool.handle(api_name, db.primary_pragmas)
  let dns_pool = pool.handle(dns_name, db.read_pragmas)
  let serving = dns_serve.Serving(dns_pool, apex)
  let browse = browse_surface(cfg, agents_name, writers_name)
  let auth =
    auth_api.AuthContext(
      reads.Reads(api_pool),
      cfg.entry_url,
      mail,
      option.map(cfg.google, fn(pair) { google.provider(pair.0, pair.1) }),
      option.map(cfg.github, fn(pair) { github.provider(pair.0, pair.1) }),
      fn(conn, now, actor, change) {
        publish.publish_in_tx(conn, csk, now, actor, change)
      },
      // Serve mode: commit is publication; there is nobody to nudge.
      fn() { Nil },
      cfg.cue_provisioning,
    )
  let ctx =
    router.Context(
      keys.anchor_line(apex, csk.public),
      keys.ds_line(apex, csk.public),
      router.Writable(auth),
      router.ServingZone(serving),
      browse,
    )
  let handler = fn(req) { router.handle(req, ctx) }
  let http =
    wisp_mist.handler(handler, cfg.session_secret)
    |> edge.handler(edge.Surface(browse, api_pool, cfg.session_secret))
    |> mist.new
    |> mist.bind(cfg.http_listen.address)
    |> mist.port(cfg.http_listen.port)
  // One tree, one policy: every long-lived process restarts in place; the
  // node itself only gives up when a child exhausts a generous restart
  // budget — the control plane must not die because one part hiccuped.
  use _ <- result.try(
    sup.new(sup.OneForOne)
    |> sup.restart_tolerance(intensity: 60, period: 10)
    |> sup.add(pool.supervised(
      api_name,
      cfg.db_path,
      sqlite.ReadWrite,
      db.primary_pragmas,
      4,
    ))
    |> sup.add(pool.supervised(
      dns_name,
      cfg.db_path,
      sqlite.ReadOnly,
      db.read_pragmas,
      4,
    ))
    |> sup.add(server_udp.supervised(
      udp_name,
      cfg.dns_listen.address,
      cfg.dns_listen.port,
      serving,
    ))
    |> sup.add(server_tcp.supervised(
      cfg.dns_listen.address,
      cfg.dns_listen.port,
      serving,
    ))
    |> sup.add(agent.supervised(agents_name))
    |> sup.add(cloud_writer.supervised(writers_name))
    |> sup.add(mist.supervised(http))
    |> sup.add(resign.supervised(cfg.db_path, csk))
    |> sup.start
    |> result.map_error(fn(_) { "could not start supervision tree" }),
  )
  io.println(
    "serving "
    <> cfg.base_domain
    <> " — dns "
    <> endpoint(cfg.dns_listen)
    <> " http "
    <> endpoint(cfg.http_listen),
  )
  process.sleep_forever()
  Ok(Nil)
}

/// External mode (docs/EXTERNAL-DNS-PROVIDER.md): the provider hosts and
/// signs the zone; this tree runs the product API and two convergence
/// loops — the reconciler that pushes records through the provider's API,
/// and the key watcher that keeps the transparency claim covering whatever
/// keys the provider is signing with. No DNS listeners, no zone key, no
/// re-sign job: there are no RRSIGs of ours to expire.
///
/// And no TUF refresh job — in either mode. Which shard to submit to is
/// answered from `priv/tuf/sigstore_trusted_root.json`, which ships in the
/// image and moves on a deploy (see `tuf/trusted_root`).
fn serve_external(
  cfg: Config,
  provider_cfg: config.ProviderConfig,
  signing_zone_name: String,
) -> Result(Nil, String) {
  use apex <- result.try(
    name.parse(cfg.base_domain) |> result.replace_error("bad base domain"),
  )
  use signing_zone <- result.try(signing_zone_of(cfg, apex))
  use Nil <- result.try({
    use conn <- result.try(open_primary_db(cfg))
    use Nil <- result.try(publish.ensure_meta_external(conn, cfg.base_domain))
    use _ <- result.try(
      publish.publish_external(conn, now_unix(), "system:boot")
      |> result.map_error(fn(e) { "publishing zone: " <> string.inspect(e) }),
    )
    sqlite.close(conn)
    Ok(Nil)
  })
  use #(prov, provider_name, zone_id) <- result.try(connect_provider(
    provider_cfg,
    cfg.base_domain,
    signing_zone_name,
  ))
  io.println("dns provider: " <> prov.describe)

  let mail = case cfg.smtp {
    option.Some(#(host, port, user, pass, from)) ->
      mailer.Smtp(host, port, user, pass, from)
    option.None -> mailer.LogOnly
  }
  io.println("mailer: " <> mailer.describe(mail))
  let api_name = process.new_name("cp_api_pool")
  let sync_name = process.new_name("cp_provider_sync")
  let agents_name = process.new_name("cp_agents")
  let writers_name = process.new_name("cp_writers")
  let api_pool = pool.handle(api_name, db.primary_pragmas)
  let browse = browse_surface(cfg, agents_name, writers_name)
  let auth =
    auth_api.AuthContext(
      reads.Reads(api_pool),
      cfg.entry_url,
      mail,
      option.map(cfg.google, fn(pair) { google.provider(pair.0, pair.1) }),
      option.map(cfg.github, fn(pair) { github.provider(pair.0, pair.1) }),
      // External mode gates at the render, not at the publish: the
      // reconciler holds membership TXT back while a live key is unlogged.
      fn(conn, now, actor, _change) {
        publish.publish_external_in_tx(conn, now, actor)
      },
      // After commit: nudge the reconciler, so a mutation reaches the
      // provider in seconds while the hourly sweep stays the safety net.
      fn() { provider_sync.poke(sync_name) },
      cfg.cue_provisioning,
    )
  let ctx =
    router.Context(
      "",
      "",
      router.Writable(auth),
      router.ExternalZone(api_pool),
      browse,
    )
  let handler = fn(req) { router.handle(req, ctx) }
  let http =
    wisp_mist.handler(handler, cfg.session_secret)
    |> edge.handler(edge.Surface(browse, api_pool, cfg.session_secret))
    |> mist.new
    |> mist.bind(cfg.http_listen.address)
    |> mist.port(cfg.http_listen.port)
  use _ <- result.try(
    sup.new(sup.OneForOne)
    |> sup.restart_tolerance(intensity: 60, period: 10)
    |> sup.add(pool.supervised(
      api_name,
      cfg.db_path,
      sqlite.ReadWrite,
      db.primary_pragmas,
      4,
    ))
    |> sup.add(agent.supervised(agents_name))
    |> sup.add(cloud_writer.supervised(writers_name))
    // The jobs before the listener, and the order is load-bearing: children
    // start in the order they are added, `provider_sync` registers its name
    // inside its own initialiser, and every mutating API request pokes that
    // name after its transaction commits. Accepting HTTP first leaves a
    // window in which a committed revocation cannot reach the reconciler.
    |> sup.add(provider_sync.supervised(
      sync_name,
      cfg.db_path,
      prov,
      provider_name,
      zone_id,
    ))
    |> sup.add(zonekey_watch.supervised(
      cfg.db_path,
      apex,
      signing_zone,
      // Validating: this watcher spends its answer on record_observed, which
      // decides which keys the zone serves proofs for and is checked by
      // nothing downstream. The publish path above uses the plain resolver —
      // its answer becomes a chain every reader verifies.
      chain.doh_validating(chain.resolver_url()),
      sync_name,
    ))
    |> sup.add(mist.supervised(http))
    |> sup.start
    |> result.map_error(fn(_) { "could not start supervision tree" }),
  )
  io.println(
    "external mode for "
    <> cfg.base_domain
    <> " — provider "
    <> provider_name
    <> ", http "
    <> endpoint(cfg.http_listen),
  )
  process.sleep_forever()
  Ok(Nil)
}

/// Builds the configured provider leg. Discovery and Bunny's relative
/// names use the **signing zone** — the provider-hosted zone. Listing
/// still scopes to names strictly below the apex this deployment owns.
fn connect_provider(
  provider_cfg: config.ProviderConfig,
  apex: String,
  signing_zone: String,
) -> Result(#(provider.Provider, String, String), String) {
  case provider_cfg {
    config.Cloudflare(token, zone_id, api_url) -> {
      use prov <- result.try(cloudflare.connect(
        token,
        zone_id,
        api_url,
        apex,
        signing_zone,
      ))
      Ok(#(prov, "cloudflare", describe_zone(prov.describe)))
    }
    config.Bunny(key, zone_id, api_url) -> {
      use prov <- result.try(bunny.connect(
        key,
        zone_id,
        api_url,
        apex,
        signing_zone,
      ))
      Ok(#(prov, "bunny", describe_zone(prov.describe)))
    }
    config.LogOnly -> Ok(#(provider.log_only(), "log-only", ""))
  }
}

/// The zone id out of a leg's describe line ("<provider> zone <id>").
fn describe_zone(describe: String) -> String {
  case string.split(describe, " zone ") {
    [_, id] -> id
    _ -> ""
  }
}

/// One reconciler pass from the command line: connect, converge, exit.
/// What an operator runs at cutover instead of waiting for the sweep.
fn provider_sync_once() -> Result(Nil, String) {
  use cfg <- result.try(config.load())
  use #(provider_cfg, signing_zone) <- result.try(case cfg.dns_mode {
    config.External(provider_cfg, signing_zone) ->
      Ok(#(provider_cfg, signing_zone))
    config.Serve -> Error("provider-sync needs CP_DNS_MODE=external")
  })
  use #(prov, provider_name, zone_id) <- result.try(connect_provider(
    provider_cfg,
    cfg.base_domain,
    signing_zone,
  ))
  io.println("dns provider: " <> prov.describe)
  provider_sync.run_once(cfg.db_path, prov, provider_name, zone_id)
  Ok(Nil)
}

/// Loads config, opens the database and hands off to tools/seed.
fn run_seed() -> Result(Nil, String) {
  use cfg <- result.try(config.load())
  use conn <- result.try(open_primary_db(cfg))
  use csk <- result.try(keys.load(cfg.key_file))
  let seeded = seed.run(cfg, conn, csk)
  sqlite.close(conn)
  seeded
}

/// First-user bootstrap: prints a one-time magic link for `email`.
fn seed_admin(email: String) -> Result(Nil, String) {
  use cfg <- result.try(config.load())
  use conn <- result.try(open_primary_db(cfg))
  use token <- result.try(
    magic.create_token(conn, email, now_unix())
    |> result.map_error(fn(e) { "creating token: " <> string.inspect(e) }),
  )
  io.println(
    "one-time sign-in link (15 minutes):\n"
    <> cfg.entry_url
    <> "/auth/magic/redeem?token="
    <> token,
  )
  sqlite.close(conn)
  Ok(Nil)
}

/// Mints the cloud data plane's credential and prints the token, once.
///
/// The same posture as `seed-admin`: an operator with a shell on the primary
/// gets a secret out of the database that no HTTP request could have asked
/// for. Here it is not a convenience but the design (docs/CLOUD-DATAPLANE.md
/// §3.2) — this key can enumerate every org's hosted networks, so putting a
/// mint route behind it would mean one leak buys a replacement that outlives
/// the revocation. There is no list route either, for the same reason, and
/// none of that is a gap somebody should later fill in.
///
/// `--expires-in` is seconds from now, and its absence means no expiry, which
/// matches how `api_keys` spells the same choice. A duration rather than a
/// date so nothing depends on the operator's clock agreeing with the
/// service's. Unlike a join key it is *not* required: the fleet holds this key
/// for as long as the fleet runs, and an expiry nobody arranged to renew would
/// stop every hosted tenant converging at an hour nobody chose.
fn dataplane_key_mint(
  key_name: String,
  dp_id: String,
  expires_in: String,
) -> Result(Nil, String) {
  use cfg <- result.try(config.load())
  let now = now_unix()
  // Parsed before the database is opened: a typo in the flag should not cost
  // an open connection and a csqlite process nobody closes.
  use expires_at <- result.try(case expires_in {
    "" -> Ok(option.None)
    seconds ->
      case int.parse(seconds) {
        Ok(secs) if secs > 0 -> Ok(option.Some(now + secs))
        _ -> Error("--expires-in takes a positive number of seconds")
      }
  })
  use conn <- result.try(open_primary_db(cfg))
  // The data plane has to exist first. The foreign key would refuse the
  // insert anyway, but a constraint violation names a column and this names
  // the mistake — and the fix, which is one command away.
  use known <- result.try(
    dataplane.exists(conn, dp_id)
    |> result.map_error(fn(e) { "reading the fleet: " <> string.inspect(e) }),
  )
  use _ <- result.try(case known {
    True -> Ok(Nil)
    False ->
      Error(
        "no data plane called "
        <> dp_id
        <> ": register it first with `controlplane dataplane register "
        <> dp_id
        <> "`",
      )
  })
  let key_id = id.new()
  use #(token, prefix) <- result.try(
    dataplane_key.create(conn, key_id, key_name, dp_id, expires_at, now)
    |> result.map_error(fn(e) { "minting the key: " <> string.inspect(e) }),
  )
  // The mint goes in the trail, with `org_id` NULL because this credential
  // belongs to the deployment rather than to an org. It is written straight to
  // the table rather than through `api/common.audit`, which takes a
  // `Principal` — and the actor here is not a request, it is whoever had a
  // shell.
  use _ <- result.try(
    sqlite.exec(
      conn,
      "INSERT INTO audit_log (at, actor, org_id, action, detail)
       VALUES (?, 'system:dataplane-key-mint', NULL, 'dataplane.key.mint', ?)",
      [
        sqlite.Int(now),
        sqlite.Text(
          json.to_string(
            json.object([
              #("id", json.string(key_id)),
              #("name", json.string(key_name)),
              #("dp", json.string(dp_id)),
              #("prefix", json.string(prefix)),
              #("expires_at", json.nullable(expires_at, json.int)),
            ]),
          ),
        ),
      ],
    )
    |> result.map_error(fn(e) { "recording the mint: " <> string.inspect(e) }),
  )
  sqlite.close(conn)
  io.println(
    "data-plane key "
    <> key_id
    <> " ("
    <> key_name
    <> ") minted for data plane "
    <> dp_id
    <> case expires_at {
      option.Some(at) -> ", expires at " <> int.to_string(at)
      option.None -> ", no expiry"
    }
    <> "\n; this is the only time the token exists outside your hands:\n"
    <> token
    <> "\n; give it to the data plane as SYNCH_DP_TOKEN; it is sent as\n"
    <> "; Authorization: Bearer <token> and reaches /dp/v1 and nothing else.",
  )
  Ok(Nil)
}

/// `dataplane register <dp-id>` — names one pod of the hosting fleet.
///
/// The id is the operator's own name for the pod, because it is the string
/// they will read back in logs, in `dataplane list`, and in the metering
/// heartbeat every tenant on that pod sends. There is no HTTP route that does
/// this, for the reason there is none that mints a key: the fleet's shape is
/// not something the credential authenticating against it should be able to
/// change (docs/CLOUD-DATAPLANE.md §3.2).
fn dataplane_register(dp_id: String) -> Result(Nil, String) {
  use cfg <- result.try(config.load())
  use conn <- result.try(open_primary_db(cfg))
  let now = now_unix()
  // Asked before the insert so a repeat says what happened rather than
  // reporting a UNIQUE violation at an operator. The registry is not a
  // hot path and the race is a human running one command twice.
  use known <- result.try(
    dataplane.exists(conn, dp_id)
    |> result.map_error(fn(e) { "reading the fleet: " <> string.inspect(e) }),
  )
  use _ <- result.try(case known {
    False -> Ok(Nil)
    True -> Error("data plane " <> dp_id <> " is already registered")
  })
  use _ <- result.try(
    dataplane.register(conn, dp_id, now)
    |> result.map_error(fn(e) {
      "registering " <> dp_id <> ": " <> string.inspect(e)
    }),
  )
  use _ <- result.try(
    sqlite.exec(
      conn,
      "INSERT INTO audit_log (at, actor, org_id, action, detail)
       VALUES (?, 'system:dataplane-register', NULL, 'dataplane.register', ?)",
      [
        sqlite.Int(now),
        sqlite.Text(json.to_string(json.object([#("dp", json.string(dp_id))]))),
      ],
    )
    |> result.map_error(fn(e) {
      "recording the registration: " <> string.inspect(e)
    }),
  )
  sqlite.close(conn)
  io.println(
    "data plane "
    <> dp_id
    <> " registered\n; mint its key with `controlplane dataplane-key mint "
    <> dp_id
    <> " --dp "
    <> dp_id
    <> "`",
  )
  Ok(Nil)
}

/// `dataplane list` — the fleet, and what each pod is carrying.
///
/// The hosted-network count is the number an operator places by, and the
/// unassigned tally under it is the one they act on: a hosted network with no
/// data plane is replicated by nobody, and nothing else in the system says so
/// out loud.
fn dataplane_list() -> Result(Nil, String) {
  use cfg <- result.try(config.load())
  use conn <- result.try(open_primary_db(cfg))
  use fleet <- result.try(
    dataplane.list(conn)
    |> result.map_error(fn(e) { "reading the fleet: " <> string.inspect(e) }),
  )
  use orphans <- result.try(
    sqlite.query(
      conn,
      "SELECT o.slug, n.name FROM networks n JOIN orgs o ON o.id = n.org_id
       WHERE n.cloud_hosted = 1 AND n.cloud_dp_id IS NULL
       ORDER BY o.slug, n.name",
      [],
    )
    |> result.map_error(fn(e) {
      "reading unassigned networks: " <> string.inspect(e)
    }),
  )
  sqlite.close(conn)
  case fleet {
    [] -> io.println("no data planes registered")
    _ ->
      list.each(fleet, fn(row) {
        let #(dp_id, hosted) = row
        io.println(dp_id <> "\t" <> int.to_string(hosted) <> " hosted")
      })
  }
  case orphans {
    [] -> Nil
    rows -> {
      io.println(
        "\n"
        <> int.to_string(list.length(rows))
        <> " hosted network(s) assigned to no data plane — replicated by nobody:",
      )
      list.each(rows, fn(row) {
        case row {
          [sqlite.Text(slug), sqlite.Text(network)] ->
            io.println("  " <> slug <> "/" <> network)
          _ -> Nil
        }
      })
    }
  }
  Ok(Nil)
}

/// `dataplane assign <org> <network> <dp-id>` — moves one network's hosting.
///
/// The only path that reassigns, and it is an operator's on purpose. Moving a
/// tenant means one pod stops writing its database stream and another starts;
/// nothing in this service can tell that the losing pod has actually stopped,
/// so the judgement is left with the person who can look. Automating it on a
/// signal as noisy as "the fleet looks uneven" is how two pods end up writing
/// one tenant's stream, which is the failure the whole assignment exists to
/// remove (docs/CLOUD-DATAPLANE.md §7.2).
fn dataplane_assign(
  org_slug: String,
  network_name: String,
  dp_id: String,
) -> Result(Nil, String) {
  use cfg <- result.try(config.load())
  use conn <- result.try(open_primary_db(cfg))
  let now = now_unix()
  use known <- result.try(
    dataplane.exists(conn, dp_id)
    |> result.map_error(fn(e) { "reading the fleet: " <> string.inspect(e) }),
  )
  use _ <- result.try(case known {
    True -> Ok(Nil)
    False -> Error("no data plane called " <> dp_id)
  })
  use rows <- result.try(
    sqlite.query(
      conn,
      "SELECT n.id FROM networks n JOIN orgs o ON o.id = n.org_id
       WHERE o.slug = ? AND n.name = ?",
      [sqlite.Text(org_slug), sqlite.Text(network_name)],
    )
    |> result.map_error(fn(e) {
      "looking up the network: " <> string.inspect(e)
    }),
  )
  use network_id <- result.try(case rows {
    [[sqlite.Text(network_id)]] -> Ok(network_id)
    _ -> Error("no network " <> org_slug <> "/" <> network_name)
  })
  use previous <- result.try(
    dataplane.assignment(conn, network_id)
    |> result.map_error(fn(e) {
      "reading the assignment: " <> string.inspect(e)
    }),
  )
  use _ <- result.try(
    dataplane.assign(conn, network_id, dp_id, now)
    |> result.map_error(fn(e) { "assigning: " <> string.inspect(e) }),
  )
  use _ <- result.try(
    sqlite.exec(
      conn,
      "INSERT INTO audit_log (at, actor, org_id, action, detail)
       VALUES (?, 'system:dataplane-assign', NULL, 'dataplane.assign', ?)",
      [
        sqlite.Int(now),
        sqlite.Text(
          json.to_string(
            json.object([
              #("org", json.string(org_slug)),
              #("network", json.string(network_name)),
              #("dp", json.string(dp_id)),
              #("from", case previous {
                Ok(from) -> json.string(from)
                Error(Nil) -> json.null()
              }),
            ]),
          ),
        ),
      ],
    )
    |> result.map_error(fn(e) {
      "recording the assignment: " <> string.inspect(e)
    }),
  )
  sqlite.close(conn)
  io.println(
    org_slug
    <> "/"
    <> network_name
    <> " is now hosted by "
    <> dp_id
    <> case previous {
      Ok(from) if from != dp_id ->
        "\n; it was on "
        <> from
        <> ": make sure that pod has drained the tenant before this one"
        <> "\n; opens the same database stream"
      _ -> ""
    },
  )
  Ok(Nil)
}

fn endpoint(listen: config.Listen) -> String {
  case string.contains(listen.address, ":") {
    True -> "[" <> listen.address <> "]:" <> int.to_string(listen.port)
    False -> listen.address <> ":" <> int.to_string(listen.port)
  }
}

/// Step 1 of a zone-key rollover: publish the incoming key beside the one
/// in service, without handing it any signing duty.
///
/// The zone then serves a two-key DNSKEY RRset, still signed by the active
/// key. That is what makes the rest of the rollover possible: the parent
/// can be given the incoming DS, and `rekor-publish` can claim a key set
/// that already contains the incoming key — which is the step the publish
/// gate will look for when the incoming key later takes over.
fn zone_key_stage(
  apex_text: String,
  key_file: String,
  incoming_key_file: String,
) -> Result(Nil, String) {
  use cfg <- result.try(config.load())
  use apex <- result.try(
    name.parse(apex_text) |> result.replace_error("invalid apex domain"),
  )
  use csk <- result.try(keys.load(key_file))
  use incoming <- result.try(keys.load(incoming_key_file))
  use conn <- result.try(open_primary_db(cfg))
  case
    publish.stage_incoming(
      conn,
      csk,
      incoming.public,
      now_unix(),
      "zone-key stage",
    )
  {
    Ok(_) -> {
      io.println("; incoming key staged and published beside the active key.")
      print_material(apex, incoming)
      io.println("")
      io.println("; next: give the parent zone the DS above, wait for it to")
      io.println("; appear and for the old DS's TTL to pass, then run")
      io.println(";   controlplane rekor-publish " <> key_file)
      io.println("; so the log entry claims a key set containing both keys.")
      io.println("; only then swap in the incoming key file and run")
      io.println(
        ";   controlplane zone-key promote "
        <> apex_text
        <> " <incoming-keyfile>",
      )
      Ok(Nil)
    }
    Error(publish.IncomingIsActive) ->
      Error("that key is already the active zone key")
    Error(other) -> Error("staging the incoming key: " <> string.inspect(other))
  }
}

/// Step 2: the staged key becomes the signer and the outgoing key leaves
/// the RRset. `key_file` is the incoming key's own file.
///
/// Gated: after this the zone is signed by the incoming key, so under
/// `CP_REKOR_REQUIRE=true` it refuses unless that key is already on the
/// public record — which is exactly what step 1 and the `rekor-publish`
/// between them arranged.
fn zone_key_promote(
  apex_text: String,
  key_file: String,
) -> Result(Nil, String) {
  use cfg <- result.try(config.load())
  use _apex <- result.try(
    name.parse(apex_text) |> result.replace_error("invalid apex domain"),
  )
  use csk <- result.try(keys.load(key_file))
  use conn <- result.try(open_primary_db(cfg))
  case publish.promote_incoming(conn, csk, now_unix(), "zone-key promote") {
    Ok(_) -> {
      io.println("; promoted: the zone is now signed by this key, and the")
      io.println("; outgoing key has left the DNSKEY RRset.")
      io.println("; next: remove the outgoing DS from the parent, then run")
      io.println(";   controlplane rekor-publish " <> key_file)
      io.println("; so the record claims only the key now in service.")
      Ok(Nil)
    }
    Error(publish.NoIncomingKey) ->
      Error("no rollover in flight: run `zone-key stage` first")
    Error(publish.KeyMismatch) ->
      Error("this is not the staged incoming key file")
    // The gate refusing here means the incoming key was never logged while
    // it was staged — the one ordering mistake this whole sequence exists
    // to prevent, so name the step that was skipped rather than the rule.
    Error(publish.NoRekorRecord(tag)) ->
      Error(
        "the incoming key (tag "
        <> int.to_string(tag)
        <> ") is not on the public record: run `rekor-publish` while it is "
        <> "still staged, then promote",
      )
    Error(other) ->
      Error("promoting the incoming key: " <> string.inspect(other))
  }
}
