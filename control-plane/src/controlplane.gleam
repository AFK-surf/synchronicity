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
////   migrate-check         replay the migration chain against a scratch DB

import api/agent
import api/auth_api
import api/browse_api
import api/edge
import api/reads
import api/router
import auth/github
import auth/google
import auth/magic
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
    ["serve"] -> run_or_die(serve)
    _ -> {
      io.println_error(
        "usage: controlplane serve | keygen <apex> <keyfile> | ds <apex> <keyfile> | rekor-publish <keyfile> | rekor-retire <keyfile> | zone-key stage <apex> <keyfile> <incoming-keyfile> | zone-key promote <apex> <keyfile> | provider-sync | seed | seed-admin <email> | migrate-check",
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
/// line: it is the zone this deployment publishes and signs, so a
/// command-line apex was only ever a typo or a way to put an entry naming
/// somebody else's apex into a public log. Public so the suite can hold that
/// down without a database or a log.
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

/// The browse surface a deployment offers, or `option.None` with `CP_BROWSE`
/// off — which is how every route, the tunnel and the apex record disappear
/// together rather than one of them being left behind.
fn browse_surface(
  cfg: Config,
  agents: process.Name(agent.Msg),
) -> option.Option(browse_api.Browse) {
  case cfg.browse {
    True ->
      option.Some(browse_api.Browse(agents, agent.attach_url(cfg.public_url)))
    False -> option.None
  }
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
/// With `CP_DASHBOARD=on` it also serves the dashboard and the read half of
/// the product API off that same copy, and with `CP_BROWSE=on` the browse
/// surface too — daemons attach *here*, to this node's own `CP_PUBLIC_URL`,
/// because the registry of attached sessions is one process's memory and a
/// node with no tunnel of its own can answer no browse question however
/// faithfully the database replicated. The primary lists the fleet's
/// endpoints in the apex record with `CP_BROWSE_ENDPOINTS`, and every daemon
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
  let dns_pool = pool.handle(dns_name, db.read_pragmas)
  let serving = dns_serve.Serving(dns_pool, meta.apex)
  // The dashboard reads the same pool the nameserver does: both are
  // read-only against the same replicated file, and a second pool would only
  // double the workers competing for it.
  let api = case cfg.dashboard {
    True -> option.Some(router.ReadOnly(reads.Reads(dns_pool), cfg.primary_url))
    False -> option.None
  }
  let browse = browse_surface(cfg, agents_name)
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
  // cookie the primary minted verifies here. A replica with no dashboard
  // reads no cookie at all, and the placeholder says so rather than looking
  // like a key somebody chose badly.
  let cookie_secret = case cfg.dashboard {
    True -> cfg.session_secret
    False -> "replica-has-no-sessions-0000000000000000"
  }
  let http =
    wisp_mist.handler(handler, cookie_secret)
    |> edge.handler(edge.surface(browse, dns_pool, cookie_secret))
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
      replica_pool_size(cfg),
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
  let tree = case browse {
    option.Some(_) -> sup.add(tree, agent.supervised(agents_name))
    option.None -> tree
  }
  use _ <- result.try(
    tree
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
    <> case cfg.dashboard {
      True -> " — read-only dashboard, writes at " <> cfg.primary_url
      False -> " — dns only"
    }
    <> case cfg.browse {
      True -> " — attach at " <> agent.attach_url(cfg.public_url)
      False -> ""
    },
  )
  process.sleep_forever()
  Ok(Nil)
}

/// How many pooled readers a replica runs.
///
/// Four is what a nameserver alone needs: a DNS answer is one short read
/// transaction out of a pre-signed table. A replica that also serves the
/// dashboard has a second kind of caller — a browse call resolves its org on
/// a connection, and `router.with_session` borrows one to check the cookie
/// before the handler borrows its own — so it gets the primary's eight.
/// Sizing them the same would let a handful of dashboard tabs queue DNS
/// answers behind them.
fn replica_pool_size(cfg: Config) -> Int {
  case cfg.dashboard {
    True -> 8
    False -> 4
  }
}

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
  let api_pool = pool.handle(api_name, db.primary_pragmas)
  let dns_pool = pool.handle(dns_name, db.read_pragmas)
  let serving = dns_serve.Serving(dns_pool, apex)
  let browse = browse_surface(cfg, agents_name)
  let auth =
    auth_api.AuthContext(
      reads.Reads(api_pool),
      cfg.public_url,
      mail,
      option.map(cfg.google, fn(pair) { google.provider(pair.0, pair.1) }),
      option.map(cfg.github, fn(pair) { github.provider(pair.0, pair.1) }),
      fn(conn, now, actor, change) {
        publish.publish_in_tx(conn, csk, now, actor, change)
      },
      // Serve mode: commit is publication; there is nobody to nudge.
      fn() { Nil },
      cfg.cookie_domain,
    )
  let ctx =
    router.Context(
      keys.anchor_line(apex, csk.public),
      keys.ds_line(apex, csk.public),
      option.Some(router.Writable(auth)),
      router.ServingZone(serving),
      browse,
    )
  let handler = fn(req) { router.handle(req, ctx) }
  let http =
    wisp_mist.handler(handler, cfg.session_secret)
    |> edge.handler(edge.surface(browse, api_pool, cfg.session_secret))
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
/// image and moves on a deploy (see `tuf/trusted_root`); nothing here walks
/// a repository. This comment used to say the opposite, which sent a reader
/// looking for a job that migration v8 removed.
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
  let api_pool = pool.handle(api_name, db.primary_pragmas)
  let browse = browse_surface(cfg, agents_name)
  let auth =
    auth_api.AuthContext(
      reads.Reads(api_pool),
      cfg.public_url,
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
      cfg.cookie_domain,
    )
  let ctx =
    router.Context(
      "",
      "",
      option.Some(router.Writable(auth)),
      router.ExternalZone(api_pool),
      browse,
    )
  let handler = fn(req) { router.handle(req, ctx) }
  let http =
    wisp_mist.handler(handler, cfg.session_secret)
    |> edge.handler(edge.surface(browse, api_pool, cfg.session_secret))
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
    <> cfg.public_url
    <> "/auth/magic/redeem?token="
    <> token,
  )
  sqlite.close(conn)
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
