//// Entry point for the synchronicity control plane: CLI dispatch and the
//// two supervision trees (primary, replica).
////
//// Subcommands:
////   serve                 run the service (configuration from CP_* env)
////   keygen <apex> <file>  generate the zone CSK; print DNSKEY / DS / anchor
////   ds <apex> <file>      print DS + anchor material for an existing key
////   seed                  create a demo org/network/devices and publish
////   seed-admin <email>    first-user bootstrap: print a one-time magic link
////   migrate-check         replay the migration chain against a scratch DB

import api/auth_api
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
import gleam/option
import gleam/otp/static_supervisor as sup
import gleam/result
import gleam/string
import jobs/resign
import mist
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
    ["migrate-check"] -> migrate_check()
    ["seed"] -> run_or_die(run_seed)
    ["seed-admin", email] -> run_or_die(fn() { seed_admin(email) })
    ["serve"] -> run_or_die(serve)
    _ -> {
      io.println_error(
        "usage: controlplane serve | keygen <apex> <keyfile> | ds <apex> <keyfile> | seed | seed-admin <email> | migrate-check",
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
  use _ <- result.try(
    publish.publish(conn, csk, now_unix(), "system:boot")
    |> result.map_error(fn(e) { "publishing zone: " <> string.inspect(e) }),
  )
  sqlite.close(conn)
  Ok(csk)
}

fn serve() -> Result(Nil, String) {
  use cfg <- result.try(config.load())
  case cfg.role {
    Primary -> serve_primary(cfg)
    Replica -> serve_replica(cfg)
  }
}

/// A replica serves DNS/DoH from a database an external process refreshes
/// (atomic rename); it holds no key material and mounts no product API.
/// No reload signal exists or is needed: every pooled checkout reopens
/// the database file, so a swapped replacement is seen on the next query.
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
  let dns_pool = pool.handle(dns_name, db.read_pragmas)
  let serving = dns_serve.Serving(dns_pool, meta.apex)
  let ctx =
    router.Context(
      keys.anchor_line(meta.apex, meta.dnskey_public),
      keys.ds_line(meta.apex, meta.dnskey_public),
      option.None,
      serving,
    )
  let handler = fn(req) { router.handle(req, ctx) }
  let http =
    wisp_mist.handler(handler, "replica-has-no-sessions-0000000000000000")
    |> mist.new
    |> mist.bind(cfg.http_listen.address)
    |> mist.port(cfg.http_listen.port)
  use _ <- result.try(
    sup.new(sup.OneForOne)
    |> sup.restart_tolerance(intensity: 60, period: 10)
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
    <> endpoint(cfg.http_listen),
  )
  process.sleep_forever()
  Ok(Nil)
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
  let api_pool = pool.handle(api_name, db.primary_pragmas)
  let dns_pool = pool.handle(dns_name, db.read_pragmas)
  let serving = dns_serve.Serving(dns_pool, apex)
  let auth =
    auth_api.AuthContext(
      api_pool,
      cfg.public_url,
      mail,
      option.map(cfg.google, fn(pair) { google.provider(pair.0, pair.1) }),
      option.map(cfg.github, fn(pair) { github.provider(pair.0, pair.1) }),
      csk,
    )
  let ctx =
    router.Context(
      keys.anchor_line(apex, csk.public),
      keys.ds_line(apex, csk.public),
      option.Some(auth),
      serving,
    )
  let handler = fn(req) { router.handle(req, ctx) }
  let http =
    wisp_mist.handler(handler, cfg.session_secret)
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
