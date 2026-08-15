//// Entry point for the synchronicity control plane.
////
//// Subcommands:
////   serve                 run the service (configuration from CP_* env)
////   keygen <apex> <file>  generate the zone CSK; print DNSKEY / DS / anchor
////   ds <apex> <file>      print DS + anchor material for an existing key
////   seed                  create a demo org/network/devices and publish
////   migrate-check         replay the migration chain against a scratch DB
////   seed-admin <email>    (later) first-user bootstrap

import api/auth_api
import api/router
import auth/github
import auth/google
import config.{type Config, Primary, Replica}
import dns/name
import dns/server_tcp
import dns/server_udp
import dnssec/keys
import email/mailer
import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/option
import gleam/result
import gleam/string
import mist
import store/db
import store/migrate
import store/sqlite
import thirtytwo
import wisp
import wisp/wisp_mist
import zone/publish
import zone/snapshot

@external(erlang, "cp_sys_ffi", "argv")
fn argv() -> List(String)

@external(erlang, "cp_sys_ffi", "now_unix")
fn now_unix() -> Int

@external(erlang, "cp_crypto_ffi", "ed25519_generate_public")
fn ed25519_generate_public() -> BitArray

@external(erlang, "erlang", "halt")
fn halt(code: Int) -> Nil

pub fn main() {
  case argv() {
    ["keygen", apex, key_file] -> keygen(apex, key_file)
    ["ds", apex, key_file] -> print_key_material(apex, key_file)
    ["migrate-check"] -> migrate_check()
    ["seed"] -> run_or_die(seed)
    ["serve"] -> run_or_die(serve)
    _ -> {
      io.println_error(
        "usage: controlplane serve | keygen <apex> <keyfile> | ds <apex> <keyfile> | seed | migrate-check",
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
  io.println(keys.ds_line(apex, csk))
  io.println("; trust-anchor line for synch --dnssec-anchor:")
  io.println(keys.anchor_line(apex, csk))
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

fn prepare_primary(
  cfg: Config,
) -> Result(#(sqlite.Connection, keys.Csk), String) {
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
  use snap <- result.try(snapshot.load(conn, now_unix()))
  snapshot.install(snap)
  Ok(#(conn, csk))
}

fn serve() -> Result(Nil, String) {
  use cfg <- result.try(config.load())
  case cfg.role {
    Primary -> serve_primary(cfg)
    Replica -> Error("replica role lands with the replication milestone")
  }
}

fn serve_primary(cfg: Config) -> Result(Nil, String) {
  use #(_conn, csk) <- result.try(prepare_primary(cfg))
  use apex <- result.try(
    name.parse(cfg.base_domain) |> result.replace_error("bad base domain"),
  )
  let mail = case cfg.smtp {
    option.Some(#(host, port, user, pass, from)) ->
      mailer.Smtp(host, port, user, pass, from)
    option.None -> mailer.LogOnly
  }
  io.println("mailer: " <> mailer.describe(mail))
  let auth =
    auth_api.AuthContext(
      cfg.db_path,
      cfg.public_url,
      mail,
      option.map(cfg.google, fn(pair) { google.provider(pair.0, pair.1) }),
      option.map(cfg.github, fn(pair) { github.provider(pair.0, pair.1) }),
      csk,
    )
  let ctx =
    router.Context(
      keys.anchor_line(apex, csk),
      keys.ds_line(apex, csk),
      option.Some(auth),
    )

  use Nil <- result.try(server_udp.start(cfg.dns_port))
  use Nil <- result.try(server_tcp.start(cfg.dns_port))

  let secret = cfg.session_secret
  let handler = fn(req) { router.handle(req, ctx) }
  use _ <- result.try(
    wisp_mist.handler(handler, secret)
    |> mist.new
    |> mist.bind("0.0.0.0")
    |> mist.port(cfg.http_port)
    |> mist.start
    |> result.map_error(fn(_) { "could not start HTTP listener" }),
  )
  io.println(
    "serving "
    <> cfg.base_domain
    <> " — dns :"
    <> int.to_string(cfg.dns_port)
    <> " http :"
    <> int.to_string(cfg.http_port),
  )
  process.sleep_forever()
  Ok(Nil)
}

/// Demo data: org acme, network prod, device nas (one active key, one
/// revoked), device laptop (rotation window: active + retiring). Prints
/// the generated keys so e2e can assert on exact contents.
fn seed() -> Result(Nil, String) {
  use cfg <- result.try(config.load())
  use #(conn, csk) <- result.try({
    use conn <- result.try(open_primary_db(cfg))
    use csk <- result.try(keys.load(cfg.key_file))
    use Nil <- result.try(publish.ensure_meta(conn, cfg.base_domain, csk))
    use _ <- result.try(
      publish.set_ns_hosts(conn, cfg.ns_hosts)
      |> result.map_error(fn(e) { "ns hosts: " <> string.inspect(e) }),
    )
    Ok(#(conn, csk))
  })
  let nk = fn() { thirtytwo.z_base_32_encode(ed25519_generate_public()) }
  let nas_active = nk()
  let nas_revoked = nk()
  let laptop_active = nk()
  let laptop_retiring = nk()
  let now = int.to_string(now_unix())
  use _ <- result.try(
    sqlite.script(
      conn,
      "INSERT OR IGNORE INTO users VALUES ('seed-user', 'seed@example.com', 'Seed', "
        <> now
        <> ");
       INSERT OR IGNORE INTO orgs VALUES ('org-acme', 'acme', 'Acme', "
        <> now
        <> ");
       INSERT OR IGNORE INTO org_members VALUES ('org-acme', 'seed-user', 'owner', "
        <> now
        <> ");
       INSERT OR IGNORE INTO networks VALUES ('net-prod', 'org-acme', 'prod', "
        <> now
        <> ");
       DELETE FROM network_devices;
       DELETE FROM device_keys;
       DELETE FROM devices;
       INSERT INTO devices VALUES ('dev-nas', 'org-acme', 'nas', NULL, NULL, 'seed-user', "
        <> now
        <> ");
       INSERT INTO devices VALUES ('dev-laptop', 'org-acme', 'laptop', NULL, NULL, 'seed-user', "
        <> now
        <> ");
       INSERT INTO network_devices VALUES ('net-prod', 'dev-nas', "
        <> now
        <> ");
       INSERT INTO network_devices VALUES ('net-prod', 'dev-laptop', "
        <> now
        <> ");",
    )
    |> result.map_error(fn(e) { "seeding: " <> string.inspect(e) }),
  )
  let add_key = fn(id: String, device: String, z32: String, state: String) {
    sqlite.exec(
      conn,
      "INSERT INTO device_keys VALUES (?, ?, ?, ?, ?, ?, NULL)",
      [
        sqlite.Text(id),
        sqlite.Text(device),
        sqlite.Text(z32),
        sqlite.Blob(unwrap_nk(z32)),
        sqlite.Text(state),
        sqlite.Int(now_unix()),
      ],
    )
    |> result.map_error(fn(e) { "seeding key: " <> string.inspect(e) })
  }
  use _ <- result.try(add_key("key-nas-1", "dev-nas", nas_active, "active"))
  use _ <- result.try(add_key("key-nas-0", "dev-nas", nas_revoked, "revoked"))
  use _ <- result.try(add_key(
    "key-laptop-1",
    "dev-laptop",
    laptop_active,
    "active",
  ))
  use _ <- result.try(add_key(
    "key-laptop-0",
    "dev-laptop",
    laptop_retiring,
    "retiring",
  ))
  use serial <- result.try(
    publish.publish(conn, csk, now_unix(), "system:seed")
    |> result.map_error(fn(e) { "publishing: " <> string.inspect(e) }),
  )
  io.println("seeded domain=prod.acme." <> cfg.base_domain)
  io.println("serial=" <> int.to_string(serial))
  io.println("nas_active=" <> nas_active)
  io.println("nas_revoked=" <> nas_revoked)
  io.println("laptop_active=" <> laptop_active)
  io.println("laptop_retiring=" <> laptop_retiring)
  Ok(Nil)
}

fn unwrap_nk(z32: String) -> BitArray {
  let decoded = thirtytwo.z_base_32_decode(z32)
  case decoded {
    Ok(bytes) -> bytes
    Error(Nil) -> <<>>
  }
}
