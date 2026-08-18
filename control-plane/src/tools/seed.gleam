//// The `seed` CLI subcommand: demo data for the e2e suite — org acme,
//// network prod, device nas (one active key, one revoked), device laptop
//// (rotation window: active + retiring) — published, with the generated
//// keys printed so e2e can assert on exact zone contents.

import config.{type Config}
import dnssec/keys.{type Csk}
import gleam/int
import gleam/io
import gleam/result
import gleam/string
import store/sqlite.{type Connection}
import thirtytwo
import zone/publish

@external(erlang, "cp_sys_ffi", "now_unix")
fn now_unix() -> Int

@external(erlang, "cp_crypto_ffi", "ed25519_generate_public")
fn ed25519_generate_public() -> BitArray

/// Seeds the demo zone on an open, migrated primary connection and
/// publishes it. The caller (controlplane's dispatch) owns the connection.
pub fn run(cfg: Config, conn: Connection, csk: Csk) -> Result(Nil, String) {
  use Nil <- result.try(publish.ensure_meta(conn, cfg.base_domain, csk))
  use _ <- result.try(
    publish.set_ns_hosts(conn, cfg.ns_hosts)
    |> result.map_error(fn(e) { "ns hosts: " <> string.inspect(e) }),
  )
  let nk = fn() { thirtytwo.z_base_32_encode(ed25519_generate_public()) }
  let nas_active = nk()
  let nas_revoked = nk()
  let laptop_active = nk()
  let laptop_retiring = nk()
  let now = int.to_string(now_unix())
  // Literal-and-integer concatenation only — the script() contract.
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
       INSERT OR IGNORE INTO networks (id, org_id, name, created_at)
       VALUES ('net-prod', 'org-acme', 'prod', "
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
  use _ <- result.try(add_key(
    conn,
    "key-nas-1",
    "dev-nas",
    nas_active,
    "active",
  ))
  use _ <- result.try(add_key(
    conn,
    "key-nas-0",
    "dev-nas",
    nas_revoked,
    "revoked",
  ))
  use _ <- result.try(add_key(
    conn,
    "key-laptop-1",
    "dev-laptop",
    laptop_active,
    "active",
  ))
  use _ <- result.try(add_key(
    conn,
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

fn add_key(
  conn: Connection,
  id: String,
  device: String,
  z32: String,
  state: String,
) -> Result(Nil, String) {
  sqlite.exec(conn, "INSERT INTO device_keys VALUES (?, ?, ?, ?, ?, ?, NULL)", [
    sqlite.Text(id),
    sqlite.Text(device),
    sqlite.Text(z32),
    sqlite.Blob(unwrap_nk(z32)),
    sqlite.Text(state),
    sqlite.Int(now_unix()),
  ])
  |> result.map_error(fn(e) { "seeding key: " <> string.inspect(e) })
  |> result.replace(Nil)
}

fn unwrap_nk(z32: String) -> BitArray {
  case thirtytwo.z_base_32_decode(z32) {
    Ok(bytes) -> bytes
    Error(Nil) -> <<>>
  }
}
