import config
import controlplane
import dns/name
import envoy
import gleam/option.{None}

fn primary_env() -> Nil {
  envoy.set("CP_ROLE", "primary")
  envoy.set("CP_BASE_DOMAIN", "sync.test")
  // The database sits in its own subdirectory so the csqlite sandbox's
  // directory grant never covers the sibling signing key.
  envoy.set("CP_DB_PATH", "/var/lib/cp/db/cp.db")
  envoy.set("CP_KEY_FILE", "/var/lib/cp/csk.key")
  envoy.set("CP_SESSION_SECRET", "0123456789abcdef0123456789abcdef")
  envoy.unset("CP_HTTP_PORT")
  envoy.unset("CP_DNS_PORT")
  envoy.unset("CP_HTTP_LISTEN")
  envoy.unset("CP_DNS_LISTEN")
  envoy.unset("CP_NS_HOSTS")
  envoy.unset("CP_PUBLIC_URL")
  envoy.unset("CP_SMTP_HOST")
  envoy.unset("CP_GOOGLE_CLIENT_ID")
  envoy.unset("CP_GOOGLE_CLIENT_SECRET")
  envoy.unset("CP_GITHUB_CLIENT_ID")
  envoy.unset("CP_GITHUB_CLIENT_SECRET")
}

pub fn listen_defaults_to_all_interfaces_test() {
  primary_env()
  let assert Ok(cfg) = config.load()
  assert cfg.http_listen == config.Listen("0.0.0.0", 8080)
  assert cfg.dns_listen == config.Listen("0.0.0.0", 53)
  assert cfg.smtp == None
}

pub fn listen_addresses_from_env_test() {
  primary_env()
  envoy.set("CP_HTTP_LISTEN", "127.0.0.1:8053")
  envoy.set("CP_DNS_LISTEN", "[::1]:5359")
  let assert Ok(cfg) = config.load()
  assert cfg.http_listen == config.Listen("127.0.0.1", 8053)
  assert cfg.dns_listen == config.Listen("::1", 5359)
}

pub fn localhost_listen_is_accepted_test() {
  primary_env()
  envoy.set("CP_HTTP_LISTEN", "localhost:8080")
  envoy.set("CP_DNS_LISTEN", "localhost:53")
  let assert Ok(cfg) = config.load()
  assert cfg.http_listen == config.Listen("localhost", 8080)
  assert cfg.dns_listen == config.Listen("localhost", 53)
}

pub fn listen_must_include_a_port_test() {
  primary_env()
  envoy.set("CP_DNS_LISTEN", "127.0.0.1")
  let assert Error(message) = config.load()
  assert message
    == "CP_DNS_LISTEN must be address:port (IPv4, [IPv6], or localhost)"
}

pub fn listen_rejects_unbracketed_ipv6_test() {
  primary_env()
  envoy.set("CP_DNS_LISTEN", "::1:53")
  let assert Error(message) = config.load()
  assert message
    == "CP_DNS_LISTEN must be address:port (IPv4, [IPv6], or localhost)"
}

pub fn listen_rejects_bad_port_test() {
  primary_env()
  envoy.set("CP_HTTP_LISTEN", "127.0.0.1:70000")
  let assert Error(message) = config.load()
  assert message
    == "CP_HTTP_LISTEN must be address:port (IPv4, [IPv6], or localhost)"
}

pub fn listen_rejects_non_address_host_test() {
  primary_env()
  envoy.set("CP_DNS_LISTEN", "not-an-ip:53")
  let assert Error(message) = config.load()
  assert message
    == "CP_DNS_LISTEN must be address:port (IPv4, [IPv6], or localhost)"
}

pub fn separate_port_env_is_removed_test() {
  primary_env()
  envoy.set("CP_HTTP_PORT", "8080")
  let assert Error(message) = config.load()
  assert message
    == "CP_HTTP_PORT is removed; set CP_HTTP_LISTEN to address:port"
}

pub fn db_path_must_be_absolute_test() {
  primary_env()
  envoy.set("CP_DB_PATH", "cp.db")
  let assert Error(message) = config.load()
  assert message == "CP_DB_PATH must be an absolute path, got: cp.db"
}

pub fn db_must_not_share_a_directory_with_the_key_test() {
  primary_env()
  envoy.set("CP_DB_PATH", "/var/lib/cp/cp.db")
  envoy.set("CP_KEY_FILE", "/var/lib/cp/csk.key")
  let assert Error(message) = config.load()
  assert message
    == "CP_DB_PATH and CP_KEY_FILE must not share a directory: the csqlite "
    <> "sandbox grants the database's directory, so the signing key must "
    <> "sit elsewhere. Put the database in its own subdirectory, e.g. "
    <> "/var/lib/cp/db/."
}

/// The ceremony commands take the apex from configuration, never from argv.
///
/// `rekor-publish` puts an entry naming an apex into a public log. Reading that
/// apex from the command line made a typo a claim about a name this deployment
/// does not own, and the configuration already says which name that is. The
/// signing zone follows the mode: the apex itself in serve mode, the
/// provider-hosted zone above it in external mode.
pub fn a_ceremony_names_the_configured_apex_test() {
  primary_env()
  let assert Ok(cfg) = config.load()
  let assert Ok(apex) = name.parse("sync.test")
  assert controlplane.ceremony_zones(cfg) == Ok(#(apex, apex))

  envoy.unset("CP_KEY_FILE")
  envoy.set("CP_DNS_MODE", "external")
  envoy.set("CP_DNS_PROVIDER", "log-only")
  envoy.set("CP_SIGNING_ZONE", "test")
  let assert Ok(external) = config.load()
  let assert Ok(signing_zone) = name.parse("test")
  assert controlplane.ceremony_zones(external) == Ok(#(apex, signing_zone))
  envoy.unset("CP_DNS_MODE")
  envoy.unset("CP_DNS_PROVIDER")
  envoy.unset("CP_SIGNING_ZONE")
}
