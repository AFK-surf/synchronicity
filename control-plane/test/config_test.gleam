import config
import envoy
import gleam/option.{None}

fn primary_env() -> Nil {
  envoy.set("CP_ROLE", "primary")
  envoy.set("CP_BASE_DOMAIN", "sync.test")
  envoy.set("CP_DB_PATH", "/tmp/cp.db")
  envoy.set("CP_KEY_FILE", "/tmp/csk.key")
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
