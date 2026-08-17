//// Boot configuration from the environment. Missing required
//// configuration names itself and refuses to start — no defaults for
//// anything that changes what the service *is*.

import envoy
import gleam/bool
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

/// The database's directory, used to keep it disjoint from the key file.
@external(erlang, "filename", "dirname")
fn dirname(path: String) -> String

pub type Role {
  Primary
  Replica
}

/// How the zone reaches the wire (docs/EXTERNAL-DNS-PROVIDER.md).
pub type DnsMode {
  /// This service is the authoritative DNSSEC nameserver — today's shape.
  Serve
  /// A managed provider hosts and signs the zone; this service publishes
  /// the data records through its API and runs no DNS listeners and no key
  /// material at all — transparency claims are signed with an ephemeral
  /// key minted per entry, because the signature is attribution and
  /// authorization is the chain (docs/EXTERNAL-DNS-PROVIDER.md §2.1).
  ///
  /// `signing_zone` is the DNS zone the provider actually hosts, which need
  /// not be the apex: a control plane at `sync.example.com` may live
  /// entirely inside the `example.com` zone, with no delegation of its own.
  /// The zone's own keys sign every record under it, so that zone — not the
  /// apex — is where the proof and TUF records go and where a chain's
  /// ladder starts. Equal to the apex unless `CP_SIGNING_ZONE` says
  /// otherwise.
  External(provider: ProviderConfig, signing_zone: String)
}

/// Which provider, and how to reach it. `zone_id` empty means "discover by
/// zone name at boot" where the provider's API allows it. `api_url` empty
/// means the provider's real endpoint; tests and the e2e stub override it.
pub type ProviderConfig {
  Cloudflare(api_token: String, zone_id: String, api_url: String)
  Bunny(api_key: String, zone_id: String, api_url: String)
  /// No credentials: print the change set instead of applying it.
  LogOnly
}

/// Bind address and port, from `address:port` (IPv6 as `[::1]:53`).
pub type Listen {
  Listen(address: String, port: Int)
}

pub type Config {
  Config(
    role: Role,
    /// The zone apex, e.g. "sync.example" (no trailing dot).
    base_domain: String,
    db_path: String,
    /// Primary only; replicas must not have key material.
    key_file: String,
    http_listen: Listen,
    dns_listen: Listen,
    /// (hostname, ipv4, ipv6) — hostname relative to apex unless dotted.
    ns_hosts: List(#(String, String, String)),
    public_url: String,
    /// Signs session cookies; sessions survive restarts because of it.
    session_secret: String,
    /// (host, port, username, password, from) — absent means log-only mail.
    smtp: Option(#(String, Int, String, String, String)),
    /// (client_id, client_secret) — absent disables the provider.
    google: Option(#(String, String)),
    github: Option(#(String, String)),
    dns_mode: DnsMode,
  )
}

pub fn load() -> Result(Config, String) {
  use role <- result.try(case envoy.get("CP_ROLE") {
    Ok("primary") -> Ok(Primary)
    Ok("replica") -> Ok(Replica)
    Ok(other) -> Error("CP_ROLE must be primary or replica, got " <> other)
    Error(Nil) -> Error("CP_ROLE is required (primary | replica)")
  })
  use base_domain <- result.try(required("CP_BASE_DOMAIN"))
  use dns_mode <- result.try(dns_mode(role, base_domain))
  use db_path <- result.try(required("CP_DB_PATH"))
  use key_file <- result.try(case role, dns_mode {
    // External mode holds no zone key — the provider signs the zone, and a
    // CP_KEY_FILE lying around would be dead config pretending otherwise.
    Primary, External(..) ->
      case envoy.get("CP_KEY_FILE") {
        Ok(_) -> Error("CP_KEY_FILE must NOT be set with CP_DNS_MODE=external")
        Error(Nil) -> Ok("")
      }
    Primary, Serve -> required("CP_KEY_FILE")
    Replica, _ ->
      case envoy.get("CP_KEY_FILE") {
        Ok(_) -> Error("CP_KEY_FILE must NOT be set on a replica")
        Error(Nil) -> Ok("")
      }
  })
  use _ <- result.try(validate_db_path(db_path, key_file))
  use _ <- result.try(removed("CP_HTTP_PORT", "CP_HTTP_LISTEN"))
  use _ <- result.try(removed("CP_DNS_PORT", "CP_DNS_LISTEN"))
  use http_listen <- result.try(listen_from("CP_HTTP_LISTEN", "0.0.0.0:8080"))
  use _ <- result.try(case dns_mode {
    // No listeners in external mode: the provider answers. A listen address
    // configured anyway is a lie waiting to be believed.
    External(..) ->
      case envoy.get("CP_DNS_LISTEN") {
        Ok(_) ->
          Error("CP_DNS_LISTEN must NOT be set with CP_DNS_MODE=external")
        Error(Nil) -> Ok(Nil)
      }
    Serve -> Ok(Nil)
  })
  use dns_listen <- result.try(listen_from("CP_DNS_LISTEN", "0.0.0.0:53"))
  use ns_hosts <- result.try(case dns_mode {
    External(..) ->
      case envoy.get("CP_NS_HOSTS") {
        Ok(_) -> Error("CP_NS_HOSTS must NOT be set with CP_DNS_MODE=external")
        Error(Nil) -> Ok([])
      }
    Serve -> ns_hosts()
  })
  let public_url =
    envoy.get("CP_PUBLIC_URL")
    |> result.unwrap("http://127.0.0.1:" <> int.to_string(http_listen.port))
  use session_secret <- result.try(case role {
    Primary -> {
      use secret <- result.try(required("CP_SESSION_SECRET"))
      case string.length(secret) >= 32 {
        True -> Ok(secret)
        False -> Error("CP_SESSION_SECRET must be at least 32 characters")
      }
    }
    Replica -> Ok("")
  })
  use smtp <- result.try(smtp_config())
  Ok(Config(
    role,
    base_domain,
    db_path,
    key_file,
    http_listen,
    dns_listen,
    ns_hosts,
    public_url,
    session_secret,
    smtp,
    credential_pair("CP_GOOGLE_CLIENT_ID", "CP_GOOGLE_CLIENT_SECRET"),
    credential_pair("CP_GITHUB_CLIENT_ID", "CP_GITHUB_CLIENT_SECRET"),
    dns_mode,
  ))
}

/// `CP_DNS_MODE`: `serve` (the default — today's behavior, zero-config
/// compatible) or `external`. External mode names its provider and its
/// operational key, refuses on a replica, and — the other direction —
/// provider configuration present while the mode is `serve` is refused as
/// dead config: a credential that quietly does nothing is a lie.
fn dns_mode(role: Role, base_domain: String) -> Result(DnsMode, String) {
  let provider_env_present =
    list.any(
      ["CP_DNS_PROVIDER", "CP_CLOUDFLARE_API_TOKEN", "CP_BUNNY_API_KEY"],
      fn(key) { result.is_ok(envoy.get(key)) },
    )
  case envoy.get("CP_DNS_MODE") {
    Error(Nil) | Ok("serve") if provider_env_present ->
      Error(
        "provider configuration (CP_DNS_PROVIDER / CP_*_API_*) is set "
        <> "but CP_DNS_MODE is not external — remove it, or set "
        <> "CP_DNS_MODE=external",
      )
    Error(Nil) | Ok("serve") ->
      case result.is_ok(envoy.get("CP_SIGNING_ZONE")) {
        True ->
          Error(
            "CP_SIGNING_ZONE is only meaningful with CP_DNS_MODE=external: "
            <> "a serving control plane is the authoritative nameserver for "
            <> "its own apex, so the apex is the signing zone by definition",
          )
        False -> Ok(Serve)
      }
    Ok("external") -> {
      use Nil <- result.try(case role {
        Replica ->
          Error(
            "CP_DNS_MODE=external is a primary-only mode: the provider's "
            <> "fleet is the redundancy, and a replica has nothing to serve",
          )
        Primary -> Ok(Nil)
      })
      use provider <- result.try(provider_config())
      use signing_zone <- result.try(signing_zone(base_domain))
      Ok(External(provider, signing_zone))
    }
    Ok(other) -> Error("CP_DNS_MODE must be serve or external, got " <> other)
  }
}

/// The zone the provider hosts. Defaults to the apex — the ordinary case,
/// where the control plane runs a delegated zone of its own — and must
/// otherwise be a name that *contains* the apex, since a zone that does not
/// hold the apex's records cannot sign them.
fn signing_zone(base_domain: String) -> Result(String, String) {
  case envoy.get("CP_SIGNING_ZONE") {
    Error(Nil) -> Ok(base_domain)
    Ok(zone) -> {
      let zone = string.lowercase(string.trim(zone))
      let apex = string.lowercase(base_domain)
      case zone == apex || string.ends_with(apex, "." <> zone) {
        True -> Ok(zone)
        False ->
          Error(
            "CP_SIGNING_ZONE "
            <> zone
            <> " does not contain CP_BASE_DOMAIN "
            <> apex
            <> ", so it cannot be the zone that signs its records",
          )
      }
    }
  }
}

fn provider_config() -> Result(ProviderConfig, String) {
  case envoy.get("CP_DNS_PROVIDER") {
    Ok("cloudflare") -> {
      use token <- result.try(required("CP_CLOUDFLARE_API_TOKEN"))
      Ok(Cloudflare(
        api_token: token,
        zone_id: envoy.get("CP_CLOUDFLARE_ZONE_ID") |> result.unwrap(""),
        api_url: envoy.get("CP_CLOUDFLARE_API_URL") |> result.unwrap(""),
      ))
    }
    Ok("bunny") -> {
      use key <- result.try(required("CP_BUNNY_API_KEY"))
      Ok(Bunny(
        api_key: key,
        zone_id: envoy.get("CP_BUNNY_ZONE_ID") |> result.unwrap(""),
        api_url: envoy.get("CP_BUNNY_API_URL") |> result.unwrap(""),
      ))
    }
    Ok("log-only") -> Ok(LogOnly)
    Ok(other) ->
      Error(
        "CP_DNS_PROVIDER must be cloudflare, bunny or log-only, got " <> other,
      )
    Error(Nil) -> Error("CP_DNS_PROVIDER is required with CP_DNS_MODE=external")
  }
}

fn smtp_config() -> Result(
  Option(#(String, Int, String, String, String)),
  String,
) {
  case envoy.get("CP_SMTP_HOST") {
    Error(Nil) -> Ok(None)
    Ok(host) -> {
      use port <- result.try(port_from("CP_SMTP_PORT", 587))
      use from <- result.try(required("CP_SMTP_FROM"))
      let user = envoy.get("CP_SMTP_USER") |> result.unwrap("")
      let pass = envoy.get("CP_SMTP_PASS") |> result.unwrap("")
      Ok(Some(#(host, port, user, pass, from)))
    }
  }
}

fn credential_pair(
  id_key: String,
  secret_key: String,
) -> Option(#(String, String)) {
  case envoy.get(id_key), envoy.get(secret_key) {
    Ok(client_id), Ok(client_secret) -> Some(#(client_id, client_secret))
    _, _ -> None
  }
}

fn required(key: String) -> Result(String, String) {
  envoy.get(key) |> result.replace_error(key <> " is required")
}

/// The csqlite sandbox grants read+write over the *directory* of the
/// database (Landlock/unveil cannot name a single file), so two things
/// must hold: the path is absolute — a relative one would resolve
/// against the service's working directory and grant the release tree —
/// and the signing key lives in a different directory, or a compromised
/// worker's directory grant would cover it. `key_file` is "" on replicas
/// (no key), which trivially satisfies the second check.
fn validate_db_path(db_path: String, key_file: String) -> Result(Nil, String) {
  use <- bool.guard(
    !string.starts_with(db_path, "/"),
    Error("CP_DB_PATH must be an absolute path, got: " <> db_path),
  )
  case key_file == "" || dirname(db_path) != dirname(key_file) {
    True -> Ok(Nil)
    False ->
      Error(
        "CP_DB_PATH and CP_KEY_FILE must not share a directory: the csqlite "
        <> "sandbox grants the database's directory, so the signing key must "
        <> "sit elsewhere. Put the database in its own subdirectory, e.g. "
        <> dirname(db_path)
        <> "/db/"
        <> ".",
      )
  }
}

@external(erlang, "cp_udp_ffi", "valid_listen")
fn valid_listen(address: String) -> Bool

fn removed(old: String, instead: String) -> Result(Nil, String) {
  case envoy.get(old) {
    Ok(_) -> Error(old <> " is removed; set " <> instead <> " to address:port")
    Error(Nil) -> Ok(Nil)
  }
}

fn listen_from(key: String, default: String) -> Result(Listen, String) {
  let text = envoy.get(key) |> result.unwrap(default)
  parse_listen(key, text)
}

fn parse_listen(key: String, text: String) -> Result(Listen, String) {
  use #(address, port_text) <- result.try(
    split_host_port(text) |> result.replace_error(listen_error(key)),
  )
  use port <- result.try(
    parse_port_number(port_text) |> result.replace_error(listen_error(key)),
  )
  case valid_listen(address) {
    True -> Ok(Listen(address, port))
    False -> Error(listen_error(key))
  }
}

fn listen_error(key: String) -> String {
  key <> " must be address:port (IPv4, [IPv6], or localhost)"
}

fn split_host_port(text: String) -> Result(#(String, String), Nil) {
  case string.starts_with(text, "[") {
    True ->
      case string.split_once(text, "]:") {
        Ok(#(host, port)) ->
          case string.drop_start(host, 1) {
            "" -> Error(Nil)
            address -> Ok(#(address, port))
          }
        Error(Nil) -> Error(Nil)
      }
    False ->
      case string.split_once(text, ":") {
        Ok(#(host, port)) ->
          case host != "" && port != "" && !string.contains(port, ":") {
            True -> Ok(#(host, port))
            False -> Error(Nil)
          }
        Error(Nil) -> Error(Nil)
      }
  }
}

fn parse_port_number(text: String) -> Result(Int, Nil) {
  case int.parse(text) {
    Ok(port) ->
      case port >= 0 && port <= 65_535 {
        True -> Ok(port)
        False -> Error(Nil)
      }
    Error(Nil) -> Error(Nil)
  }
}

fn port_from(key: String, default: Int) -> Result(Int, String) {
  case envoy.get(key) {
    Error(Nil) -> Ok(default)
    Ok(text) ->
      int.parse(text) |> result.replace_error(key <> " must be a port number")
  }
}

/// CP_NS_HOSTS: semicolon-separated `host=ipv4[,ipv6]` entries, e.g.
/// "ns1=192.0.2.1;ns2=192.0.2.53,2001:db8::53". Hostnames without dots
/// are relative to the base domain. Required on the primary — a zone
/// without NS records is not a zone.
fn ns_hosts() -> Result(List(#(String, String, String)), String) {
  case envoy.get("CP_NS_HOSTS") {
    Error(Nil) -> Ok([])
    Ok(text) ->
      text
      |> string.split(";")
      |> list.filter(fn(entry) { entry != "" })
      |> list.try_map(fn(entry) {
        case string.split_once(entry, "=") {
          Ok(#(host, addresses)) ->
            case string.split(addresses, ",") {
              [ipv4] -> Ok(#(host, ipv4, ""))
              [ipv4, ipv6] -> Ok(#(host, ipv4, ipv6))
              _ -> Error("CP_NS_HOSTS entry not host=ipv4[,ipv6]: " <> entry)
            }
          Error(Nil) -> Ok(#(entry, "", ""))
        }
      })
  }
}
