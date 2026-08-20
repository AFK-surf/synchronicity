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
  /// That zone — not the apex — is where DNSKEY and RRSIGs live, and where
  /// a chain's ladder starts. Proof records still live at the apex (the
  /// membership `apex=` field). Equal to the apex unless `CP_SIGNING_ZONE`
  /// says otherwise.
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
    /// Whether daemons may attach and browse (`CP_BROWSE`). Off by default:
    /// the attach endpoint, the apex record naming it, and the browse API
    /// all exist only when this is on, in the same shape an unset optional
    /// provider takes.
    browse: Bool,
    /// Whether this node mounts the dashboard and the product API.
    ///
    /// Always true on the primary — the dashboard is what a primary is for.
    /// On a replica it is `CP_DASHBOARD=on`, and what it mounts is the *read*
    /// half: the SPA, every GET route, and the browse surface. A replica's
    /// database is a read-only copy, so there is no write half to mount.
    dashboard: Bool,
    /// Where the writes live, as a replica's dashboard tells its users
    /// (`CP_PRIMARY_URL`). Empty on the primary, which *is* that place.
    ///
    /// A read-only node that answers "no" to a sign-in without saying where
    /// to go instead is a dead end, and the one fact that resolves it — the
    /// primary's public URL — is not derivable from anything a replica holds.
    primary_url: String,
    /// The `Domain` attribute session cookies are set with
    /// (`CP_COOKIE_DOMAIN`), or `None` for a host-only cookie — the default,
    /// and the only correct answer for a single-node deployment.
    ///
    /// A fleet whose nodes have names of their own (`ns1.sync.example`
    /// beside `sync.example`) needs one session to be readable at all of
    /// them, and a host-only cookie is by definition not. Set to a parent of
    /// every node's name, it is; the trade is that every host under that
    /// name receives the cookie, which is why it is opt-in and never derived
    /// from the apex.
    cookie_domain: Option(String),
    /// The attach endpoints the apex record names, in publication order:
    /// this node's own first, then `CP_BROWSE_ENDPOINTS`. Empty when
    /// `CP_BROWSE` is off, which is how the record's owner name stops
    /// existing at all.
    browse_endpoints: List(String),
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
  use dashboard <- result.try(dashboard_enabled(role))
  use session_secret <- result.try(case role, dashboard {
    // The secret signs session cookies, so a node that reads them needs it —
    // and a replica needs *the primary's*, byte for byte, or every cookie the
    // primary minted fails its signature check here and the dashboard it
    // mounts can never be signed in to.
    Primary, _ | Replica, True -> {
      use secret <- result.try(required("CP_SESSION_SECRET"))
      case string.length(secret) >= 32 {
        True -> Ok(secret)
        False -> Error("CP_SESSION_SECRET must be at least 32 characters")
      }
    }
    Replica, False ->
      case envoy.get("CP_SESSION_SECRET") {
        Ok(_) ->
          Error(
            "CP_SESSION_SECRET is only read with CP_DASHBOARD=on: a replica "
            <> "serving DNS alone reads no cookie, and a secret that signs "
            <> "nothing is dead config",
          )
        Error(Nil) -> Ok("")
      }
  })
  use primary_url <- result.try(primary_url(role, dashboard))
  use cookie_domain <- result.try(cookie_domain(dashboard))
  use smtp <- result.try(smtp_config())
  use browse <- result.try(browse_enabled(dashboard, public_url))
  use browse_endpoints <- result.try(validated_browse_endpoints(role, browse))
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
    browse,
    dashboard,
    primary_url,
    cookie_domain,
    browse_endpoints,
  ))
}

/// `CP_DASHBOARD`: `on` or `off` (the default), and a replica's switch alone.
///
/// The primary always mounts the dashboard — it is what a primary is for — so
/// the variable there is not a knob but a claim about the service that the
/// service does not honour, and it is refused rather than ignored.
fn dashboard_enabled(role: Role) -> Result(Bool, String) {
  case role, envoy.get("CP_DASHBOARD") {
    Primary, Error(Nil) -> Ok(True)
    Primary, Ok(_) ->
      Error(
        "CP_DASHBOARD is replica-only: the primary always serves the "
        <> "dashboard, so setting it here would name a switch that does not "
        <> "exist",
      )
    Replica, Error(Nil) | Replica, Ok("off") -> Ok(False)
    Replica, Ok("on") -> Ok(True)
    Replica, Ok(other) -> Error("CP_DASHBOARD must be on or off, got " <> other)
  }
}

/// `CP_PRIMARY_URL`: where a replica's dashboard sends the writes it cannot do.
///
/// Required with `CP_DASHBOARD=on` and refused everywhere else. A replica
/// holds a read-only copy of the database, so signing in, creating a network
/// and every other mutation has exactly one place it can happen; a dashboard
/// that refuses them without naming that place is a dead end, and nothing a
/// replica holds names it — the database records the fleet's zone, not which
/// of its nodes took the writes.
fn primary_url(role: Role, dashboard: Bool) -> Result(String, String) {
  case role, dashboard {
    Replica, True -> {
      use url <- result.try(required("CP_PRIMARY_URL"))
      let url = trim_trailing_slash(string.trim(url))
      case is_origin(url) {
        True -> Ok(url)
        False ->
          Error(
            "CP_PRIMARY_URL must be an https:// or http:// origin, got " <> url,
          )
      }
    }
    _, _ ->
      case envoy.get("CP_PRIMARY_URL") {
        Ok(_) ->
          Error(
            "CP_PRIMARY_URL is only meaningful on a replica with "
            <> "CP_DASHBOARD=on: it names where the writes this node refuses "
            <> "are taken, and every other node takes its own",
          )
        Error(Nil) -> Ok("")
      }
  }
}

/// `CP_COOKIE_DOMAIN`: the `Domain` attribute session cookies carry.
///
/// Unset is a host-only cookie, which is right for one node and wrong for a
/// fleet: `ns1.sync.example` never receives a cookie the primary set at
/// `sync.example`, so a session minted there is invisible at every replica
/// however faithfully the row replicated. Setting it to a name that is a
/// parent of every node's makes one session work fleet-wide, at the price
/// that every host under that name is sent the cookie — which is why it is
/// the operator's decision and not derived from `CP_BASE_DOMAIN`.
///
/// A leading dot is accepted and dropped: RFC 6265 ignores it, and operators
/// write it from habit.
fn cookie_domain(dashboard: Bool) -> Result(Option(String), String) {
  case envoy.get("CP_COOKIE_DOMAIN"), dashboard {
    Error(Nil), _ -> Ok(None)
    Ok(_), False ->
      Error(
        "CP_COOKIE_DOMAIN is only read where sessions are: this node mounts "
        <> "no dashboard, so it sets no cookie for the attribute to appear on",
      )
    Ok(text), True -> {
      let host = case string.starts_with(string.trim(text), ".") {
        True -> string.drop_start(string.trim(text), 1)
        False -> string.trim(text)
      }
      // The value lands in a `Set-Cookie` header, where a semicolon or a
      // space would end the attribute and start another one.
      case host != "" && record_safe(host) && !string.contains(host, ";") {
        True -> Ok(Some(host))
        False ->
          Error(
            "CP_COOKIE_DOMAIN must be a bare domain name with no whitespace "
            <> "or semicolon: it is a Set-Cookie attribute, and either one "
            <> "ends it early",
          )
      }
    }
  }
}

/// `CP_BROWSE`: `on` or `off` (the default).
///
/// Allowed on either role, because a tunnel is not a write: a daemon's attach
/// is resolved against `device_keys` with a SELECT, and every browse call
/// reads the replicated tables and then asks a node on the operator's own
/// network. What a replica cannot do is *mint* a session, which is why the
/// switch requires `CP_DASHBOARD=on` there — a browse API with no session to
/// authorize it answers nobody.
///
/// Refused on any node that has not been told its own public URL, because the
/// apex record names that URL and a daemon signs its attach proof over it — a
/// loopback default published into DNS would send every node nowhere. Each
/// node names *itself* here: a replica's `CP_PUBLIC_URL` is the replica's, and
/// the primary gathers the fleet's into the record with
/// `CP_BROWSE_ENDPOINTS`.
fn browse_enabled(dashboard: Bool, public_url: String) -> Result(Bool, String) {
  case envoy.get("CP_BROWSE") {
    Error(Nil) | Ok("off") -> Ok(False)
    Ok("on") ->
      case dashboard, result.is_ok(envoy.get("CP_PUBLIC_URL")) {
        False, _ ->
          Error(
            "CP_BROWSE=on needs CP_DASHBOARD=on on a replica: the browse API "
            <> "is session-gated, and a node that mounts no dashboard reads "
            <> "no session to gate it with",
          )
        _, False ->
          Error(
            "CP_BROWSE=on needs CP_PUBLIC_URL: the apex record publishes it "
            <> "and attaching daemons sign their proof over it, so the "
            <> "default "
            <> public_url
            <> " would send them nowhere",
          )
        _, True ->
          // The value is rendered straight into a signed apex TXT record as
          // `v=synccp1 url=<it>`, and the client parses that record as
          // whitespace-separated `key=value` pairs and requires the URL to be
          // an origin — `https://` or `http://` with something after it. So a
          // bare host, or one with a space in it, publishes a record every
          // daemon rejects: signed, cached for its TTL, and failing in the
          // client rather than here. `build.valid_hint` exists to keep
          // free-form values out of that grammar and did not cover this one.
          //
          // `http://` is accepted because the client accepts it — a deployment
          // behind a TLS terminator is the case it was widened for. The
          // attach record's integrity does not rest on the scheme either way:
          // the zone key that published it is gated on the transparency log,
          // and on `https://` WebPKI sits on top of that rather than under it.
          case is_origin(browse_endpoint()), record_safe(browse_endpoint()) {
            True, True -> Ok(True)
            False, _ ->
              Error(
                "CP_BROWSE=on needs CP_PUBLIC_URL to be an https:// or "
                <> "http:// origin: daemons refuse any other shape, so the "
                <> "record would be published and rejected",
              )
            _, False ->
              Error(
                "CP_BROWSE=on needs a CP_PUBLIC_URL with no whitespace: the "
                <> "attach record is whitespace-separated key=value pairs and "
                <> "a space in the value changes what it says",
              )
          }
      }
    Ok(other) -> Error("CP_BROWSE must be on or off, got " <> other)
  }
}

/// The attach endpoint the apex publishes, or `""` when browsing is off.
///
/// Read here rather than threaded through every publish path: it is a
/// deployment constant, and this module is the one place the environment is
/// read. An empty answer means the record is not emitted at all, which is
/// what a zone with the feature off looks like to a client.
/// Whether a value can sit inside a `key=value` record without changing what
/// the record says.
///
/// The same rule as `zone/build.valid_hint`, restated rather than imported:
/// `zone/build` imports this module through `zone/model`, so the dependency
/// only runs one way. Both are one sentence — printable ASCII, no space, no
/// quote — and both exist because the record grammar is whitespace-separated.
/// Whether a value is an origin the client's `parse_control_plane_record`
/// accepts: one of the two schemes with something after it.
///
/// Per scheme rather than one length test, because the two prefixes are
/// different lengths and a shared bound is wrong for one of them: `http://x`
/// is eight characters and is an origin, while `https://` is eight characters
/// and is not.
fn is_origin(value: String) -> Bool {
  ["https://", "http://"]
  |> list.any(fn(scheme) {
    string.starts_with(value, scheme)
    && string.length(value) > string.length(scheme)
  })
}

fn record_safe(value: String) -> Bool {
  string.length(value) <= 255
  && string.to_utf_codepoints(value)
  |> list.all(fn(point) {
    let code = string.utf_codepoint_to_int(point)
    code >= 0x21 && code <= 0x7E && code != 0x22
  })
}

pub fn browse_endpoint() -> String {
  case envoy.get("CP_BROWSE"), envoy.get("CP_PUBLIC_URL") {
    Ok("on"), Ok(url) -> trim_trailing_slash(string.trim(url))
    _, _ -> ""
  }
}

/// Every attach endpoint the apex record names: this node's own, then the
/// rest of the fleet's from `CP_BROWSE_ENDPOINTS`.
///
/// **One RRset, one rdata per endpoint** — not one record listing several.
/// A daemon needs a live tunnel to *every* node that may be asked a browse
/// question, because the registry of attached sessions is one process's
/// memory and a node with no tunnel of its own can answer nothing; so the
/// record has to name them all. Spelling that as extra records rather than
/// extra `url=` fields is what keeps a daemon built before this change
/// working: it reads the first record it can parse and attaches there, which
/// is one node of the fleet instead of all of them, while a second `url=`
/// in one record is a duplicate field it refuses outright.
///
/// Order is publication order and carries no precedence: a daemon opens all
/// of them.
pub fn browse_endpoints() -> List(String) {
  case browse_endpoint() {
    "" -> []
    // Deduplicated *here*, where the zone builder reads it, and not only in
    // the boot-time validator: an RRset is a set, and RFC 4034 §6.3 has a
    // signer remove duplicate RRs before signing. Two identical rdatas would
    // be signed as two, and a validator that canonicalizes to one computes a
    // different hash — an RRSIG mismatch, which is the whole zone failing
    // closed rather than one wasted record. An operator listing their own
    // `CP_PUBLIC_URL` in `CP_BROWSE_ENDPOINTS` is an ordinary mistake.
    own -> list.unique([own, ..extra_browse_endpoints()])
  }
}

/// `CP_BROWSE_ENDPOINTS`: the fleet's *other* attach endpoints, comma- or
/// semicolon-separated, in the same origin form as `CP_PUBLIC_URL`.
///
/// Configured rather than discovered because nothing in this service knows
/// its replicas: replication is external and operator-owned (ops/RUNBOOK.md),
/// so the fleet's shape is a fact only the operator holds. It is read on the
/// node that publishes the zone, which is the primary — a replica publishes
/// nothing, and one that set this would be describing a record it does not
/// write.
fn extra_browse_endpoints() -> List(String) {
  envoy.get("CP_BROWSE_ENDPOINTS")
  |> result.unwrap("")
  |> string.replace(each: ";", with: ",")
  |> string.split(",")
  |> list.map(fn(entry) { trim_trailing_slash(string.trim(entry)) })
  |> list.filter(fn(entry) { entry != "" })
}

/// The endpoints validated and deduplicated, or the reason the operator's
/// list cannot be published.
///
/// Each entry is checked exactly as `CP_PUBLIC_URL` is, and for the same
/// reason: a value that is not an origin, or that carries whitespace, is a
/// record every daemon rejects — signed, cached for its TTL, and failing in
/// the client rather than at the boot that produced it.
fn validated_browse_endpoints(
  role: Role,
  browse: Bool,
) -> Result(List(String), String) {
  let configured = result.is_ok(envoy.get("CP_BROWSE_ENDPOINTS"))
  use Nil <- result.try(case role, browse, configured {
    Replica, _, True ->
      Error(
        "CP_BROWSE_ENDPOINTS is primary-only: it names the fleet the apex "
        <> "record lists, and only the node that publishes the zone writes "
        <> "that record. A replica names itself with CP_PUBLIC_URL",
      )
    _, False, True ->
      Error(
        "CP_BROWSE_ENDPOINTS is set but CP_BROWSE is not on: with browsing "
        <> "off there is no attach record for the endpoints to appear in",
      )
    _, _, _ -> Ok(Nil)
  })
  let endpoints = browse_endpoints()
  use Nil <- result.try(
    list.try_each(endpoints, fn(endpoint) {
      case is_origin(endpoint), record_safe(endpoint) {
        True, True -> Ok(Nil)
        False, _ ->
          Error(
            "CP_BROWSE_ENDPOINTS entry "
            <> endpoint
            <> " is not an https:// or http:// origin: daemons refuse any "
            <> "other shape, so the record would be published and rejected",
          )
        _, False ->
          Error(
            "CP_BROWSE_ENDPOINTS entry "
            <> endpoint
            <> " has whitespace or a quote in it: the attach record is "
            <> "whitespace-separated key=value pairs and either one changes "
            <> "what it says",
          )
      }
    }),
  )
  // `browse_endpoints` has already deduplicated, so the cap counts the
  // records that will actually be published rather than the entries the
  // operator typed.
  case list.length(endpoints) > max_browse_endpoints {
    True ->
      Error(
        "CP_BROWSE_ENDPOINTS names more than "
        <> int.to_string(max_browse_endpoints)
        <> " attach endpoints (including CP_PUBLIC_URL): every daemon in "
        <> "every network opens a standing tunnel to each one, and the "
        <> "client refuses to open more than that many",
      )
    False -> Ok(endpoints)
  }
}

/// How many attach endpoints one apex may name.
///
/// The same ceiling the client applies (`MAX_CP_ENDPOINTS` in
/// `crates/synch-net/src/dns.rs`), restated here so the refusal reaches the
/// operator at boot rather than the fleet at its next refresh. Every entry
/// costs every daemon a standing WebSocket, so the zone decides how much a
/// node spends and the bound is what keeps that decision small.
pub const max_browse_endpoints = 8

fn trim_trailing_slash(url: String) -> String {
  case string.ends_with(url, "/") {
    True -> trim_trailing_slash(string.drop_end(url, 1))
    False -> url
  }
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
