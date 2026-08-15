//! The iroh endpoint wrapper, with both ALPNs mounted and membership enforced
//! at accept time (§2, §3.2).

use std::{net::SocketAddr, sync::Arc};

use iroh::{
    address_lookup::{PkarrPublisher, PkarrResolver},
    endpoint::{presets, Connection, RelayMode},
    protocol::Router,
    Endpoint, EndpointAddr, RelayUrl, TransportAddr,
};
use iroh_base::SecretKey;
use synch_core::{NodeId, ALPN_BLOB, ALPN_MPT};
use synch_store::Store;

use crate::{
    blob::{BlobClient, BlobProtocol},
    error::NetError,
    mpt::{MptClient, MptProtocol},
};

/// How long a dial may take before the peer is reported unreachable.
///
/// Generous enough for hole-punching and a relay fallback; bounded so a dead
/// address costs seconds, not the 30–60 s QUIC would spend retrying — every
/// stale binding used to stall `sync`, `take`, and each head push for that
/// long, silently.
pub const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How the endpoint should be bound.
#[derive(Debug, Clone, Default)]
pub struct NetOptions {
    /// An explicit bind address. `None` binds an ephemeral port on all
    /// interfaces.
    pub bind_addr: Option<SocketAddr>,
    /// Disables relays and address discovery entirely.
    ///
    /// Peers must then be reached by direct address. Tests use this so they
    /// never touch the network; self-hosted deployments can use it on closed
    /// networks.
    pub offline: bool,
    /// Iroh relay server URLs replacing n0's public relay map (§3.3).
    ///
    /// Self-hosted deployments point every node at their own relay here.
    /// A relay forwards encrypted QUIC traffic only — it learns neither
    /// membership nor content — so choosing one is an availability decision,
    /// not a trust one. Empty means n0's relays. Ignored when `offline`.
    pub relay_urls: Vec<String>,
    /// A pkarr relay URL for address discovery — a self-hosted
    /// iroh-dns-server such as `https://dns.example.com/pkarr` — replacing
    /// n0's iroh.link publisher and resolver (§3.3).
    ///
    /// Discovery is addressing, not membership: a broken or hostile lookup
    /// can strand a dial but never redirect one, because the QUIC handshake
    /// authenticates the device key and membership is enforced at accept.
    /// `None` means n0's. Ignored when `offline`.
    pub discovery_url: Option<String>,
    /// Notified when a connection is refused because the dialing device key
    /// has no live binding (§3.4).
    ///
    /// A peer that rotated its key and whose new record this node has not
    /// resolved yet arrives exactly this way, so the refusal is the cue for an
    /// immediate DNS re-resolution. The endpoint only rings the bell; the rate
    /// limiting and the resolving belong to whoever is listening.
    pub on_unknown_key: Option<Arc<tokio::sync::Notify>>,
}

impl NetOptions {
    /// Options for a loopback-only, fully offline endpoint.
    pub fn loopback() -> Self {
        NetOptions {
            bind_addr: Some("127.0.0.1:0".parse().expect("valid loopback address")),
            offline: true,
            relay_urls: Vec::new(),
            discovery_url: None,
            on_unknown_key: None,
        }
    }
}

/// Parses relay URLs into a custom relay mode, naming the offender.
fn parse_relay_mode(urls: &[String]) -> Result<RelayMode, NetError> {
    let mut parsed = Vec::with_capacity(urls.len());
    for raw in urls {
        let url: RelayUrl = raw
            .parse()
            .map_err(|e| NetError::Endpoint(format!("relay url {raw}: {e}")))?;
        parsed.push(url);
    }
    Ok(RelayMode::custom(parsed))
}

/// Parses the pkarr relay URL address discovery publishes to and resolves
/// through, naming it on failure.
fn parse_discovery_url(raw: &str) -> Result<reqwest::Url, NetError> {
    reqwest::Url::parse(raw).map_err(|e| NetError::Endpoint(format!("discovery url {raw}: {e}")))
}

/// A bound endpoint serving both ALPNs.
#[derive(Debug, Clone)]
pub struct Net {
    router: Router,
    store: Arc<Store>,
}

impl Net {
    /// Binds an endpoint under `secret` and mounts both protocol handlers.
    pub async fn bind(
        store: Arc<Store>,
        secret: SecretKey,
        options: NetOptions,
    ) -> Result<Net, NetError> {
        // §3.3's discovery stack: n0's pkarr/DNS address lookup and public
        // relays by default, overridable for self-hosted deployments. None of
        // it is trusted — see NetOptions — so these are plain configuration.
        let mut builder = Endpoint::builder(presets::N0).secret_key(secret);
        if let Some(raw) = &options.discovery_url {
            let url = parse_discovery_url(raw)?;
            builder = builder
                .clear_address_lookup()
                .address_lookup(PkarrPublisher::builder(url.clone()))
                .address_lookup(PkarrResolver::builder(url));
        }
        if !options.relay_urls.is_empty() {
            builder = builder.relay_mode(parse_relay_mode(&options.relay_urls)?);
        }
        if options.offline {
            builder = builder
                .relay_mode(RelayMode::Disabled)
                .clear_address_lookup();
        }
        if let Some(addr) = options.bind_addr {
            builder = builder
                .clear_ip_transports()
                .bind_addr(addr)
                .map_err(|e| NetError::Endpoint(e.to_string()))?;
        }
        let endpoint = builder
            .alpns(vec![ALPN_MPT.to_vec(), ALPN_BLOB.to_vec()])
            .bind()
            .await
            .map_err(|e| {
                // Name the address: "Failed to bind sockets" with no port sent
                // an operator to `synch init` when the fix was another --bind.
                NetError::Endpoint(match options.bind_addr {
                    Some(addr) => {
                        format!("could not bind {addr}: {e} (is the port already in use?)")
                    }
                    None => e.to_string(),
                })
            })?;

        let router = Router::builder(endpoint)
            .accept(
                ALPN_MPT,
                MptProtocol::new(store.clone()).on_unknown_key(options.on_unknown_key.clone()),
            )
            .accept(
                ALPN_BLOB,
                BlobProtocol::new(store.clone()).on_unknown_key(options.on_unknown_key.clone()),
            )
            .spawn();

        Ok(Net { router, store })
    }

    /// The underlying iroh endpoint.
    pub fn endpoint(&self) -> &Endpoint {
        self.router.endpoint()
    }

    /// This endpoint's device key.
    pub fn id(&self) -> NodeId {
        self.endpoint().id()
    }

    /// The store this endpoint serves from.
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// An address carrying only this endpoint's directly bound sockets.
    ///
    /// This is what offline peers exchange: no relay, no discovery, just
    /// addresses that work on the local network.
    pub fn direct_addr(&self) -> EndpointAddr {
        EndpointAddr::from_parts(
            self.id(),
            self.endpoint()
                .bound_sockets()
                .into_iter()
                .map(TransportAddr::Ip),
        )
    }

    /// The endpoint's full address, including relay and discovered addresses
    /// when they are available.
    pub fn addr(&self) -> EndpointAddr {
        let addr = self.endpoint().addr();
        if addr.is_empty() {
            self.direct_addr()
        } else {
            addr
        }
    }

    /// Dials a peer on the metadata ALPN.
    pub async fn connect_mpt(&self, addr: impl Into<EndpointAddr>) -> Result<MptClient, NetError> {
        Ok(MptClient::new(self.connect(addr, ALPN_MPT).await?))
    }

    /// Dials a peer on the content ALPN.
    pub async fn connect_blob(
        &self,
        addr: impl Into<EndpointAddr>,
    ) -> Result<BlobClient, NetError> {
        Ok(BlobClient::new(self.connect(addr, ALPN_BLOB).await?))
    }

    async fn connect(
        &self,
        addr: impl Into<EndpointAddr>,
        alpn: &[u8],
    ) -> Result<Connection, NetError> {
        let addr = addr.into();
        // Dial only peers we ourselves trust: trust is unilateral per node, and
        // both sides must hold it for a session to work (§3.2).
        if !self.store.is_trusted_key(&addr.id, synch_core::now_ns())? {
            return Err(NetError::Untrusted(addr.id.fmt_short().to_string()));
        }
        let peer = addr.id.fmt_short().to_string();
        match tokio::time::timeout(DIAL_TIMEOUT, self.endpoint().connect(addr, alpn)).await {
            Ok(connected) => connected.map_err(|e| NetError::Endpoint(e.to_string())),
            Err(_) => Err(NetError::Endpoint(format!(
                "{peer} did not answer within {}s",
                DIAL_TIMEOUT.as_secs()
            ))),
        }
    }

    /// Shuts the router and endpoint down cleanly.
    pub async fn shutdown(&self) -> Result<(), NetError> {
        self.router
            .shutdown()
            .await
            .map_err(|e| NetError::Endpoint(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_urls_parse_or_name_the_offender() {
        let mode = parse_relay_mode(&["https://relay.example.com".to_string()]).unwrap();
        assert!(matches!(mode, RelayMode::Custom(_)));
        let err = parse_relay_mode(&["not a url".to_string()]).unwrap_err();
        assert!(err.to_string().contains("not a url"), "{err}");
    }

    #[test]
    fn discovery_urls_parse_or_name_the_offender() {
        parse_discovery_url("https://dns.example.com/pkarr").unwrap();
        let err = parse_discovery_url("dns.example.com/pkarr").unwrap_err();
        assert!(err.to_string().contains("dns.example.com/pkarr"), "{err}");
    }
}
