//! The iroh endpoint wrapper, with both ALPNs mounted and membership enforced
//! at accept time (§2, §3.2).

use std::{net::SocketAddr, sync::Arc};

use iroh::{
    endpoint::{presets, Connection, RelayMode},
    protocol::Router,
    Endpoint, EndpointAddr, TransportAddr,
};
use iroh_base::SecretKey;
use synch_core::{NodeId, ALPN_BLOB, ALPN_MPT};
use synch_store::Store;

use crate::{
    blob::{BlobClient, BlobProtocol},
    error::NetError,
    mpt::{MptClient, MptProtocol},
};

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
            on_unknown_key: None,
        }
    }
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
        let mut builder = Endpoint::builder(presets::Minimal).secret_key(secret);
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
            .map_err(|e| NetError::Endpoint(e.to_string()))?;

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
        self.endpoint()
            .connect(addr, alpn)
            .await
            .map_err(|e| NetError::Endpoint(e.to_string()))
    }

    /// Shuts the router and endpoint down cleanly.
    pub async fn shutdown(&self) -> Result<(), NetError> {
        self.router
            .shutdown()
            .await
            .map_err(|e| NetError::Endpoint(e.to_string()))
    }
}
