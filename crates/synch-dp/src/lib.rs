//! The cloud data plane: multi-tenant hosted replicas.
//!
//! A managed hosting service that runs one embedded synchronicity replica node
//! per customer network, joins each as an ordinary zone-named device, and
//! replicates everything those networks publish into provider object storage.
//! It is the replicate mode of the daemon, operated as a service — see
//! `docs/CLOUD-DATAPLANE.md` for the design this implements, whose section
//! numbers the modules here cite.
//!
//! The service is an *embedder* of [`synch_engine`], not a fork of the daemon:
//! one tenant is one [`Node`](synch_engine::Node), whole, with its own data
//! directory, database, device key, endpoint and CAS prefix (§4.1).

pub mod config;
pub mod control;
pub mod dbrepl;
pub mod error;
pub mod metrics;
pub mod reconciler;
pub mod rotation;
pub mod spaces;
pub mod store;
pub mod tenant;

pub use config::{DpConfig, SLOT};
pub use error::{DpError, Result};
pub use reconciler::Reconciler;
pub use store::ObjectStore;
