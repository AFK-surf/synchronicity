//! The local control socket: the CLI's only way to reach a node (§9.3).
//!
//! [`transport`] is the platform socket, [`proto`] the framing and schema,
//! [`server`] the daemon side, [`client`] the CLI side.

pub mod client;
pub mod proto;
pub mod server;
pub mod transport;

pub use client::Client;
pub use proto::{ControlError, EntryInfo, ErrorCode, Request, Response, Upload, CONTROL_VERSION};
pub use server::Server;
