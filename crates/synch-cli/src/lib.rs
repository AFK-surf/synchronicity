//! The `synch` daemon, its control socket, and the CLI that drives it (§9.1).
//!
//! **The daemon owns the node; the CLI is only a client of it.** Three commands
//! do not use the local control socket: `synch init` creates the datadir,
//! `synch daemon run` *is* the daemon, and `synch daemon start` launches that
//! daemon in the background. Every other command is a request over the socket
//! (§9.3). There is no in-process fallback: with no daemon running, a command
//! fails with a message naming the socket path and both ways to start one.
//!
//! The crate is a library so the control protocol, the server, and the client
//! can be exercised in process; `src/main.rs` is the argument-parsing shell
//! over it.
#![deny(missing_docs)]

pub mod cli;
pub mod commands;
pub mod connect;
pub mod control;
pub mod daemon;
pub mod fetch;
pub mod mcp;
pub mod render;
pub mod write;

/// The platform data directory both binaries default to (§9.3).
///
/// Re-exported so a control client can find the datadir holding
/// `control.token` without linking the engine. `synch-s3` is the one that
/// needs it: it is a client of the daemon and nothing more, and a dependency
/// on the node it must not open would be exactly the wrong shape (§9.4).
pub use synch_engine::default_data_dir;
