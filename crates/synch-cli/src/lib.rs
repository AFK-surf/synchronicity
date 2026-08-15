//! The `synch` daemon, its control socket, and the CLI that drives it (§9.1).
//!
//! **The daemon owns the node; the CLI is only a client of it.** Every command
//! except the two that bootstrap or *are* the daemon — `synch init`, which
//! creates the datadir before any daemon can exist, and `synch daemon run` —
//! is a request over the local control socket (§9.3). There is no in-process
//! fallback: with no daemon running, a command fails with a message naming the
//! socket path and the command to start one.
//!
//! The crate is a library so the control protocol, the server, and the client
//! can be exercised in process; `src/main.rs` is the argument-parsing shell
//! over it.
#![deny(missing_docs)]

pub mod cli;
pub mod commands;
pub mod control;
pub mod daemon;
pub mod render;

/// The platform data directory both binaries default to (§9.3).
///
/// Re-exported so a control-socket client can find the datadir holding
/// `control.token` without linking the engine. `synch-s3` is the one that
/// needs it: it is a client of the daemon and nothing more, and a dependency
/// on the node it must not open would be exactly the wrong shape (§9.4).
pub use synch_engine::default_data_dir;
