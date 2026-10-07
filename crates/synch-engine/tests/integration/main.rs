//! The engine's integration tests, in one binary.
//!
//! Each module is one subject — a cluster of nodes, git, locks, recovery —
//! against real loopback endpoints. They share a binary rather than taking
//! one each because every test binary links the whole dependency graph and
//! instantiates the engine's generic code again: fourteen of them cost
//! several times the compile of one. Filter by module to run one subject,
//! e.g. `cargo test -p synch-engine --test integration -- locks::`.

mod common;

mod cluster;
mod convergence;
mod delegation;
mod dnssec;
mod git;
mod locks;
mod recovery;
mod replication;
mod scope_changes;
mod servable_heads;
mod sockets;
mod tree_writes;
mod trust_boundaries;
mod two_nodes;
