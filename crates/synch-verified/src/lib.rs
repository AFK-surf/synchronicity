//! Mandatory statically linked Lean core. There is no Rust fallback.

/// The host boundary, printed into Cargo's output directory by
/// `lean/Hostgen.lean` from the Lean effect algebras and command types: the
/// host traits, the request frames with their decoder and dispatch, the
/// mirrored command and outcome types with their codecs, and the
/// `host_unexpected!` stubs for test doubles.
#[macro_use]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

pub mod cas;
pub mod history;
pub mod host;
mod native;
mod operation;
pub mod replication;
pub mod suspend;
pub mod trie;
