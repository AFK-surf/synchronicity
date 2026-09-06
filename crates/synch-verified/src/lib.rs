//! Mandatory statically linked Lean core. There is no Rust fallback.

pub mod cas;
mod generated;
pub mod history;
pub mod host;
mod native;
mod operation;
pub mod trie;
