//! Mandatory statically linked Lean core. There is no Rust fallback.

pub mod cas;
pub mod history;
pub mod host;
mod native;
mod operation;
pub mod trie;
pub use native::{
    group_count, plan_cas_commit, settle_size, CasCommit, CertificateCache, ChildShape,
    MissingWalk, Scope, Settlement, Shape, WalkError, WalkNode, WalkPosition,
};
