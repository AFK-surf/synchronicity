//! Mandatory statically linked Lean core. There is no Rust fallback.

mod native;
pub use native::{
    group_count, settle_size, CertificateCache, MissingWalk, Scope, Settlement, Shape, WalkNode,
    WalkPosition,
};
