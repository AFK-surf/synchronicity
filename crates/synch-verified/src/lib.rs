//! Mandatory statically linked Lean core. There is no Rust fallback.

mod native;
pub use native::{
    group_count, settle_size, CertificateCache, ChildShape, MissingWalk, Scope, Settlement, Shape,
    WalkError, WalkNode, WalkPosition,
};
