//! Statically linked Lean core. `native` is an explicit integration feature;
//! when disabled this crate exports no substitute implementation.

#[cfg(feature = "native")]
mod native;
#[cfg(feature = "native")]
pub use native::{group_count, settle_size, Scope, Settlement, Shape};
