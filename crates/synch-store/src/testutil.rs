//! Fixtures shared by the crate's inline test modules: the tempdir-backed
//! store, the usual test origins, signed-head construction, and deterministic
//! test data. Not yet wired into the existing modules; each one keeps its own
//! local copies until it is migrated.

use iroh_base::SecretKey;
use synch_core::{Hash, OriginId, SignedHead};

use crate::Store;

/// A fresh store in a temporary directory, deleted when the guard drops.
#[allow(dead_code)]
pub(crate) fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let s = Store::open(dir.path()).unwrap();
    (dir, s)
}

/// The default origin most tests publish under.
#[allow(dead_code)]
pub(crate) fn origin() -> OriginId {
    origin_named("nas")
}

/// An origin named `name` under the usual test domain.
#[allow(dead_code)]
pub(crate) fn origin_named(name: &str) -> OriginId {
    OriginId::named(name, "x.example").unwrap()
}

/// A head signed by `key` for the default origin at `seq`, whose root is
/// `byte` repeated, at timestamp zero.
#[allow(dead_code)]
pub(crate) fn sign_head(key: &SecretKey, seq: u64, byte: u8) -> SignedHead {
    SignedHead::sign(key, origin(), seq, Hash([byte; 32]), 0)
}

/// Deterministic test data of length `n`.
#[allow(dead_code)]
pub(crate) fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 + 7) as u8).collect()
}
