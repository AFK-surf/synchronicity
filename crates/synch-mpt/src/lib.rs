//! The synchronicity Merkle-Patricia Trie (§4.3).
//!
//! A radix-16 (nibble) trie with leaf, extension, branch and routing nodes,
//! hashed with BLAKE3 under a per-kind domain-separation tag. Compressed nodes
//! inline values of at most 128 bytes. Routing nodes address every payload
//! separately so their public paths can be shared without exposing a value.
//!
//! The trie is stateless: every operation takes a root hash and returns a new
//! one, and nodes are content-addressed, so successive roots share every
//! subtree that did not change. That single property is what makes publishing
//! cheap, diffing cheap, and anti-entropy bandwidth proportional to the change
//! rather than to the tree.
//!
//! Mutations preserve canonical node encoding and structural invariants.
//! Legacy compressed and routing representations may have different roots
//! for the same entries; a signed version commits to its particular root.
#![deny(missing_docs)]

pub mod diff;
pub mod error;
mod lean_storage;
pub mod nibbles;
pub mod node;
/// Merkle proofs of presence and absence for individual keys (§4.3).
///
/// Behind a feature and off by default. No v1 flow needs them — anti-entropy
/// replicates whole tries rather than proving single keys — and DESIGN.md §13
/// is explicit that the capability is deliberately ahead of its use. Shipping
/// it in the default surface would make it a public, tested, maintained API
/// with no production caller; behind a flag it stays available
/// to the partial-replication work §13 describes without being something every
/// build has to keep correct.
#[cfg(feature = "proofs")]
pub mod proof;
pub mod scope;
pub mod store;
pub mod trie;

pub use diff::{Change, ChangeKind, ChangeView};
pub use error::MptError;
pub use nibbles::Nibbles;
pub use node::{TrieNode, ValueRef, Verdict};
#[cfg(feature = "proofs")]
pub use proof::Proof;
pub use scope::Scope;
pub use store::{MemStore, NodeStore};
pub use trie::{Entry, Trie};
