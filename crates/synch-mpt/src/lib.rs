//! The synchronicity Merkle-Patricia Trie (§4.3).
//!
//! A radix-16 (nibble) trie with three node kinds — leaf, extension, branch —
//! hashed with BLAKE3 under a per-kind domain-separation tag. Values of at most
//! 128 bytes are inlined in their node; larger ones are stored out-of-line and
//! addressed by hash.
//!
//! The trie is stateless: every operation takes a root hash and returns a new
//! one, and nodes are content-addressed, so successive roots share every
//! subtree that did not change. That single property is what makes publishing
//! cheap, diffing cheap, and anti-entropy bandwidth proportional to the change
//! rather than to the tree.
//!
//! Canonical form is maintained on every mutation: any two tries holding the
//! same key/value map have the same root hash, regardless of the order of
//! operations that produced them.
#![deny(missing_docs)]

pub mod diff;
pub mod error;
pub mod nibbles;
pub mod node;
pub mod proof;
pub mod store;
pub mod trie;

pub use diff::{Change, ChangeKind, ResolvedChange};
pub use error::MptError;
pub use nibbles::{common_prefix_len, Nibbles};
pub use node::{TrieNode, ValueRef, BRANCH_TAG, EXT_TAG, LEAF_TAG};
pub use proof::Proof;
pub use store::{MemStore, NodeStore};
pub use trie::{root_opt, Entry, Missing, MissingWalk, Reachable, Trie};
