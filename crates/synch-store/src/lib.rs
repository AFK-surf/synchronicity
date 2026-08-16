//! SQLite metadata store and content-addressed blob store (§6.2, §10).
#![deny(missing_docs)]

pub mod bindings;
pub mod cas;
pub mod db;
pub mod error;
pub mod gc;
pub mod heads;
pub mod proof;
pub mod recovery;
pub mod schema;
pub mod unified;
pub mod views;

pub use bindings::{Binding, BindingSource};
pub use cas::{BlobRow, BLOCK_SIZE};
pub use db::{DeviceKey, KeyState, Store, Txn, CAS_DIR, DB_FILE};
pub use error::{Result, StoreError};
pub use gc::{GcStats, TrieStats};
pub use heads::{Equivocation, Slot, StoredHead};
pub use proof::{Donor, ProvenSubtree};
pub use recovery::ObservedHead;
pub use schema::SCHEMA_VERSION;
pub use unified::{Selection, Version, VersionPolicy, VersionSet};
pub use views::{EntryRow, LocalFile, MirrorRow, PeerSeen, SpaceRow};
