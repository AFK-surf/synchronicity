//! SQLite metadata store and content-addressed blob store (§6.2, §10).
#![deny(missing_docs)]

pub mod backend;
pub mod bindings;
pub mod cas;
pub mod clock;
pub mod cloud;
pub mod db;
pub mod error;
pub mod gc;
pub mod heads;
pub mod proof;
pub mod recovery;
pub mod replica;
pub mod schema;
pub mod sockets;
#[cfg(test)]
mod testutil;
pub mod unified;
pub mod uploads;
pub mod views;

pub use bindings::{Binding, BindingSource, PublishScope};
pub use cas::{PinHolder, PinRow};
pub use clock::ClockStatus;
pub use db::{
    Checkpointing, DeviceKey, IdentityAdoption, KeyState, Store, StoreOptions, Txn, CAS_DIR,
    DB_FILE,
};
pub use error::{Result, StoreError};
pub use gc::{GcStats, TrieStats};
pub use heads::{Equivocation, Slot};
pub use proof::{Donor, Proven, ProvenSubtree};
pub use replica::{ReplicaCoverage, WantRow};
pub use sockets::SocketActivation;
pub use unified::{Selection, Version, VersionPolicy, VersionSet};
pub use uploads::{
    CompleteStart, Upload, UploadPart, UploadState, MAX_PART_NUMBER, MAX_PART_SIZE, MIN_PART_SIZE,
};
pub use views::{
    EntryRow, LocalFile, ReplicaPolicy, ReplicaRow, SourceKind, SourceRow,
    DEFAULT_REPLICA_GRACE_SECS,
};
