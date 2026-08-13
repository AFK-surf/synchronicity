//! The embeddable synchronicity node (§11).
//!
//! Everything a host application needs: identity and membership, indexed
//! spaces with a streaming scanner, a publisher that turns staged changes into
//! one signed root, the anti-entropy scheduler, the verified content fetcher,
//! and read-only mirrors. The two shipped binaries are thin shells over this
//! crate, and any Rust application can embed a full node the same way.
#![deny(missing_docs)]

pub mod aae;
pub mod config;
pub mod error;
pub mod fetcher;
pub mod ignore;
pub mod membership;
pub mod mirror;
pub mod node;
pub mod publisher;
pub mod recovery;
pub mod reference;
pub mod rotation;
pub mod scanner;
pub mod tree;
pub mod watcher;

pub use aae::RoundReport;
pub use config::{default_data_dir, NodeConfig};
pub use error::{EngineError, Result};
pub use fetcher::{FetchReport, PreparedRange, Provider};
pub use ignore::IgnoreSet;
pub use membership::{DoctorReport, DomainRefresh, HeadStatus};
pub use mirror::MirrorReport;
pub use node::{InitReport, Node, StagedChange};
pub use publisher::{Publisher, DEFAULT_PUBLISH_BATCH_MAX, DEFAULT_PUBLISH_QUIESCE};
pub use recovery::{
    ObserveRound, RecoveryOptions, RecoveryProgress, RecoveryReport, RecoveryState,
    UnreconciledHistory, DEFAULT_RECOVERY_QUIESCE, DEFAULT_SEQ_GAP,
};
pub use reference::EntryRef;
pub use rotation::{Activation, PeerBindings, RotationPlan};
pub use scanner::ScanReport;
pub use synch_store::{Selection, Version, VersionPolicy, VersionSet};
pub use tree::reference_of;
pub use watcher::SpaceWatcher;
