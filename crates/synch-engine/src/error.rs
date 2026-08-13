//! Errors produced by the engine.

/// The engine result alias.
pub type Result<T> = std::result::Result<T, EngineError>;

/// An error from the node API.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The store failed.
    #[error(transparent)]
    Store(#[from] synch_store::StoreError),
    /// A trie operation failed.
    #[error(transparent)]
    Mpt(#[from] synch_mpt::MptError),
    /// The network failed.
    #[error(transparent)]
    Net(#[from] synch_net::NetError),
    /// Filesystem I/O failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A record could not be encoded or decoded.
    #[error("record: {0}")]
    Record(String),
    /// A path or key was invalid.
    #[error(transparent)]
    Key(#[from] synch_core::KeyError),
    /// The node has not been initialized (`synch init`).
    #[error("this data directory has no identity: run `synch init` first")]
    NotInitialized,
    /// The node has no active device key.
    #[error("no active device key")]
    NoActiveKey,
    /// A space, origin, or entry was not found.
    #[error("not found: {0}")]
    NotFound(String),
    /// A caller supplied an invalid argument.
    #[error("{0}")]
    Invalid(String),
    /// This node is in key-loss recovery and must not publish (§3.4).
    ///
    /// Publishing anyway would mint heads at a seq every peer correctly
    /// rejects, with nothing on either side saying why.
    #[error(
        "{origin} is in key-loss recovery: peers hold heads for it up to seq {observed_seq}, \
         so a publish at seq {would_publish} would be rejected by every one of them. \
         Run `synch recover` to collect what peers have seen and resume publishing above it"
    )]
    InRecovery {
        /// This node's own origin.
        origin: synch_core::OriginId,
        /// The highest seq any peer has advertised for it.
        observed_seq: u64,
        /// The seq the refused publish would have carried.
        would_publish: u64,
    },
}

impl EngineError {
    /// Builds an invalid-argument error.
    pub fn invalid(msg: impl Into<String>) -> Self {
        EngineError::Invalid(msg.into())
    }

    /// Builds a not-found error.
    pub fn not_found(msg: impl Into<String>) -> Self {
        EngineError::NotFound(msg.into())
    }
}
