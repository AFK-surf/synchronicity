//! One error type for the service.

/// Anything that can go wrong hosting a tenant.
#[derive(Debug, thiserror::Error)]
pub enum DpError {
    /// A local filesystem operation failed, named by what it was doing.
    #[error("{context}: {source}")]
    Io {
        /// What was being attempted.
        context: &'static str,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// The object store refused or could not answer.
    #[error("object store: {0}")]
    Objects(#[from] opendal::Error),
    /// The control plane refused, or could not be reached.
    #[error("control plane: {0}")]
    Control(String),
    /// The store or the node refused.
    #[error("node: {0}")]
    Engine(String),
    /// The configuration is unusable, and says why.
    #[error("configuration: {0}")]
    Config(String),
    /// The database stream could not be sealed or opened.
    ///
    /// Deliberately says nothing about which: a decrypt failure is either a
    /// wrong key or a tampered object, and telling them apart is exactly the
    /// service an attacker would like.
    #[error("database stream cryptography failed")]
    Crypto,
}

impl DpError {
    /// Wraps an IO failure with what was being attempted.
    pub fn io(context: &'static str, source: std::io::Error) -> Self {
        DpError::Io { context, source }
    }

    /// Wraps a store failure.
    pub fn store(error: impl std::fmt::Display) -> Self {
        DpError::Engine(error.to_string())
    }
}

impl From<synch_store::StoreError> for DpError {
    fn from(error: synch_store::StoreError) -> Self {
        DpError::Engine(error.to_string())
    }
}

impl From<synch_engine::EngineError> for DpError {
    fn from(error: synch_engine::EngineError) -> Self {
        DpError::Engine(error.to_string())
    }
}

/// This crate's result.
pub type Result<T> = std::result::Result<T, DpError>;
