//! Errors produced by the store.

use synch_core::Hash;

/// The store result alias.
pub type Result<T> = std::result::Result<T, StoreError>;

/// An error from the metadata store or the content-addressed blob store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// SQLite failed.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Filesystem I/O failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A cloud object-store operation failed.
    #[error("cloud {operation} {path}: {source}")]
    Cloud {
        /// The semantic operation being attempted.
        operation: &'static str,
        /// The provider-neutral object path.
        path: String,
        /// OpenDAL's normalized provider error and source chain.
        #[source]
        source: Box<opendal::Error>,
    },
    /// A strongly consistent cloud service authoritatively reported no object.
    #[error("cloud object {path} is missing")]
    CloudNotFound {
        /// The provider-neutral object path.
        path: String,
        /// OpenDAL's normalized NotFound error.
        #[source]
        source: Box<opendal::Error>,
    },
    /// A trie operation failed.
    #[error(transparent)]
    Mpt(#[from] synch_mpt::MptError),
    /// A stored record could not be decoded.
    #[error("corrupt record: {0}")]
    Decode(String),
    /// A stored value had the wrong shape (e.g. a 31-byte hash column).
    #[error("corrupt column {column}: {reason}")]
    Column {
        /// The column name.
        column: &'static str,
        /// What was wrong with it.
        reason: String,
    },
    /// A blob was not in the local content store.
    #[error("blob {0} is not in the local store")]
    MissingBlob(Hash),
    /// Untrusted wire data or a metadata claim failed validation.
    #[error("object validation failed for {root}: {reason}")]
    Verification {
        /// The object root the content failed against.
        root: Hash,
        /// What went wrong.
        reason: String,
    },
    /// The requested byte range lies outside the object.
    #[error("range {start}..{end} is outside object of size {size}")]
    RangeOutOfBounds {
        /// Range start.
        start: u64,
        /// Range end.
        end: u64,
        /// The object size.
        size: u64,
    },
    /// A caller supplied an invalid argument.
    #[error("{0}")]
    Invalid(String),
}

impl StoreError {
    /// Builds a column-shape error.
    pub fn column(column: &'static str, reason: impl Into<String>) -> Self {
        StoreError::Column {
            column,
            reason: reason.into(),
        }
    }

    /// Builds an invalid-argument error.
    pub fn invalid(msg: impl Into<String>) -> Self {
        StoreError::Invalid(msg.into())
    }
}
