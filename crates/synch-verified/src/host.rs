//! Domain-neutral services requested by executable Lean operations. The
//! service traits are generated from the Lean effect algebras; the raw value
//! types they exchange are defined here.

pub use crate::generated::{
    ByteWrites, Clock, Construct, Crypto, Digest, FileIO, Lease, Output, Resources, SourceIO,
    Storage, TemporaryFiles,
};

/// The raw services an ingestion directs besides its relational storage. The
/// transport depends only on these service types, never on domain commands.
pub struct IngestResources<'a, E> {
    pub files: &'a mut dyn FileIO<Error = E>,
    pub construct: &'a mut dyn Construct<Error = E>,
    pub temporary: &'a mut dyn TemporaryFiles<Error = E>,
    pub leases: &'a mut dyn Lease<Error = E>,
    pub source: &'a mut dyn SourceIO<Error = E>,
}
impl<E> std::fmt::Debug for IngestResources<'_, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IngestResources").finish_non_exhaustive()
    }
}

/// Raw storage cell. Interpretation belongs to the requesting Lean domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cell {
    /// SQL NULL, distinct from an absent row or an empty byte string.
    Null,
    /// Signed integer bits, without domain-specific coercion.
    Integer(i64),
    /// Valid UTF-8 text.
    Text(String),
    /// Opaque stored bytes.
    Blob(Vec<u8>),
    /// Observed IEEE-754 bits, without numeric/domain coercion.
    Real(u64),
    /// SQLite text bytes retained without requiring valid UTF-8.
    RawText(Vec<u8>),
}

/// A projected row, in the requested column order.
pub type Row = Vec<Cell>;
/// Named raw cells used as equality predicates or explicit write values.
pub type Fields = Vec<(String, Cell)>;

/// Literal equality predicates AND an optional disjunction of SQL LIKE predicates.
/// An empty `like_any` adds no restriction. Equality compares raw stored cells;
/// the adapter must not parse or reinterpret domain fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub relation: String,
    pub equals: Fields,
    pub like_any: Vec<(String, String)>,
    /// Rows whose stored cell `IS NOT` the value are selected; NULL is a value.
    pub not_equals: Fields,
}

/// An explicit value or a raw source-column projection for INSERT SELECT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceValue {
    Literal(Cell),
    Column(String),
}

/// Raw SQLite conflict expressions. These preserve SQLite NULL, storage-class,
/// collation and scalar maximum semantics; they do not interpret domain data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictValue {
    Current(String),
    Excluded(String),
    Coalesce(Box<(Self, Self)>),
    Maximum(Box<(Self, Self)>),
}

/// Bulk object construction over resources the requesting operation owns.
///
/// Whether the host synchronized a directory or cannot on this platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStatus {
    Synced,
    Unsupported,
}

/// Mechanical I/O classification; interpretation remains in Lean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFailureKind {
    Missing,
    ShortRead,
    Other,
}

/// Original I/O error paired with its mechanical classification.
#[derive(Debug)]
pub struct FileFailure<E> {
    pub error: E,
    pub kind: FileFailureKind,
}

/// Ordering by the column's stored type, not a domain reinterpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    pub column: String,
    pub descending: bool,
}

/// A raw NOT EXISTS query that must be checked in the mutation statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exclusion {
    pub relation: String,
    pub equals: Fields,
    /// Base-column to excluded-column SQL equality, per candidate row.
    pub keys: Vec<(String, String)>,
}

/// Inner equality join from base-table columns to the named relation's columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Join {
    pub relation: String,
    pub keys: Vec<(String, String)>,
}

/// Read-only byte storage capability, without relational or transaction policy.
pub trait ByteStorage {
    /// Original backing-store failure.
    type Error;
    /// Read opaque bytes by namespace/key, preserving absence versus empty.
    fn read_bytes(&mut self, space: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;
}

/// The relational host: transactions, raw projections, mutations and byte
/// reads. The interpreter executes requests literally; algorithms, metadata
/// interpretation and operation sequencing remain in Lean.
///
/// Raw prefix and optional trailing scan failure; no domain interpretation.
#[derive(Debug)]
pub struct Scan<E> {
    pub rows: Vec<Row>,
    pub failure: Option<E>,
}
