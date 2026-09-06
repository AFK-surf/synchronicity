//! Domain-neutral services requested by executable Lean operations.

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

/// Raw input observations. Successful bounded reads may be short at EOF;
/// freeze retains an immutable copy under an invocation-owned input handle.
pub trait SourceIO {
    type Error;
    fn stat(&mut self, space: &str, key: &[u8]) -> Result<u64, Self::Error>;
    fn read_some(&mut self, handle: u64, offset: u64, count: u64) -> Result<Vec<u8>, Self::Error>;
    fn freeze(&mut self, bytes: &[u8]) -> Result<u64, Self::Error>;
}

/// Bulk object construction over resources the requesting operation owns.
///
/// The operation decides what is built, from which opened source and into
/// which owned temporaries; the host streams the bytes, hashes them into the
/// BLAKE3 tree and lays out the Bao outboard. Neither call publishes, flushes
/// or records anything.
pub trait Construct {
    type Error;
    /// Stream exactly `size` bytes of `source`, from its start, into the
    /// `payload` temporary, write the object's outboard into the `outboard`
    /// temporary and return the 32-byte root. A source shorter than `size`
    /// is an error, not a shorter object.
    fn build(
        &mut self,
        source: u64,
        payload: u64,
        outboard: u64,
        size: u64,
    ) -> Result<Vec<u8>, Self::Error>;
    /// The BLAKE3 root of bytes the operation already holds.
    fn hash(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectorySync {
    Synced,
    Unsupported,
}

/// Invocation-owned staging resources. Abandonment releases handles and
/// removes unpublished temporary names; replacement consumes temporary ownership.
pub trait TemporaryFiles {
    type Error;
    fn create_temporary(&mut self, space: &str) -> Result<u64, Self::Error>;
    fn flush(&mut self, handle: u64) -> Result<(), Self::Error>;
    fn replace(&mut self, handle: u64, space: &str, key: &[u8]) -> Result<(), Self::Error>;
    fn discard(&mut self, handle: u64) -> Result<(), Self::Error>;
    fn sync_parent(&mut self, space: &str, key: &[u8]) -> Result<DirectorySync, Self::Error>;
}

/// Opaque counted resource leases ordered against competing deletion. Host
/// abandonment releases outstanding tokens; policy chooses their lifetime.
pub trait Lease {
    type Error;
    fn acquire(&mut self, space: &str, key: &[u8]) -> Result<u64, Self::Error>;
    fn release(&mut self, token: u64) -> Result<(), Self::Error>;
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

/// Session-local raw file handles. Dropping the host releases outstanding handles.
pub trait FileIO {
    type Error;
    /// Open one keyed file and retain its handle for this interpreter session.
    fn open(&mut self, space: &str, key: &[u8]) -> Result<u64, FileFailure<Self::Error>>;
    /// Read exactly `count` bytes at `offset`, returning `ShortRead` at EOF.
    /// The host checks representability and must not truncate offset/count.
    fn read_at(
        &mut self,
        handle: u64,
        offset: u64,
        count: u64,
    ) -> Result<Vec<u8>, FileFailure<Self::Error>>;
    /// Fill `buffer` from `offset`, returning `ShortRead` at EOF. The
    /// interpreter hands over the tail of the operation's output sink, so a
    /// transfer costs one read into the bytes the caller receives.
    fn read_into(
        &mut self,
        handle: u64,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<(), FileFailure<Self::Error>>;
    fn close(&mut self, handle: u64) -> Result<(), Self::Error>;
}

/// Wall-clock input; the operation chooses when to observe it.
pub trait Clock {
    type Error;
    fn now_ns(&mut self) -> Result<i64, Self::Error>;
}

/// Operation-local byte sink. Appended bytes are provisional until the whole
/// operation succeeds; the caller discards the sink on failure.
pub trait Output {
    type Error;
    fn append(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
    /// Extend the sink by `count` bytes and hand them back for an in-place
    /// fill, so a file transfer lands directly in the result.
    fn grow(&mut self, count: u64) -> Result<&mut [u8], Self::Error>;
    /// Take back the last `count` bytes after a fill failed.
    fn shrink(&mut self, count: u64);
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

/// Non-transactional raw resources, separate from the relational capability.
/// Callers retain any required ordering guards for the entire operation.
pub trait Resources {
    type Error;
    /// Read a keyed counter; an absent key has count zero.
    fn read_counter(&mut self, space: &str, key: &[u8]) -> Result<u64, Self::Error>;
    /// Remove one keyed file. The requesting program selects failure handling.
    fn remove_file(&mut self, space: &str, key: &[u8]) -> Result<(), Self::Error>;
}

/// The relational host: transactions, raw projections, mutations and byte
/// reads. The interpreter executes requests literally; algorithms, metadata
/// interpretation and operation sequencing remain in Lean.
///
/// Transaction handles are local to one interpreter session. A failed commit
/// does not acknowledge success. Dropping a session must release its resources
/// and roll back any transaction it still owns.
pub trait Storage {
    /// Original host error, retained without converting it into a policy result.
    type Error;

    /// Scan literal raw projections, retaining rows before the first stepping
    /// failure. Preparation/binding failures use the outer error. No domain
    /// conversion may run here or replace an earlier row's validation error.
    fn scan_rows(
        &mut self,
        tx: u64,
        relation: &str,
        columns: &[String],
        equals: &Fields,
        order: &[Order],
        joins: &[Join],
    ) -> Result<Scan<Self::Error>, Self::Error>;

    /// Begin an immediate transaction before the operation's relevant reads.
    fn begin(&mut self) -> Result<u64, Self::Error>;
    /// Commit the identified transaction.
    fn commit(&mut self, tx: u64) -> Result<(), Self::Error>;
    /// Roll back the identified transaction.
    fn rollback(&mut self, tx: u64) -> Result<(), Self::Error>;
    /// Read raw projections matching all named equality predicates.
    fn read_rows(
        &mut self,
        tx: u64,
        relation: &str,
        columns: &[String],
        equals: &Fields,
        order: &[Order],
        joins: &[Join],
    ) -> Result<Vec<Row>, Self::Error>;
    /// Existence query without materializing all matching rows.
    fn exists_rows(
        &mut self,
        tx: u64,
        relation: &str,
        equals: &Fields,
    ) -> Result<bool, Self::Error>;
    /// Insert explicit values; on the named conflict, update only the named
    /// columns from those values. An empty update list means do nothing.
    fn upsert(
        &mut self,
        tx: u64,
        relation: &str,
        values: &Fields,
        conflict_columns: &[String],
        update_columns: &[String],
    ) -> Result<(), Self::Error>;
    /// Delete matching rows only if every exclusion is absent in the same
    /// statement, not by a preceding read. `at_most` adds column <= bound
    /// predicates using the stored SQL types (NULL does not satisfy <=).
    /// Return the affected row count.
    fn delete_rows(
        &mut self,
        tx: u64,
        relation: &str,
        equals: &Fields,
        unless: &[Exclusion],
        at_most: &Fields,
    ) -> Result<u64, Self::Error>;
    /// Read opaque bytes by namespace and key, preserving absence versus empty.
    fn read_bytes(&mut self, space: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Read outside an explicitly requested transaction, preserving a successful
    /// raw row prefix and any trailing stepping error.
    fn snapshot(
        &mut self,
        selection: &Selection,
        columns: &[String],
    ) -> Result<Scan<Self::Error>, Self::Error>;
    /// Update explicit raw values for the matching rows in the named transaction.
    fn update(
        &mut self,
        tx: u64,
        selection: &Selection,
        values: &Fields,
    ) -> Result<u64, Self::Error>;
    /// INSERT SELECT with literal values or source-column projections, ignoring
    /// only conflicts on the specified target columns.
    fn copy_rows(
        &mut self,
        tx: u64,
        target: &str,
        source: &Selection,
        values: &[(String, SourceValue)],
        conflicts: &[String],
    ) -> Result<u64, Self::Error>;
    /// Delete selected rows in one statement, returning the affected row count.
    fn delete_selected(&mut self, tx: u64, selection: &Selection) -> Result<u64, Self::Error>;
    /// One atomic INSERT with explicit conflict assignments over raw bound cells.
    fn write(
        &mut self,
        tx: u64,
        relation: &str,
        values: &Fields,
        conflicts: &[String],
        assignments: &[(String, ConflictValue)],
    ) -> Result<(), Self::Error>;
}

/// Raw prefix and optional trailing scan failure; no domain interpretation.
#[derive(Debug)]
pub struct Scan<E> {
    pub rows: Vec<Row>,
    pub failure: Option<E>,
}

/// Primitive cryptography, separate from storage and domain validation.
pub trait Crypto {
    /// Original host error, distinct from invalid key bytes.
    type Error;
    /// Check whether bytes represent a valid Ed25519 public key. Does not parse
    /// origins, verify signatures, or validate a stored head.
    fn validate_ed25519(&mut self, bytes: &[u8]) -> Result<bool, Self::Error>;
}
