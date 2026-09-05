//! Domain-neutral services requested by executable Lean operations.

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
}

/// A projected row, in the requested column order.
pub type Row = Vec<Cell>;
/// Named raw cells used as equality predicates or explicit write values.
pub type Fields = Vec<(String, Cell)>;

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

/// Host storage capabilities. The interpreter executes requests literally;
/// algorithms, metadata interpretation and operation sequencing remain in Lean.
///
/// Transaction handles are local to one interpreter session. A failed commit
/// does not acknowledge success. Dropping a session must release its resources
/// and roll back any transaction it still owns.
pub trait Storage {
    /// Original host error, retained without converting it into a policy result.
    type Error;

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
    /// statement, not by a preceding read. Return the affected row count.
    fn delete_rows(
        &mut self,
        tx: u64,
        relation: &str,
        equals: &Fields,
        unless: &[Exclusion],
    ) -> Result<u64, Self::Error>;
    /// Read opaque bytes by namespace and key, preserving absence versus empty.
    fn read_bytes(&mut self, space: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;
}
