//! Literal raw-storage interpreter for Lean programs. No domain predicates.

use rusqlite::{params_from_iter, types::Value, Connection, OptionalExtension};
use synch_verified::host::{Cell, Fields, Row, Storage};

use crate::{Result, StoreError};

/// Raw keyed resources; no CAS protection or cleanup policy is interpreted here.
pub(crate) struct Resources<'a>(pub(crate) &'a crate::Store);

impl synch_verified::host::Resources for Resources<'_> {
    type Error = StoreError;
    fn read_counter(&mut self, space: &str, key: &[u8]) -> Result<u64> {
        let root = synch_core::Hash::from_slice(key)
            .map_err(|error| StoreError::invalid(error.to_string()))?;
        match space {
            "cas_writers" => Ok(self.0.writer_count(&root) as u64),
            _ => Err(StoreError::invalid("unsupported counter namespace")),
        }
    }
    fn remove_file(&mut self, space: &str, key: &[u8]) -> Result<()> {
        let root = synch_core::Hash::from_slice(key)
            .map_err(|error| StoreError::invalid(error.to_string()))?;
        let path = match space {
            "cas_payload" => self.0.blob_path(&root),
            "cas_outboard" => self.0.outboard_path(&root),
            _ => return Err(StoreError::invalid("unsupported file namespace")),
        };
        std::fs::remove_file(path).map_err(Into::into)
    }
}

/// One synchronous interpreter session borrowing its caller's guarded connection.
/// The caller retains connection and applicable ordering guards until the program
/// finishes or is dropped. No borrowed transaction/guard lifetime is extended.
#[derive(Debug)]
pub(crate) struct SqliteStorage<'a> {
    conn: &'a Connection,
    active: Option<u64>,
    next: u64,
}

impl<'a> SqliteStorage<'a> {
    pub(crate) fn new(conn: &'a Connection) -> Self {
        Self {
            conn,
            active: None,
            next: 1,
        }
    }

    fn require_transaction(&self, tx: u64) -> Result<()> {
        if self.active != Some(tx) {
            return Err(StoreError::invalid("unknown or stale storage transaction"));
        }
        Ok(())
    }

    fn require_live_transaction(&self, tx: u64) -> Result<()> {
        self.require_transaction(tx)?;
        if self.conn.is_autocommit() {
            return Err(StoreError::invalid("storage transaction was rolled back"));
        }
        Ok(())
    }
}

impl Drop for SqliteStorage<'_> {
    fn drop(&mut self) {
        if self.active.is_some() && !self.conn.is_autocommit() {
            // Cancellation releases an uncommitted host resource. Normal
            // recovery and error selection are requested by the Lean program.
            let _ = self.conn.execute_batch("ROLLBACK");
        }
    }
}

/// Schema identifiers are capabilities, not SQL supplied by the core.
fn columns_for(relation: &str) -> Result<&'static [&'static str]> {
    match relation {
        "blobs" => Ok(&[
            "root",
            "size",
            "complete",
            "bitmap",
            "inline",
            "last_access",
            "durable",
        ]),
        "pins" => Ok(&["root", "holder", "created_at", "release_after"]),
        "entries" => Ok(&["content"]),
        "content_want" => Ok(&[
            "root",
            "holder",
            "size",
            "prev",
            "first_wanted",
            "attempts",
            "last_attempt",
            "last_error",
        ]),
        "heads" => Ok(&[
            "origin_id",
            "slot",
            "seq",
            "root",
            "received_at",
            "verified_at",
        ]),
        "head_history" => Ok(&[
            "origin_id",
            "seq",
            "root",
            "created_at",
            "signed_by",
            "sig",
            "recorded_at",
        ]),
        "trie_nodes" | "trie_values" => Ok(&["hash", "data"]),
        _ => Err(StoreError::invalid("unsupported storage relation")),
    }
}

fn column(relation: &str, name: &str) -> Result<String> {
    if !columns_for(relation)?.contains(&name) {
        return Err(StoreError::invalid("unsupported storage column"));
    }
    Ok(format!("\"{name}\""))
}

fn projection(relation: &str, columns: &[String]) -> Result<String> {
    columns
        .iter()
        .map(|name| column(relation, name))
        .collect::<Result<Vec<_>>>()
        .map(|names| names.join(", "))
}

fn values(fields: &Fields) -> Vec<Value> {
    fields
        .iter()
        .map(|(_, cell)| match cell {
            Cell::Null => Value::Null,
            Cell::Integer(value) => Value::Integer(*value),
            Cell::Text(value) => Value::Text(value.clone()),
            Cell::Blob(value) => Value::Blob(value.clone()),
        })
        .collect()
}

fn predicate(relation: &str, equals: &Fields) -> Result<String> {
    let terms = equals
        .iter()
        .map(|(name, _)| column(relation, name).map(|name| format!("{name} IS ?")))
        .collect::<Result<Vec<_>>>()?;
    Ok(if terms.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", terms.join(" AND "))
    })
}

impl Storage for SqliteStorage<'_> {
    type Error = StoreError;

    fn exists_rows(&mut self, tx: u64, relation: &str, equals: &Fields) -> Result<bool> {
        self.require_live_transaction(tx)?;
        columns_for(relation)?;
        let sql = format!(
            "SELECT EXISTS(SELECT 1 FROM \"{relation}\"{})",
            predicate(relation, equals)?
        );
        self.conn
            .query_row(&sql, params_from_iter(values(equals)), |row| row.get(0))
            .map_err(Into::into)
    }

    fn begin(&mut self) -> Result<u64> {
        if self.active.is_some() || !self.conn.is_autocommit() {
            return Err(StoreError::invalid("storage transaction already active"));
        }
        let next = self
            .next
            .checked_add(1)
            .ok_or_else(|| StoreError::invalid("storage transaction identifiers exhausted"))?;
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let tx = self.next;
        self.next = next;
        self.active = Some(tx);
        Ok(tx)
    }

    fn commit(&mut self, tx: u64) -> Result<()> {
        self.require_transaction(tx)?;
        self.conn.execute_batch("COMMIT")?;
        self.active = None;
        Ok(())
    }

    fn rollback(&mut self, tx: u64) -> Result<()> {
        self.require_transaction(tx)?;
        // SQLite can itself roll back a transaction after certain I/O errors.
        // Already rolled back is a released resource, not a successful commit.
        if !self.conn.is_autocommit() {
            self.conn.execute_batch("ROLLBACK")?;
        }
        self.active = None;
        Ok(())
    }

    fn read_rows(
        &mut self,
        tx: u64,
        relation: &str,
        columns: &[String],
        equals: &Fields,
    ) -> Result<Vec<Row>> {
        self.require_live_transaction(tx)?;
        columns_for(relation)?;
        if columns.is_empty() {
            return Err(StoreError::invalid("empty storage projection"));
        }
        let sql = format!(
            "SELECT {} FROM \"{relation}\"{}",
            projection(relation, columns)?,
            predicate(relation, equals)?
        );
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values(equals)), |row| {
            columns
                .iter()
                .enumerate()
                .map(|(index, name)| match row.get_ref(index)? {
                    rusqlite::types::ValueRef::Null => Ok(Cell::Null),
                    rusqlite::types::ValueRef::Integer(value) => Ok(Cell::Integer(value)),
                    rusqlite::types::ValueRef::Text(value) => Ok(Cell::Text(
                        std::str::from_utf8(value)
                            .map_err(rusqlite::Error::Utf8Error)?
                            .to_owned(),
                    )),
                    rusqlite::types::ValueRef::Blob(value) => Ok(Cell::Blob(value.to_vec())),
                    rusqlite::types::ValueRef::Real(_) => Err(rusqlite::Error::InvalidColumnType(
                        index,
                        name.clone(),
                        rusqlite::types::Type::Real,
                    )),
                })
                .collect::<rusqlite::Result<Row>>()
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    fn upsert(
        &mut self,
        tx: u64,
        relation: &str,
        fields: &Fields,
        conflict_columns: &[String],
        update_columns: &[String],
    ) -> Result<()> {
        self.require_live_transaction(tx)?;
        columns_for(relation)?;
        if fields.is_empty() {
            return Err(StoreError::invalid("empty storage write"));
        }
        let names: Vec<String> = fields.iter().map(|(name, _)| name.clone()).collect();
        if names
            .iter()
            .enumerate()
            .any(|(i, name)| names[..i].contains(name))
        {
            return Err(StoreError::invalid("duplicate storage write column"));
        }
        if conflict_columns
            .iter()
            .chain(update_columns)
            .any(|name| !names.contains(name))
        {
            return Err(StoreError::invalid("UPSERT names a column without a value"));
        }
        let conflict = if conflict_columns.is_empty() {
            String::new()
        } else {
            format!(" ({})", projection(relation, conflict_columns)?)
        };
        let update = if update_columns.is_empty() {
            "DO NOTHING".to_owned()
        } else {
            let updates = update_columns
                .iter()
                .map(|name| column(relation, name).map(|name| format!("{name} = excluded.{name}")))
                .collect::<Result<Vec<_>>>()?;
            format!("DO UPDATE SET {}", updates.join(", "))
        };
        let sql = format!(
            "INSERT INTO \"{relation}\" ({}) VALUES ({}) ON CONFLICT{conflict} {update}",
            projection(relation, &names)?,
            vec!["?"; fields.len()].join(", ")
        );
        self.conn.execute(&sql, params_from_iter(values(fields)))?;
        Ok(())
    }

    fn delete_rows(&mut self, tx: u64, relation: &str, equals: &Fields) -> Result<u64> {
        self.require_live_transaction(tx)?;
        columns_for(relation)?;
        let sql = format!("DELETE FROM \"{relation}\"{}", predicate(relation, equals)?);
        Ok(self.conn.execute(&sql, params_from_iter(values(equals)))? as u64)
    }

    fn read_bytes(&mut self, space: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let sql = match space {
            "trie_nodes" => "SELECT data FROM trie_nodes WHERE hash = ?1",
            "trie_values" => "SELECT data FROM trie_values WHERE hash = ?1",
            _ => return Err(StoreError::invalid("unsupported byte-storage namespace")),
        };
        self.conn
            .query_row(sql, [key], |row| row.get(0))
            .optional()
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE pins (root BLOB, holder TEXT, created_at INTEGER,
               release_after INTEGER, PRIMARY KEY(root, holder));
             CREATE TABLE content_want (root BLOB, holder TEXT, size INTEGER,
               prev BLOB, first_wanted INTEGER, attempts INTEGER,
               last_attempt INTEGER, last_error TEXT, PRIMARY KEY(root, holder));
             CREATE TABLE blobs (root BLOB PRIMARY KEY, size INTEGER, complete INTEGER,
               bitmap BLOB, inline BLOB, last_access INTEGER, durable INTEGER);
             CREATE TABLE trie_nodes (hash BLOB PRIMARY KEY, data BLOB);
             CREATE TABLE trie_values (hash BLOB PRIMARY KEY, data BLOB);",
        )
        .unwrap();
        conn
    }

    fn names(columns: &[&str]) -> Vec<String> {
        columns.iter().map(|name| (*name).to_owned()).collect()
    }

    fn pin_values(created_at: i64, release: Cell) -> Fields {
        vec![
            ("root".into(), Cell::Blob(vec![1])),
            ("holder".into(), Cell::Text("replica:space".into())),
            ("created_at".into(), Cell::Integer(created_at)),
            ("release_after".into(), release),
        ]
    }

    fn insert_pin(storage: &mut SqliteStorage<'_>, tx: u64) -> Result<()> {
        storage.upsert(
            tx,
            "pins",
            &pin_values(20, Cell::Null),
            &names(&["root", "holder"]),
            &names(&["release_after"]),
        )
    }

    #[test]
    fn raw_projections_preserve_types_null_empty_and_column_order() {
        let conn = connection();
        conn.execute(
            "INSERT INTO blobs VALUES (?1, -9, 1, NULL, ?2, 0, -7)",
            rusqlite::params![vec![1u8], Vec::<u8>::new()],
        )
        .unwrap();
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        assert_eq!(
            storage
                .read_rows(
                    tx,
                    "blobs",
                    &names(&["inline", "bitmap", "size", "durable"]),
                    &vec![]
                )
                .unwrap(),
            vec![vec![
                Cell::Blob(vec![]),
                Cell::Null,
                Cell::Integer(-9),
                Cell::Integer(-7)
            ]]
        );
        assert_eq!(
            storage
                .read_rows(
                    tx,
                    "blobs",
                    &names(&["root"]),
                    &vec![("bitmap".into(), Cell::Null)]
                )
                .unwrap(),
            vec![vec![Cell::Blob(vec![1])]]
        );
        assert!(storage
            .read_rows(
                tx,
                "blobs",
                &names(&["root"]),
                &vec![("root".into(), Cell::Blob(vec![2]))]
            )
            .unwrap()
            .is_empty());
        storage.commit(tx).unwrap();
    }

    #[test]
    fn upsert_preserves_unmentioned_columns_and_existing_row_identity() {
        let conn = connection();
        conn.execute_batch(
            "INSERT INTO pins VALUES (X'01', 'replica:space', 3, 17);
             CREATE TRIGGER no_pin_deletion BEFORE DELETE ON pins
               BEGIN SELECT RAISE(ABORT, 'unexpected replacement'); END;",
        )
        .unwrap();
        let old_rowid: i64 = conn
            .query_row("SELECT rowid FROM pins", [], |r| r.get(0))
            .unwrap();
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        insert_pin(&mut storage, tx).unwrap();
        assert_eq!(
            storage
                .read_rows(
                    tx,
                    "pins",
                    &names(&["created_at", "release_after"]),
                    &vec![]
                )
                .unwrap(),
            vec![vec![Cell::Integer(3), Cell::Null]]
        );
        storage.commit(tx).unwrap();
        let new_rowid: i64 = conn
            .query_row("SELECT rowid FROM pins", [], |r| r.get(0))
            .unwrap();
        assert_eq!(old_rowid, new_rowid);
    }

    #[test]
    fn drop_rolls_back_owned_transaction_and_does_not_touch_an_outer_transaction() {
        let conn = connection();
        {
            let mut storage = SqliteStorage::new(&conn);
            let tx = storage.begin().unwrap();
            insert_pin(&mut storage, tx).unwrap();
        }
        assert!(conn.is_autocommit());
        assert_eq!(
            conn.query_row("SELECT count(*) FROM pins", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        {
            let mut storage = SqliteStorage::new(&conn);
            assert!(storage.begin().is_err());
        }
        assert!(!conn.is_autocommit());
        conn.execute_batch("ROLLBACK").unwrap();
    }

    #[test]
    fn stale_and_mismatched_transaction_handles_cannot_mutate_or_commit() {
        let conn = connection();
        let mut storage = SqliteStorage::new(&conn);
        let first = storage.begin().unwrap();
        assert!(storage.begin().is_err());
        assert!(storage.commit(first + 1).is_err());
        assert!(storage.delete_rows(first + 1, "pins", &vec![]).is_err());
        storage.rollback(first).unwrap();
        let next = storage.begin().unwrap();
        assert_ne!(next, first);
        assert!(storage.rollback(first).is_err());
        storage.commit(next).unwrap();
    }

    #[test]
    fn mutation_and_commit_failures_remain_rollbackable() {
        for at_commit in [false, true] {
            let conn = connection();
            conn.execute_batch(
                "INSERT INTO content_want (root, holder) VALUES (X'01', 'replica:space')",
            )
            .unwrap();
            if at_commit {
                conn.execute_batch(
                    "CREATE TABLE parent (id INTEGER PRIMARY KEY);
                     CREATE TABLE child (parent INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);
                     CREATE TRIGGER fail_pin AFTER INSERT ON pins
                       BEGIN INSERT INTO child VALUES (1); END;",
                ).unwrap();
            } else {
                conn.execute_batch(
                    "CREATE TRIGGER fail_pin BEFORE INSERT ON pins
                       BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
                )
                .unwrap();
            }
            let mut storage = SqliteStorage::new(&conn);
            let tx = storage.begin().unwrap();
            assert_eq!(storage.delete_rows(tx, "content_want", &vec![]).unwrap(), 1);
            if at_commit {
                insert_pin(&mut storage, tx).unwrap();
                assert!(storage.commit(tx).is_err());
            } else {
                assert!(insert_pin(&mut storage, tx).is_err());
            }
            storage.rollback(tx).unwrap();
            assert_eq!(
                conn.query_row("SELECT count(*) FROM content_want", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                1
            );
            assert_eq!(
                conn.query_row("SELECT count(*) FROM pins", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn unsupported_identifiers_and_cell_types_fail_without_coercion() {
        let conn = connection();
        conn.execute_batch("INSERT INTO blobs (root, durable) VALUES (X'01', 1.5)")
            .unwrap();
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        assert!(storage
            .read_rows(tx, "blobs; DROP TABLE pins", &names(&["root"]), &vec![])
            .is_err());
        assert!(storage
            .read_rows(tx, "blobs", &names(&["root FROM blobs; --"]), &vec![])
            .is_err());
        assert!(storage
            .read_rows(tx, "blobs", &names(&["durable"]), &vec![])
            .is_err());
        assert!(storage.read_rows(tx, "blobs", &[], &vec![]).is_err());
        storage.rollback(tx).unwrap();
        assert!(storage.read_bytes("trie_nodes; --", &[1]).is_err());
    }

    #[test]
    fn sqlite_automatic_rollback_cannot_turn_later_effects_into_autocommit_writes() {
        let conn = connection();
        conn.execute_batch(
            "CREATE TRIGGER abort_transaction BEFORE INSERT ON pins
               BEGIN SELECT RAISE(ROLLBACK, 'injected automatic rollback'); END;",
        )
        .unwrap();
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        assert!(insert_pin(&mut storage, tx).is_err());
        assert!(conn.is_autocommit());
        conn.execute_batch("DROP TRIGGER abort_transaction")
            .unwrap();
        assert!(insert_pin(&mut storage, tx).is_err());
        assert!(storage.delete_rows(tx, "pins", &vec![]).is_err());
        assert!(storage
            .read_rows(tx, "pins", &names(&["root"]), &vec![])
            .is_err());
        assert!(storage.commit(tx).is_err());
        storage.rollback(tx).unwrap();
        let fresh = storage.begin().unwrap();
        insert_pin(&mut storage, fresh).unwrap();
        storage.commit(fresh).unwrap();
    }

    #[test]
    fn byte_reads_preserve_absence_and_empty_objects() {
        let conn = connection();
        conn.execute(
            "INSERT INTO trie_nodes VALUES (?1, ?2)",
            rusqlite::params![vec![1u8], Vec::<u8>::new()],
        )
        .unwrap();
        let mut storage = SqliteStorage::new(&conn);
        assert_eq!(
            storage.read_bytes("trie_nodes", &[1]).unwrap(),
            Some(vec![])
        );
        assert_eq!(storage.read_bytes("trie_nodes", &[2]).unwrap(), None);
        assert_eq!(storage.read_bytes("trie_values", &[1]).unwrap(), None);
    }
}
