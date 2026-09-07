//! Literal raw-storage interpreter for Lean programs. No domain predicates.

use rusqlite::{
    params_from_iter,
    types::{ToSqlOutput, ValueRef},
    Connection, OptionalExtension, ToSql,
};
use synch_verified::host::{
    Cell, ConflictValue, Fields, Row, Scan, Selection, SourceValue, Storage,
};

use crate::{Result, StoreError};

#[cfg(test)]
thread_local! {
    static BYTE_READ_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Counts raw native commands on this test thread, without interpreting trie shape.
#[cfg(test)]
pub(crate) fn take_byte_read_calls() -> usize {
    BYTE_READ_CALLS.with(|calls| calls.replace(0))
}

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
    conn: ConnectionSource<'a>,
    active: Option<u64>,
    next: u64,
}

#[derive(Debug)]
enum ConnectionSource<'a> {
    Borrowed(&'a Connection),
    Owned(crate::db::ConnectionLease<'a>),
    /// The connection the remover's critical section holds, shared with the
    /// section's token for as long as either lives.
    Shared(std::rc::Rc<crate::db::ConnectionLease<'a>>),
}

impl std::ops::Deref for ConnectionSource<'_> {
    type Target = Connection;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(conn) => conn,
            Self::Owned(conn) => conn,
            Self::Shared(conn) => conn,
        }
    }
}

/// The connection state one invocation's storage session and its lease
/// service share: the connection a critical section (`Lease::order`) holds,
/// which every statement inside the section then runs on, and whether a
/// transaction is open, which is when a section may not begin.
#[derive(Debug, Default)]
pub(crate) struct Shared<'a> {
    pub(crate) held: Option<std::rc::Rc<crate::db::ConnectionLease<'a>>>,
    pub(crate) transaction: bool,
}

pub(crate) type Section<'a> = std::rc::Rc<std::cell::RefCell<Shared<'a>>>;

impl<'a> SqliteStorage<'a> {
    pub(crate) fn new(conn: &'a Connection) -> Self {
        Self {
            conn: ConnectionSource::Borrowed(conn),
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

/// Acquires connection/reentry guards only for a raw snapshot or an explicitly
/// requested transaction. No connection guard survives a completed transaction.
#[derive(Debug)]
pub(crate) struct Session<'a> {
    store: &'a crate::Store,
    active: Option<SqliteStorage<'a>>,
    next: u64,
    section: Section<'a>,
}

impl<'a> Session<'a> {
    pub(crate) fn new(store: &'a crate::Store) -> Self {
        Self {
            store,
            active: None,
            next: 1,
            section: Section::default(),
        }
    }

    /// The connection state a lease service of the same invocation shares,
    /// so a critical section it opens carries this session's statements.
    pub(crate) fn section(&self) -> Section<'a> {
        self.section.clone()
    }

    fn transaction(&mut self) -> Result<&mut SqliteStorage<'a>> {
        self.active
            .as_mut()
            .ok_or_else(|| StoreError::invalid("no active storage transaction"))
    }

    fn snapshot_storage(&self) -> Result<SqliteStorage<'a>> {
        if self.active.is_some() {
            return Err(StoreError::invalid("snapshot during storage transaction"));
        }
        // Inside a critical section the connection is already held; taking
        // it again would wait on the invocation's own guard forever.
        let conn = match self.section.borrow().held.as_ref() {
            Some(held) => ConnectionSource::Shared(held.clone()),
            None => ConnectionSource::Owned(self.store.connection_lease()),
        };
        Ok(SqliteStorage {
            conn,
            active: None,
            next: self.next,
        })
    }

    fn finish(&mut self) {
        self.active = None;
        self.section.borrow_mut().transaction = false;
    }
}

impl Storage for Session<'_> {
    type Error = StoreError;

    fn begin(&mut self) -> Result<u64> {
        let mut storage = self.snapshot_storage()?;
        let tx = storage.begin()?;
        self.next = storage.next;
        self.active = Some(storage);
        self.section.borrow_mut().transaction = true;
        Ok(tx)
    }

    fn commit(&mut self, tx: u64) -> Result<()> {
        self.transaction()?.commit(tx)?;
        self.finish();
        Ok(())
    }

    fn rollback(&mut self, tx: u64) -> Result<()> {
        self.transaction()?.rollback(tx)?;
        self.finish();
        Ok(())
    }

    fn snapshot_excluding(
        &mut self,
        selection: &Selection,
        columns: &[String],
        excluding: &[synch_verified::host::Exclusion],
    ) -> Result<Scan<StoreError>> {
        self.snapshot_storage()?
            .snapshot_excluding(selection, columns, excluding)
    }

    fn exists_rows(&mut self, tx: u64, relation: &str, equals: &Fields) -> Result<bool> {
        self.transaction()?.exists_rows(tx, relation, equals)
    }

    fn read_rows(
        &mut self,
        tx: u64,
        relation: &str,
        columns: &[String],
        equals: &Fields,
        order: &[synch_verified::host::Order],
        joins: &[synch_verified::host::Join],
    ) -> Result<Vec<Row>> {
        self.transaction()?
            .read_rows(tx, relation, columns, equals, order, joins)
    }

    fn scan_rows(
        &mut self,
        tx: u64,
        relation: &str,
        columns: &[String],
        equals: &Fields,
        order: &[synch_verified::host::Order],
        joins: &[synch_verified::host::Join],
    ) -> Result<Scan<StoreError>> {
        self.transaction()?
            .scan_rows(tx, relation, columns, equals, order, joins)
    }

    fn upsert(
        &mut self,
        tx: u64,
        relation: &str,
        fields: &Fields,
        conflicts: &[String],
        updates: &[String],
    ) -> Result<()> {
        self.transaction()?
            .upsert(tx, relation, fields, conflicts, updates)
    }

    fn delete_rows(
        &mut self,
        tx: u64,
        relation: &str,
        equals: &Fields,
        unless: &[synch_verified::host::Exclusion],
        at_most: &Fields,
    ) -> Result<u64> {
        self.transaction()?
            .delete_rows(tx, relation, equals, unless, at_most)
    }

    fn delete_except(
        &mut self,
        tx: u64,
        relation: &str,
        column: &str,
        keys: &[&[u8]],
    ) -> Result<u64> {
        self.transaction()?
            .delete_except(tx, relation, column, keys)
    }

    fn read_bytes(&mut self, space: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        #[cfg(test)]
        BYTE_READ_CALLS.with(|calls| calls.set(calls.get() + 1));
        if let Some(storage) = self.active.as_mut() {
            storage.read_bytes(space, key)
        } else {
            self.snapshot_storage()?.read_bytes(space, key)
        }
    }

    fn snapshot(&mut self, selection: &Selection, columns: &[String]) -> Result<Scan<StoreError>> {
        self.snapshot_storage()?.snapshot(selection, columns)
    }
    fn update(&mut self, tx: u64, selection: &Selection, fields: &Fields) -> Result<u64> {
        self.transaction()?.update(tx, selection, fields)
    }
    fn copy_rows(
        &mut self,
        tx: u64,
        target: &str,
        source: &Selection,
        fields: &[(String, SourceValue)],
        conflicts: &[String],
    ) -> Result<u64> {
        self.transaction()?
            .copy_rows(tx, target, source, fields, conflicts)
    }
    fn delete(&mut self, tx: u64, selection: &Selection) -> Result<u64> {
        self.transaction()?.delete(tx, selection)
    }

    fn write(
        &mut self,
        tx: u64,
        relation: &str,
        fields: &Fields,
        conflicts: &[String],
        assignments: &[(String, ConflictValue)],
    ) -> Result<()> {
        self.transaction()?
            .write(tx, relation, fields, conflicts, assignments)
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

fn unique_columns(relation: &str, names: &[String]) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for name in names {
        column(relation, name)?;
        if !seen.insert(name) {
            return Err(StoreError::invalid("duplicate expression UPSERT column"));
        }
    }
    Ok(())
}

fn conflict_expression(
    relation: &str,
    value: &ConflictValue,
    depth: usize,
    remaining: &mut usize,
) -> Result<String> {
    if depth > 32 || *remaining == 0 {
        return Err(StoreError::invalid(
            "expression UPSERT exceeds complexity limit",
        ));
    }
    *remaining -= 1;
    match value {
        ConflictValue::Current(name) => Ok(format!("\"{relation}\".{}", column(relation, name)?)),
        ConflictValue::Excluded(name) => Ok(format!("excluded.{}", column(relation, name)?)),
        ConflictValue::Coalesce(pair) | ConflictValue::Maximum(pair) => {
            let left = conflict_expression(relation, &pair.0, depth + 1, remaining)?;
            let right = conflict_expression(relation, &pair.1, depth + 1, remaining)?;
            let function = if matches!(value, ConflictValue::Coalesce(_)) {
                "coalesce"
            } else {
                "max"
            };
            Ok(format!("{function}({left}, {right})"))
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
        "entries" => Ok(&["content", "space"]),
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
        "trie_node_origins" => Ok(&["origin_id", "hash"]),
        "config" => Ok(&["key", "value"]),
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

fn read_column(base: &str, joins: &[synch_verified::host::Join], name: &str) -> Result<String> {
    let (relation, name) = name.split_once('.').unwrap_or((base, name));
    if relation != base && !joins.iter().any(|join| join.relation == relation) {
        return Err(StoreError::invalid("column outside storage query"));
    }
    Ok(format!("\"{relation}\".{}", column(relation, name)?))
}

struct BoundCell<'a>(&'a Cell);

impl ToSql for BoundCell<'_> {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Borrowed(match self.0 {
            Cell::Null => ValueRef::Null,
            Cell::Integer(value) => ValueRef::Integer(*value),
            Cell::Text(value) => ValueRef::Text(value.as_bytes()),
            Cell::RawText(value) => ValueRef::Text(value),
            Cell::Blob(value) => ValueRef::Blob(value),
            Cell::Real(bits) => ValueRef::Real(f64::from_bits(*bits)),
        }))
    }
}

fn values(fields: &Fields) -> Vec<BoundCell<'_>> {
    fields.iter().map(|(_, cell)| BoundCell(cell)).collect()
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

/// The correlated `NOT EXISTS` terms of raw exclusions against the base
/// relation aliased `"target"`, with the literals they bind, in order.
fn exclusion_terms(
    relation: &str,
    exclusions: &[synch_verified::host::Exclusion],
) -> Result<(Vec<String>, Vec<Cell>)> {
    let mut terms = Vec::new();
    let mut bindings = Vec::new();
    for exclusion in exclusions {
        columns_for(&exclusion.relation)?;
        let mut guards = exclusion
            .equals
            .iter()
            .map(|(name, _)| {
                column(&exclusion.relation, name).map(|name| format!("\"guard\".{name} IS ?"))
            })
            .collect::<Result<Vec<_>>>()?;
        for (base, excluded) in &exclusion.keys {
            guards.push(format!(
                "\"target\".{} = \"guard\".{}",
                column(relation, base)?,
                column(&exclusion.relation, excluded)?
            ));
        }
        let predicate = if guards.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", guards.join(" AND "))
        };
        terms.push(format!(
            "NOT EXISTS (SELECT 1 FROM \"{}\" AS \"guard\"{predicate})",
            exclusion.relation
        ));
        bindings.extend(exclusion.equals.iter().map(|(_, cell)| cell.clone()));
    }
    Ok((terms, bindings))
}

/// Build only whitelisted identifiers; every literal remains a bound cell.
/// WHERE 1 also disambiguates SQLite's INSERT SELECT ... ON CONFLICT grammar.
fn selection_sql(selection: &Selection) -> Result<(String, Vec<Cell>)> {
    columns_for(&selection.relation)?;
    let mut terms = Vec::new();
    let mut bindings = Vec::new();
    for (name, value) in &selection.equals {
        terms.push(format!("{} IS ?", column(&selection.relation, name)?));
        bindings.push(value.clone());
    }
    if !selection.like_any.is_empty() {
        let mut alternatives = Vec::new();
        for (name, pattern) in &selection.like_any {
            alternatives.push(format!("{} LIKE ?", column(&selection.relation, name)?));
            bindings.push(Cell::Text(pattern.clone()));
        }
        terms.push(format!("({})", alternatives.join(" OR ")));
    }
    for (name, value) in &selection.not_equals {
        terms.push(format!("{} IS NOT ?", column(&selection.relation, name)?));
        bindings.push(value.clone());
    }
    Ok((
        format!(
            " WHERE {}",
            if terms.is_empty() {
                "1".to_owned()
            } else {
                terms.join(" AND ")
            }
        ),
        bindings,
    ))
}

fn raw_scan(
    conn: &Connection,
    sql: &str,
    bindings: &[Cell],
    width: usize,
) -> Result<Scan<StoreError>> {
    let mut statement = conn.prepare(sql)?;
    let rows = statement.query_map(params_from_iter(bindings.iter().map(BoundCell)), |row| {
        (0..width)
            .map(|index| {
                Ok(match row.get_ref(index)? {
                    ValueRef::Null => Cell::Null,
                    ValueRef::Integer(value) => Cell::Integer(value),
                    ValueRef::Text(value) => match std::str::from_utf8(value) {
                        Ok(text) => Cell::Text(text.to_owned()),
                        Err(_) => Cell::RawText(value.to_vec()),
                    },
                    ValueRef::Blob(value) => Cell::Blob(value.to_vec()),
                    ValueRef::Real(value) => Cell::Real(value.to_bits()),
                })
            })
            .collect::<rusqlite::Result<Row>>()
    })?;
    let mut scan = Scan {
        rows: Vec::new(),
        failure: None,
    };
    for row in rows {
        match row {
            Ok(row) => scan.rows.push(row),
            Err(error) => {
                scan.failure = Some(error.into());
                break;
            }
        }
    }
    Ok(scan)
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
        order: &[synch_verified::host::Order],
        joins: &[synch_verified::host::Join],
    ) -> Result<Vec<Row>> {
        let scan = self.scan_rows(tx, relation, columns, equals, order, joins)?;
        match scan.failure {
            Some(error) => Err(error),
            None => Ok(scan.rows),
        }
    }

    fn scan_rows(
        &mut self,
        tx: u64,
        relation: &str,
        columns: &[String],
        equals: &Fields,
        order: &[synch_verified::host::Order],
        joins: &[synch_verified::host::Join],
    ) -> Result<synch_verified::host::Scan<StoreError>> {
        self.require_live_transaction(tx)?;
        columns_for(relation)?;
        if columns.is_empty() {
            return Err(StoreError::invalid("empty storage projection"));
        }
        let mut source = format!("\"{relation}\"");
        for (index, join) in joins.iter().enumerate() {
            columns_for(&join.relation)?;
            if join.relation == relation
                || joins[..index]
                    .iter()
                    .any(|prior| prior.relation == join.relation)
                || join.keys.is_empty()
            {
                return Err(StoreError::invalid("duplicate or unkeyed storage join"));
            }
            let keys = join
                .keys
                .iter()
                .map(|(left, right)| {
                    Ok(format!(
                        "\"{relation}\".{} = \"{}\".{}",
                        column(relation, left)?,
                        join.relation,
                        column(&join.relation, right)?
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            source.push_str(&format!(
                " JOIN \"{}\" ON {}",
                join.relation,
                keys.join(" AND ")
            ));
        }
        let projected = columns
            .iter()
            .map(|name| read_column(relation, joins, name))
            .collect::<Result<Vec<_>>>()?;
        let mut sql = format!("SELECT {} FROM {source}", projected.join(", "));
        if !equals.is_empty() {
            let terms = equals
                .iter()
                .map(|(name, _)| {
                    read_column(relation, joins, name).map(|column| format!("{column} IS ?"))
                })
                .collect::<Result<Vec<_>>>()?;
            sql.push_str(&format!(" WHERE {}", terms.join(" AND ")));
        }
        if !order.is_empty() {
            let terms = order
                .iter()
                .map(|term| {
                    read_column(relation, joins, &term.column).map(|column| {
                        format!("{column} {}", if term.descending { "DESC" } else { "ASC" })
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            sql.push_str(" ORDER BY ");
            sql.push_str(&terms.join(", "));
        }
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values(equals)), |row| {
            columns
                .iter()
                .enumerate()
                .map(|(index, _)| match row.get_ref(index)? {
                    rusqlite::types::ValueRef::Null => Ok(Cell::Null),
                    rusqlite::types::ValueRef::Integer(value) => Ok(Cell::Integer(value)),
                    rusqlite::types::ValueRef::Text(value) => {
                        Ok(match std::str::from_utf8(value) {
                            Ok(text) => Cell::Text(text.to_owned()),
                            Err(_) => Cell::RawText(value.to_vec()),
                        })
                    }
                    rusqlite::types::ValueRef::Blob(value) => Ok(Cell::Blob(value.to_vec())),
                    rusqlite::types::ValueRef::Real(value) => Ok(Cell::Real(value.to_bits())),
                })
                .collect::<rusqlite::Result<Row>>()
        })?;
        let mut scan = synch_verified::host::Scan {
            rows: Vec::new(),
            failure: None,
        };
        for row in rows {
            match row {
                Ok(row) => scan.rows.push(row),
                Err(error) => {
                    scan.failure = Some(error.into());
                    break;
                }
            }
        }
        Ok(scan)
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

    fn delete_rows(
        &mut self,
        tx: u64,
        relation: &str,
        equals: &Fields,
        unless: &[synch_verified::host::Exclusion],
        at_most: &Fields,
    ) -> Result<u64> {
        self.require_live_transaction(tx)?;
        columns_for(relation)?;
        // Explicit aliases keep correlations unambiguous even when the excluded
        // relation is the table being deleted. Identifiers still pass the same
        // schema capability checks; only values become SQL parameters.
        let mut terms = equals
            .iter()
            .map(|(name, _)| column(relation, name).map(|name| format!("\"target\".{name} IS ?")))
            .collect::<Result<Vec<_>>>()?;
        terms.extend(
            at_most
                .iter()
                .map(|(name, _)| {
                    column(relation, name).map(|name| format!("\"target\".{name} <= ?"))
                })
                .collect::<Result<Vec<_>>>()?,
        );
        let mut bindings = values(equals);
        bindings.extend(values(at_most));
        let (excluded, guards) = exclusion_terms(relation, unless)?;
        terms.extend(excluded);
        bindings.extend(guards.iter().map(BoundCell));
        let predicate = if terms.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", terms.join(" AND "))
        };
        let sql = format!("DELETE FROM \"{relation}\" AS \"target\"{predicate}");
        Ok(self.conn.execute(&sql, params_from_iter(bindings))? as u64)
    }

    fn delete_except(
        &mut self,
        tx: u64,
        relation: &str,
        column: &str,
        keys: &[&[u8]],
    ) -> Result<u64> {
        self.require_live_transaction(tx)?;
        let column = self::column(relation, column)?;
        // The kept set goes through a temporary table rather than an
        // `IN (?, ?, …)` list: it is the size of the live trie, far past
        // SQLite's parameter limit, and one statement sweeps the rest.
        self.conn.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS lean_kept (key BLOB PRIMARY KEY);
             DELETE FROM lean_kept;",
        )?;
        {
            let mut insert = self
                .conn
                .prepare("INSERT OR IGNORE INTO lean_kept (key) VALUES (?1)")?;
            for key in keys {
                insert.execute(rusqlite::params![*key])?;
            }
        }
        let sql =
            format!("DELETE FROM \"{relation}\" WHERE {column} NOT IN (SELECT key FROM lean_kept)");
        let swept = self.conn.execute(&sql, [])?;
        self.conn.execute_batch("DELETE FROM lean_kept;")?;
        Ok(swept as u64)
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

    fn snapshot(&mut self, selection: &Selection, columns: &[String]) -> Result<Scan<StoreError>> {
        self.snapshot_excluding(selection, columns, &[])
    }

    fn snapshot_excluding(
        &mut self,
        selection: &Selection,
        columns: &[String],
        excluding: &[synch_verified::host::Exclusion],
    ) -> Result<Scan<StoreError>> {
        if self.active.is_some() || !self.conn.is_autocommit() {
            return Err(StoreError::invalid("snapshot during storage transaction"));
        }
        if columns.is_empty() {
            return Err(StoreError::invalid("empty storage projection"));
        }
        // The same alias a delete's blockers correlate against, so the
        // exclusion rendering is shared with `delete_rows`.
        let (mut predicate, mut bindings) = selection_sql(selection)?;
        let (excluded, guards) = exclusion_terms(&selection.relation, excluding)?;
        for term in excluded {
            predicate.push_str(" AND ");
            predicate.push_str(&term);
        }
        bindings.extend(guards);
        let sql = format!(
            "SELECT {} FROM \"{}\" AS \"target\"{predicate}",
            projection(&selection.relation, columns)?,
            selection.relation
        );
        raw_scan(&self.conn, &sql, &bindings, columns.len())
    }

    fn update(&mut self, tx: u64, selection: &Selection, fields: &Fields) -> Result<u64> {
        self.require_live_transaction(tx)?;
        if fields.is_empty() {
            return Err(StoreError::invalid("empty storage write"));
        }
        let mut assignments = Vec::new();
        let mut bindings = Vec::new();
        for (index, (name, value)) in fields.iter().enumerate() {
            if fields[..index].iter().any(|(prior, _)| prior == name) {
                return Err(StoreError::invalid("duplicate storage write column"));
            }
            assignments.push(format!("{} = ?", column(&selection.relation, name)?));
            bindings.push(value.clone());
        }
        let (predicate, selected) = selection_sql(selection)?;
        bindings.extend(selected);
        let sql = format!(
            "UPDATE \"{}\" SET {}{predicate}",
            selection.relation,
            assignments.join(", ")
        );
        Ok(self
            .conn
            .execute(&sql, params_from_iter(bindings.iter().map(BoundCell)))? as u64)
    }

    fn copy_rows(
        &mut self,
        tx: u64,
        target: &str,
        source: &Selection,
        fields: &[(String, SourceValue)],
        conflicts: &[String],
    ) -> Result<u64> {
        self.require_live_transaction(tx)?;
        columns_for(target)?;
        if fields.is_empty() {
            return Err(StoreError::invalid("empty storage write"));
        }
        let mut names = Vec::new();
        let mut projected = Vec::new();
        let mut bindings = Vec::new();
        for (name, value) in fields {
            if names.contains(name) {
                return Err(StoreError::invalid("duplicate storage write column"));
            }
            names.push(name.clone());
            projected.push(match value {
                SourceValue::Column(name) => column(&source.relation, name)?,
                SourceValue::Literal(value) => {
                    bindings.push(value.clone());
                    "?".to_owned()
                }
            });
        }
        if conflicts.iter().any(|name| !names.contains(name)) {
            return Err(StoreError::invalid("UPSERT names a column without a value"));
        }
        let (predicate, selected) = selection_sql(source)?;
        bindings.extend(selected);
        let conflict = if conflicts.is_empty() {
            String::new()
        } else {
            format!(" ({})", projection(target, conflicts)?)
        };
        let sql = format!("INSERT INTO \"{target}\" ({}) SELECT {} FROM \"{}\"{predicate} ON CONFLICT{conflict} DO NOTHING",
            projection(target, &names)?, projected.join(", "), source.relation);
        Ok(self
            .conn
            .execute(&sql, params_from_iter(bindings.iter().map(BoundCell)))? as u64)
    }

    fn delete(&mut self, tx: u64, selection: &Selection) -> Result<u64> {
        self.require_live_transaction(tx)?;
        let (predicate, bindings) = selection_sql(selection)?;
        let sql = format!("DELETE FROM \"{}\"{predicate}", selection.relation);
        Ok(self
            .conn
            .execute(&sql, params_from_iter(bindings.iter().map(BoundCell)))? as u64)
    }

    fn write(
        &mut self,
        tx: u64,
        relation: &str,
        fields: &Fields,
        conflicts: &[String],
        assignments: &[(String, ConflictValue)],
    ) -> Result<()> {
        self.require_live_transaction(tx)?;
        columns_for(relation)?;
        if fields.is_empty() {
            return Err(StoreError::invalid("empty expression UPSERT"));
        }
        let names: Vec<_> = fields.iter().map(|(name, _)| name.clone()).collect();
        unique_columns(relation, &names)?;
        unique_columns(relation, conflicts)?;
        unique_columns(
            relation,
            &assignments
                .iter()
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>(),
        )?;
        let conflict = if conflicts.is_empty() {
            String::new()
        } else {
            format!(" ({})", projection(relation, conflicts)?)
        };
        let mut remaining = 4096;
        let updates = assignments
            .iter()
            .map(|(name, value)| {
                Ok(format!(
                    "{} = {}",
                    column(relation, name)?,
                    conflict_expression(relation, value, 0, &mut remaining)?
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let update = if updates.is_empty() {
            "DO NOTHING".to_owned()
        } else {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use synch_verified::host::{Exclusion, Join, Order};

    fn selected(relation: &str) -> Selection {
        Selection {
            relation: relation.into(),
            equals: vec![],
            like_any: vec![],
            not_equals: vec![],
        }
    }

    #[test]
    fn access_like_alternatives_are_grouped_with_equalities_and_keep_sqlite_case_rules() {
        let conn = connection();
        conn.execute_batch(
            "INSERT INTO pins VALUES
            (X'01', 'SOURCE:a', 1, NULL), (X'01', 'replica:b', 2, NULL),
            (X'01', 'operator:c', 3, NULL), (X'02', 'replica:d', 4, NULL)",
        )
        .unwrap();
        let selection = Selection {
            relation: "pins".into(),
            equals: vec![("root".into(), Cell::Blob(vec![1]))],
            like_any: vec![
                ("holder".into(), "source:%".into()),
                ("holder".into(), "replica:%".into()),
            ],
            not_equals: vec![],
        };
        let mut storage = SqliteStorage::new(&conn);
        assert_eq!(
            storage
                .snapshot(&selection, &names(&["holder"]))
                .unwrap()
                .rows
                .len(),
            2
        );
        let tx = storage.begin().unwrap();
        assert_eq!(
            storage
                .update(
                    tx,
                    &selection,
                    &vec![("release_after".into(), Cell::Integer(9))]
                )
                .unwrap(),
            2
        );
        assert_eq!(storage.delete(tx, &selection).unwrap(), 2);
        storage.commit(tx).unwrap();
        assert_eq!(
            storage
                .snapshot(&selected("pins"), &names(&["holder"]))
                .unwrap()
                .rows
                .len(),
            2
        );
    }

    fn copy_fields() -> Vec<(String, SourceValue)> {
        vec![
            ("root".into(), SourceValue::Column("root".into())),
            ("holder".into(), SourceValue::Column("holder".into())),
            ("size".into(), SourceValue::Literal(Cell::Integer(-7))),
            ("prev".into(), SourceValue::Literal(Cell::Null)),
            (
                "first_wanted".into(),
                SourceValue::Literal(Cell::Integer(11)),
            ),
        ]
    }

    #[test]
    fn access_copy_conflict_preserves_existing_fields_and_empty_selection_is_valid() {
        let conn = connection();
        conn.execute_batch("INSERT INTO pins VALUES (X'01', 'a', 0, NULL), (X'02', 'b', 0, NULL);
            INSERT INTO content_want(root, holder, size, prev, first_wanted) VALUES (X'01', 'a', 99, X'03', 4)").unwrap();
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        assert_eq!(
            storage
                .copy_rows(
                    tx,
                    "content_want",
                    &selected("pins"),
                    &copy_fields(),
                    &names(&["root", "holder"])
                )
                .unwrap(),
            1
        );
        let none = Selection {
            relation: "pins".into(),
            equals: vec![],
            like_any: vec![("holder".into(), "absent:%".into())],
            not_equals: vec![],
        };
        assert_eq!(
            storage
                .copy_rows(
                    tx,
                    "content_want",
                    &none,
                    &copy_fields(),
                    &names(&["root", "holder"])
                )
                .unwrap(),
            0
        );
        storage.commit(tx).unwrap();
        let existing = conn
            .query_row(
                "SELECT size, prev, first_wanted FROM content_want WHERE root = X'01'",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(existing, (99, vec![3], 4));
        assert_eq!(
            conn.query_row(
                "SELECT size FROM content_want WHERE root = X'02'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            -7
        );
    }

    #[test]
    fn access_copy_failure_is_one_atomic_statement() {
        let conn = connection();
        conn.execute_batch(
            "INSERT INTO pins VALUES (X'01', 'a', 0, NULL), (X'02', 'b', 0, NULL);
            CREATE TRIGGER fail_copy BEFORE INSERT ON content_want WHEN NEW.root = X'02'
            BEGIN SELECT RAISE(ABORT, 'copy failed'); END",
        )
        .unwrap();
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        assert!(storage
            .copy_rows(
                tx,
                "content_want",
                &selected("pins"),
                &copy_fields(),
                &names(&["root", "holder"])
            )
            .is_err());
        assert!(!storage.exists_rows(tx, "content_want", &vec![]).unwrap());
        storage.rollback(tx).unwrap();
    }

    #[test]
    fn access_rejects_untrusted_identifiers_and_duplicate_assignments() {
        let conn = connection();
        let mut storage = SqliteStorage::new(&conn);
        assert!(storage
            .snapshot(&selected("pins; DELETE FROM pins"), &names(&["root"]))
            .is_err());
        let invalid = Selection {
            relation: "pins".into(),
            equals: vec![],
            like_any: vec![("holder OR 1".into(), "%".into())],
            not_equals: vec![],
        };
        assert!(storage.snapshot(&invalid, &names(&["root"])).is_err());
        let tx = storage.begin().unwrap();
        assert!(storage
            .update(
                tx,
                &selected("pins"),
                &vec![("holder".into(), Cell::Null), ("holder".into(), Cell::Null)]
            )
            .is_err());
        assert!(storage
            .copy_rows(
                tx,
                "content_want",
                &selected("pins"),
                &[("root".into(), SourceValue::Column("root; --".into()))],
                &[]
            )
            .is_err());
        assert!(storage.delete(tx, &invalid).is_err());
        storage.rollback(tx).unwrap();
    }

    #[test]
    fn access_snapshot_keeps_rows_before_step_failure() {
        let conn = connection();
        conn.execute_batch(
            "CREATE TEMP TABLE scan_source(id INTEGER PRIMARY KEY);
            INSERT INTO scan_source VALUES (1), (2);
            CREATE TEMP VIEW blobs AS SELECT id AS root,
            CASE WHEN id = 2 THEN abs(-9223372036854775808) ELSE 1 END AS durable FROM scan_source",
        )
        .unwrap();
        let mut storage = SqliteStorage::new(&conn);
        let scan = storage
            .snapshot(&selected("blobs"), &names(&["root", "durable"]))
            .unwrap();
        assert_eq!(scan.rows, [vec![Cell::Integer(1), Cell::Integer(1)]]);
        assert!(matches!(scan.failure, Some(StoreError::Sqlite(_))));
        assert!(conn.is_autocommit());
    }

    #[test]
    fn session_releases_snapshot_commit_rollback_and_drop_leases() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::Store::open(dir.path()).unwrap();
        let mut session = Session::new(&store);
        assert!(session
            .snapshot(&selected("blobs"), &names(&["root"]))
            .unwrap()
            .rows
            .is_empty());
        assert!(store.conn().is_autocommit());
        let first = session.begin().unwrap();
        assert!(session
            .snapshot(&selected("blobs"), &names(&["root"]))
            .is_err());
        session.commit(first).unwrap();
        assert!(store.conn().is_autocommit());
        let second = session.begin().unwrap();
        assert_ne!(first, second);
        assert!(session.commit(first).is_err());
        session.rollback(second).unwrap();
        assert!(store.conn().is_autocommit());
        let _ = session.begin().unwrap();
        drop(session);
        assert!(store.conn().is_autocommit());
    }

    #[test]
    fn session_failed_commit_retains_rollback_capability() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::Store::open(dir.path()).unwrap();
        store.conn().execute_batch(
            "CREATE TABLE test_parent (id INTEGER PRIMARY KEY);
             CREATE TABLE test_child (parent INTEGER REFERENCES test_parent(id) DEFERRABLE INITIALLY DEFERRED);
             CREATE TRIGGER fail_session_pin AFTER INSERT ON pins
               BEGIN INSERT INTO test_child VALUES (1); END;",
        ).unwrap();
        let mut session = Session::new(&store);
        let tx = session.begin().unwrap();
        session
            .upsert(
                tx,
                "pins",
                &vec![
                    ("root".into(), Cell::Blob(vec![1; 32])),
                    ("holder".into(), Cell::Text("test".into())),
                    ("created_at".into(), Cell::Integer(0)),
                    ("release_after".into(), Cell::Null),
                ],
                &names(&["root", "holder"]),
                &[],
            )
            .unwrap();
        assert!(session.commit(tx).is_err());
        assert!(session
            .snapshot(&selected("pins"), &names(&["root"]))
            .is_err());
        session.rollback(tx).unwrap();
        assert!(store.conn().is_autocommit());
        assert!(session
            .snapshot(&selected("pins"), &names(&["root"]))
            .unwrap()
            .rows
            .is_empty());
    }

    #[test]
    fn raw_scan_retains_prefix_before_sqlite_step_failure() {
        let conn = connection();
        conn.execute_batch(
            "CREATE TEMP TABLE scan_source (id INTEGER PRIMARY KEY);
            INSERT INTO scan_source VALUES (1), (2);
            CREATE TEMP VIEW blobs AS SELECT id AS root,
              CASE WHEN id = 2 THEN abs(-9223372036854775808) ELSE 1 END AS durable
              FROM scan_source;",
        )
        .unwrap();
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        let scan = storage
            .scan_rows(tx, "blobs", &names(&["root", "durable"]), &vec![], &[], &[])
            .unwrap();
        assert_eq!(scan.rows, [vec![Cell::Integer(1), Cell::Integer(1)]]);
        assert!(matches!(scan.failure, Some(StoreError::Sqlite(_))));
        storage.rollback(tx).unwrap();
    }

    #[test]
    fn raw_text_and_real_values_keep_their_storage_classes() {
        let conn = connection();
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        let raw = vec![255, 0, 254];
        storage
            .upsert(
                tx,
                "blobs",
                &vec![
                    ("root".into(), Cell::Blob(vec![1])),
                    ("inline".into(), Cell::RawText(raw.clone())),
                    ("durable".into(), Cell::Real(1.5f64.to_bits())),
                ],
                &names(&["root"]),
                &[],
            )
            .unwrap();
        assert_eq!(
            storage
                .read_rows(
                    tx,
                    "blobs",
                    &names(&["inline", "durable"]),
                    &vec![("inline".into(), Cell::RawText(raw.clone()))],
                    &[],
                    &[]
                )
                .unwrap(),
            vec![vec![Cell::RawText(raw), Cell::Real(1.5f64.to_bits())]]
        );
        assert_eq!(
            conn.query_row(
                "SELECT typeof(inline), typeof(durable) FROM blobs",
                [],
                |row| { Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)) }
            )
            .unwrap(),
            ("text".into(), "real".into())
        );
        storage.rollback(tx).unwrap();
    }

    #[test]
    fn raw_inner_join_skips_orphans_before_decoding_and_preserves_projection_order() {
        let conn = connection();
        conn.execute_batch("CREATE TABLE heads (origin_id TEXT, slot TEXT, seq INTEGER, root BLOB, received_at, verified_at);
            CREATE TABLE head_history (origin_id TEXT, seq INTEGER, root BLOB, created_at, signed_by BLOB, sig BLOB, recorded_at INTEGER);
            INSERT INTO heads VALUES ('origin', 'complete', 1, X'01', CAST(X'FF' AS TEXT), 2);
            INSERT INTO head_history VALUES ('origin', 1, X'02', 3, X'', X'', 4);").unwrap();
        let joins = [Join {
            relation: "head_history".into(),
            keys: vec![
                ("origin_id".into(), "origin_id".into()),
                ("seq".into(), "seq".into()),
                ("root".into(), "root".into()),
            ],
        }];
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        let equals = vec![
            ("origin_id".into(), Cell::Text("origin".into())),
            ("slot".into(), Cell::Text("complete".into())),
        ];
        let projection = names(&["received_at", "head_history.created_at", "seq"]);
        assert!(storage
            .read_rows(tx, "heads", &projection, &equals, &[], &joins)
            .unwrap()
            .is_empty());
        conn.execute_batch("UPDATE head_history SET root = X'01'")
            .unwrap();
        assert_eq!(
            storage
                .read_rows(tx, "heads", &projection, &equals, &[], &joins)
                .unwrap(),
            vec![vec![
                Cell::RawText(vec![255]),
                Cell::Integer(3),
                Cell::Integer(1)
            ]]
        );
        conn.execute_batch("UPDATE heads SET received_at = 7")
            .unwrap();
        assert_eq!(
            storage
                .read_rows(tx, "heads", &projection, &equals, &[], &joins)
                .unwrap(),
            vec![vec![Cell::Integer(7), Cell::Integer(3), Cell::Integer(1)]]
        );
        // Inner equality joins never match two SQL NULLs.
        conn.execute_batch("UPDATE heads SET seq = NULL; UPDATE head_history SET seq = NULL")
            .unwrap();
        assert!(storage
            .read_rows(tx, "heads", &projection, &equals, &[], &joins)
            .unwrap()
            .is_empty());
        storage.rollback(tx).unwrap();
    }

    #[test]
    fn joins_reject_unbound_columns_duplicate_relations_and_unkeyed_sources() {
        let conn = connection();
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        let good = Join {
            relation: "pins".into(),
            keys: vec![("root".into(), "root".into())],
        };
        for joins in [
            vec![Join {
                relation: "pins; --".into(),
                keys: good.keys.clone(),
            }],
            vec![Join {
                relation: "pins".into(),
                keys: vec![],
            }],
            vec![Join {
                relation: "blobs".into(),
                keys: good.keys.clone(),
            }],
            vec![good.clone(), good.clone()],
            vec![Join {
                relation: "pins".into(),
                keys: vec![("root".into(), "missing".into())],
            }],
        ] {
            assert!(storage
                .read_rows(tx, "blobs", &names(&["root"]), &vec![], &[], &joins)
                .is_err());
        }
        assert!(storage
            .read_rows(
                tx,
                "blobs",
                &names(&["content_want.root"]),
                &vec![],
                &[],
                &[good]
            )
            .is_err());
        storage.rollback(tx).unwrap();
    }

    #[test]
    fn ordered_reads_use_signed_storage_values_and_explicit_tiebreakers() {
        let conn = connection();
        for (root, size) in [(1u8, i64::MIN), (2, -1), (3, 0), (4, i64::MAX), (5, 0)] {
            conn.execute(
                "INSERT INTO blobs (root, size) VALUES (?1, ?2)",
                rusqlite::params![vec![root], size],
            )
            .unwrap();
        }
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        let order = [
            Order {
                column: "size".into(),
                descending: true,
            },
            Order {
                column: "root".into(),
                descending: true,
            },
        ];
        assert_eq!(
            storage
                .read_rows(tx, "blobs", &names(&["root"]), &vec![], &order, &[])
                .unwrap(),
            [4, 5, 3, 2, 1].map(|n| vec![Cell::Blob(vec![n])]).to_vec()
        );
        assert!(storage
            .read_rows(
                tx,
                "blobs",
                &names(&["root"]),
                &vec![],
                &[Order {
                    column: "size; DROP TABLE blobs".into(),
                    descending: false
                }],
                &[]
            )
            .is_err());
        storage.rollback(tx).unwrap();
    }

    #[test]
    fn exclusions_recheck_trigger_changed_rows_at_each_mutation() {
        let conn = connection();
        conn.execute_batch(
            "INSERT INTO blobs (root) VALUES (X'01'), (X'02');
            CREATE TRIGGER protect_next AFTER DELETE ON blobs WHEN OLD.root = X'02'
            BEGIN INSERT INTO pins (root, holder) VALUES (X'01', 'trigger'); END;",
        )
        .unwrap();
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        // Both rows are candidates at selection time.
        assert!(!storage.exists_rows(tx, "pins", &vec![]).unwrap());
        for (root, expected) in [(2, 1), (1, 0)] {
            let equals = vec![("root".into(), Cell::Blob(vec![root]))];
            let guards = [Exclusion {
                relation: "pins".into(),
                equals: equals.clone(),
                keys: vec![],
            }];
            assert_eq!(
                storage
                    .delete_rows(tx, "blobs", &equals, &guards, &vec![])
                    .unwrap(),
                expected
            );
        }
        storage.commit(tx).unwrap();
        assert_eq!(
            conn.query_row("SELECT root FROM blobs", [], |row| row.get::<_, Vec<u8>>(0))
                .unwrap(),
            vec![1]
        );
    }

    #[test]
    fn exclusions_bind_each_predicate_and_reject_unknown_identifiers() {
        let conn = connection();
        conn.execute_batch(
            "INSERT INTO blobs (root) VALUES (X'01');
            INSERT INTO pins (root, holder) VALUES (X'02', 'pin');",
        )
        .unwrap();
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        let guards = [
            Exclusion {
                relation: "content_want".into(),
                equals: vec![],
                keys: vec![],
            },
            Exclusion {
                relation: "pins".into(),
                equals: vec![("root".into(), Cell::Blob(vec![2]))],
                keys: vec![],
            },
        ];
        assert_eq!(
            storage
                .delete_rows(tx, "blobs", &vec![], &guards, &vec![])
                .unwrap(),
            0
        );
        assert!(storage
            .delete_rows(
                tx,
                "blobs",
                &vec![],
                &[Exclusion {
                    relation: "pins; --".into(),
                    equals: vec![],
                    keys: vec![],
                }],
                &vec![],
            )
            .is_err());
        assert!(storage
            .delete_rows(
                tx,
                "blobs",
                &vec![],
                &[Exclusion {
                    relation: "pins".into(),
                    equals: vec![("unknown".into(), Cell::Null)],
                    keys: vec![],
                }],
                &vec![],
            )
            .is_err());
        let absent = [Exclusion {
            relation: "pins".into(),
            equals: vec![("root".into(), Cell::Blob(vec![3]))],
            keys: vec![],
        }];
        assert_eq!(
            storage
                .delete_rows(tx, "blobs", &vec![], &absent, &vec![])
                .unwrap(),
            1
        );
        storage.rollback(tx).unwrap();
    }

    #[test]
    fn bounded_deletion_preserves_raw_sqlite_comparisons() {
        let conn = connection();
        conn.execute_batch(
            "INSERT INTO pins (root, holder, release_after) VALUES
            (X'01', 'h', -9223372036854775808), (X'02', 'h', -1),
            (X'03', 'h', 0), (X'04', 'h', 9223372036854775807),
            (X'05', 'h', NULL), (X'06', 'h', -0.5), (X'07', 'h', 'bad');",
        )
        .unwrap();
        let mut storage = SqliteStorage::new(&conn);
        for (bound, expected) in [
            (Cell::Null, 0),
            (Cell::Integer(i64::MIN), 1),
            (Cell::Integer(-1), 2),
            (Cell::Integer(0), 4),
            (Cell::Real((-0.5f64).to_bits()), 3),
            (Cell::Integer(i64::MAX), 5),
            (Cell::Text("bad".into()), 6),
        ] {
            let tx = storage.begin().unwrap();
            assert_eq!(
                storage
                    .delete_rows(
                        tx,
                        "pins",
                        &vec![],
                        &[],
                        &vec![("release_after".into(), bound)]
                    )
                    .unwrap(),
                expected
            );
            storage.rollback(tx).unwrap();
        }
    }

    #[test]
    fn correlated_exclusions_protect_only_matching_rows_and_space() {
        let conn = connection();
        conn.execute_batch(
            "INSERT INTO pins (root, holder, release_after) VALUES
            (X'01', 'a', -1), (X'02', 'a', -1), (X'03', 'a', 1),
            (X'04', 'b', -1), (NULL, 'a', -1);
            INSERT INTO entries VALUES (X'01', 7), (X'02', 8), (NULL, 7);",
        )
        .unwrap();
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        let guards = [Exclusion {
            relation: "entries".into(),
            equals: vec![("space".into(), Cell::Integer(7))],
            keys: vec![("root".into(), "content".into())],
        }];
        assert_eq!(
            storage
                .delete_rows(
                    tx,
                    "pins",
                    &vec![("holder".into(), Cell::Text("a".into()))],
                    &guards,
                    &vec![("release_after".into(), Cell::Integer(0))]
                )
                .unwrap(),
            2
        );
        assert_eq!(
            storage
                .read_rows(
                    tx,
                    "pins",
                    &names(&["root"]),
                    &vec![],
                    &[Order {
                        column: "root".into(),
                        descending: false
                    }],
                    &[]
                )
                .unwrap(),
            [1, 3, 4].map(|n| vec![Cell::Blob(vec![n])]).to_vec()
        );
        storage.rollback(tx).unwrap();
    }

    #[test]
    fn self_correlations_use_distinct_qualified_aliases() {
        let conn = connection();
        conn.execute_batch(
            "INSERT INTO pins (root, holder) VALUES
            (X'01', 'a'), (X'01', 'b'), (X'02', 'a');",
        )
        .unwrap();
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        assert_eq!(
            storage
                .delete_rows(
                    tx,
                    "pins",
                    &vec![("holder".into(), Cell::Text("a".into()))],
                    &[Exclusion {
                        relation: "pins".into(),
                        equals: vec![("holder".into(), Cell::Text("b".into()))],
                        keys: vec![("root".into(), "root".into())]
                    }],
                    &vec![]
                )
                .unwrap(),
            1
        );
        assert_eq!(
            storage
                .read_rows(tx, "pins", &names(&["root"]), &vec![], &[], &[])
                .unwrap(),
            vec![vec![Cell::Blob(vec![1])], vec![Cell::Blob(vec![1])]]
        );
        storage.rollback(tx).unwrap();
    }

    #[test]
    fn invalid_bound_and_correlation_identifiers_cannot_mutate() {
        let conn = connection();
        conn.execute_batch("INSERT INTO pins (root, holder) VALUES (X'01', 'a');")
            .unwrap();
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        for invalid in [
            "missing",
            "root; DELETE FROM pins",
            "pins.root",
            "root\" OR 1=1 --",
        ] {
            assert!(storage
                .delete_rows(
                    tx,
                    "pins",
                    &vec![],
                    &[],
                    &vec![(invalid.into(), Cell::Integer(0))]
                )
                .is_err());
            for keys in [
                vec![(invalid.into(), "content".into())],
                vec![("root".into(), invalid.into())],
            ] {
                assert!(storage
                    .delete_rows(
                        tx,
                        "pins",
                        &vec![],
                        &[Exclusion {
                            relation: "entries".into(),
                            equals: vec![],
                            keys
                        }],
                        &vec![]
                    )
                    .is_err());
            }
        }
        assert!(storage.exists_rows(tx, "pins", &vec![]).unwrap());
        storage.rollback(tx).unwrap();
    }

    #[test]
    fn bounded_correlated_delete_failure_is_atomic_and_rollbackable() {
        let conn = connection();
        conn.execute_batch(
            "INSERT INTO pins (root, holder, release_after) VALUES
             (X'01', 'a', -1), (X'02', 'a', -1);
             CREATE TRIGGER fail_delete BEFORE DELETE ON pins WHEN OLD.root = X'02'
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        assert!(storage
            .delete_rows(
                tx,
                "pins",
                &vec![],
                &[Exclusion {
                    relation: "entries".into(),
                    equals: vec![],
                    keys: vec![("root".into(), "content".into())]
                }],
                &vec![("release_after".into(), Cell::Integer(0))]
            )
            .is_err());
        assert_eq!(
            storage
                .read_rows(tx, "pins", &names(&["root"]), &vec![], &[], &[])
                .unwrap()
                .len(),
            2
        );
        storage.rollback(tx).unwrap();
        assert!(conn.is_autocommit());
    }

    fn connection() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE pins (root BLOB, holder TEXT, created_at INTEGER,
               release_after INTEGER, PRIMARY KEY(root, holder));
             CREATE TABLE entries (content BLOB, space INTEGER);
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

    #[test]
    fn expression_upsert_preserves_raw_coalesce_and_max_semantics() {
        let conn = connection();
        conn.execute_batch("INSERT INTO blobs VALUES(X'01', 9, 0, NULL, X'', 0, -7)")
            .unwrap();
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        let assignments = vec![
            (
                "inline".into(),
                ConflictValue::Coalesce(Box::new((
                    ConflictValue::Excluded("inline".into()),
                    ConflictValue::Current("inline".into()),
                ))),
            ),
            (
                "durable".into(),
                ConflictValue::Maximum(Box::new((
                    ConflictValue::Current("durable".into()),
                    ConflictValue::Excluded("durable".into()),
                ))),
            ),
        ];
        for (incoming, expected) in [
            (Cell::Integer(-9), Cell::Integer(-7)),
            (Cell::Integer(3), Cell::Integer(3)),
            (Cell::Real(3.5_f64.to_bits()), Cell::Real(3.5_f64.to_bits())),
            (Cell::RawText(vec![255]), Cell::RawText(vec![255])),
            (Cell::Blob(vec![0]), Cell::Blob(vec![0])),
            (Cell::Null, Cell::Null),
        ] {
            storage
                .write(
                    tx,
                    "blobs",
                    &vec![
                        ("root".into(), Cell::Blob(vec![1])),
                        ("inline".into(), Cell::Null),
                        ("durable".into(), incoming),
                    ],
                    &names(&["root"]),
                    &assignments,
                )
                .unwrap();
            let rows = storage
                .read_rows(
                    tx,
                    "blobs",
                    &names(&["inline", "durable"]),
                    &vec![],
                    &[],
                    &[],
                )
                .unwrap();
            assert_eq!(rows, vec![vec![Cell::Blob(vec![]), expected]]);
        }
        storage.rollback(tx).unwrap();
    }

    #[test]
    fn expression_upsert_validates_names_duplicates_and_depth_before_mutation() {
        let conn = connection();
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        let fields = vec![("root".into(), Cell::Blob(vec![1]))];
        let current = ConflictValue::Current("size".into());
        let mut deep = current.clone();
        for _ in 0..34 {
            deep = ConflictValue::Coalesce(Box::new((deep, current.clone())));
        }
        for assignments in [
            vec![("size".into(), ConflictValue::Excluded("bad".into()))],
            vec![("bad".into(), current.clone())],
            vec![
                ("size".into(), current.clone()),
                ("size".into(), current.clone()),
            ],
            vec![("size".into(), deep)],
        ] {
            assert!(storage
                .write(tx, "blobs", &fields, &names(&["root"]), &assignments)
                .is_err());
        }
        assert!(storage
            .write(
                tx,
                "blobs",
                &vec![fields[0].clone(), fields[0].clone()],
                &[],
                &[]
            )
            .is_err());
        assert!(storage
            .write(tx, "blobs", &fields, &names(&["root", "root"]), &[])
            .is_err());
        assert!(storage.write(tx, "bad", &fields, &[], &[]).is_err());
        assert_eq!(
            conn.query_row("SELECT count(*) FROM blobs", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        storage.rollback(tx).unwrap();
    }

    #[test]
    fn expression_upsert_failure_is_atomic_and_drop_rolls_back() {
        let conn = connection();
        conn.execute_batch("INSERT INTO blobs VALUES(X'01', 9, 0, NULL, NULL, 0, 0);
            CREATE TRIGGER reject_update BEFORE UPDATE ON blobs BEGIN SELECT RAISE(ABORT, 'rejected'); END;").unwrap();
        {
            let mut storage = SqliteStorage::new(&conn);
            let tx = storage.begin().unwrap();
            let fields = vec![
                ("root".into(), Cell::Blob(vec![1])),
                ("size".into(), Cell::Integer(10)),
            ];
            assert!(storage
                .write(
                    tx,
                    "blobs",
                    &fields,
                    &names(&["root"]),
                    &[("size".into(), ConflictValue::Excluded("size".into()))]
                )
                .is_err());
            assert_eq!(
                conn.query_row("SELECT size FROM blobs", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                9
            );
            storage
                .write(
                    tx,
                    "blobs",
                    &vec![("root".into(), Cell::Blob(vec![2]))],
                    &names(&["root"]),
                    &[],
                )
                .unwrap();
        }
        assert!(conn.is_autocommit());
        assert_eq!(
            conn.query_row("SELECT count(*) FROM blobs", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn expression_upsert_session_abandonment_rolls_back() {
        let (_dir, store) = crate::testutil::store();
        {
            let mut session = Session::new(&store);
            let tx = session.begin().unwrap();
            session
                .write(
                    tx,
                    "trie_values",
                    &vec![
                        ("hash".into(), Cell::Blob(vec![1; 32])),
                        ("data".into(), Cell::Blob(vec![7])),
                    ],
                    &names(&["hash"]),
                    &[],
                )
                .unwrap();
        }
        assert_eq!(
            store
                .conn()
                .query_row("SELECT count(*) FROM trie_values", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
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
                    &vec![],
                    &[],
                    &[]
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
                    &vec![("bitmap".into(), Cell::Null)],
                    &[],
                    &[]
                )
                .unwrap(),
            vec![vec![Cell::Blob(vec![1])]]
        );
        assert!(storage
            .read_rows(
                tx,
                "blobs",
                &names(&["root"]),
                &vec![("root".into(), Cell::Blob(vec![2]))],
                &[],
                &[]
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
                    &vec![],
                    &[],
                    &[]
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
        assert!(storage
            .delete_rows(first + 1, "pins", &vec![], &[], &vec![])
            .is_err());
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
            assert_eq!(
                storage
                    .delete_rows(tx, "content_want", &vec![], &[], &vec![])
                    .unwrap(),
                1
            );
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
    fn unsupported_identifiers_fail_and_real_cells_remain_raw() {
        let conn = connection();
        conn.execute_batch("INSERT INTO blobs (root, durable) VALUES (X'01', 1.5)")
            .unwrap();
        let mut storage = SqliteStorage::new(&conn);
        let tx = storage.begin().unwrap();
        assert!(storage
            .read_rows(
                tx,
                "blobs; DROP TABLE pins",
                &names(&["root"]),
                &vec![],
                &[],
                &[]
            )
            .is_err());
        assert!(storage
            .read_rows(
                tx,
                "blobs",
                &names(&["root FROM blobs; --"]),
                &vec![],
                &[],
                &[]
            )
            .is_err());
        assert_eq!(
            storage
                .read_rows(tx, "blobs", &names(&["durable"]), &vec![], &[], &[])
                .unwrap(),
            vec![vec![Cell::Real(1.5f64.to_bits())]]
        );
        assert!(storage
            .read_rows(tx, "blobs", &[], &vec![], &[], &[])
            .is_err());
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
        assert!(storage
            .delete_rows(tx, "pins", &vec![], &[], &vec![])
            .is_err());
        assert!(storage
            .read_rows(tx, "pins", &names(&["root"]), &vec![], &[], &[])
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
