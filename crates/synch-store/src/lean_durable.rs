//! Durability transitions executed by the Lean domain program over raw
//! storage, clock and resource services. Rust binds the services and names
//! the diagnostics; which rows change, and in what order, is Lean's.

use synch_core::Hash;
use synch_verified::{cas, host};

use crate::{lean_diagnostics, Result, Store, StoreError};

struct Clock;
impl host::Clock for Clock {
    type Error = StoreError;
    fn now_ns(&mut self) -> Result<i64> {
        Ok(synch_core::now_ns())
    }
}

fn error(root: Option<&Hash>, error: cas::DurableError<StoreError>) -> StoreError {
    use cas::{DurableDomainError as Domain, DurableError, OperationError};
    match error {
        DurableError::Operation(OperationError::Host(error)) => error,
        DurableError::Operation(OperationError::MalformedMetadata(_))
        | DurableError::Domain(Domain::Malformed) => {
            StoreError::Decode("invalid CAS durability metadata".into())
        }
        DurableError::Operation(OperationError::Protocol) => {
            StoreError::invalid("invalid native durability-operation protocol")
        }
        DurableError::Domain(Domain::ColumnType {
            index,
            column,
            actual,
        }) => lean_diagnostics::column_type(index, column, actual),
        DurableError::Domain(Domain::SizeMismatch {
            recorded, offered, ..
        }) => {
            let root = root.map(ToString::to_string).unwrap_or_default();
            StoreError::invalid(format!(
                "size mismatch for {root}: have {recorded}, offered {offered}"
            ))
        }
    }
}

pub(crate) fn mark_durable(store: &Store, root: &Hash) -> Result<bool> {
    let mut storage = crate::lean_storage::Session::new(store);
    cas::mark_durable(&mut storage, root.as_bytes()).map_err(|failure| error(Some(root), failure))
}

pub(crate) fn adopt_durable(store: &Store, root: &Hash, size: u64, now: i64) -> Result<()> {
    let mut storage = crate::lean_storage::Session::new(store);
    cas::adopt_durable(&mut storage, root.as_bytes(), size, now)
        .map_err(|failure| error(Some(root), failure))
}

pub(crate) fn heal_missing(store: &Store, root: &Hash) -> Result<bool> {
    let mut storage = crate::lean_storage::Session::new(store);
    cas::heal_missing(&mut storage, &mut Clock, root.as_bytes())
        .map_err(|failure| error(Some(root), failure))
}

pub(crate) fn reconcile_scratch(store: &Store, marker: &str) -> Result<bool> {
    let mut storage = crate::lean_storage::Session::new(store);
    cas::reconcile_scratch(&mut storage, marker).map_err(|failure| error(None, failure))
}

/// The caller holds the CAS ordering guard, so the writer count Lean reads
/// first cannot change before the rows and files it then clears.
pub(crate) fn clear_cache(store: &Store, conn: &rusqlite::Connection, root: &Hash) -> Result<bool> {
    let mut storage = crate::lean_storage::SqliteStorage::new(conn);
    let mut resources = crate::lean_storage::Resources(store);
    cas::clear_cache(&mut storage, &mut resources, root.as_bytes())
        .map_err(|failure| error(Some(root), failure))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{testutil::store, PinHolder};
    use rusqlite::params;

    #[test]
    fn marking_never_creates_a_row_and_adoption_refuses_a_disagreeing_size() {
        let (_dir, store) = store();
        let root = Hash::new(b"absent");
        assert!(!store.mark_blob_durable(&root).unwrap());
        assert!(store.blob(&root).unwrap().is_none());

        store.adopt_durable_blob(&root, 10, 5).unwrap();
        let row = store.blob(&root).unwrap().unwrap();
        assert!(row.durable && !row.complete && row.bitmap.is_none() && row.inline.is_none());
        assert_eq!((row.size, row.last_access), (10, 5));

        let failure = store.adopt_durable_blob(&root, 11, 6).unwrap_err();
        assert_eq!(
            failure.to_string(),
            format!("size mismatch for {root}: have 10, offered 11")
        );
        assert!(store.conn().is_autocommit());
        let row = store.blob(&root).unwrap().unwrap();
        assert_eq!((row.size, row.last_access), (10, 5));
        store.adopt_durable_blob(&root, 10, 7).unwrap();
        assert_eq!(store.blob(&root).unwrap().unwrap().last_access, 5);
    }

    #[test]
    fn healing_withdraws_once_and_moves_only_machine_roles_to_wants() {
        let (_dir, store) = store();
        let payload = crate::testutil::data(100_000);
        let root = store.ingest_bytes(&payload, 1).unwrap();
        let source = PinHolder::Source("media".into());
        let replica = PinHolder::Replica("media".into());
        for holder in [&source, &replica, &PinHolder::Operator] {
            assert!(store.pin(&root, holder, 2).unwrap());
        }
        store
            .conn()
            .execute(
                "INSERT INTO content_want (root, holder, size, prev, first_wanted) VALUES (?1, ?2, 999, NULL, -7)",
                params![root.as_bytes().as_slice(), source.render()],
            )
            .unwrap();
        assert!(store.heal_missing_durable_blob(&root).unwrap());
        let row = store.blob(&root).unwrap().unwrap();
        assert!(row.complete && !row.durable);
        let pins = store.pins_for(&root).unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].holder, PinHolder::Operator);
        let wants: Vec<(String, i64, i64)> = store
            .conn()
            .prepare("SELECT holder, size, first_wanted FROM content_want WHERE root = ?1 ORDER BY holder")
            .unwrap()
            .query_map([root.as_bytes().as_slice()], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(wants.len(), 2);
        assert_eq!(wants[0].0, replica.render());
        assert_eq!(wants[0].1, payload.len() as i64);
        assert!(wants[0].2 > 0);
        assert_eq!(wants[1], (source.render(), 999, -7));

        // Already withdrawn: nothing to heal, and the operator's pin stands.
        assert!(!store.heal_missing_durable_blob(&root).unwrap());
        assert_eq!(store.pins_for(&root).unwrap().len(), 1);
        assert!(!store
            .heal_missing_durable_blob(&Hash::new(b"absent"))
            .unwrap());
    }

    #[test]
    fn a_scratch_generation_change_drops_staged_rows_and_clears_durable_groups() {
        let (_dir, store) = store();
        // A cloud backend: local ingestion stages rows, marking makes claims.
        store.set_remote_cas(true);
        let staged = store
            .ingest_bytes(&crate::testutil::data(100_000), 1)
            .unwrap();
        let durable = store
            .ingest_bytes(&crate::testutil::data(70_000), 2)
            .unwrap();
        let inline = store.ingest_bytes(b"inline", 3).unwrap();
        assert!(store.mark_blob_durable(&durable).unwrap());
        assert!(store.reconcile_scratch_generation("one").unwrap());
        assert!(store.blob(&staged).unwrap().is_none());
        let cold = store.blob(&durable).unwrap().unwrap();
        assert!(cold.durable && !cold.complete && cold.bitmap.is_none());
        assert!(store.blob(&inline).unwrap().unwrap().complete);
        assert!(!store.reconcile_scratch_generation("one").unwrap());
        assert!(store.reconcile_scratch_generation("two").unwrap());
        assert!(store.blob(&inline).unwrap().unwrap().complete);
        store
            .conn()
            .execute(
                "UPDATE config SET value = x'ff' WHERE key = 'cas.cloud.scratch_generation'",
                [],
            )
            .unwrap();
        assert!(matches!(
            store.reconcile_scratch_generation("two"),
            Err(StoreError::Sqlite(rusqlite::Error::InvalidColumnType(0, column, _)))
                if column == "value"
        ));
    }

    #[test]
    fn clearing_the_cache_keeps_the_claim_and_drops_a_staged_row() {
        let (_dir, store) = store();
        store.set_remote_cas(true);
        let payload = crate::testutil::data(100_000);
        let durable = store.ingest_bytes(&payload, 0).unwrap();
        assert!(store.mark_blob_durable(&durable).unwrap());
        assert!(store.clear_blob_cache(&durable).unwrap());
        let row = store.blob(&durable).unwrap().unwrap();
        assert!(row.durable && !row.complete && row.bitmap.is_none());
        assert!(!store.blob_path(&durable).exists());
        assert!(!store.outboard_path(&durable).exists());
        // The files are already gone; clearing again is not an error.
        assert!(store.clear_blob_cache(&durable).unwrap());

        let staged = store
            .ingest_bytes(&crate::testutil::data(90_000), 0)
            .unwrap();
        assert!(store.clear_blob_cache(&staged).unwrap());
        assert!(store.blob(&staged).unwrap().is_none());
        assert!(!store.blob_path(&staged).exists());
        let inline = store.ingest_bytes(b"inline", 0).unwrap();
        assert!(store.clear_blob_cache(&inline).unwrap());
        assert!(store.blob(&inline).unwrap().unwrap().complete);
    }
}
