//! Keeping the content store within bounds through the Lean domain program:
//! the access clock, eviction by least recent use, the collection of objects
//! nothing references, and the removal of object files no row accounts for.
//! Rust binds the services and names the diagnostics; which rows and files
//! go, in what order, and under which guard is Lean's.

use synch_core::Hash;
use synch_verified::cas;

use crate::{
    lean_diagnostics,
    lean_resources::Leases,
    lean_storage::{Resources, Session},
    lean_sweep::Sweeper,
    Result, Store, StoreError,
};

fn error(error: cas::CollectError<StoreError>) -> StoreError {
    use cas::{CollectDomainError as Domain, CollectError, OperationError};
    match error {
        CollectError::Operation(OperationError::Host(error)) => error,
        CollectError::Operation(OperationError::MalformedMetadata(_))
        | CollectError::Domain(Domain::Malformed) => {
            StoreError::Decode("invalid CAS retention metadata".into())
        }
        CollectError::Operation(OperationError::Protocol) => {
            StoreError::invalid("invalid native retention-operation protocol")
        }
        CollectError::Domain(Domain::ColumnType {
            index,
            column,
            actual,
        }) => lean_diagnostics::column_type(index, column, actual),
        CollectError::Domain(Domain::SizeMismatch {
            root,
            recorded,
            offered,
        }) => {
            let root = Hash::from_slice(&root)
                .map(|root| root.to_string())
                .unwrap_or_default();
            StoreError::invalid(format!(
                "size mismatch for {root}: have {recorded}, offered {offered}"
            ))
        }
    }
}

/// One sweep's services: the storage session and the lease service share
/// the connection the remover's critical section holds.
fn sweep<T>(
    store: &Store,
    run: impl FnOnce(
        &mut Session<'_>,
        cas::CollectResources<'_, StoreError>,
    ) -> std::result::Result<T, cas::CollectError<StoreError>>,
) -> Result<T> {
    let mut storage = Session::new(store);
    let mut resources = Resources(store);
    let mut clock = crate::lean_durable::Clock;
    let mut leases = Leases::ordered(store, storage.section());
    let mut sweeper = Sweeper::new(store);
    run(
        &mut storage,
        cas::CollectResources {
            resources: &mut resources,
            clock: &mut clock,
            leases: &mut leases,
            sweep: &mut sweeper,
        },
    )
    .map_err(error)
}

pub(crate) fn touch(store: &Store, root: &Hash) -> Result<bool> {
    sweep(store, |storage, resources| {
        cas::touch(storage, resources, root.as_bytes())
    })
}

pub(crate) fn evict(store: &Store, limit: Option<u64>, shortfall: u64) -> Result<(usize, u64)> {
    let evicted = sweep(store, |storage, resources| {
        cas::evict(storage, resources, limit, shortfall)
    })?;
    Ok((
        usize::try_from(evicted.entries).unwrap_or(usize::MAX),
        evicted.freed,
    ))
}

pub(crate) fn gc_content(store: &Store, before: i64) -> Result<usize> {
    let swept = sweep(store, |storage, resources| {
        cas::gc_content(storage, resources, before)
    })?;
    Ok(usize::try_from(swept).unwrap_or(usize::MAX))
}

pub(crate) fn gc_orphans(store: &Store, before: i64) -> Result<usize> {
    let swept = sweep(store, |storage, resources| {
        cas::gc_orphans(storage, resources, before)
    })?;
    Ok(usize::try_from(swept).unwrap_or(usize::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{data, store};
    use crate::PinHolder;

    #[test]
    fn touching_moves_the_clock_at_most_once_a_minute_and_never_backwards() {
        let (_dir, store) = store();
        let root = store.ingest_bytes(&data(100_000), 0).unwrap();
        // The clock reads far past the row's stamp, so the first touch moves
        // it; the second, within a minute of the first, is coalesced.
        assert!(store.touch_blob(&root).unwrap());
        let moved = store.blob(&root).unwrap().unwrap().last_access;
        assert!(moved > 0);
        assert!(!store.touch_blob(&root).unwrap());
        assert_eq!(store.blob(&root).unwrap().unwrap().last_access, moved);
        // A row stamped in the future stays where it is.
        let future = store.ingest_bytes(&data(90_000), i64::MAX / 2).unwrap();
        assert!(!store.touch_blob(&future).unwrap());
        assert_eq!(
            store.blob(&future).unwrap().unwrap().last_access,
            i64::MAX / 2
        );
        assert!(!store.touch_blob(&Hash::new(b"absent")).unwrap());
    }

    #[test]
    fn eviction_clears_the_least_recently_used_cached_durable_rows_first() {
        let (_dir, store) = store();
        store.set_remote_cas(true);
        let cold = store.ingest_bytes(&data(100_000), 1).unwrap();
        let warm = store.ingest_bytes(&data(110_000), 2).unwrap();
        let staged = store.ingest_bytes(&data(120_000), 0).unwrap();
        let inline = store.ingest_bytes(b"inline", 0).unwrap();
        for root in [&cold, &warm] {
            assert!(store.mark_blob_durable(root).unwrap());
        }
        assert!(store.pin(&cold, &PinHolder::Operator, 3).unwrap());
        let cold_bytes = crate::lean_sweep::file_bytes(&store.blob_path(&cold))
            + crate::lean_sweep::file_bytes(&store.outboard_path(&cold));

        // Nothing to do when there is neither a limit nor a shortfall.
        assert_eq!(store.evict_durable_cache(None, 0).unwrap(), (0, 0));
        assert!(store.blob_path(&cold).exists());

        // A shortfall of one byte takes exactly the coldest entry, pinned or
        // not, and leaves its durable claim; the staged and inline rows are
        // never candidates.
        let (evicted, freed) = store.evict_durable_cache(None, 1).unwrap();
        assert_eq!((evicted, freed), (1, cold_bytes));
        let row = store.blob(&cold).unwrap().unwrap();
        assert!(row.durable && !row.complete && !store.blob_path(&cold).exists());
        assert!(store.blob(&warm).unwrap().unwrap().complete);
        assert!(store.blob_path(&staged).exists());
        assert!(store.blob(&inline).unwrap().unwrap().complete);

        // A limit of zero takes the rest of the cache.
        let (evicted, freed) = store.evict_durable_cache(Some(0), 0).unwrap();
        assert_eq!(evicted, 1);
        assert!(freed > 0);
        assert!(!store.blob_path(&warm).exists());
        assert_eq!(store.evict_durable_cache(Some(0), 0).unwrap(), (0, 0));
    }

    #[test]
    fn eviction_skips_an_object_a_writer_holds() {
        let (_dir, store) = store();
        store.set_remote_cas(true);
        let held = store.ingest_bytes(&data(100_000), 1).unwrap();
        assert!(store.mark_blob_durable(&held).unwrap());
        let lease = store.lease_write(&held);
        assert_eq!(store.evict_durable_cache(Some(0), 0).unwrap(), (0, 0));
        assert!(store.blob_path(&held).exists());
        drop(lease);
        assert_eq!(store.evict_durable_cache(Some(0), 0).unwrap().0, 1);
    }

    #[test]
    fn collection_decides_each_candidate_again_inside_its_own_section() {
        let (_dir, store) = store();
        let referenced = store.ingest_bytes(&data(100_000), 0).unwrap();
        let pinned = store.ingest_bytes(&data(90_000), 0).unwrap();
        let held = store.ingest_bytes(&data(80_000), 0).unwrap();
        let fresh = store.ingest_bytes(&data(70_000), 5).unwrap();
        let cold = store.ingest_bytes(&data(60_000), 0).unwrap();
        store
            .put_entry(
                &crate::testutil::origin(),
                "s",
                "a",
                &synch_core::FileEntry::file(100_000, 0, referenced, 1),
            )
            .unwrap();
        assert!(store.pin(&pinned, &PinHolder::Operator, 1).unwrap());
        let lease = store.lease_write(&held);

        assert_eq!(crate::lean_collect::gc_content(&store, 3).unwrap(), 1);
        assert!(store.blob(&cold).unwrap().is_none());
        assert!(!store.blob_path(&cold).exists());
        for root in [&referenced, &pinned, &held, &fresh] {
            assert!(store.blob(root).unwrap().is_some());
            assert!(store.blob_path(root).exists());
        }
        drop(lease);
        assert_eq!(crate::lean_collect::gc_content(&store, 3).unwrap(), 1);
        assert!(store.blob(&held).unwrap().is_none());
        assert!(store.conn().is_autocommit());
        assert_eq!(store.writer_count(&held), 0);
    }

    #[test]
    fn orphan_files_go_only_when_stale_unaccounted_and_unheld() {
        let (_dir, store) = store();
        let live = store.ingest_bytes(&data(100_000), 0).unwrap();
        let stale = Hash::new(b"a fetch that never verified");
        let written = Hash::new(b"a fetch still being written");
        for root in [&stale, &written] {
            let path = store.blob_path(root);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"leftovers").unwrap();
            std::fs::write(store.outboard_path(root), b"leftovers").unwrap();
        }
        let stranger = store.cas_dir().join("ab").join("README");
        std::fs::create_dir_all(stranger.parent().unwrap()).unwrap();
        std::fs::write(&stranger, b"not ours").unwrap();

        // Inside the horizon nothing goes; past it, only the files of an
        // object no row accounts for and no writer holds.
        assert_eq!(crate::lean_collect::gc_orphans(&store, 0).unwrap(), 0);
        let lease = store.lease_write(&written);
        let horizon = synch_core::now_ns() + 60 * 1_000_000_000;
        assert_eq!(crate::lean_collect::gc_orphans(&store, horizon).unwrap(), 2);
        assert!(!store.blob_path(&stale).exists() && !store.outboard_path(&stale).exists());
        assert!(store.blob_path(&written).exists() && store.outboard_path(&written).exists());
        assert!(store.blob_path(&live).exists());
        assert!(stranger.exists());
        drop(lease);
        assert_eq!(crate::lean_collect::gc_orphans(&store, horizon).unwrap(), 2);
        assert!(!store.blob_path(&written).exists());
        // The section was released with the sweep.
        assert!(store.conn().is_autocommit());
        let _still_free = store.cas_order();
    }
}
