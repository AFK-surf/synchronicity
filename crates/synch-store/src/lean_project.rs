//! The projections of the content store through the Lean domain program:
//! one row, every row, the narrow summary, the claims and the pinned roots.
//! Lean owns the statements, the row validation the read path applies, the
//! pin state read as one join, the ordering and the holder spelling; this
//! module binds the storage session, converts to the store's public types
//! and names the diagnostics.

use synch_core::Hash;
use synch_verified::cas;

use crate::{
    cas::{BlobRow, BlobSummary, PinHolder, PinRow},
    lean_diagnostics, Result, Store, StoreError,
};

fn error(error: cas::ProjectError<StoreError>) -> StoreError {
    use cas::{OperationError, ProjectDomainError as Domain, ProjectError};
    match error {
        ProjectError::Operation(OperationError::Host(error)) => error,
        ProjectError::Operation(OperationError::MalformedMetadata(_))
        | ProjectError::Domain(Domain::Malformed) => {
            StoreError::Decode("invalid local blob metadata".into())
        }
        ProjectError::Operation(OperationError::Protocol) => {
            StoreError::invalid("invalid native projection protocol")
        }
        ProjectError::Domain(Domain::ColumnType {
            index,
            column,
            actual,
        }) => lean_diagnostics::column_type(index, column, actual),
        ProjectError::Domain(Domain::Column { column, reason }) => match column.as_str() {
            "blobs.root" => StoreError::column("blobs.root", reason),
            "pins.root" => StoreError::column("pins.root", reason),
            "pins.holder" => StoreError::column("pins.holder", reason),
            _ => StoreError::invalid("unknown native projection error column"),
        },
    }
}

fn root_of(bytes: &[u8], column: &'static str) -> Result<Hash> {
    Hash::from_slice(bytes).map_err(|error| StoreError::column(column, error.to_string()))
}

fn row_of(blob: cas::ProjectedBlob) -> Result<BlobRow> {
    Ok(BlobRow {
        root: root_of(&blob.root, "blobs.root")?,
        size: blob.size,
        complete: blob.complete,
        durable: blob.durable,
        bitmap: blob.bitmap,
        inline: blob.inline,
        pinned: blob.pinned,
        last_access: blob.last_access,
        verified_groups: synch_core::ChunkRanges {
            ranges: blob
                .verified_groups
                .into_iter()
                .map(|(start, end)| synch_core::GroupRange::new(start, end))
                .collect(),
        },
        advertised_spans: blob.advertised_spans,
    })
}

fn summary_of(summary: cas::ProjectedSummary) -> Result<BlobSummary> {
    Ok(BlobSummary {
        root: root_of(&summary.root, "blobs.root")?,
        size: summary.size,
        complete: summary.complete,
        durable: summary.durable,
        pinned: summary.pinned,
        last_access: summary.last_access,
    })
}

fn pin_of(pin: cas::ProjectedPin) -> Result<PinRow> {
    Ok(PinRow {
        root: root_of(&pin.root, "pins.root")?,
        holder: match pin.holder {
            cas::PinHolder::Operator => PinHolder::Operator,
            cas::PinHolder::Source(space) => PinHolder::Source(space),
            cas::PinHolder::Replica(space) => PinHolder::Replica(space),
            cas::PinHolder::Other(text) => PinHolder::Other(text),
        },
        created_at: pin.created_at,
        release_after: pin.release_after,
    })
}

pub(crate) fn blob(store: &Store, root: &Hash) -> Result<Option<BlobRow>> {
    let mut storage = crate::lean_storage::Session::new(store);
    cas::blob(&mut storage, root.as_bytes())
        .map_err(error)?
        .map(row_of)
        .transpose()
}

pub(crate) fn blob_in(conn: &rusqlite::Connection, root: &Hash) -> Result<Option<BlobRow>> {
    let (mut storage, transaction) = crate::lean_storage::SqliteStorage::borrow_transaction(conn)?;
    cas::blob_in(&mut storage, transaction, root.as_bytes())
        .map_err(error)?
        .map(row_of)
        .transpose()
}

pub(crate) fn blobs(store: &Store) -> Result<Vec<BlobRow>> {
    let mut storage = crate::lean_storage::Session::new(store);
    cas::blobs(&mut storage)
        .map_err(error)?
        .into_iter()
        .map(row_of)
        .collect()
}

pub(crate) fn blob_candidates(store: &Store) -> Result<Vec<BlobSummary>> {
    let mut storage = crate::lean_storage::Session::new(store);
    cas::blob_candidates(&mut storage)
        .map_err(error)?
        .into_iter()
        .map(summary_of)
        .collect()
}

pub(crate) fn pins(store: &Store, root: Option<&Hash>) -> Result<Vec<PinRow>> {
    let mut storage = crate::lean_storage::Session::new(store);
    cas::pins(&mut storage, root.map(Hash::as_bytes))
        .map_err(error)?
        .into_iter()
        .map(pin_of)
        .collect()
}

pub(crate) fn pinned_blobs(store: &Store) -> Result<Vec<Hash>> {
    let mut storage = crate::lean_storage::Session::new(store);
    cas::pinned_blobs(&mut storage)
        .map_err(error)?
        .iter()
        .map(|root| root_of(root, "pins.root"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{data, store};
    use rusqlite::params;

    #[test]
    fn native_advertisements_never_round_out_into_missing_content() {
        let (_dir, store) = store();
        let root = Hash::new(b"projected availability");
        let g = synch_core::AD_SPAN_GRANULARITY;
        let chunk = synch_core::CHUNK_GROUP_SIZE;
        let cases = [
            (
                10 * g,
                vec![(0, 1), (5 * g / chunk, 5 * g / chunk + 1)],
                vec![],
            ),
            (
                10 * g,
                vec![(g / chunk - 1, 3 * g / chunk + 1)],
                vec![(g, 3 * g)],
            ),
            (
                10 * g,
                vec![(0, 2 * g / chunk), (2 * g / chunk, 4 * g / chunk)],
                vec![(0, 4 * g)],
            ),
            (g / 2, vec![(0, 4 * g / chunk)], vec![(0, g / 2)]),
            (g / 2, vec![(0, 1)], vec![]),
            (10 * 1024 * 1024, vec![(0, 8 * 1024 * 1024 / chunk)], vec![]),
            (
                u64::MAX,
                vec![(0, synch_core::group_count(u64::MAX))],
                vec![(0, u64::MAX)],
            ),
        ];
        for (size, groups, expected) in cases {
            let bitmap = postcard::to_stdvec(&groups).unwrap();
            store.conn().execute(
                "INSERT OR REPLACE INTO blobs (root,size,complete,bitmap,inline,last_access,durable) VALUES (?1,?2,0,?3,NULL,0,0)",
                params![root.as_bytes().as_slice(), size as i64, bitmap],
            ).unwrap();
            let row = store.blob(&root).unwrap().unwrap();
            assert_eq!(
                row.to_ad().state.spans,
                expected,
                "size={size}, groups={groups:?}"
            );
        }
        let runs: Vec<(u64, u64)> = (0..1100)
            .map(|i| (2 * i * g / chunk, (2 * i + 1) * g / chunk))
            .collect();
        store
            .conn()
            .execute(
                "UPDATE blobs SET bitmap=?1",
                params![postcard::to_stdvec(&runs).unwrap()],
            )
            .unwrap();
        let ad = store.blob(&root).unwrap().unwrap().to_ad();
        assert_eq!(ad.state.spans.len(), synch_core::record::MAX_AD_SPANS);
        assert_eq!(ad.state.spans.last(), Some(&(2046 * g, 2047 * g)));
        let decoded: synch_core::BlobAd =
            postcard::from_bytes(&postcard::to_stdvec(&ad).unwrap()).unwrap();
        assert_eq!(decoded, ad);
        store
            .conn()
            .execute("UPDATE blobs SET bitmap=X'FF', durable=1", [])
            .unwrap();
        let row = store.blob(&root).unwrap().unwrap();
        assert!(row.verified_groups().is_empty());
        assert_eq!(row.to_ad().state.spans, vec![(0, u64::MAX)]);
    }

    #[test]
    fn native_transaction_projection_neither_commits_nor_aborts_publication() {
        use synch_verified::host::Storage;
        let (_dir, store) = store();
        let root = store.ingest_bytes(b"existing", 1).unwrap();
        let result: Result<()> = store.transaction(|txn| {
            txn.conn().execute(
                "UPDATE blobs SET durable=0, last_access=77 WHERE root=?1",
                params![root.as_bytes().as_slice()],
            )?;
            let row = txn.blob(&root)?.unwrap();
            assert_eq!(row.last_access, 77);
            assert!(!row.durable);
            assert_eq!(row.verified_groups(), synch_core::ChunkRanges::single(0, 1));
            assert_eq!(row.to_ad(), synch_core::BlobAd::complete(8));
            let (mut borrowed, token) =
                crate::lean_storage::SqliteStorage::borrow_transaction(txn.conn())?;
            assert!(borrowed.commit(token).is_err());
            assert!(borrowed.rollback(token).is_err());
            drop(borrowed);
            assert!(!txn.conn().is_autocommit());
            Err(StoreError::invalid("abort outer publication"))
        });
        assert!(result.is_err());
        let row = store.blob(&root).unwrap().unwrap();
        assert_eq!(row.last_access, 1);
        assert!(row.durable);
    }
    #[test]
    fn rows_are_listed_most_recent_first_with_their_pin_state() {
        let (_dir, store) = store();
        let cold = store.ingest_bytes(&data(100_000), 1).unwrap();
        let warm = store.ingest_bytes(&data(90_000), 2).unwrap();
        let inline = store.ingest_bytes(b"inline", 3).unwrap();
        assert!(store.pin(&warm, &PinHolder::Operator, 4).unwrap());
        assert!(store
            .pin(&warm, &PinHolder::Source("media".into()), 5)
            .unwrap());

        let rows = store.blobs().unwrap();
        assert_eq!(
            rows.iter().map(|row| row.root).collect::<Vec<_>>(),
            vec![inline, warm, cold]
        );
        assert_eq!(
            rows.iter().map(|row| row.pinned).collect::<Vec<_>>(),
            vec![false, true, false]
        );
        assert_eq!(rows[0].inline.as_deref(), Some(&b"inline"[..]));
        assert!(rows[1].complete && rows[1].bitmap.is_none());
        let candidates = store.blob_candidates().unwrap();
        assert_eq!(
            candidates
                .iter()
                .map(|row| (row.root, row.pinned, row.last_access))
                .collect::<Vec<_>>(),
            vec![(inline, false, 3), (warm, true, 2), (cold, false, 1)]
        );
        let one = store.blob(&warm).unwrap().unwrap();
        assert!(one.pinned && one.size == 90_000);
        assert!(store.blob(&Hash::new(b"absent")).unwrap().is_none());
        assert_eq!(store.pinned_blobs().unwrap(), vec![warm]);
    }

    #[test]
    fn claims_are_listed_by_object_then_holder_and_unknown_spellings_are_kept() {
        let (_dir, store) = store();
        let first = store.ingest_bytes(&data(100_000), 1).unwrap();
        let second = store.ingest_bytes(&data(90_000), 2).unwrap();
        let (low, high) = if first < second {
            (first, second)
        } else {
            (second, first)
        };
        assert!(store.pin(&high, &PinHolder::Operator, 4).unwrap());
        assert!(store
            .pin(&low, &PinHolder::Replica("media".into()), 5)
            .unwrap());
        store
            .conn()
            .execute(
                "INSERT INTO pins (root, holder, created_at, release_after) VALUES (?1, 'future:x', 6, 7)",
                params![low.as_bytes().as_slice()],
            )
            .unwrap();
        let pins = store.pins().unwrap();
        assert_eq!(
            pins.iter()
                .map(|pin| (
                    pin.root,
                    pin.holder.clone(),
                    pin.created_at,
                    pin.release_after
                ))
                .collect::<Vec<_>>(),
            vec![
                (low, PinHolder::Other("future:x".into()), 6, Some(7)),
                (low, PinHolder::Replica("media".into()), 5, None),
                (high, PinHolder::Operator, 4, None),
            ]
        );
        assert_eq!(store.pins_for(&high).unwrap().len(), 1);
        assert_eq!(store.pinned_blobs().unwrap(), vec![low, high]);
    }

    #[test]
    fn a_malformed_row_is_reported_by_its_column() {
        let (_dir, store) = store();
        let root = store.ingest_bytes(&data(100_000), 1).unwrap();
        store
            .conn()
            .execute(
                "UPDATE blobs SET size = 'nine' WHERE root = ?1",
                params![root.as_bytes().as_slice()],
            )
            .unwrap();
        assert!(matches!(
            store.blob(&root),
            Err(StoreError::Sqlite(rusqlite::Error::InvalidColumnType(1, column, _)))
                if column == "size"
        ));
        assert!(matches!(
            store.blobs(),
            Err(StoreError::Sqlite(rusqlite::Error::InvalidColumnType(1, column, _)))
                if column == "size"
        ));
    }
}
