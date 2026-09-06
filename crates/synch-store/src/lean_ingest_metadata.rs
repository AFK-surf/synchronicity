//! Whole native ingestion regressions for the existing metadata contract.
use crate::{lean_ingest, lean_resources::Input, Store, StoreError};
use rusqlite::{params, types::Value};
use synch_core::Hash;

fn data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

fn root(bytes: &[u8]) -> Hash {
    Hash::from_slice(blake3::hash(bytes).as_bytes()).unwrap()
}

fn insert_claim(
    store: &Store,
    root: &Hash,
    size: i64,
    complete: i64,
    durable: Value,
    bitmap: Option<Vec<u8>>,
) {
    store
        .conn()
        .execute(
            "INSERT INTO blobs(root,size,complete,durable,bitmap,inline,last_access)
         VALUES(?1,?2,?3,?4,?5,NULL,7)",
            params![root.as_bytes().as_slice(), size, complete, durable, bitmap],
        )
        .unwrap();
}

fn raw_claim(store: &Store, root: &Hash) -> Vec<String> {
    store
        .conn()
        .query_row(
            "SELECT size,complete,durable,bitmap,inline,last_access FROM blobs WHERE root=?1",
            params![root.as_bytes().as_slice()],
            |row| {
                (0..6)
                    .map(|index| row.get_ref(index).map(|value| format!("{value:?}")))
                    .collect()
            },
        )
        .unwrap()
}

fn assert_released(store: &Store, root: &Hash) {
    assert!(store.conn().is_autocommit());
    assert!(!store.is_being_written(root));
    assert!(store.active_temporaries().is_empty());
    assert_eq!(
        std::fs::read_dir(store.staging_dir())
            .map(|entries| entries.count())
            .unwrap_or(0),
        0
    );
}

#[test]
fn native_attested_conflicting_sizes_preserve_original_metadata_and_published_files() {
    for (complete, durable, bitmap) in [
        (1, 0, None),
        (0, 1, None),
        (0, 2, None),
        // Recorded size has three groups; holding its last group attests it.
        (
            0,
            0,
            Some(postcard::to_stdvec(&vec![(2_u64, 3_u64)]).unwrap()),
        ),
    ] {
        let (_dir, store) = crate::testutil::store();
        let bytes = data(32769);
        let root = root(&bytes);
        insert_claim(
            &store,
            &root,
            32770,
            complete,
            Value::Integer(durable),
            bitmap,
        );
        let before = raw_claim(&store, &root);
        let error = lean_ingest::ingest(&store, Input::Bytes(&bytes), 99).unwrap_err();
        assert!(
            matches!(error, StoreError::Verification { root: actual, ref reason }
            if actual == root && reason == "size mismatch: have 32770, offered 32769")
        );
        assert_eq!(raw_claim(&store, &root), before);
        assert_released(&store, &root);
        // Physical publication precedes metadata settlement. Cleanup does not
        // erase final names, even when settlement refuses the incoming size.
        assert_eq!(std::fs::read(store.blob_path(&root)).unwrap(), bytes);
        assert!(store.outboard_path(&root).exists());
    }
}

#[test]
fn native_unattested_size_replacement_completes_and_discards_old_bitmap() {
    for bitmap in [
        None,
        Some(postcard::to_stdvec(&vec![(0_u64, 1_u64)]).unwrap()),
        Some(vec![255]),
    ] {
        let (_dir, store) = crate::testutil::store();
        let bytes = data(32769);
        let root = root(&bytes);
        insert_claim(&store, &root, 70000, 0, Value::Integer(0), bitmap);
        assert_eq!(
            lean_ingest::ingest(&store, Input::Bytes(&bytes), 99).unwrap(),
            (root, bytes.len() as u64)
        );
        let row = store.blob(&root).unwrap().unwrap();
        assert_eq!(row.size, bytes.len() as u64);
        assert!(row.complete && row.durable);
        assert!(row.bitmap.is_none());
        assert_eq!(row.last_access, 99);
        assert_eq!(store.read_all(&root).unwrap(), bytes);
        assert_released(&store, &root);
    }
}

#[test]
fn native_noncanonical_integer_durability_is_preserved_not_normalized() {
    let (_dir, store) = crate::testutil::store();
    let bytes = data(32769);
    let root = root(&bytes);
    insert_claim(
        &store,
        &root,
        bytes.len() as i64,
        0,
        Value::Integer(2),
        None,
    );
    lean_ingest::ingest(&store, Input::Bytes(&bytes), 99).unwrap();
    assert_eq!(
        store
            .conn()
            .query_row(
                "SELECT durable FROM blobs WHERE root=?1",
                params![root.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        2
    );
    assert_eq!(store.read_all(&root).unwrap(), bytes);
    assert_released(&store, &root);
}

#[test]
fn native_noninteger_durability_rejects_before_metadata_mutation() {
    let (_dir, store) = crate::testutil::store();
    let bytes = data(32769);
    let root = root(&bytes);
    insert_claim(
        &store,
        &root,
        bytes.len() as i64,
        1,
        Value::Text("invalid".into()),
        None,
    );
    let before = raw_claim(&store, &root);
    let error = lean_ingest::ingest(&store, Input::Bytes(&bytes), 99).unwrap_err();
    assert!(
        matches!(error, StoreError::Sqlite(rusqlite::Error::InvalidColumnType(2, ref name, rusqlite::types::Type::Text)) if name == "durable")
    );
    assert_eq!(raw_claim(&store, &root), before);
    assert_eq!(std::fs::read(store.blob_path(&root)).unwrap(), bytes);
    assert_released(&store, &root);
}

#[test]
fn native_out_of_line_ingestion_preserves_uninspected_raw_inline_cell() {
    for value in ["NULL", "X''", "X'0102'", "17", "CAST(X'ff' AS TEXT)"] {
        let (_dir, store) = crate::testutil::store();
        let bytes = data(32769);
        let root = root(&bytes);
        insert_claim(
            &store,
            &root,
            bytes.len() as i64,
            0,
            Value::Integer(0),
            None,
        );
        store
            .conn()
            .execute_batch(&format!("UPDATE blobs SET inline={value}"))
            .unwrap();
        let before = raw_claim(&store, &root)[4].clone();
        lean_ingest::ingest(&store, Input::Bytes(&bytes), 99).unwrap();
        assert_eq!(raw_claim(&store, &root)[4], before);
        assert_eq!(std::fs::read(store.blob_path(&root)).unwrap(), bytes);
        assert_released(&store, &root);
    }
}

#[test]
fn native_inline_ingestion_replaces_existing_inline_with_actual_bytes() {
    let (_dir, store) = crate::testutil::store();
    let bytes = b"captured";
    let root = root(bytes);
    insert_claim(
        &store,
        &root,
        bytes.len() as i64,
        0,
        Value::Integer(0),
        None,
    );
    store
        .conn()
        .execute_batch("UPDATE blobs SET inline=CAST(X'ff' AS TEXT)")
        .unwrap();
    lean_ingest::ingest(&store, Input::Bytes(bytes), 99).unwrap();
    assert_eq!(store.read_all(&root).unwrap(), bytes);
    assert_released(&store, &root);
}
