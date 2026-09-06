//! Unix stream compatibility, with bounded waits and no timing sleeps.
use std::{fs::OpenOptions, io::Write, sync::mpsc, time::Duration};

use synch_verified::host::{FileIO, SourceIO};

use crate::{
    lean_resources::{Files, Input},
    Store,
};

#[test]
fn sequential_source_reads_preserve_offsets_without_moving_positioned_reads() {
    let (directory, store) = crate::testutil::store();
    let path = directory.path().join("seekable");
    std::fs::write(&path, b"abcdefgh").unwrap();
    let mut files = Files::new(&store, Input::File(&path));
    let handle = files.open("input", &[]).unwrap();
    assert_eq!(files.read_some(handle, 0, 2).unwrap(), b"ab");
    // Out-of-order reads retain positional semantics and don't alter cursor2.
    assert_eq!(files.read_some(handle, 6, 2).unwrap(), b"gh");
    assert_eq!(files.read_some(handle, 2, 2).unwrap(), b"cd");
    assert_eq!(files.read_at(handle, 0, 2).unwrap(), b"ab");
    assert_eq!(files.read_some(handle, 4, 2).unwrap(), b"ef");
    assert_eq!(files.read_some(handle, 6, 8).unwrap(), b"gh");
    assert!(files.read_some(handle, 8, 8).unwrap().is_empty());
    assert!(files.read_some(handle, 8, 65537).is_err());
    files.close(handle).unwrap();
}

#[test]
fn public_and_internal_ingest_nonseekable_streams_to_actual_eof() {
    for size in [3_usize, 131075] {
        let expected: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
        let mut results = Vec::new();
        for internal in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("input.fifo");
            rustix::fs::mkfifoat(
                rustix::fs::CWD,
                &path,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )
            .unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
            let (completed_tx, completed_rx) = mpsc::channel();
            let writer_path = path.clone();
            let input = expected.clone();
            let writer = std::thread::spawn(move || {
                let mut file = OpenOptions::new().write(true).open(writer_path)?;
                // Several writes cover short-read boundaries and force the
                // larger capture across both 16-KiB and 64-KiB boundaries.
                for chunk in input.chunks(7777) {
                    file.write_all(chunk)?;
                }
                Ok::<(), std::io::Error>(())
            });
            let store_path = directory.path().to_owned();
            let reader = std::thread::spawn(move || {
                let observed = (|| -> crate::Result<_> {
                    // Invocation-owned Rc resources are constructed here,
                    // never sent between threads.
                    let store = Store::open(&store_path)?;
                    let (root, captured) = if internal {
                        crate::lean_ingest::ingest(&store, Input::File(&path), 17)?
                    } else {
                        store.ingest_file(&path, 17)?
                    };
                    let bytes = store.read_all(&root)?;
                    let row = store.blob(&root)?.unwrap();
                    assert!(store.active_temporaries().is_empty());
                    assert!(!store.is_being_written(&root));
                    Ok((root, captured, bytes, row.inline.is_some()))
                })()
                .map_err(|error| error.to_string());
                let _ = completed_tx.send(observed);
            });
            // No barrier/sleep race determines EOF: closing the writer does.
            // A regression that blocks either FIFO endpoint fails this test
            // after a bounded wait. Detached failed workers do not block the
            // test harness process from terminating.
            let observed = completed_rx
                .recv_timeout(Duration::from_secs(30))
                .expect("FIFO ingestion did not complete within the bounded wait")
                .unwrap_or_else(|error| panic!("internal={internal}, size={size}: {error}"));
            reader.join().unwrap();
            writer.join().unwrap().unwrap();
            assert_eq!(observed.1, size as u64);
            assert_eq!(observed.0.as_bytes(), blake3::hash(&expected).as_bytes());
            assert_eq!(observed.2, expected);
            assert_eq!(observed.3, size <= synch_core::INLINE_BLOB_MAX as usize);
            results.push(observed);
        }
        assert_eq!(results[0], results[1]);
    }
}
