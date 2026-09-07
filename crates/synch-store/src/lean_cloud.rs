//! Whole native cloud restoration over raw provider and cache services.
//! The continuation and resource owners remain on one blocking worker; only
//! owned requests and replies cross an asynchronous provider wait.

use std::{fs::OpenOptions, sync::Arc};

use bao_tree::io::sync::WriteAt;
use synch_core::{ChunkRanges, Hash};
use synch_verified::{
    cloud::{self, DomainError, OperationError, ProviderReply, ProviderRequest, ProviderStep},
    host::{self, FileFailure, FileFailureKind},
};

use crate::{
    cloud::CloudStore,
    lean_resources::{target as path, Files, Input, Leases},
    lean_storage::Session,
    Result, Store, StoreError,
};

struct Cache<'a> {
    store: &'a Store,
    files: Files<'a>,
}

impl host::CacheIO for Cache<'_> {
    type Error = StoreError;

    fn is_file(&mut self, space: &str, key: &[u8]) -> Result<bool> {
        Ok(path(self.store, space, key)?.is_file())
    }

    fn write_at(&mut self, space: &str, key: &[u8], offset: u64, bytes: &[u8]) -> Result<()> {
        let path = path(self.store, space, key)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?
            .write_all_at(offset, bytes)?;
        Ok(())
    }

    fn flush(&mut self, space: &str, key: &[u8]) -> Result<()> {
        let path = path(self.store, space, key)?;
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)?
            .sync_all()?;
        #[cfg(not(windows))]
        {
            let parent = path
                .parent()
                .ok_or_else(|| StoreError::invalid("cache file has no parent"))?;
            // A newly created shard adds an entry to the CAS root too. Both
            // must reach disk before this primitive acknowledges the write.
            for directory in [parent.to_path_buf(), self.store.cas_dir()] {
                match std::fs::File::open(directory)?.sync_all() {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::Unsupported => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(())
    }

    fn write_temporary(&mut self, handle: u64, offset: u64, bytes: &[u8]) -> Result<()> {
        self.files.write_temporary(handle, offset, bytes)
    }
}

fn operation_error(error: OperationError<StoreError>) -> StoreError {
    match error {
        OperationError::Host(error) => error,
        _ => StoreError::invalid("invalid native cloud-operation protocol"),
    }
}

fn domain_error(error: DomainError) -> StoreError {
    match error {
        DomainError::Malformed => StoreError::Decode("invalid cloud cache metadata".into()),
        DomainError::ColumnType {
            index,
            column,
            actual,
        } => crate::lean_diagnostics::column_type(index, column, actual),
        DomainError::Column { column, reason } => match column.as_str() {
            "blobs.root" => StoreError::column("blobs.root", reason),
            _ => StoreError::invalid("unknown native cloud error column"),
        },
        DomainError::MissingBlob(root) => match Hash::from_slice(&root) {
            Ok(root) => StoreError::MissingBlob(root),
            Err(_) => StoreError::invalid("invalid native cloud root"),
        },
        DomainError::SizeMismatch {
            root,
            recorded,
            offered,
        } => match Hash::from_slice(&root) {
            Ok(root) => StoreError::invalid(format!(
                "size mismatch for {root}: have {recorded}, offered {offered}"
            )),
            Err(_) => StoreError::invalid("invalid native cloud root"),
        },
        DomainError::CacheBusy => {
            StoreError::invalid("the cloud cache is currently being filled by another operation")
        }
        DomainError::InvalidRange { start, stop, size } => StoreError::RangeOutOfBounds {
            start,
            end: stop,
            size,
        },
        DomainError::UnalignedRange => {
            StoreError::invalid("trusted cache writes must cover whole chunk groups")
        }
        DomainError::IncompleteInline => {
            StoreError::invalid("an inline cache fill must contain the whole object")
        }
    }
}

type Answer = ProviderReply<StoreError>;
type Reply = dyn FnMut(&ProviderRequest) -> Option<Answer>;

fn run<T>(
    store: &Store,
    reply: &mut Reply,
    start: impl FnOnce(
        &mut Session<'_>,
        cloud::Resources<'_, StoreError>,
    ) -> cloud::Outcome<T, StoreError>,
) -> Result<T> {
    let mut storage = Session::new(store);
    let mut temporary = Files::new(store, Input::Bytes(&[]));
    let mut cache = Cache {
        store,
        files: temporary.clone(),
    };
    let mut leases = Leases::ordered(store, storage.section());
    let mut clock = crate::lean_durable::Clock;
    let mut bao = crate::lean_bao::Bao::new(store);
    let mut access = crate::lean_storage::Resources(store);
    let mut step = start(
        &mut storage,
        cloud::Resources {
            clock: &mut clock,
            bao: &mut bao,
            leases: &mut leases,
            temporary: &mut temporary,
            access: &mut access,
            cache: &mut cache,
        },
    )
    .map_err(operation_error)?;
    loop {
        match step {
            ProviderStep::Done(result) => return result.map_err(domain_error),
            ProviderStep::Suspended(waiting) => {
                let answer = reply(waiting.request())
                    .ok_or_else(|| StoreError::invalid("cloud restoration was cancelled"))?;
                step = cloud::resume(
                    waiting,
                    answer,
                    &mut storage,
                    cloud::Resources {
                        clock: &mut clock,
                        bao: &mut bao,
                        leases: &mut leases,
                        temporary: &mut temporary,
                        access: &mut access,
                        cache: &mut cache,
                    },
                )
                .map_err(operation_error)?;
            }
        }
    }
}

fn failure(error: StoreError) -> FileFailure<StoreError> {
    let kind = if matches!(&error, StoreError::CloudNotFound { .. }) {
        FileFailureKind::Missing
    } else {
        FileFailureKind::Other
    };
    FileFailure { error, kind }
}

fn object_key(space: &str, key: &[u8]) -> Result<String> {
    let root = Hash::from_slice(key).map_err(|error| StoreError::invalid(error.to_string()))?;
    match space {
        "cas_payload" => Ok(CloudStore::payload_key(&root)),
        "cas_outboard" => Ok(CloudStore::outboard_key(&root)),
        _ => Err(StoreError::invalid("unsupported provider namespace")),
    }
}

async fn answer(objects: &CloudStore, request: ProviderRequest) -> Answer {
    match request {
        ProviderRequest::Stat { space, key } => ProviderReply::Stat(
            async { objects.stat_object(&object_key(&space, &key)?).await }
                .await
                .map_err(failure),
        ),
        ProviderRequest::ReadAll { space, key } => ProviderReply::ReadAll(
            async {
                Ok(objects
                    .read_object(&object_key(&space, &key)?)
                    .await?
                    .to_vec())
            }
            .await
            .map_err(failure),
        ),
        ProviderRequest::ReadRange {
            space,
            key,
            offset,
            count,
        } => ProviderReply::ReadRange(
            async {
                let end = offset
                    .checked_add(count)
                    .ok_or_else(|| StoreError::invalid("provider range overflowed"))?;
                Ok(objects
                    .read_object_range(&object_key(&space, &key)?, offset..end)
                    .await?
                    .to_vec())
            }
            .await
            .map_err(failure),
        ),
    }
}

async fn execute<T: Send + 'static>(
    store: Arc<Store>,
    objects: CloudStore,
    start: impl FnOnce(&Store, &mut Reply) -> Result<T> + Send + 'static,
) -> Result<T> {
    execute_with(store, start, move |request| {
        let objects = objects.clone();
        async move { answer(&objects, request).await }
    })
    .await
}

async fn execute_with<T: Send + 'static, F, Fut>(
    store: Arc<Store>,
    start: impl FnOnce(&Store, &mut Reply) -> Result<T> + Send + 'static,
    mut respond: F,
) -> Result<T>
where
    F: FnMut(ProviderRequest) -> Fut + Send,
    Fut: std::future::Future<Output = Answer> + Send,
{
    let (requests, mut receiver) = tokio::sync::mpsc::channel(1);
    let working = synch_core::offload(move || {
        start(&store, &mut move |request| {
            let (sender, answer) = std::sync::mpsc::sync_channel(1);
            requests.blocking_send((request.clone(), sender)).ok()?;
            answer.recv().ok()
        })
    });
    tokio::pin!(working);
    loop {
        tokio::select! {
            result = &mut working => return result,
            request = receiver.recv() => {
                let Some((request, sender)) = request else { return working.await; };
                // Cancellation drops the reply sender, releasing the blocked
                // worker and its continuation, leases and temporary handles.
                let _ = sender.send(respond(request).await);
            }
        }
    }
}

pub(crate) async fn ensure_cached(
    store: Arc<Store>,
    objects: CloudStore,
    root: Hash,
    size: u64,
) -> Result<()> {
    execute(store, objects, move |store, reply| {
        run(store, reply, |storage, resources| {
            cloud::ensure_cached(storage, resources, root.as_bytes(), size)
        })
    })
    .await
}

pub(crate) async fn ensure_ranges(
    store: Arc<Store>,
    objects: CloudStore,
    root: Hash,
    size: u64,
    ranges: ChunkRanges,
) -> Result<()> {
    execute(store, objects, move |store, reply| {
        run(store, reply, |storage, resources| {
            cloud::ensure_ranges(
                storage,
                resources,
                root.as_bytes(),
                size,
                &crate::lean_bao::pairs_of(&ranges),
            )
        })
    })
    .await
}

pub(crate) async fn hydrate(
    store: Arc<Store>,
    objects: CloudStore,
    root: Hash,
    size: u64,
    ranges: ChunkRanges,
) -> Result<()> {
    execute(store, objects, move |store, reply| {
        run(store, reply, |storage, resources| {
            cloud::hydrate(
                storage,
                resources,
                root.as_bytes(),
                size,
                &crate::lean_bao::pairs_of(&ranges),
            )
        })
    })
    .await
}

pub(crate) async fn outboard(
    store: Arc<Store>,
    objects: CloudStore,
    root: Hash,
    force: bool,
) -> Result<Vec<u8>> {
    execute(store, objects, move |store, reply| {
        run(store, reply, |storage, resources| {
            cloud::outboard(storage, resources, root.as_bytes(), force)
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use opendal::{services::Memory, Operator};
    use std::time::Duration;

    #[tokio::test]
    async fn cancellation_during_provider_wait_releases_cache_resources() {
        let directory = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(directory.path()).unwrap());
        store.set_remote_cas(true);
        let objects = CloudStore::from_operator(
            Operator::new(Memory::default()).unwrap(),
            scratch.path().to_path_buf(),
        )
        .unwrap();
        let ingested = objects.ingest_bytes(&vec![7; 100_000]).await.unwrap();
        let (root, size) = (ingested.root, ingested.size);
        store.adopt_durable_blob(&root, size, 1).unwrap();
        let (waiting, observed) = tokio::sync::oneshot::channel();
        let mut waiting = Some(waiting);
        let task = tokio::spawn(execute_with(
            store.clone(),
            move |store, reply| {
                run(store, reply, |storage, resources| {
                    cloud::ensure_cached(storage, resources, root.as_bytes(), size)
                })
            },
            move |request| {
                let objects = objects.clone();
                let waiting = if matches!(&request, ProviderRequest::ReadRange { .. }) {
                    waiting.take()
                } else {
                    None
                };
                async move {
                    if let Some(waiting) = waiting {
                        let _ = waiting.send(());
                        std::future::pending::<()>().await;
                    }
                    answer(&objects, request).await
                }
            },
        ));
        tokio::time::timeout(Duration::from_secs(5), observed)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(store.writer_count(&root), 1);
        assert!(store.active_temporaries().is_empty());
        // The actual command has published its outboard and released the SQL
        // transaction before the payload wait. Another reader can proceed.
        let reading = store.clone();
        assert!(tokio::time::timeout(
            Duration::from_secs(5),
            synch_core::offload(move || reading.blob(&root)),
        )
        .await
        .unwrap()
        .unwrap()
        .is_some());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(5), async {
            while store.writer_count(&root) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(store.active_temporaries().is_empty());
        assert!(store
            .blob(&root)
            .unwrap()
            .unwrap()
            .verified_groups()
            .is_empty());
        assert!(store.clear_blob_cache(&root).unwrap());
    }
}
