//! Replicating a tenant's database (`docs/CLOUD-DATAPLANE.md` §5.3).
//!
//! Every tenant's SQLite database lives on an ephemeral volume, so the copy
//! that survives is the one in object storage. Putting it there is
//! `celld-ltx`'s job, not this crate's: a Rust reimplementation of Litestream
//! v0.5 writing the LTX format. This module is the thin part — pointing it at
//! a tenant's database and prefix, and driving it on an interval.
//!
//! # Why not write the shipper
//!
//! Because it is a specialist's problem that looks like an easy one. SQLite
//! spills a large transaction's pages into the write-ahead log *before* it
//! commits, and rolls back by rewinding its own high-water mark while leaving
//! those bytes for the next transaction to overwrite — so a shipper that goes
//! by file length ships frames that are about to be replaced and then misses
//! their replacements, silently, with the stream reporting healthy the whole
//! time. Getting that right means tracking commit boundaries, verifying
//! SQLite's frame checksum chain to notice a log rewritten behind you, and
//! ordering a snapshot against a checkpoint so a failed upload cannot strand
//! writes. Litestream has learned those; this service inherits them rather
//! than rediscovering them.
//!
//! # Why a thread per tenant
//!
//! A replica owns a SQLite connection, which is `Send` but not `Sync`, and the
//! library's `sync` holds `&self` across an await — so its future is not
//! `Send` and cannot be handed to `tokio::spawn` at all. Rather than bend that
//! (there is no sound way to: the bound is telling the truth about a
//! connection that must not be touched from two threads), each replicator owns
//! one thread running a current-thread runtime, and this type is the
//! `Send + Sync` handle onto it. Two things fall out of that and are worth
//! having on their own: the blocking half of a capture is real SQLite work and
//! belongs off the async workers regardless, and commands are served one at a
//! time, so a final ship can never interleave with a tick.
//!
//! # What this crate still owes it
//!
//! One thing: nothing else may checkpoint. `celld-ltx` disables autocheckpoint
//! on its own connections and owns checkpointing from there, but
//! `PRAGMA wal_autocheckpoint` is per-connection, so the *node's* writer would
//! still recycle frames behind it. That is what
//! [`Checkpointing::Embedder`](synch_store::Checkpointing::Embedder) is for,
//! and it is the whole of engine change (d) in §7.3.

use std::path::{Path, PathBuf};
use std::time::Duration;

use celld_ltx::{Db, Replica, ReplicaClient};
use tokio::sync::{mpsc, oneshot};

use crate::error::{DpError, Result};

/// How often the replicator captures and ships.
///
/// One second, which bounds what an ungraceful kill can lose — the same
/// asynchrony Litestream accepts, and the number §5.3 quotes.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(1);

/// Where a tenant's database stream is written.
///
/// The replication library ships exactly two clients — S3-compatible object
/// storage and a local directory — and neither is a trait object, so this is
/// where the deployment's choice becomes a concrete type. Dispatch happens
/// once, at start and at restore; [`Replicator`] itself is not generic, so
/// nothing downstream has to care which arm was taken.
pub enum DbClient {
    /// The bucket, beside the tenant CAS prefixes (§5.1).
    ///
    /// Boxed: it carries a whole S3 configuration and is ten times the size of
    /// the other variant, which every value of this type would otherwise pay
    /// for.
    Objects(Box<celld_ltx::ObjectStoreClient>),
    /// A local directory. Test deployments only — see `DpConfig::db_client`.
    Files(celld_ltx::FileReplicaClient),
}

impl std::fmt::Debug for DbClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the config: it carries credentials.
        match self {
            DbClient::Objects(_) => f.write_str("DbClient::Objects"),
            DbClient::Files(_) => f.write_str("DbClient::Files"),
        }
    }
}

/// What the owner asks the replica thread to do.
///
/// Each carries the channel its answer goes back on, so a caller that awaits
/// one knows the work is done rather than merely queued.
enum Command {
    /// Capture what the database has committed, then ship it.
    Sync(oneshot::Sender<Result<()>>),
    /// Close the database, releasing its long-running read lock.
    Close(oneshot::Sender<Result<()>>),
}

/// One tenant's replica stream.
///
/// A handle, not the replica: the replica lives on the thread this spawned.
pub struct Replicator {
    tenant: String,
    commands: mpsc::UnboundedSender<Command>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for Replicator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Replicator")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl Replicator {
    /// Attaches to the database at `db_path` and replicates it through
    /// `client`.
    ///
    /// Returns once the replica is open, so a failure to open is this call's
    /// failure and not a warning from a thread nobody is watching.
    ///
    /// The behind-replica check runs here, before any sync. It is what makes a
    /// hard recovery safe: restore an old snapshot, write to it, and without
    /// this the fresh local database starts at a transaction id the remote is
    /// already past, so the upload loop never runs and the new writes are
    /// silently dropped.
    pub async fn start(
        db_path: &Path,
        client: DbClient,
        tenant: impl Into<String>,
    ) -> Result<Self> {
        match client {
            DbClient::Objects(client) => Self::start_with(db_path, *client, tenant).await,
            DbClient::Files(client) => Self::start_with(db_path, client, tenant).await,
        }
    }

    /// [`start`](Self::start) once the client's type is known.
    async fn start_with<C>(db_path: &Path, client: C, tenant: impl Into<String>) -> Result<Self>
    where
        C: ReplicaClient + Send + 'static,
    {
        let tenant = tenant.into();
        let db_path = db_path.to_path_buf();
        let (commands, requests) = mpsc::unbounded_channel();
        let (ready, opened) = oneshot::channel();
        let worker = std::thread::Builder::new()
            // Named for the tenant: a stuck thread in a stack dump has to say
            // which of a shard's tenants it belongs to.
            .name(format!("ltx-{tenant}"))
            .spawn(move || serve(db_path, client, requests, ready))
            .map_err(|error| DpError::io("spawning the replication thread", error))?;

        let outcome = match opened.await {
            Ok(outcome) => outcome,
            // The thread ended without answering, which only a panic does.
            Err(_) => Err(DpError::Engine(
                "the replication thread stopped before it opened the database".into(),
            )),
        };
        match outcome {
            Ok(()) => Ok(Self {
                tenant,
                commands,
                worker: Some(worker),
            }),
            Err(error) => {
                // Already finished — it answered by ending — so this join
                // returns immediately rather than parking a runtime worker.
                let _ = worker.join();
                Err(error)
            }
        }
    }

    /// Captures what the database has committed, then ships it.
    pub async fn tick(&mut self) -> Result<()> {
        self.request(Command::Sync).await
    }

    /// Ships everything outstanding. The last thing a draining tenant does.
    pub async fn flush(&mut self) -> Result<()> {
        self.tick().await
    }

    /// Closes the database cleanly and stops the thread.
    pub async fn close(mut self) -> Result<()> {
        let outcome = self.request(Command::Close).await;
        // Before returning, not after: a caller that closes in order to remove
        // the data directory needs the connection actually gone, not merely
        // asked to go.
        if let Some(worker) = self.worker.take() {
            if tokio::task::spawn_blocking(move || worker.join())
                .await
                .is_err()
            {
                tracing::warn!(
                    tenant = %self.tenant,
                    "could not wait for the replication thread to finish"
                );
            }
        }
        tracing::debug!(tenant = %self.tenant, "closed the tenant's replicated database");
        outcome
    }

    /// Asks the thread for one thing and waits for its answer.
    async fn request(&self, command: fn(oneshot::Sender<Result<()>>) -> Command) -> Result<()> {
        let (reply, answer) = oneshot::channel();
        self.commands.send(command(reply)).map_err(|_| stopped())?;
        answer.await.map_err(|_| stopped())?
    }
}

impl Drop for Replicator {
    fn drop(&mut self) {
        // Dropping the command sender ends the loop, and dropping the replica
        // there closes the connection. Deliberately not joined: a drop cannot
        // await, and blocking a runtime worker on a thread that is still
        // uploading would be worse than letting it finish detached.
        if self.worker.is_some() {
            tracing::debug!(
                tenant = %self.tenant,
                "dropping a replicator that was not closed; its thread will end on its own"
            );
        }
    }
}

/// The replica thread: a runtime of its own, then commands until told to stop.
fn serve<C: ReplicaClient>(
    db_path: PathBuf,
    client: C,
    requests: mpsc::UnboundedReceiver<Command>,
    ready: oneshot::Sender<Result<()>>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = ready.send(Err(DpError::io("building the replication runtime", error)));
            return;
        }
    };
    runtime.block_on(replicate(db_path, client, requests, ready));
}

/// Opens the replica, reports whether that worked, then serves commands.
async fn replicate<C: ReplicaClient>(
    db_path: PathBuf,
    client: C,
    mut requests: mpsc::UnboundedReceiver<Command>,
    ready: oneshot::Sender<Result<()>>,
) {
    let mut replica = match open(&db_path, client).await {
        Ok(replica) => {
            if ready.send(Ok(())).is_err() {
                // Nobody is waiting for this replica any more, so there is
                // nothing to serve; falling through would hold the read lock
                // on a database the caller has given up on.
                return;
            }
            replica
        }
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    while let Some(command) = requests.recv().await {
        match command {
            Command::Sync(reply) => {
                let _ = reply.send(sync(&mut replica).await);
            }
            Command::Close(reply) => {
                let _ = reply.send(close(replica));
                return;
            }
        }
    }
}

/// Opens the database and its replica, and checks it is not behind the stream.
async fn open<C: ReplicaClient>(db_path: &Path, client: C) -> Result<Replica<C>> {
    let db = Db::open(db_path).map_err(engine)?;
    let mut replica = Replica::new(db, client);
    replica
        .check_database_behind_replica()
        .await
        .map_err(engine)?;
    Ok(replica)
}

/// One capture and ship, in the library's own order.
///
/// The capture reads the write-ahead log into local LTX segments and is
/// synchronous SQLite work — which is why this runs on a thread of its own —
/// and the upload is ordinary async IO.
async fn sync<C: ReplicaClient>(replica: &mut Replica<C>) -> Result<()> {
    replica
        .db_mut()
        .expect("a replicator always owns its database")
        .sync()
        .map_err(engine)?;
    match replica.sync().await {
        Ok(()) => Ok(()),
        Err(error) if is_waiting_for_data(&error) => Ok(()),
        Err(error) => Err(engine(error)),
    }
}

/// Closes the database, releasing the long-running read lock.
fn close<C: ReplicaClient>(replica: Replica<C>) -> Result<()> {
    match replica.into_db() {
        Some(db) => db.close().map_err(engine),
        None => Ok(()),
    }
}

/// Restores a tenant's database into `data_dir`, if the stream holds one.
///
/// Returns `false` when there is nothing there — a network never hosted, or
/// one whose stream is gone. That is the signal to initialize a fresh node,
/// and it is deliberately distinguishable from an error: "there is nothing
/// here" and "I could not tell" must not lead to the same action, because one
/// of them silently replaces an identity.
pub async fn restore(client: DbClient, data_dir: &Path) -> Result<bool> {
    match client {
        DbClient::Objects(client) => restore_with(*client, data_dir).await,
        DbClient::Files(client) => restore_with(client, data_dir).await,
    }
}

/// [`restore`] once the client's type is known.
async fn restore_with<C: ReplicaClient>(client: C, data_dir: &Path) -> Result<bool> {
    std::fs::create_dir_all(data_dir)
        .map_err(|error| DpError::io("creating the tenant data directory", error))?;
    let db_path = data_dir.join(synch_store::DB_FILE);
    // The free function rather than `Replica::restore`: that one takes `&self`
    // on a type holding a SQLite connection, so its future is not `Send` and
    // could not be awaited from a spawned task.
    match celld_ltx::restore(&client, &db_path, celld_ltx::TXID(0)).await {
        Ok(stats) => {
            tracing::info!(?stats, "restored a tenant database from its replica stream");
            Ok(true)
        }
        Err(error) if is_empty_stream(&error) => Ok(false),
        Err(error) => Err(engine(error)),
    }
}

/// Whether a restore failed only because the stream holds nothing yet.
///
/// Restoring at [`TXID(0)`](celld_ltx::TXID) asks for "whatever is latest", and
/// the only way that plan comes back unsatisfiable is that the prefix holds no
/// LTX files at all — so these two variants mean an empty stream here and
/// nothing else. Deliberately narrow: every other failure stays an error, so a
/// tenant whose stream exists but cannot be read parks instead of quietly
/// initializing a second identity over the top of the one already in the zone.
fn is_empty_stream(error: &celld_ltx::Error) -> bool {
    matches!(
        error,
        celld_ltx::Error::TxNotAvailable | celld_ltx::Error::NoSnapshots
    )
}

/// Whether a sync failed only because the database has committed nothing yet.
///
/// A tenant that has just initialized has no transaction to ship. The library
/// reports that as an error, and only as a message — treating it as one here
/// would put a warning in the log every second until the first write lands.
fn is_waiting_for_data(error: &celld_ltx::Error) -> bool {
    matches!(error, celld_ltx::Error::Other(cause) if cause.to_string().contains("waiting for data"))
}

/// Every failure from the replication library reaches this crate the same way.
fn engine(error: impl std::fmt::Display) -> DpError {
    DpError::Engine(error.to_string())
}

/// The replica thread is gone, so nothing more can be shipped through it.
fn stopped() -> DpError {
    DpError::Engine("the replication thread has stopped".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use celld_ltx::FileReplicaClient;

    /// Opens a store the way the service does: off the runtime's workers, and
    /// with checkpointing left to the replicator.
    async fn open_store(dir: &Path) -> std::sync::Arc<synch_store::Store> {
        let dir = dir.to_path_buf();
        std::sync::Arc::new(
            synch_core::offload(move || {
                synch_store::Store::open_with(
                    &dir,
                    synch_store::StoreOptions {
                        checkpointing: synch_store::Checkpointing::Embedder,
                    },
                )
            })
            .await
            .unwrap(),
        )
    }

    fn client(dir: &Path) -> DbClient {
        DbClient::Files(FileReplicaClient::new(dir.to_string_lossy().to_string()))
    }

    /// The property this module exists for: what the stream holds restores to
    /// a database carrying the writes that were shipped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_shipped_stream_restores_the_writes_it_carried() {
        let source = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();
        let store = open_store(source.path()).await;
        let mut replicator =
            Replicator::start(&store.db_path(), client(remote.path()), "acme/prod")
                .await
                .unwrap();

        {
            let store = store.clone();
            synch_core::offload(move || store.set_config("dbrepl.probe", "shipped"))
                .await
                .unwrap();
        }
        replicator.flush().await.unwrap();
        replicator.close().await.unwrap();
        drop(store);

        let restored = tempfile::tempdir().unwrap();
        assert!(restore(client(remote.path()), restored.path())
            .await
            .unwrap());

        let reopened = open_store(restored.path()).await;
        let value = {
            let reopened = reopened.clone();
            synch_core::offload(move || reopened.config("dbrepl.probe"))
                .await
                .unwrap()
        };
        assert_eq!(value.as_deref(), Some("shipped"));
    }

    /// Ticking is what the service does forever, so a second tick with nothing
    /// new to say must be quiet rather than an error the ticker logs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ticking_with_nothing_new_is_not_an_error() {
        let source = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();
        let store = open_store(source.path()).await;
        let mut replicator =
            Replicator::start(&store.db_path(), client(remote.path()), "acme/prod")
                .await
                .unwrap();
        replicator.tick().await.unwrap();
        replicator.tick().await.unwrap();
        replicator.close().await.unwrap();
    }

    /// A stream nothing has been written to is not an error — it is the signal
    /// to initialize a new node, and must be distinguishable from a failure.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_empty_stream_restores_nothing() {
        let remote = tempfile::tempdir().unwrap();
        let restored = tempfile::tempdir().unwrap();
        assert!(!restore(client(remote.path()), restored.path())
            .await
            .unwrap());
    }
}
