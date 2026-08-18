//! The batching publisher (§7.1).
//!
//! Staged changes are accumulated and turned into a *single* new trie root:
//! bump `seq`, sign, store, `HeadPush`. A burst of editor saves therefore costs
//! one head rather than one head per save, and a 100k-file initial index costs
//! a handful.
//!
//! A batch flushes when either trigger fires, whichever comes first:
//!
//! - `publish_quiesce` (default 2 s) passes with nothing new staged, or
//! - the buffer reaches `publish_batch_max` (default 1000) entries.
//!
//! Callers that must publish before they return — `synch scan`, `synch take` —
//! flush explicitly instead of waiting for either.

use std::{sync::Mutex, time::Duration};

use synch_core::SignedHead;
use tokio::sync::Notify;

use crate::{
    error::Result,
    node::{Node, StagedChange},
};

/// How long staging must go quiet before a batch is published (§7.1).
pub const DEFAULT_PUBLISH_QUIESCE: Duration = Duration::from_secs(2);

/// How many staged entries force a batch out without waiting (§7.1).
pub const DEFAULT_PUBLISH_BATCH_MAX: usize = 1000;

/// The buffer between staging and one signed root.
///
/// Held by the [`Node`]; the timer that drains it is [`Node::run_publisher`],
/// and any caller can drain it by hand with [`Node::flush_staged`].
#[derive(Debug)]
pub struct Publisher {
    quiesce: Duration,
    batch_max: usize,
    staged: Mutex<Vec<StagedChange>>,
    wake: Notify,
}

impl Publisher {
    /// Builds a publisher with the given batch triggers.
    pub fn new(quiesce: Duration, batch_max: usize) -> Publisher {
        Publisher {
            quiesce,
            batch_max,
            staged: Mutex::new(Vec::new()),
            wake: Notify::new(),
        }
    }

    /// How long staging must go quiet before the batch is published.
    pub fn quiesce(&self) -> Duration {
        self.quiesce
    }

    /// How many staged entries force the batch out without waiting.
    pub fn batch_max(&self) -> usize {
        self.batch_max
    }

    /// Adds changes to the current batch.
    ///
    /// Cheap and non-blocking: it appends and wakes the timer, and never
    /// touches the database.
    pub fn stage(&self, changes: impl IntoIterator<Item = StagedChange>) {
        let added = {
            let mut staged = self.buffer();
            let before = staged.len();
            staged.extend(changes);
            staged.len() - before
        };
        if added > 0 {
            // A stored permit means a waiter that has not started waiting yet
            // still sees this, so a change staged in the gap is never lost.
            self.wake.notify_one();
        }
    }

    /// How many changes are waiting to be published.
    pub fn pending(&self) -> usize {
        self.buffer().len()
    }

    /// Whether the batch has reached `publish_batch_max`.
    pub fn is_full(&self) -> bool {
        self.pending() >= self.batch_max
    }

    /// Resolves once something has been staged since the last wake.
    pub(crate) async fn woken(&self) {
        self.wake.notified().await
    }

    /// Takes the whole batch, leaving the buffer empty.
    pub(crate) fn take(&self) -> Vec<StagedChange> {
        std::mem::take(&mut *self.buffer())
    }

    /// Puts a batch back at the front after a publish failed, so the next
    /// flush retries it rather than dropping it on the floor.
    pub(crate) fn restage(&self, changes: Vec<StagedChange>) {
        let mut staged = self.buffer();
        let queued = std::mem::replace(&mut *staged, changes);
        staged.extend(queued);
    }

    fn buffer(&self) -> std::sync::MutexGuard<'_, Vec<StagedChange>> {
        self.staged
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Node {
    /// Adds changes to the batch the publisher is accumulating (§7.1).
    ///
    /// Returns immediately: what turns a batch into a root is either the
    /// quiesce timer in [`Node::run_publisher`] or an explicit
    /// [`Node::flush_staged`].
    pub fn stage(&self, changes: impl IntoIterator<Item = StagedChange>) {
        self.publisher().stage(changes);
    }

    /// Publishes everything staged so far as one new signed root and pushes it
    /// to reachable peers (§7.1).
    ///
    /// This is the whole batch, not one caller's share of it: a `synch scan`
    /// that lands while a watcher-triggered rescan is still buffered publishes
    /// both, which is the point of batching.
    ///
    /// A failed publish puts the batch back rather than dropping it, so the
    /// next flush retries it. A failed *push* does not fail the flush: the head
    /// is published, and peers pick it up at the next anti-entropy round.
    pub async fn flush_staged(&self) -> Result<Option<SignedHead>> {
        let head = self.publish_staged().await?;
        if let Some(head) = &head {
            if let Err(e) = self.push_head(head).await {
                tracing::debug!(error = %e, "could not push the new head");
            }
            // This node's own origin's tree just moved, and mirrors follow
            // the unified tree — which includes it.
            self.mirror_wake().notify_one();
        }
        Ok(head)
    }

    /// Publishes everything staged so far as one new signed root, without
    /// telling anybody about it.
    ///
    /// The half of a flush that is this node's own business. Peers learn the
    /// head from the push in [`Node::flush_staged`], or from the next
    /// anti-entropy round if nobody pushes it.
    async fn publish_staged(&self) -> Result<Option<SignedHead>> {
        let batch = self.publisher().take();
        if batch.is_empty() {
            return Ok(None);
        }
        // On the blocking pool: a publish inserts every staged change into the
        // trie, signs a head, re-materializes the changed leaves and fsyncs the
        // lot as one SQLite transaction — up to `publish_batch_max` entries of
        // it (§7.1, §10).
        //
        // The restage happens *inside* the closure, not around the await. A
        // blocking task cannot be cancelled, so once it starts it always either
        // publishes the batch or puts it back — while anything written around
        // the await would be skipped entirely if this future were dropped
        // first. It can be: control connections are spawned detached
        // (`control::Server::run`), so a `daemon stop` landing mid-flush drops
        // one wherever it happens to be parked, and this used to be the one
        // await point where that meant a batch taken out of the buffer and
        // never put back.
        let node = self.clone();
        let head = crate::blocking::offload(move || match node.publish(&batch) {
            Ok(head) => Ok(head),
            Err(e) => {
                node.publisher().restage(batch);
                Err(e)
            }
        })
        .await?;
        Ok(head)
    }

    /// Runs the batching publisher until `shutdown` resolves (§7.1).
    ///
    /// One flush per quiet period or per full batch, whichever comes first,
    /// and one last flush on the way out so a clean stop never strands a
    /// buffered batch.
    pub async fn run_publisher(&self, shutdown: impl std::future::Future<Output = ()>) {
        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => return self.flush_on_stop().await,
                _ = self.publisher().woken() => {}
            }
            // Wait out the quiesce window, restarting it whenever something
            // else is staged — unless the batch is already full, which
            // publishes at once however busy staging still is.
            while !self.publisher().is_full() {
                tokio::select! {
                    _ = &mut shutdown => return self.flush_on_stop().await,
                    _ = self.publisher().woken() => continue,
                    _ = tokio::time::sleep(self.publisher().quiesce()) => break,
                }
            }
            if let Err(e) = self.flush_staged().await {
                tracing::warn!(error = %e, "publishing a batch failed; it stays staged");
            }
        }
    }

    /// Publishes whatever is still buffered, on the way out (§7.1).
    ///
    /// Published but not pushed. The batch must not be stranded — that is what
    /// this is for — but telling peers means dialing them, and a peer that
    /// accepts and then says nothing would hold the whole daemon open for its
    /// request deadline while an operator waits on `synch daemon stop`. The
    /// head is durable either way, and peers pick it up at the next
    /// anti-entropy round.
    async fn flush_on_stop(&self) {
        if self.publisher().pending() == 0 {
            return;
        }
        if let Err(e) = self.publish_staged().await {
            tracing::warn!(error = %e, "the last batch could not be published");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(key: &str) -> StagedChange {
        (key.as_bytes().to_vec(), Some(b"v".to_vec()))
    }

    #[test]
    fn staging_accumulates_until_taken() {
        let publisher = Publisher::new(Duration::from_secs(2), 3);
        assert_eq!(publisher.pending(), 0);
        publisher.stage([change("a")]);
        publisher.stage([change("b"), change("c")]);
        assert_eq!(publisher.pending(), 3);
        assert!(publisher.is_full());

        let batch = publisher.take();
        assert_eq!(batch.len(), 3);
        assert_eq!(publisher.pending(), 0);
        assert!(!publisher.is_full());
    }

    #[test]
    fn restaging_keeps_the_failed_batch_first() {
        let publisher = Publisher::new(Duration::from_secs(2), 1000);
        publisher.stage([change("a")]);
        let failed = publisher.take();
        publisher.stage([change("b")]);
        publisher.restage(failed);

        let batch = publisher.take();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].0, b"a".to_vec());
        assert_eq!(batch[1].0, b"b".to_vec());
    }

    #[tokio::test]
    async fn a_change_staged_before_the_wait_still_wakes_it() {
        let publisher = Publisher::new(Duration::from_secs(2), 1000);
        publisher.stage([change("a")]);
        tokio::time::timeout(Duration::from_secs(5), publisher.woken())
            .await
            .expect("a permit staged before the wait must still be seen");
    }

    // ---- the publisher against a real node --------------------------------

    use crate::config::NodeConfig;

    /// A node whose batch triggers are set for a test rather than for a desk.
    async fn node(quiesce: Duration, batch_max: usize) -> (tempfile::TempDir, Node) {
        let dir = tempfile::tempdir().unwrap();
        Node::init(dir.path(), None).unwrap();
        let mut config = NodeConfig::loopback(dir.path());
        config.publish_quiesce = quiesce;
        config.publish_batch_max = batch_max;
        (dir, Node::open(config).await.unwrap())
    }

    fn entry(node: &Node, path: &str) -> StagedChange {
        let entry = synch_core::FileEntry::file(1, 0, synch_core::Hash::new(path.as_bytes()), 1);
        (
            node.key_for("s", path).unwrap(),
            Some(postcard::to_stdvec(&entry).unwrap()),
        )
    }

    /// Polls until `ready` holds, or gives up. Timing-sensitive tests assert
    /// "soon", never "at 50 ms".
    async fn eventually(mut ready: impl FnMut() -> bool) -> bool {
        for _ in 0..200 {
            if ready() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    /// Runs the publisher loop until the returned sender fires.
    fn run(
        node: &Node,
    ) -> (
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let runner = node.clone();
        let handle = tokio::spawn(async move {
            runner
                .run_publisher(async {
                    let _ = rx.await;
                })
                .await
        });
        (tx, handle)
    }

    async fn stop(tx: tokio::sync::oneshot::Sender<()>, handle: tokio::task::JoinHandle<()>) {
        let _ = tx.send(());
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("the loop must stop promptly")
            .unwrap();
    }

    /// The property the whole design rests on: many staged changes, one head.
    #[tokio::test]
    async fn a_batch_becomes_exactly_one_head() {
        let (_d, node) = node(Duration::from_secs(60), 1000).await;
        node.stage([entry(&node, "a.txt")]);
        node.stage([entry(&node, "b.txt"), entry(&node, "c.txt")]);
        assert_eq!(node.publisher().pending(), 3);

        let head = node.flush_staged().await.unwrap().unwrap();
        assert_eq!(head.seq, 1, "one batch is one seq, not three");
        assert_eq!(node.publisher().pending(), 0);
        assert_eq!(
            node.store()
                .list_entries(Some(node.origin()), "s", "", None, None)
                .unwrap()
                .len(),
            3
        );
        // And a flush with nothing staged mints nothing.
        assert!(node.flush_staged().await.unwrap().is_none());
        node.shutdown().await.unwrap();
    }

    /// Quiescence publishes on its own, with no explicit flush.
    #[tokio::test]
    async fn staging_flushes_once_it_goes_quiet() {
        let (_d, node) = node(Duration::from_millis(50), 1000).await;
        let (tx, handle) = run(&node);

        node.stage([entry(&node, "a.txt")]);
        let published = eventually(|| node.own_head().unwrap().is_some()).await;
        assert!(published, "a quiet batch must publish itself");
        assert_eq!(node.own_head().unwrap().unwrap().seq, 1);

        stop(tx, handle).await;
        node.shutdown().await.unwrap();
    }

    /// A full batch does not wait for the quiesce window at all.
    #[tokio::test]
    async fn a_full_batch_publishes_without_waiting() {
        // A quiesce far longer than the test could tolerate: if the batch is
        // published, it is the size trigger that did it.
        let (_d, node) = node(Duration::from_secs(600), 2).await;
        let (tx, handle) = run(&node);

        node.stage([entry(&node, "a.txt"), entry(&node, "b.txt")]);
        let published = eventually(|| node.own_head().unwrap().is_some()).await;
        assert!(published, "a full batch must not wait out the quiesce");

        stop(tx, handle).await;
        node.shutdown().await.unwrap();
    }

    /// Stopping the loop publishes what is still buffered rather than
    /// stranding it.
    #[tokio::test]
    async fn a_clean_stop_flushes_the_last_batch() {
        let (_d, node) = node(Duration::from_secs(600), 1000).await;
        let (tx, handle) = run(&node);
        node.stage([entry(&node, "a.txt")]);
        stop(tx, handle).await;

        assert_eq!(node.publisher().pending(), 0);
        assert_eq!(node.own_head().unwrap().unwrap().seq, 1);
        node.shutdown().await.unwrap();
    }

    /// The case batching exists for: several rescans, one head.
    #[tokio::test]
    async fn a_burst_of_rescans_costs_one_head() {
        let (_d, node) = node(Duration::from_millis(50), 1000).await;
        let space = tempfile::tempdir().unwrap();
        node.add_space("media", space.path()).unwrap();

        // Two rescans, as a watcher hint per save would produce. Both are
        // staged before the loop starts, so what is asserted is the batching
        // and not the width of a timing window.
        std::fs::write(space.path().join("a.txt"), b"first").unwrap();
        node.scan_and_stage().unwrap();
        std::fs::write(space.path().join("b.txt"), b"second").unwrap();
        node.scan_and_stage().unwrap();
        assert!(node.own_head().unwrap().is_none(), "nothing published yet");

        let (tx, handle) = run(&node);
        assert!(eventually(|| node.own_head().unwrap().is_some()).await);
        stop(tx, handle).await;

        assert_eq!(node.own_head().unwrap().unwrap().seq, 1);
        assert_eq!(
            node.store()
                .list_entries(Some(node.origin()), "media", "", None, None)
                .unwrap()
                .len(),
            2
        );
        node.shutdown().await.unwrap();
    }

    /// A publish that fails keeps its batch: the changes are retried, not lost.
    #[tokio::test]
    async fn a_refused_publish_keeps_the_batch_staged() {
        let (_d, node) = node(Duration::from_secs(600), 1000).await;
        // A peer advertising a head for our own origin puts the node in
        // key-loss recovery, where publishing is refused (§3.4).
        node.store()
            .record_observed_head(
                node.origin(),
                42,
                &synch_core::Hash([7u8; 32]),
                true,
                None,
                synch_core::now_ns(),
            )
            .unwrap();

        node.stage([entry(&node, "a.txt")]);
        assert!(node.flush_staged().await.is_err());
        assert_eq!(
            node.publisher().pending(),
            1,
            "the refused batch stays staged for the next attempt"
        );
        node.shutdown().await.unwrap();
    }
}
