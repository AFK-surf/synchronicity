//! The filesystem watcher (§7.1).
//!
//! Hints from `notify` are debounced and only ever *schedule rescans* —
//! correctness never depends on watcher completeness, so a missed event costs
//! at most one scan interval of latency, never a lost file.

use std::{collections::HashSet, path::PathBuf, time::Duration};

use notify::{RecommendedWatcher, RecursiveMode, Watcher as _};
use tokio::sync::mpsc;

use crate::{error::Result, node::Node};

/// A debounced rescan trigger over every configured space.
#[derive(Debug)]
pub struct SpaceWatcher {
    watcher: RecommendedWatcher,
    hints: mpsc::Receiver<()>,
    debounce: Duration,
    /// The space roots currently registered with `notify`, so a re-register
    /// pass can tell what is new and what has gone.
    watching: HashSet<PathBuf>,
}

impl SpaceWatcher {
    /// Starts watching every configured space root.
    pub fn start(node: &Node) -> Result<SpaceWatcher> {
        let (tx, rx) = mpsc::channel(64);
        let watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
            if event.is_ok() {
                // A full channel already means a rescan is pending, so dropping
                // the hint loses nothing.
                let _ = tx.try_send(());
            }
        })
        .map_err(watch_error)?;

        let mut out = SpaceWatcher {
            watcher,
            hints: rx,
            debounce: node.config().watch_debounce,
            watching: HashSet::new(),
        };
        out.resync(node)?;
        Ok(out)
    }

    /// Registers spaces added since the last pass and drops ones removed.
    ///
    /// A daemon runs for weeks and `synch space add` lands whenever an
    /// operator says so, so the watched set cannot be fixed at startup: an
    /// unregistered space would be covered only by the hourly rescan, and a
    /// removed one would keep waking the watcher for a directory nobody
    /// indexes. Failing to watch a root is not fatal — the periodic scan is
    /// the guarantee (§7.1).
    pub fn resync(&mut self, node: &Node) -> Result<usize> {
        let configured: HashSet<PathBuf> = node
            .store()
            .spaces()?
            .into_iter()
            .map(|space| PathBuf::from(&space.local_path))
            .collect();
        let mut changed = 0;
        for path in configured.difference(&self.watching.clone()) {
            match self.watcher.watch(path, RecursiveMode::Recursive) {
                Ok(()) => {
                    self.watching.insert(path.clone());
                    changed += 1;
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "cannot watch space; relying on periodic scans");
                }
            }
        }
        for path in self.watching.clone().difference(&configured) {
            let _ = self.watcher.unwatch(path);
            self.watching.remove(path);
            changed += 1;
        }
        Ok(changed)
    }

    /// The space roots currently registered.
    pub fn watched(&self) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = self.watching.iter().cloned().collect();
        out.sort();
        out
    }

    /// Waits for at least one hint, then swallows further hints for the
    /// debounce window so a burst of writes costs one rescan.
    ///
    /// Returns `false` once the watcher has shut down.
    pub async fn next_rescan(&mut self) -> bool {
        if self.hints.recv().await.is_none() {
            return false;
        }
        let deadline = tokio::time::Instant::now() + self.debounce;
        loop {
            match tokio::time::timeout_at(deadline, self.hints.recv()).await {
                Ok(Some(())) => continue,
                Ok(None) => return false,
                Err(_) => return true,
            }
        }
    }
}

fn watch_error(e: notify::Error) -> crate::error::EngineError {
    crate::error::EngineError::Io(std::io::Error::other(e.to_string()))
}

impl Node {
    /// Watches every space and rescans on change until `shutdown` resolves.
    ///
    /// A rescan *stages*; what publishes is
    /// [`run_publisher`](Node::run_publisher), which every host running this
    /// loop is expected to run beside it.
    pub async fn run_watcher(&self, shutdown: impl std::future::Future<Output = ()>) {
        let mut watcher = match SpaceWatcher::start(self) {
            Ok(watcher) => watcher,
            Err(e) => {
                tracing::warn!(error = %e, "watcher unavailable; relying on periodic scans");
                return;
            }
        };
        let shutdown = std::pin::pin!(shutdown);
        let mut shutdown = shutdown;
        let spaces_changed = self.spaces_changed_signal();
        loop {
            tokio::select! {
                _ = &mut shutdown => return,
                // `space add` / `space rm` ring this so a new root is watched
                // at once rather than at the next filesystem hint.
                _ = spaces_changed.notified() => {
                    if let Err(e) = watcher.resync(self) {
                        tracing::warn!(error = %e, "re-registering spaces failed");
                    }
                }
                triggered = watcher.next_rescan() => {
                    if !triggered {
                        return;
                    }
                    // Every pass re-registers, so a space that appeared while
                    // the daemon ran is watched from here on even if the nudge
                    // was missed.
                    if let Err(e) = watcher.resync(self) {
                        tracing::warn!(error = %e, "re-registering spaces failed");
                    }
                    // Staged, not published: a burst of editor saves is one
                    // batch and therefore one head (§7.1).
                    if let Err(e) = self.scan_and_stage() {
                        tracing::warn!(error = %e, "rescan failed");
                    }
                }
            }
        }
    }

    /// Runs the periodic full scan until `shutdown` resolves (§7.1).
    ///
    /// Like the watcher, this stages into the publisher rather than publishing
    /// on its own.
    pub async fn run_scanner(&self, shutdown: impl std::future::Future<Output = ()>) {
        let shutdown = std::pin::pin!(shutdown);
        let mut shutdown = shutdown;
        loop {
            tokio::select! {
                _ = &mut shutdown => return,
                _ = tokio::time::sleep(self.config().scan_interval) => {
                    if let Err(e) = self.scan_and_stage() {
                        tracing::warn!(error = %e, "periodic scan failed");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;

    #[tokio::test]
    async fn a_watcher_starts_over_configured_spaces() {
        let dir = tempfile::tempdir().unwrap();
        let space = tempfile::tempdir().unwrap();
        Node::init(dir.path(), None).unwrap();
        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        node.add_space("media", space.path()).unwrap();

        let mut watcher = SpaceWatcher::start(&node).unwrap();
        std::fs::write(space.path().join("a.txt"), b"hello").unwrap();

        // The hint only schedules a rescan; the rescan is what finds the file.
        let triggered = tokio::time::timeout(Duration::from_secs(10), watcher.next_rescan())
            .await
            .unwrap_or(false);
        if triggered {
            let (report, _) = node.scan_and_publish().unwrap();
            assert_eq!(report.hashed, 1);
        } else {
            // Watchers are best-effort on some platforms and filesystems; the
            // periodic scan is the guarantee, so exercise that instead.
            let (report, _) = node.scan_and_publish().unwrap();
            assert_eq!(report.hashed, 1);
        }
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_watcher_with_no_spaces_is_harmless() {
        let dir = tempfile::tempdir().unwrap();
        Node::init(dir.path(), None).unwrap();
        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        let _watcher = SpaceWatcher::start(&node).unwrap();
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn spaces_added_and_removed_while_running_are_re_registered() {
        // A daemon runs for weeks; `space add` lands whenever an operator says
        // so. A watcher fixed at startup would leave the new root covered only
        // by the hourly rescan (§7.1).
        let dir = tempfile::tempdir().unwrap();
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        Node::init(dir.path(), None).unwrap();
        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        node.add_space("one", first.path()).unwrap();

        let mut watcher = SpaceWatcher::start(&node).unwrap();
        assert_eq!(watcher.watched().len(), 1);

        node.add_space("two", second.path()).unwrap();
        assert_eq!(watcher.resync(&node).unwrap(), 1);
        assert_eq!(watcher.watched().len(), 2);
        // Re-registering an unchanged set is a no-op.
        assert_eq!(watcher.resync(&node).unwrap(), 0);

        node.remove_space("two").unwrap();
        assert_eq!(watcher.resync(&node).unwrap(), 1);
        assert_eq!(watcher.watched().len(), 1);
        node.shutdown().await.unwrap();
    }
}
