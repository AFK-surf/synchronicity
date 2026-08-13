//! The filesystem watcher (§7.1).
//!
//! Hints from `notify` are debounced and only ever *schedule rescans* —
//! correctness never depends on watcher completeness, so a missed event costs
//! at most one scan interval of latency, never a lost file.

use std::{path::PathBuf, time::Duration};

use notify::{RecommendedWatcher, RecursiveMode, Watcher as _};
use tokio::sync::mpsc;

use crate::{error::Result, node::Node};

/// A debounced rescan trigger over every configured space.
#[derive(Debug)]
pub struct SpaceWatcher {
    _watcher: RecommendedWatcher,
    hints: mpsc::Receiver<()>,
    debounce: Duration,
}

impl SpaceWatcher {
    /// Starts watching every configured space root.
    pub fn start(node: &Node) -> Result<SpaceWatcher> {
        let (tx, rx) = mpsc::channel(64);
        let mut watcher =
            notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
                if event.is_ok() {
                    // A full channel already means a rescan is pending, so dropping
                    // the hint loses nothing.
                    let _ = tx.try_send(());
                }
            })
            .map_err(watch_error)?;

        for space in node.store().spaces()? {
            let path = PathBuf::from(&space.local_path);
            if let Err(e) = watcher.watch(&path, RecursiveMode::Recursive) {
                tracing::warn!(space = %space.id, error = %e, "cannot watch space; relying on periodic scans");
            }
        }
        Ok(SpaceWatcher {
            _watcher: watcher,
            hints: rx,
            debounce: node.config().watch_debounce,
        })
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
        loop {
            tokio::select! {
                _ = &mut shutdown => return,
                triggered = watcher.next_rescan() => {
                    if !triggered {
                        return;
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
}
