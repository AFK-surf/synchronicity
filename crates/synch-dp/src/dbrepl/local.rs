//! Retention for the capture spool, not for the durable replica stream.
//!
//! celld-ltx captures and uploads segments but leaves local retention to its
//! embedder. Keeping every uploaded segment eventually exhausts the shard's
//! bytes or inodes. Only older acknowledged segments are disposable: the
//! newest local segment is also the library's continuity/reopen baseline.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use celld_ltx::{Replica, ReplicaClient};

pub(super) struct LocalSegments {
    next_scan: tokio::time::Instant,
    pruned_to: u64,
}

impl LocalSegments {
    pub(super) fn new() -> Self {
        Self {
            next_scan: tokio::time::Instant::now(),
            pruned_to: 0,
        }
    }

    /// Runs on the replica's owner thread, between captures and uploads.
    /// A failed upload cannot advance the acknowledged frontier. Even a
    /// committed upload whose response was lost keeps its local segment.
    pub(super) fn prune<C: ReplicaClient>(&mut self, replica: &Replica<C>) -> io::Result<()> {
        let durable = replica.pos().txid.0;
        let now = tokio::time::Instant::now();
        if durable <= self.pruned_to || now < self.next_scan {
            return Ok(());
        }
        // Bound scans and retries, including when the filesystem is unhealthy.
        // Unchanged tenants never rescan their directories.
        self.next_scan = now + Duration::from_secs(60);
        let db = replica.db().expect("a replicator owns its database");
        let directory = celld_ltx::ltx_level_dir(&db.meta_path().to_string_lossy(), 0);
        let mut segments: Vec<(u64, PathBuf)> = Vec::new();
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if let Ok((_, max)) = celld_ltx::ltx::parse_filename(name) {
                segments.push((max.0, entry.path()));
            }
        }
        // Also retain the newest local file if a future library version ever
        // reports a remote position ahead of its local capture position.
        let newest = segments.iter().map(|(txid, _)| *txid).max().unwrap_or(0);
        let before = durable.min(newest);
        for (txid, path) in segments {
            if txid < before {
                std::fs::remove_file(path)?;
            }
        }
        self.pruned_to = durable;
        Ok(())
    }
}
