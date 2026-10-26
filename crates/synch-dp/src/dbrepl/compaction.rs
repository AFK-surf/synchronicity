//! Progress for this shard's sole writer of each tenant's compaction levels.
//!
//! `celld-ltx` does the merge and continuity checks. Its stateless entry point
//! lists the whole destination level to find its last transaction on every
//! invocation. Hydrate that frontier once, then advance it only after a
//! successful publication. The cache holds at most one file per level; it is
//! never used by restore, collection, or the L0 shipper.

use std::sync::atomic::{AtomicBool, Ordering};

use celld_ltx::replica_compactor::{CompactionOutput, ReplicaCompactor};
use celld_ltx::{FileInfo, ReplicaClient, TXID};

#[derive(Debug, Default)]
pub(super) struct Compaction {
    // Outer None is unknown; Some(None) is a known-empty destination.
    frontiers: [Option<Option<FileInfo>>; 3],
}

impl Compaction {
    pub(super) async fn compact<C: ReplicaClient>(
        &mut self,
        client: &C,
        level: i32,
        published: u64,
    ) -> celld_ltx::Result<Option<CompactionOutput>> {
        let index = match level {
            1..=3 => (level - 1) as usize,
            _ => return Err(invalid("unexpected hosted compaction level")),
        };
        if self.frontiers[index].is_none() {
            let files = client.ltx_files(level, TXID(0)).await?;
            self.frontiers[index] = Some(files.into_iter().max_by_key(|file| file.max_txid));
        }
        let previous = self.frontiers[index].as_ref().unwrap().as_ref();
        let max = previous.map_or(0, |file| file.max_txid.0);
        let source_max = if index == 0 {
            (published != 0).then_some(published)
        } else {
            self.frontiers[index - 1]
                .as_ref()
                .map(|frontier| frontier.as_ref().map_or(0, |file| file.max_txid.0))
        };
        if source_max.is_some_and(|source| source <= max) {
            return Ok(None);
        }

        let pass = CompactionPass {
            client,
            level,
            previous,
            publishing: AtomicBool::new(false),
        };
        let result = ReplicaCompactor::new(&pass)
            .with_limits(256, 64 * 1024 * 1024)
            .compact(level)
            .await;
        let publishing = pass.publishing.load(Ordering::Relaxed);
        match &result {
            Ok(Some(output)) => self.frontiers[index] = Some(Some(output.info.clone())),
            // The remote may have accepted a PUT whose response was lost.
            // Re-read its frontier before choosing the next immutable key.
            Err(_) if publishing => self.frontiers[index] = None,
            _ => {}
        }
        result
    }
}

/// A private adapter for *one* call to ReplicaCompactor::compact. That call
/// needs only the greatest destination TXID, not a catalog of its history.
/// Its destination listing therefore projects the known frontier; source
/// enumeration and all data IO still use the real client. This is deliberately
/// not a general ReplicaClient: unexpected listing/deletion calls fail closed,
/// and it must never be passed to restore or verify_level.
struct CompactionPass<'a, C> {
    client: &'a C,
    level: i32,
    previous: Option<&'a FileInfo>,
    publishing: AtomicBool,
}

fn invalid(message: &str) -> celld_ltx::Error {
    celld_ltx::Error::Other(message.into())
}

#[async_trait::async_trait]
impl<C: ReplicaClient> ReplicaClient for CompactionPass<'_, C> {
    async fn ltx_files(&self, level: i32, seek: TXID) -> celld_ltx::Result<Vec<FileInfo>> {
        if level != self.level || seek != TXID(0) {
            return Err(invalid("unexpected compaction destination listing"));
        }
        Ok(self.previous.into_iter().cloned().collect())
    }

    async fn ltx_files_bounded(
        &self,
        level: i32,
        seek: TXID,
        limit: usize,
    ) -> celld_ltx::Result<Vec<FileInfo>> {
        if level != self.level - 1 {
            return Err(invalid("unexpected compaction source listing"));
        }
        self.client.ltx_files_bounded(level, seek, limit).await
    }

    async fn open_ltx_file(&self, level: i32, min: TXID, max: TXID) -> celld_ltx::Result<Vec<u8>> {
        self.client.open_ltx_file(level, min, max).await
    }

    async fn write_ltx_file(
        &self,
        level: i32,
        min: TXID,
        max: TXID,
        data: &[u8],
    ) -> celld_ltx::Result<FileInfo> {
        if level != self.level {
            return Err(invalid("unexpected compaction publication level"));
        }
        self.publishing.store(true, Ordering::Relaxed);
        self.client.write_ltx_file(level, min, max, data).await
    }

    async fn delete_ltx_files(&self, _: &[FileInfo]) -> celld_ltx::Result<()> {
        Err(invalid("hosted compaction must preserve source objects"))
    }

    async fn delete_all(&self) -> celld_ltx::Result<()> {
        Err(invalid("hosted compaction must preserve source objects"))
    }
}
