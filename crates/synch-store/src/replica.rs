//! The replication tables: what a replicated space wants, and what it holds
//! (`docs/REPLICATION.md` §3.3, §3.4).
//!
//! Two rows describe one object's journey through a replica. A `replica_want`
//! row is *intent* — this space needs these bytes and does not have them — and
//! a `pins` row is *possession*. Nothing is ever both: the fetch loop deletes
//! the want and inserts the pin in one transaction, so a crash between them
//! cannot leave a claim standing over content that never arrived.
//!
//! The queries here are deliberately set-shaped rather than row-shaped. A
//! reconciling sweep over a space with four million entries that issued one
//! statement per entry would hold the single write connection for the length of
//! the sweep, and the sweep is a background pass competing with publishes.

use rusqlite::{params, OptionalExtension};
use synch_core::Hash;

use crate::{db::hash_column, db::Store, error::Result, PinHolder};

/// One object a replicated space needs and does not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WantRow {
    /// The object root.
    pub root: Hash,
    /// Which space wants it.
    pub holder: PinHolder,
    /// The object size, from the entry that staged the want.
    pub size: u64,
    /// The root this version replaced, if the entry named one: the delta donor
    /// (`docs/DELTA-SYNC.md` §3.2).
    pub prev: Option<Hash>,
    /// When this was first wanted, in unix nanoseconds.
    pub first_wanted: i64,
    /// How many times a fetch has failed.
    pub attempts: i64,
    /// When the last attempt was made.
    pub last_attempt: Option<i64>,
    /// Why the last attempt failed.
    pub last_error: Option<String>,
}

/// What a replicated space holds, wants, and is about to let go of.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplicaCoverage {
    /// Objects pinned for this space.
    pub held: u64,
    /// Bytes those objects account for.
    pub held_bytes: u64,
    /// Pinned objects with a scheduled release.
    pub releasing: u64,
    /// Bytes those objects account for.
    pub releasing_bytes: u64,
    /// Objects wanted and not yet held.
    pub wanted: u64,
    /// Bytes those objects would add.
    pub wanted_bytes: u64,
    /// Wanted objects that have failed at least `attempts` times.
    pub unreachable: u64,
    /// Bytes those objects would add.
    pub unreachable_bytes: u64,
}

impl Store {
    /// Stages the intent to hold one object.
    ///
    /// Returns whether this was new. A want that already exists keeps its
    /// `first_wanted`, its failure count and its backoff: the same root
    /// arriving again through a second path is not a reason to start the clock
    /// over, and would otherwise let a churning space retry a dead object
    /// forever at full rate.
    pub fn stage_want(
        &self,
        root: &Hash,
        holder: &PinHolder,
        size: u64,
        prev: Option<&Hash>,
        now: i64,
    ) -> Result<bool> {
        let staged = self.conn().execute(
            "INSERT INTO replica_want (root, holder, size, prev, first_wanted)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(root, holder) DO NOTHING",
            params![
                root.as_bytes().to_vec(),
                holder.render(),
                size as i64,
                prev.map(|p| p.as_bytes().to_vec()),
                now
            ],
        )?;
        Ok(staged > 0)
    }

    /// Drops one want, whether it was satisfied or has stopped being wanted.
    pub fn drop_want(&self, root: &Hash, holder: &PinHolder) -> Result<bool> {
        Ok(self.conn().execute(
            "DELETE FROM replica_want WHERE root = ?1 AND holder = ?2",
            params![root.as_bytes().to_vec(), holder.render()],
        )? > 0)
    }

    /// Drops every want one holder has, for `--no-replicate`.
    pub fn drop_wants(&self, holder: &PinHolder) -> Result<usize> {
        Ok(self.conn().execute(
            "DELETE FROM replica_want WHERE holder = ?1",
            params![holder.render()],
        )?)
    }

    /// Retires a want by taking possession, in one transaction.
    ///
    /// The two halves must not be separable. A pin written before the want is
    /// dropped can be seen by a status pass as both held and wanted; a want
    /// dropped before the pin is written leaves a window in which nothing
    /// records that this node means to keep the object, and a GC pass in that
    /// window is entitled to take it.
    pub fn take_possession(&self, root: &Hash, holder: &PinHolder, now: i64) -> Result<bool> {
        self.with_immediate_tx(|tx| {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM blobs WHERE root = ?1)",
                params![root.as_bytes().to_vec()],
                |row| row.get(0),
            )?;
            if !exists {
                return Ok(false);
            }
            tx.execute(
                "DELETE FROM replica_want WHERE root = ?1 AND holder = ?2",
                params![root.as_bytes().to_vec(), holder.render()],
            )?;
            tx.execute(
                "INSERT INTO pins (root, holder, created_at, release_after)
                 VALUES (?1, ?2, ?3, NULL)
                 ON CONFLICT(root, holder) DO UPDATE SET release_after = NULL",
                params![root.as_bytes().to_vec(), holder.render(), now],
            )?;
            Ok(true)
        })
    }

    /// Records that a fetch failed, for the backoff and for the alarm.
    pub fn record_want_failure(
        &self,
        root: &Hash,
        holder: &PinHolder,
        now: i64,
        error: &str,
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE replica_want
                SET attempts = attempts + 1, last_attempt = ?3, last_error = ?4
              WHERE root = ?1 AND holder = ?2",
            params![root.as_bytes().to_vec(), holder.render(), now, error],
        )?;
        Ok(())
    }

    /// The wants worth attempting now, rarest first.
    ///
    /// Rarity is the count of origins advertising the object, ascending, so the
    /// object with one advertised holder outranks the object with nine: a
    /// replica exists to raise the floor on how many copies exist, and the
    /// object with one holder is the one about to be lost when that holder
    /// leaves. Ties go to the oldest want, so nothing starves behind a stream
    /// of equally rare newcomers.
    ///
    /// The backoff is computed per row rather than applied as one threshold,
    /// because the rows differ in how often they have failed: a want on its
    /// first retry and one that has failed all day should not come back at the
    /// same rate. It doubles from `min_backoff` per attempt and stops at
    /// `max_backoff`, both in nanoseconds, and the shift is capped so that a
    /// row that somehow accumulated thousands of attempts cannot overflow it.
    pub fn wants_to_attempt(
        &self,
        now: i64,
        min_backoff: i64,
        max_backoff: i64,
        limit: usize,
    ) -> Result<Vec<WantRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT w.root, w.holder, w.size, w.prev, w.first_wanted,
                    w.attempts, w.last_attempt, w.last_error
               FROM replica_want w
              WHERE w.last_attempt IS NULL
                 OR w.last_attempt
                    + MIN(?2 * (1 << MIN(w.attempts, 12)), ?3) <= ?1
              ORDER BY (SELECT COUNT(*) FROM blob_providers p
                         WHERE p.object_root = w.root AND p.complete != 0) ASC,
                       w.first_wanted ASC
              LIMIT ?4",
        )?;
        let rows = stmt.query_map(
            params![now, min_backoff, max_backoff, limit as i64],
            want_row,
        )?;
        collect_wants(rows)
    }

    /// Every want one holder has, oldest first.
    pub fn wants_of(&self, holder: &PinHolder) -> Result<Vec<WantRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT root, holder, size, prev, first_wanted, attempts, last_attempt, last_error
               FROM replica_want WHERE holder = ?1 ORDER BY first_wanted ASC",
        )?;
        let rows = stmt.query_map(params![holder.render()], want_row)?;
        collect_wants(rows)
    }

    /// Stages a want for every content root a space references that this
    /// holder neither holds nor already wants. Returns how many were new.
    ///
    /// One statement, because the alternative is one statement per entry under
    /// the single write connection. `size` and `prev` come from the entry that
    /// referenced the root: the fetch needs the first to divide the object into
    /// groups and the second as its delta donor, and neither survives the entry
    /// being superseded.
    ///
    /// `DISTINCT` over content rather than over entries: two origins publishing
    /// identical bytes are one object and one want.
    pub fn stage_space_wants(&self, space: &str, holder: &PinHolder, now: i64) -> Result<usize> {
        Ok(self.conn().execute(
            "INSERT INTO replica_want (root, holder, size, prev, first_wanted)
             SELECT DISTINCT e.content, ?2, e.size, e.prev, ?3
               FROM entries e
              WHERE e.space = ?1
                AND e.content IS NOT NULL
                AND NOT EXISTS (SELECT 1 FROM pins p
                                 WHERE p.root = e.content AND p.holder = ?2)
             ON CONFLICT(root, holder) DO NOTHING",
            params![space, holder.render(), now],
        )?)
    }

    /// Clears the scheduled release of anything this holder pins that some
    /// entry names again. Returns how many claims were reprieved.
    ///
    /// Content that comes back is content that stays. The same root reappears
    /// often enough to be worth a statement of its own: another origin
    /// publishing the same bytes, a `take` adopting them, a file restored from
    /// a copy — and in every case the release was decided against a tree that
    /// has since changed its mind.
    pub fn clear_returned_releases(&self, holder: &PinHolder) -> Result<usize> {
        Ok(self.conn().execute(
            "UPDATE pins SET release_after = NULL
              WHERE holder = ?1
                AND release_after IS NOT NULL
                AND EXISTS (SELECT 1 FROM entries WHERE entries.content = pins.root)",
            params![holder.render()],
        )?)
    }

    /// Schedules the release of anything this holder pins that no entry names
    /// any more. Returns how many claims were scheduled.
    ///
    /// The reference test is deliberately global rather than per space: content
    /// is addressed by hash, so a root this space has dropped may still be
    /// named by another space's entry, and releasing it there would be one
    /// space deciding for another. Holding more than strictly necessary is the
    /// safe direction and the only one available without per-space refcounting.
    ///
    /// Callers must satisfy the completeness precondition first
    /// (`docs/REPLICATION.md` §3.6). This statement cannot tell "no entry names
    /// it" from "no entry is materialized right now", and the difference is the
    /// whole store.
    pub fn schedule_stale_releases(&self, holder: &PinHolder, at: i64) -> Result<usize> {
        Ok(self.conn().execute(
            "UPDATE pins SET release_after = ?2
              WHERE holder = ?1
                AND release_after IS NULL
                AND NOT EXISTS (SELECT 1 FROM entries WHERE entries.content = pins.root)",
            params![holder.render(), at],
        )?)
    }

    /// What one space holds and wants, for `space ls <id>`.
    ///
    /// `unreachable_after` is how many failed attempts make a want an alarm
    /// rather than a backlog: those are versions whose last provider left
    /// before this node reached them, and folding them into the backlog is how
    /// a permanent loss reads as a busy afternoon.
    pub fn replica_coverage(
        &self,
        holder: &PinHolder,
        unreachable_after: i64,
    ) -> Result<ReplicaCoverage> {
        let conn = self.conn();
        let holder = holder.render();
        let mut coverage = ReplicaCoverage::default();
        // A pinned root whose blob row has gone — the cloud heal rule withdrew
        // it (`docs/SERVERLESS.md` §6.4), or a downgrade left the claim behind
        // — counts as held-with-no-bytes rather than as nothing. The count and
        // the byte total disagreeing is the visible symptom, and it should be.
        let (held, held_bytes, releasing, releasing_bytes) = conn.query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(COALESCE(b.size, 0)), 0),
                    COALESCE(SUM(p.release_after IS NOT NULL), 0),
                    COALESCE(SUM(CASE WHEN p.release_after IS NOT NULL
                                      THEN COALESCE(b.size, 0) ELSE 0 END), 0)
               FROM pins p LEFT JOIN blobs b ON b.root = p.root
              WHERE p.holder = ?1",
            params![holder],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )?;
        coverage.held = held as u64;
        coverage.held_bytes = held_bytes as u64;
        coverage.releasing = releasing as u64;
        coverage.releasing_bytes = releasing_bytes as u64;

        let (wanted, wanted_bytes, unreachable, unreachable_bytes) = conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(size), 0),
                    COALESCE(SUM(attempts >= ?2), 0),
                    COALESCE(SUM(CASE WHEN attempts >= ?2 THEN size ELSE 0 END), 0)
               FROM replica_want WHERE holder = ?1",
            params![holder, unreachable_after],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )?;
        coverage.wanted = wanted as u64;
        coverage.wanted_bytes = wanted_bytes as u64;
        coverage.unreachable = unreachable as u64;
        coverage.unreachable_bytes = unreachable_bytes as u64;
        Ok(coverage)
    }

    /// The oldest want one holder has, for "oldest 4m ago".
    pub fn oldest_want(&self, holder: &PinHolder) -> Result<Option<i64>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT MIN(first_wanted) FROM replica_want WHERE holder = ?1",
                params![holder.render()],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten())
    }

    /// The soonest scheduled release one holder has, for "oldest leaves in 3d".
    pub fn next_release(&self, holder: &PinHolder) -> Result<Option<i64>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT MIN(release_after) FROM pins
                  WHERE holder = ?1 AND release_after IS NOT NULL",
                params![holder.render()],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten())
    }
}

/// The columns of one `replica_want` row, before they become a [`WantRow`].
type RawWant = (
    Vec<u8>,
    String,
    i64,
    Option<Vec<u8>>,
    i64,
    i64,
    Option<i64>,
    Option<String>,
);

fn want_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawWant> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

fn collect_wants<I>(rows: I) -> Result<Vec<WantRow>>
where
    I: Iterator<Item = rusqlite::Result<RawWant>>,
{
    let mut out = Vec::new();
    for row in rows {
        let (root, holder, size, prev, first_wanted, attempts, last_attempt, last_error) = row?;
        out.push(WantRow {
            root: hash_column(root, "replica_want.root")?,
            holder: PinHolder::parse(&holder),
            size: size as u64,
            prev: prev
                .map(|bytes| hash_column(bytes, "replica_want.prev"))
                .transpose()?,
            first_wanted,
            attempts,
            last_attempt,
            last_error,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{origin, store};
    use crate::ReplicaPolicy;

    fn media() -> PinHolder {
        PinHolder::Replica("media".into())
    }

    #[test]
    fn a_want_becomes_a_pin_and_never_both() {
        let (_dir, store) = store();
        let root = store.ingest_bytes(b"payload", 0).unwrap();
        assert!(store.stage_want(&root, &media(), 7, None, 1).unwrap());
        // Staging the same root twice keeps the first want, so a churning path
        // cannot reset a failing object's backoff.
        assert!(!store.stage_want(&root, &media(), 7, None, 99).unwrap());
        assert_eq!(store.wants_of(&media()).unwrap()[0].first_wanted, 1);

        assert!(store.take_possession(&root, &media(), 2).unwrap());
        assert!(store.wants_of(&media()).unwrap().is_empty());
        assert_eq!(store.pins_for(&root).unwrap().len(), 1);
    }

    #[test]
    fn possession_of_content_that_is_not_here_is_refused() {
        let (_dir, store) = store();
        let absent = synch_core::Hash::new(b"absent");
        store.stage_want(&absent, &media(), 10, None, 1).unwrap();
        assert!(!store.take_possession(&absent, &media(), 2).unwrap());
        // The want survives, because the object is still wanted.
        assert_eq!(store.wants_of(&media()).unwrap().len(), 1);
    }

    #[test]
    fn a_release_is_scheduled_when_nothing_names_the_root_and_cleared_when_something_does() {
        let (_dir, store) = store();
        let root = store.ingest_bytes(b"payload", 0).unwrap();
        store.pin(&root, &media(), 1).unwrap();

        // Nothing references it: scheduled.
        assert_eq!(store.schedule_stale_releases(&media(), 500).unwrap(), 1);
        assert_eq!(store.pins_for(&root).unwrap()[0].release_after, Some(500));
        // Scheduling twice does not push the instant further out.
        assert_eq!(store.schedule_stale_releases(&media(), 900).unwrap(), 0);

        // An entry names it again: reprieved.
        let origin = origin();
        store
            .put_entry(
                &origin,
                "media",
                "a.bin",
                &synch_core::FileEntry::file(7, 1, root, 1),
            )
            .unwrap();
        assert_eq!(store.clear_returned_releases(&media()).unwrap(), 1);
        assert_eq!(store.pins_for(&root).unwrap()[0].release_after, None);
    }

    #[test]
    fn expiry_is_what_removes_a_claim_so_every_other_predicate_stays_timeless() {
        let (_dir, store) = store();
        let root = store.ingest_bytes(b"payload", 0).unwrap();
        store.pin(&root, &media(), 1).unwrap();
        store.schedule_release(&root, &media(), 500).unwrap();
        // Still held: a scheduled release is a plan, not a departure.
        assert!(store.blob(&root).unwrap().unwrap().pinned);
        assert_eq!(store.expire_pins(499).unwrap(), 0);
        assert_eq!(store.expire_pins(500).unwrap(), 1);
        assert!(!store.blob(&root).unwrap().unwrap().pinned);
    }

    #[test]
    fn a_space_sweep_wants_what_its_entries_name_and_skips_what_it_holds() {
        let (_dir, store) = store();
        let held = store.ingest_bytes(b"held", 0).unwrap();
        let missing = synch_core::Hash::new(b"elsewhere");
        let origin = origin();
        store
            .put_entry(
                &origin,
                "media",
                "held.bin",
                &synch_core::FileEntry::file(4, 1, held, 1),
            )
            .unwrap();
        store
            .put_entry(
                &origin,
                "media",
                "missing.bin",
                &synch_core::FileEntry::file(9, 1, missing, 1),
            )
            .unwrap();
        // A different space's entry is not this space's business.
        store
            .put_entry(
                &origin,
                "other",
                "x.bin",
                &synch_core::FileEntry::file(3, 1, synch_core::Hash::new(b"other"), 1),
            )
            .unwrap();
        store.pin(&held, &media(), 1).unwrap();

        assert_eq!(store.stage_space_wants("media", &media(), 5).unwrap(), 1);
        let wants = store.wants_of(&media()).unwrap();
        assert_eq!(wants.len(), 1);
        assert_eq!(wants[0].root, missing);
        assert_eq!(wants[0].size, 9);
    }

    #[test]
    fn a_failed_want_waits_longer_each_time() {
        let (_dir, store) = store();
        let root = synch_core::Hash::new(b"far away");
        let holder = media();
        store.stage_want(&root, &holder, 10, None, 0).unwrap();
        let (min, max) = (60_000_000_000, 6 * 3600 * 1_000_000_000);
        // Never attempted: ready immediately.
        assert_eq!(store.wants_to_attempt(0, min, max, 8).unwrap().len(), 1);

        store
            .record_want_failure(&root, &holder, 1_000, "no provider")
            .unwrap();
        assert!(store
            .wants_to_attempt(1_000, min, max, 8)
            .unwrap()
            .is_empty());
        assert_eq!(
            store
                .wants_to_attempt(1_000 + min, min, max, 8)
                .unwrap()
                .len(),
            1
        );

        // A second failure doubles the wait rather than repeating it.
        store
            .record_want_failure(&root, &holder, 2_000, "no provider")
            .unwrap();
        assert!(store
            .wants_to_attempt(2_000 + min, min, max, 8)
            .unwrap()
            .is_empty());
        assert_eq!(
            store
                .wants_to_attempt(2_000 + 2 * min, min, max, 8)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn coverage_separates_a_backlog_from_a_loss() {
        let (_dir, store) = store();
        let held = store.ingest_bytes(b"held", 0).unwrap();
        store.pin(&held, &media(), 1).unwrap();
        let fresh = synch_core::Hash::new(b"fresh");
        let doomed = synch_core::Hash::new(b"doomed");
        store.stage_want(&fresh, &media(), 100, None, 1).unwrap();
        store.stage_want(&doomed, &media(), 200, None, 1).unwrap();
        for _ in 0..5 {
            store
                .record_want_failure(&doomed, &media(), 2, "no provider")
                .unwrap();
        }
        let coverage = store.replica_coverage(&media(), 5).unwrap();
        assert_eq!(coverage.held, 1);
        assert_eq!(coverage.held_bytes, 4);
        assert_eq!(coverage.wanted, 2);
        assert_eq!(coverage.wanted_bytes, 300);
        assert_eq!(coverage.unreachable, 1);
        assert_eq!(coverage.unreachable_bytes, 200);
    }

    #[test]
    fn replication_is_a_property_of_a_space_and_the_two_halves_are_independent() {
        let (_dir, store) = store();
        store.put_space("media", Some("/srv/media")).unwrap();
        store
            .set_space_replication("media", Some(ReplicaPolicy::Tree), Some(60), None)
            .unwrap();
        let space = store.space("media").unwrap().unwrap();
        assert_eq!(space.local_path.as_deref(), Some("/srv/media"));
        assert_eq!(space.replicate, Some(ReplicaPolicy::Tree));
        assert_eq!(space.grace_secs(), 60);

        // Re-pointing the checkout leaves the replication half alone.
        store.put_space("media", Some("/srv/media2")).unwrap();
        let space = store.space("media").unwrap().unwrap();
        assert_eq!(space.replicate, Some(ReplicaPolicy::Tree));

        // And turning replication off leaves the checkout alone.
        store
            .set_space_replication("media", None, None, None)
            .unwrap();
        let space = store.space("media").unwrap().unwrap();
        assert_eq!(space.local_path.as_deref(), Some("/srv/media2"));
        assert!(space.replicate.is_none());
        assert_eq!(space.grace_secs(), crate::DEFAULT_REPLICA_GRACE_SECS);
    }
}
