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

/// How many candidates to consider per fetch slot when ranking by rarity.
///
/// Rarity has to be ranked over *something*, and ranking over the whole queue
/// is what makes it quadratic. Eight oldest-ready candidates per slot is enough
/// for the rare object in a batch to win without the pass reading the queue.
const RARITY_WINDOW: usize = 8;

/// The §3.6 precondition, as a SQL predicate.
///
/// True when this node's picture of what the cluster publishes is a faithful
/// one: no head is sitting pending — its origin's entries are absent or stale
/// while it does — and no bound origin is missing a complete head, which would
/// mean this node has never materialized what that member publishes. Either
/// makes "no entry names this root" mean "I do not know", and a release decided
/// from that is a release decided from ignorance.
/// "Some origin other than this one", for counting *other* holders.
///
/// A node advertises its own `b:` records like any other origin, so a provider
/// count that includes itself answers "does anyone have this?" with "I do" —
/// and a replica deciding whether it may be the last holder to let go would
/// always find one holder left, itself. The brake would then never engage at
/// its default.
const NOT_SELF: &str = "origin_id != COALESCE(
        (SELECT value FROM config WHERE key = 'self_origin_id'), '')";

const VIEW_IS_COMPLETE: &str = "NOT EXISTS (SELECT 1 FROM heads WHERE slot = 'pending')
     AND NOT EXISTS (
           SELECT 1 FROM bindings b
            WHERE b.origin_id != COALESCE(
                    (SELECT value FROM config WHERE key = 'self_origin_id'), '')
              AND NOT EXISTS (SELECT 1 FROM heads h
                               WHERE h.origin_id = b.origin_id AND h.slot = 'complete'))";

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
            // Held, not merely known. A `blobs` row exists for a partial fetch
            // too, so a row alone would let a claim stand over a 0%-complete
            // object — exactly what this function's own doc says cannot happen.
            // The predicate is `pin_object`'s, and it belongs in the store
            // rather than in the discipline of every caller.
            let held: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM blobs
                                WHERE root = ?1 AND (complete != 0 OR durable != 0))",
                params![root.as_bytes().to_vec()],
                |row| row.get(0),
            )?;
            if !held {
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

    /// The wants worth attempting now, rarest first, drawn per space.
    ///
    /// Returns a ranked *window* rather than exactly `limit` rows: `limit` is
    /// how many the caller means to start, and it may decline some of them.
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
    /// same rate. The first retry waits `min_backoff`, each failure after that
    /// doubles the wait, and it stops at `max_backoff` — both in nanoseconds.
    /// The shift is taken off `attempts - 1` so the first wait is the minimum
    /// rather than twice it, and capped so that a row which somehow
    /// accumulated thousands of attempts cannot overflow it.
    pub fn wants_to_attempt(
        &self,
        now: i64,
        min_backoff: i64,
        max_backoff: i64,
        limit: usize,
    ) -> Result<Vec<WantRow>> {
        let mut candidates = Vec::new();
        for space in self.replicated_spaces()? {
            candidates.extend(self.wants_ready_of(
                &space.holder(),
                now,
                min_backoff,
                max_backoff,
                limit * RARITY_WINDOW,
            )?);
        }
        // Ranked, not truncated: the caller may skip some — a want larger than
        // a space's remaining budget, say — and truncating here would leave it
        // nothing to fall back on, so a space near its ceiling would stop
        // fetching entirely rather than take the smaller wants that still fit.
        self.rank_rarest_first(candidates)
    }

    /// One holder's oldest ready wants, in `first_wanted` order.
    ///
    /// Filtered by holder, which is what lets SQLite walk
    /// `replica_want_by_holder` and stop as soon as it has enough. A global
    /// `ORDER BY first_wanted` over a holder-leading index cannot be served by
    /// it: the plan is a scan of the whole queue plus a temp-B-tree sort, on
    /// every pass, on the one write connection that publishes and GC also want.
    /// Per holder is also what keeps a space with a large old backlog from
    /// starving every other replicated space.
    pub fn wants_ready_of(
        &self,
        holder: &PinHolder,
        now: i64,
        min_backoff: i64,
        max_backoff: i64,
        limit: usize,
    ) -> Result<Vec<WantRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT root, holder, size, prev, first_wanted, attempts, last_attempt, last_error
               FROM replica_want
              WHERE holder = ?1
                AND (last_attempt IS NULL
                     OR last_attempt
                        + MIN(?3 * (1 << MIN(MAX(attempts - 1, 0), 12)), ?4) <= ?2)
              ORDER BY first_wanted ASC
              LIMIT ?5",
        )?;
        let rows = stmt.query_map(
            params![holder.render(), now, min_backoff, max_backoff, limit as i64],
            want_row,
        )?;
        collect_wants(rows)
    }

    /// Ranks a bounded candidate set rarest-first.
    ///
    /// One indexed count per candidate — tens of seeks, not a scan of the whole
    /// queue. Rarity counts the *other* origins advertising a complete copy, so
    /// the object with one advertised holder outranks the object with nine: a
    /// replica exists to raise the floor on how many copies exist, and the
    /// object with one holder is the one about to be lost when that holder
    /// leaves. Ties go to the oldest want, so nothing starves behind a stream
    /// of equally rare newcomers.
    pub fn rank_rarest_first(&self, mut candidates: Vec<WantRow>) -> Result<Vec<WantRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT COUNT(*) FROM blob_providers
              WHERE object_root = ?1 AND complete != 0 AND {NOT_SELF}"
        ))?;
        let mut ranked = Vec::with_capacity(candidates.len());
        for want in candidates.drain(..) {
            let holders: i64 =
                stmt.query_row(params![want.root.as_bytes().to_vec()], |row| row.get(0))?;
            ranked.push((holders, want));
        }
        ranked.sort_by_key(|(holders, want)| (*holders, want.first_wanted));
        Ok(ranked.into_iter().map(|(_, want)| want).collect())
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
    /// `DISTINCT` reduces the common case — several origins publishing the same
    /// bytes at the same size and lineage collapse to one row — but it is over
    /// the projected tuple, so two origins whose entries disagree about `prev`
    /// still produce two. What makes that harmless is the conflict clause: one
    /// want per `(root, holder)` survives either way, and which donor hint it
    /// keeps is not worth a second statement to make deterministic.
    pub fn stage_space_wants(&self, space: &str, holder: &PinHolder, now: i64) -> Result<usize> {
        self.with_immediate_tx(|tx| {
            // Content already held durably needs a claim, not a fetch. A
            // replicated space that also has a checkout would otherwise queue a
            // want for every file it publishes itself — bytes it just ingested
            // — and send each one round the fetch loop to discover that. Gated
            // on `durable` rather than `complete`, because on a cloud backend a
            // pin is a promise about the durable tier and a cache entry is not
            // one (`docs/SERVERLESS.md` §6.3).
            tx.execute(
                "INSERT INTO pins (root, holder, created_at, release_after)
                 SELECT DISTINCT e.content, ?2, ?3, NULL
                   FROM entries e
                   JOIN blobs b ON b.root = e.content
                  WHERE e.space = ?1 AND e.content IS NOT NULL AND b.durable != 0
                 ON CONFLICT(root, holder) DO NOTHING",
                params![space, holder.render(), now],
            )?;
            // Whatever was just pinned stops being wanted. Without this the two
            // rows coexist — held and wanted at once, which this module's
            // header says cannot happen — and `replica_coverage` counts the
            // object in both totals while `complete` stays false for ever.
            tx.execute(
                "DELETE FROM replica_want
                  WHERE holder = ?1
                    AND EXISTS (SELECT 1 FROM pins p
                                 WHERE p.root = replica_want.root AND p.holder = ?1)",
                params![holder.render()],
            )?;
            Ok(tx.execute(
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
        })
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
    /// The completeness precondition (`docs/REPLICATION.md` §3.6) is part of the
    /// statement rather than a check the caller makes first, because a check
    /// the caller makes first is a check that can go stale: an operator's
    /// `scope set` landing between it and this update commits `set_read_scope`'s
    /// wholesale delete of every foreign origin's entries, after which this
    /// would schedule a release for every root only those entries named. As one
    /// statement the two cannot separate. [`Node::view_state`] answers the same
    /// question for reporting, and says *why* when the answer is no.
    pub fn schedule_stale_releases(&self, holder: &PinHolder, at: i64) -> Result<usize> {
        Ok(self.conn().execute(
            &format!(
                "UPDATE pins SET release_after = ?2
                  WHERE holder = ?1
                    AND release_after IS NULL
                    AND NOT EXISTS (SELECT 1 FROM entries WHERE entries.content = pins.root)
                    AND {VIEW_IS_COMPLETE}"
            ),
            params![holder.render(), at],
        )?)
    }

    /// Schedules a stale root's release only where enough other origins
    /// advertise a complete copy of it (`docs/REPLICATION.md` §3.6, §4.3).
    ///
    /// The conservative half of what peers' assertions may be used for. A claim
    /// or an ad may make this node *keep* bytes and may never make it drop
    /// them, so this can only ever hold more than the unguarded form would —
    /// which is why it is safe to build on data a peer supplies and the
    /// releasing form of the same idea is not.
    ///
    /// `floor` is how many distinct origins must advertise the whole object
    /// before this node will let its own copy go. Zero disables the brake.
    pub fn schedule_stale_releases_above(
        &self,
        holder: &PinHolder,
        at: i64,
        floor: i64,
    ) -> Result<usize> {
        if floor <= 0 {
            return self.schedule_stale_releases(holder, at);
        }
        Ok(self.conn().execute(
            &format!(
                "UPDATE pins SET release_after = ?2
                  WHERE holder = ?1
                    AND release_after IS NULL
                    AND NOT EXISTS (SELECT 1 FROM entries WHERE entries.content = pins.root)
                    AND (SELECT COUNT(*) FROM blob_providers p
                          WHERE p.object_root = pins.root AND p.complete != 0
                            AND p.{NOT_SELF}) >= ?3
                    AND {VIEW_IS_COMPLETE}"
            ),
            params![holder.render(), at, floor],
        )?)
    }

    /// Held objects this holder would release but for the brake, so a status
    /// report can say the number out loud rather than let it look like nothing.
    pub fn held_back_by_replication_floor(&self, holder: &PinHolder, floor: i64) -> Result<u64> {
        if floor <= 0 {
            return Ok(0);
        }
        // The view predicate is here too, so a paused view is never reported as
        // the replication floor holding things back: they are different reasons
        // and `space ls` prints them on different lines.
        Ok(self.conn().query_row(
            &format!(
                "SELECT COUNT(*) FROM pins
                  WHERE holder = ?1
                    AND release_after IS NULL
                    AND NOT EXISTS (SELECT 1 FROM entries WHERE entries.content = pins.root)
                    AND (SELECT COUNT(*) FROM blob_providers p
                          WHERE p.object_root = pins.root AND p.complete != 0
                            AND p.{NOT_SELF}) < ?2
                    AND {VIEW_IS_COMPLETE}"
            ),
            params![holder.render(), floor],
            |row| row.get::<_, i64>(0),
        )? as u64)
    }

    /// Bytes held for one holder, by the origin whose entry names the content.
    ///
    /// For the operator question a budget raises but does not answer: *whose*
    /// content grew. A member can publish anything and every replica of that
    /// space fetches it, which is the membership trust model working as
    /// designed — and a reason to be able to see it happening.
    pub fn held_bytes_by_origin(&self, holder: &PinHolder) -> Result<Vec<(String, u64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT e.origin_id, SUM(b.size)
               FROM pins p
               JOIN blobs b ON b.root = p.root
               JOIN (SELECT DISTINCT origin_id, content FROM entries WHERE content IS NOT NULL) e
                 ON e.content = p.root
              WHERE p.holder = ?1
              GROUP BY e.origin_id
              ORDER BY SUM(b.size) DESC",
        )?;
        let rows = stmt.query_map(params![holder.render()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (origin, bytes) = row?;
            out.push((origin, bytes));
        }
        Ok(out)
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

    /// When this holder's oldest claim was made — how long it has been holding
    /// the space, without a second timestamp to keep in agreement with it.
    pub fn oldest_pin(&self, holder: &PinHolder) -> Result<Option<i64>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT MIN(created_at) FROM pins WHERE holder = ?1",
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
        assert_eq!(
            store.wants_ready_of(&holder, 0, min, max, 8).unwrap().len(),
            1
        );

        store
            .record_want_failure(&root, &holder, 1_000, "no provider")
            .unwrap();
        assert!(store
            .wants_ready_of(&holder, 1_000, min, max, 8)
            .unwrap()
            .is_empty());
        assert_eq!(
            store
                .wants_ready_of(&holder, 1_000 + min, min, max, 8)
                .unwrap()
                .len(),
            1
        );

        // A second failure doubles the wait rather than repeating it.
        store
            .record_want_failure(&root, &holder, 2_000, "no provider")
            .unwrap();
        assert!(store
            .wants_ready_of(&holder, 2_000 + min, min, max, 8)
            .unwrap()
            .is_empty());
        assert_eq!(
            store
                .wants_ready_of(&holder, 2_000 + 2 * min, min, max, 8)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn a_release_is_refused_while_a_head_sits_pending() {
        let (_dir, store) = store();
        let first = store.ingest_bytes(b"payload", 0).unwrap();
        store.pin(&first, &media(), 1).unwrap();

        // With a complete view, an unreferenced root is scheduled.
        assert_eq!(store.schedule_stale_releases(&media(), 500).unwrap(), 1);

        // A pending head means that origin's entries are absent or stale, so
        // "nothing names this root" becomes ignorance rather than evidence.
        // The check is part of the statement, not a precondition a caller can
        // read and then act on after it has gone stale.
        let key = iroh_base::SecretKey::generate();
        let head = crate::testutil::sign_head(&key, 1, 7);
        store
            .put_head(crate::heads::Slot::Pending, &head, 1, 1)
            .unwrap();
        let second = store.ingest_bytes(b"another payload", 0).unwrap();
        store.pin(&second, &media(), 1).unwrap();
        assert_eq!(store.schedule_stale_releases(&media(), 500).unwrap(), 0);
        assert_eq!(store.pins_for(&second).unwrap()[0].release_after, None);
    }

    #[test]
    fn a_release_is_refused_while_a_bound_origin_has_published_nothing_here() {
        let (_dir, store) = store();
        let root = store.ingest_bytes(b"payload", 0).unwrap();
        store.pin(&root, &media(), 1).unwrap();

        // A member this node admits but has never synced: its entries are
        // missing, not deleted.
        let key = iroh_base::SecretKey::generate().public();
        store
            .put_binding(&crate::Binding {
                origin: origin(),
                node_id: key,
                source: crate::BindingSource::Static,
                domain: None,
                issuer: None,
                spaces: Vec::new(),
                note: None,
                added_at: 0,
                expires_at: None,
            })
            .unwrap();
        assert_eq!(store.schedule_stale_releases(&media(), 500).unwrap(), 0);
    }

    #[test]
    fn content_already_held_is_pinned_rather_than_queued() {
        let (_dir, store) = store();
        let held = store.ingest_bytes(b"already here", 0).unwrap();
        store
            .put_entry(
                &origin(),
                "media",
                "mine.bin",
                &synch_core::FileEntry::file(12, 1, held, 1),
            )
            .unwrap();

        // A replicated space that also has a checkout publishes its own files;
        // the bytes are in the CAS the moment the entry is. Sending them round
        // the fetch loop to discover that is work nobody needs.
        assert_eq!(store.stage_space_wants("media", &media(), 5).unwrap(), 0);
        assert!(store.wants_of(&media()).unwrap().is_empty());
        assert_eq!(store.pins_for(&held).unwrap().len(), 1);
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
            .set_space_policy("media", Some(ReplicaPolicy::Tree))
            .unwrap();
        store.set_space_grace("media", 60).unwrap();
        let space = store.space("media").unwrap().unwrap();
        assert_eq!(space.local_path.as_deref(), Some("/srv/media"));
        assert_eq!(space.replicate, Some(ReplicaPolicy::Tree));
        assert_eq!(space.grace_secs(), 60);

        // Re-pointing the checkout leaves the replication half alone.
        store.put_space("media", Some("/srv/media2")).unwrap();
        let space = store.space("media").unwrap().unwrap();
        assert_eq!(space.replicate, Some(ReplicaPolicy::Tree));

        // And turning replication off leaves the checkout alone.
        store.set_space_policy("media", None).unwrap();
        let space = store.space("media").unwrap().unwrap();
        assert_eq!(space.local_path.as_deref(), Some("/srv/media2"));
        assert!(space.replicate.is_none());
        // The grace window survives the policy being cleared, because the two
        // are set separately: turning replication back on must not silently
        // hand the space a different recovery window from the one configured.
        assert_eq!(space.grace_secs(), 60);
    }
}
