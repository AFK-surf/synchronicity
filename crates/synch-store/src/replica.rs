//! The replication tables: what a replica wants, and what it holds
//! (`docs/REPLICATION.md` §3.3, §3.4).
//!
//! Two rows describe one object's journey through a replica. A `content_want`
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

/// "Some origin other than this one", for counting *other* holders.
///
/// A node advertises its own `b:` records like any other origin, so a provider
/// count that includes itself answers "does anyone have this?" with "I do" —
/// and a replica deciding whether it may be the last holder to let go would
/// always find one holder left, itself. The brake would then never engage at
/// its default.
pub(crate) const NOT_SELF: &str = "origin_id != COALESCE(
        (SELECT value FROM config WHERE key = 'self_origin_id'), '')";

use rusqlite::{params, OptionalExtension};
use synch_core::Hash;

use crate::{db::hash_column, db::Store, error::Result, PinHolder};

/// One object a replica needs and does not hold.
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

/// What a replica holds, wants, and is about to let go of.
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
            "INSERT INTO content_want (root, holder, size, prev, first_wanted)
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
        // LEAN-MODEL: cas-drop-want (Cas.DropWant)
        // `Cas.DropWant` requires the replica leaf to have left the
        // materialized active view before its unsatisfied intent is retired;
        // the entry guard makes that requirement local to this DELETE.
        Ok(self.conn().execute(
            "DELETE FROM content_want
              WHERE root = ?1 AND holder = ?2
                AND NOT EXISTS (
                  SELECT 1 FROM entries WHERE entries.content = content_want.root
                )",
            params![root.as_bytes().to_vec(), holder.render()],
        )? > 0)
    }

    /// Retires a want by taking possession, in one transaction.
    ///
    /// The two halves must not be separable. A pin written before the want is
    /// dropped can be seen by a status pass as both held and wanted; a want
    /// dropped before the pin is written leaves a window in which nothing
    /// records that this node means to keep the object, and a GC pass in that
    /// window is entitled to take it.
    pub fn take_possession(&self, root: &Hash, holder: &PinHolder, now: i64) -> Result<bool> {
        self.acquire_pin(root, holder, now, true)
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
            "UPDATE content_want
                SET attempts = attempts + 1, last_attempt = ?3, last_error = ?4
              WHERE root = ?1 AND holder = ?2",
            params![root.as_bytes().to_vec(), holder.render(), now, error],
        )?;
        Ok(())
    }

    /// The wants worth attempting now, rarest first, drawn per space.
    ///
    /// Returns a ranked *window* rather than exactly `limit` rows: `limit` is
    /// how many the caller keeps in flight, and it may decline some candidates.
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
    /// `rotate` is which space leads this round. The interleave is fair over
    /// the whole window, but the first `limit` rows occupy the initial
    /// concurrency slots, and `replicas` is ordered by id. Advancing it by one
    /// per pass keeps the same spaces from always leading those slots.
    pub fn wants_to_attempt(
        &self,
        now: i64,
        min_backoff: i64,
        max_backoff: i64,
        limit: usize,
        rotate: usize,
    ) -> Result<Vec<WantRow>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        // Ranked within a space, then interleaved across them. Ranking the
        // pooled candidates globally is what §3.3 first specified and it
        // starves: a space bootstrapping four million equally-rare objects
        // sorts ahead of every newer want in every other space, so a space
        // added afterwards fetches nothing until the first one drains — months,
        // at four objects a pass. Rarity is the right order *within* a space;
        // between spaces the only defensible order is a turn each.
        let mut holders = Vec::new();
        for source in self.sources()? {
            holders.push(PinHolder::Source(source.space));
        }
        for space in self.replicas()? {
            holders.push(space.holder());
        }
        let holder_count = holders.len();
        if holder_count > 0 {
            holders.rotate_left(rotate % holder_count);
        }
        // Engine-side policy decides whether a ready want fits its holder's
        // remaining budget, so every holder must contribute at least one
        // candidate in this pass. Otherwise empty, backed-off, or over-budget
        // holders inside an early slice hide healthy work behind them. Divide
        // the rolling window between all holders instead of asking every one
        // for a full window: candidate memory is O(holders + window), not the
        // old O(holders * window).
        let window = limit.saturating_mul(RARITY_WINDOW);
        let per_holder_limit = window.div_ceil(holders.len().max(1)).max(1);
        let mut per_space = Vec::with_capacity(holders.len());
        for holder in holders {
            let ready =
                self.wants_ready_of(&holder, now, min_backoff, max_backoff, per_holder_limit)?;
            if !ready.is_empty() {
                per_space.push(self.rank_rarest_first(ready)?.into_iter());
            }
        }
        // Interleaved, not truncated: the caller may decline some — a want
        // larger than a space's remaining budget, say — so it is handed a
        // ranked window rather than exactly `limit` rows.
        let mut out = Vec::new();
        loop {
            // Every space advances on every round. `any` will not do here: it
            // short-circuits on the first space that still has a want, so the
            // loop restarts at that space each time and emits its whole window
            // before touching the next — a concatenation wearing a
            // round-robin's shape, which is exactly the starvation this exists
            // to prevent.
            let mut progressed = false;
            for space in per_space.iter_mut() {
                if let Some(want) = space.next() {
                    out.push(want);
                    progressed = true;
                }
            }
            if !progressed {
                break;
            }
        }
        Ok(out)
    }

    /// Ready wants for one holder, rarity-ranked. Used by an explicit
    /// `replica sync <space>` so work for unrelated roles cannot consume its
    /// bounded pass.
    pub fn wants_to_attempt_of(
        &self,
        holder: &PinHolder,
        now: i64,
        min_backoff: i64,
        max_backoff: i64,
        limit: usize,
    ) -> Result<Vec<WantRow>> {
        let ready = self.wants_ready_of(
            holder,
            now,
            min_backoff,
            max_backoff,
            limit.saturating_mul(RARITY_WINDOW),
        )?;
        self.rank_rarest_first(ready)
    }

    /// One holder's oldest ready wants, in `first_wanted` order.
    ///
    /// Filtered by holder, which is what lets SQLite walk
    /// `content_want_by_holder` and stop as soon as it has enough. A global
    /// `ORDER BY first_wanted` over a holder-leading index cannot be served by
    /// it: the plan is a scan of the whole queue plus a temp-B-tree sort, on
    /// every pass, on the one write connection that publishes and GC also want.
    /// Fairness between spaces is [`Store::wants_to_attempt`]'s job, not this
    /// one's: this returns one space's window, and the caller interleaves.
    pub(crate) fn wants_ready_of(
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
               FROM content_want
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
    pub(crate) fn rank_rarest_first(&self, mut candidates: Vec<WantRow>) -> Result<Vec<WantRow>> {
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
               FROM content_want WHERE holder = ?1 ORDER BY first_wanted ASC",
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
            // replica that also has a checkout would otherwise queue a
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
                "DELETE FROM content_want
                  WHERE holder = ?1
                    AND EXISTS (SELECT 1 FROM pins p
                                 WHERE p.root = content_want.root AND p.holder = ?1)",
                params![holder.render()],
            )?;
            // `GROUP BY e.content` rather than `SELECT DISTINCT`, and the
            // already-wanted rows excluded rather than left to the conflict
            // clause. Both are about the pass that stages nothing, which is
            // every pass after the first: this runs on the standing loop's
            // every sweep, and a replica of ten thousand nodes has two hundred
            // thousand entries to re-derive the same want set from
            // (`docs/CLOUD-DATAPLANE.md` §7.1a).
            //
            // `DISTINCT` ranged over `(content, size, prev)` — the whole
            // projected row — so it could not be answered from
            // `entries_by_space_content`'s ordering and built a temporary
            // B-tree over every entry instead. Grouping by the column the
            // uniqueness is actually about lets the ordered scan answer it.
            // `size` and `prev` are then read from an arbitrary row of each
            // group, which is what `DISTINCT` plus `DO NOTHING` already did
            // with them: `size` is fixed by the content hash, and `prev` is a
            // delta-descent hint whose two candidates are equally good.
            Ok(tx.execute(
                "INSERT INTO content_want (root, holder, size, prev, first_wanted)
                 SELECT e.content, ?2, e.size, e.prev, ?3
                   FROM entries e
                  WHERE e.space = ?1
                    AND e.content IS NOT NULL
                    AND NOT EXISTS (SELECT 1 FROM pins p
                                     WHERE p.root = e.content AND p.holder = ?2)
                    AND NOT EXISTS (SELECT 1 FROM content_want w
                                     WHERE w.root = e.content AND w.holder = ?2)
                  GROUP BY e.content
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
    /// publishing the same bytes, `adopt path` selecting them, a file restored from
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
    /// `entries` contains only materialized complete heads. A pending head does
    /// not replace its origin's last complete view, and an origin with no
    /// complete head contributes no references yet. GC therefore follows this
    /// committed view directly instead of turning incomplete synchronization
    /// elsewhere on the node into a global release barrier.
    pub(crate) fn schedule_stale_releases(&self, holder: &PinHolder, at: i64) -> Result<usize> {
        Ok(self.conn().execute(
            "UPDATE pins SET release_after = ?2
                  WHERE holder = ?1
                    AND release_after IS NULL
                    AND EXISTS (SELECT 1 FROM replicas r
                                 WHERE 'replica:' || r.space = ?1
                                   AND r.retention = 'current')
                    AND NOT EXISTS (SELECT 1 FROM entries WHERE entries.content = pins.root)",
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
                    AND EXISTS (SELECT 1 FROM replicas r
                                 WHERE 'replica:' || r.space = ?1
                                   AND r.retention = 'current')
                    AND NOT EXISTS (SELECT 1 FROM entries WHERE entries.content = pins.root)
                    AND (SELECT COUNT(*) FROM blob_providers p
                          WHERE p.object_root = pins.root AND p.complete != 0
                            AND p.{NOT_SELF}) >= ?3"
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
        Ok(self.conn().query_row(
            &format!(
                "SELECT COUNT(*) FROM pins
                  WHERE holder = ?1
                    AND release_after IS NULL
                    AND NOT EXISTS (SELECT 1 FROM entries WHERE entries.content = pins.root)
                    AND (SELECT COUNT(*) FROM blob_providers p
                          WHERE p.object_root = pins.root AND p.complete != 0
                            AND p.{NOT_SELF}) < ?2"
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

    /// What one replica holds and wants, for `replica ls <id>`.
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
               FROM content_want WHERE holder = ?1",
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

    /// The oldest want one holder is still attempting, for "oldest 4m ago".
    ///
    /// Wants that have gone unreachable are excluded, by the same threshold
    /// `replica_coverage` counts them with. Both renderers show this age beside
    /// the backlog, which is `wanted - unreachable` — so an unfiltered minimum
    /// puts an age next to a count that deliberately excludes the row the age
    /// came from. A space with four abandoned wants from two months ago and one
    /// queued this morning would read "1 object, oldest 60d ago", which is the
    /// reading that sends someone looking for a stall that is not there. The
    /// unreachable column is where those rows are accounted for.
    pub fn oldest_want(&self, holder: &PinHolder, unreachable_after: i64) -> Result<Option<i64>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT MIN(first_wanted) FROM content_want
                  WHERE holder = ?1 AND attempts < ?2",
                params![holder.render(), unreachable_after],
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

/// The columns of one `content_want` row, before they become a [`WantRow`].
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
            root: hash_column(root, "content_want.root")?,
            holder: PinHolder::parse(&holder),
            size: size as u64,
            prev: prev
                .map(|bytes| hash_column(bytes, "content_want.prev"))
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
    use crate::testutil::{origin, origin_named, store};
    use crate::ReplicaPolicy;

    fn media() -> PinHolder {
        PinHolder::Replica("media".into())
    }

    fn configure_replica(store: &Store, space: &str) {
        store
            .put_replica(&crate::ReplicaRow {
                space: space.into(),
                retention: ReplicaPolicy::Current,
                grace: Some(30 * 24 * 3600),
                budget: None,
                checkout_path: None,
            })
            .unwrap();
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
    fn a_cancelled_want_cannot_become_an_orphaned_pin() {
        let (_dir, store) = store();
        let root = store.ingest_bytes(b"payload", 0).unwrap();
        assert!(store.stage_want(&root, &media(), 7, None, 1).unwrap());
        assert!(store.drop_want(&root, &media()).unwrap());

        assert!(!store.take_possession(&root, &media(), 2).unwrap());
        assert!(store.pins_for(&root).unwrap().is_empty());
    }

    #[test]
    fn possession_failure_restores_the_want_without_a_pin() {
        for fail_at_commit in [false, true] {
            let (_dir, store) = store();
            let root = store.ingest_bytes(b"payload", 0).unwrap();
            assert!(store.stage_want(&root, &media(), 7, None, 1).unwrap());
            if fail_at_commit {
                store.conn().execute_batch(
                    "CREATE TABLE acquisition_parent (id INTEGER PRIMARY KEY);
                     CREATE TABLE acquisition_child (parent INTEGER REFERENCES acquisition_parent(id)
                       DEFERRABLE INITIALLY DEFERRED);
                     CREATE TRIGGER fail_acquisition_commit AFTER INSERT ON pins
                       BEGIN INSERT INTO acquisition_child VALUES (1); END;"
                ).unwrap();
            } else {
                store
                    .conn()
                    .execute_batch(
                        "CREATE TRIGGER fail_acquisition_pin BEFORE INSERT ON pins
                       BEGIN SELECT RAISE(ABORT, 'injected pin failure'); END;",
                    )
                    .unwrap();
            }
            assert!(store.take_possession(&root, &media(), 2).is_err());
            assert_eq!(store.wants_of(&media()).unwrap().len(), 1);
            assert!(store.pins_for(&root).unwrap().is_empty());
            assert_eq!(store.read_all(&root).unwrap(), b"payload");
        }
    }

    #[test]
    fn direct_pin_preserves_want_but_possession_consumes_it() {
        let (_dir, store) = store();
        let root = store.ingest_bytes(b"payload", 0).unwrap();
        store.stage_want(&root, &media(), 7, None, 1).unwrap();
        assert!(store.pin(&root, &media(), 2).unwrap());
        assert_eq!(store.wants_of(&media()).unwrap().len(), 1);
        store.schedule_release(&root, &media(), 3).unwrap();
        assert!(store.take_possession(&root, &media(), 4).unwrap());
        assert!(store.wants_of(&media()).unwrap().is_empty());
        assert_eq!(store.pins_for(&root).unwrap()[0].release_after, None);
    }

    #[test]
    fn removing_a_source_drops_its_repair_intent_and_hold() {
        let (_dir, store) = store();
        let held = store.ingest_bytes(b"held", 0).unwrap();
        let repairing = synch_core::Hash::new(b"missing");
        let holder = PinHolder::Source("media".into());
        store
            .put_source("media", crate::SourceKind::Api, None)
            .unwrap();
        store.pin(&held, &holder, 1).unwrap();
        store.stage_want(&repairing, &holder, 7, None, 1).unwrap();

        assert!(store.remove_source("media").unwrap());
        assert!(store.wants_of(&holder).unwrap().is_empty());
        assert!(store.pins_for(&held).unwrap().is_empty());
    }

    /// A hold or a repair intent behind an entry the tree still names
    /// survives the source role's removal: the leaf stands, so what it stands
    /// on stays (`Cas.RemoveRole`). Holds nothing names go as before.
    #[test]
    fn removing_a_source_keeps_the_holds_behind_live_entries() {
        let (_dir, store) = store();
        let origin = synch_core::OriginId::named("nas", "x.example").unwrap();
        let named = store.ingest_bytes(b"named", 0).unwrap();
        let orphan = store.ingest_bytes(b"orphan", 0).unwrap();
        let wanted = synch_core::Hash::new(b"wanted");
        let holder = PinHolder::Source("media".into());
        store
            .put_source("media", crate::SourceKind::Api, None)
            .unwrap();
        store.pin(&named, &holder, 1).unwrap();
        store.pin(&orphan, &holder, 1).unwrap();
        store.stage_want(&wanted, &holder, 7, None, 1).unwrap();
        for (path, root, size) in [("a.txt", named, 5u64), ("b.txt", wanted, 7)] {
            store
                .put_entry(
                    &origin,
                    "media",
                    path,
                    &synch_core::FileEntry::file(size, 1, root, 1),
                )
                .unwrap();
        }

        assert!(store.remove_source("media").unwrap());
        assert!(!store.pins_for(&named).unwrap().is_empty());
        assert!(store.pins_for(&orphan).unwrap().is_empty());
        assert_eq!(store.wants_of(&holder).unwrap().len(), 1);
    }

    #[test]
    fn replica_removal_preserves_exactly_the_holds_committed_before_it() {
        let (_dir, store) = store();
        configure_replica(&store, "media");
        let held = store.ingest_bytes(b"held", 0).unwrap();
        let fetching = store.ingest_bytes(b"fetching", 0).unwrap();
        store.pin(&held, &media(), 1).unwrap();
        store
            .stage_want(&fetching, &media(), b"fetching".len() as u64, None, 1)
            .unwrap();

        assert!(store.remove_replica("media", true, 2).unwrap());
        assert!(store.replica("media").unwrap().is_none());
        assert!(store.wants_of(&media()).unwrap().is_empty());
        assert_eq!(
            store.pins_for(&held).unwrap()[0].holder,
            PinHolder::Operator
        );
        assert!(!store.take_possession(&fetching, &media(), 3).unwrap());
        assert!(store.pins_for(&fetching).unwrap().is_empty());
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
        configure_replica(&store, "media");
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
    fn expiry_and_want_drop_recheck_the_live_entry() {
        let (_dir, store) = store();
        let root = store.ingest_bytes(b"payload", 0).unwrap();
        store.pin(&root, &media(), 1).unwrap();
        store.schedule_release(&root, &media(), 2).unwrap();
        store.stage_want(&root, &media(), 7, None, 1).unwrap();

        // Simulate a root returning after both decisions but before either
        // cleanup statement. Correctness must not depend on a separate
        // reprieve pass winning that race.
        store
            .put_entry(
                &origin(),
                "media",
                "returned.bin",
                &synch_core::FileEntry::file(7, 1, root, 1),
            )
            .unwrap();

        assert_eq!(store.expire_pins_of(&media(), i64::MAX).unwrap(), 0);
        assert!(!store.drop_want(&root, &media()).unwrap());
        assert!(store.blob(&root).unwrap().unwrap().pinned);
        assert_eq!(store.wants_of(&media()).unwrap().len(), 1);
    }

    #[test]
    fn forever_configuration_cancels_every_scheduled_release() {
        let (_dir, store) = store();
        let root = store.ingest_bytes(b"payload", 0).unwrap();
        store.pin(&root, &media(), 1).unwrap();
        store.schedule_release(&root, &media(), 500).unwrap();

        store
            .put_replica(&crate::ReplicaRow {
                space: "media".into(),
                retention: ReplicaPolicy::Forever,
                grace: None,
                budget: None,
                checkout_path: None,
            })
            .unwrap();

        assert_eq!(store.pins_for(&root).unwrap()[0].release_after, None);
        assert_eq!(store.schedule_stale_releases(&media(), 900).unwrap(), 0);
        assert_eq!(store.expire_pins_of(&media(), i64::MAX).unwrap(), 0);
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

    /// One want per root, and nothing restaged on a pass that has nothing to do.
    ///
    /// This is the behaviour the staging query's rewrite had to preserve, not a
    /// test that tells the two versions apart — both give these answers, which
    /// is the point of writing it down. The rewrite groups by `content` where
    /// it used to `SELECT DISTINCT` the whole projected row, so what it pins is
    /// the two ways that row could vary while naming the same object: several
    /// paths, several origins, and a differing `prev`. Grouping must still
    /// yield exactly one want — and the second pass, which is every pass the
    /// standing loop actually runs, must stage nothing and leave the first
    /// pass's row untouched.
    #[test]
    fn one_root_named_many_ways_stages_one_want_and_restages_none() {
        let (_dir, store) = store();
        let shared = synch_core::Hash::new(b"shared");
        let mut first = synch_core::FileEntry::file(11, 1, shared, 1);
        first.prev = Some(synch_core::Hash::new(b"older"));
        let mut second = synch_core::FileEntry::file(11, 1, shared, 1);
        second.prev = Some(synch_core::Hash::new(b"different"));
        let third = synch_core::FileEntry::file(11, 1, shared, 1);

        // The same content at two paths under one origin, and again under
        // another — each with a different idea of what preceded it.
        store
            .put_entry(&origin(), "media", "a.bin", &first)
            .unwrap();
        store
            .put_entry(&origin(), "media", "b.bin", &second)
            .unwrap();
        store
            .put_entry(&origin_named("other"), "media", "c.bin", &third)
            .unwrap();

        assert_eq!(
            store.stage_space_wants("media", &media(), 5).unwrap(),
            1,
            "three entries naming one root are one want"
        );
        let wants = store.wants_of(&media()).unwrap();
        assert_eq!(wants.len(), 1);
        assert_eq!(wants[0].root, shared);
        assert_eq!(wants[0].size, 11);
        assert_eq!(wants[0].first_wanted, 5);

        // A second pass has nothing to stage, and must not touch the row it
        // finds: `first_wanted` is what the fetch loop ages a backlog by, so
        // restaging would keep it perpetually new.
        assert_eq!(store.stage_space_wants("media", &media(), 9).unwrap(), 0);
        let wants = store.wants_of(&media()).unwrap();
        assert_eq!(wants.len(), 1);
        assert_eq!(
            wants[0].first_wanted, 5,
            "the second pass must not restamp the first pass's want"
        );
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
    fn a_pending_head_keeps_complete_entries_without_blocking_other_releases() {
        let (_dir, store) = store();
        configure_replica(&store, "media");
        let referenced = store.ingest_bytes(b"referenced", 0).unwrap();
        store
            .put_entry(
                &origin(),
                "media",
                "kept.bin",
                &synch_core::FileEntry::file(10, 1, referenced, 1),
            )
            .unwrap();
        store.pin(&referenced, &media(), 1).unwrap();

        // A newer pending head does not replace the materialized entries from
        // the prior complete head. Those entries remain GC roots, while an
        // unrelated stale pin may still progress through its grace period.
        let key = iroh_base::SecretKey::generate();
        let head = crate::testutil::sign_head(&key, 1, 7);
        store
            .put_head(crate::heads::Slot::Pending, &head, 1, 1)
            .unwrap();
        let stale = store.ingest_bytes(b"stale", 0).unwrap();
        store.pin(&stale, &media(), 1).unwrap();

        assert_eq!(store.schedule_stale_releases(&media(), 500).unwrap(), 1);
        assert_eq!(store.pins_for(&referenced).unwrap()[0].release_after, None);
        assert_eq!(store.pins_for(&stale).unwrap()[0].release_after, Some(500));
    }

    #[test]
    fn a_bound_origin_without_a_complete_head_does_not_block_releases() {
        let (_dir, store) = store();
        configure_replica(&store, "media");
        let root = store.ingest_bytes(b"payload", 0).unwrap();
        store.pin(&root, &media(), 1).unwrap();

        // A member this node admits but has never synced contributes no
        // materialized references until its first complete head arrives.
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
        assert_eq!(store.schedule_stale_releases(&media(), 500).unwrap(), 1);
        assert_eq!(store.pins_for(&root).unwrap()[0].release_after, Some(500));
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

        // A replica that also has a checkout publishes its own files;
        // the bytes are in the CAS the moment the entry is. Sending them round
        // the fetch loop to discover that is work nobody needs.
        assert_eq!(store.stage_space_wants("media", &media(), 5).unwrap(), 0);
        assert!(store.wants_of(&media()).unwrap().is_empty());
        assert_eq!(store.pins_for(&held).unwrap().len(), 1);
    }

    #[test]
    fn the_replication_floor_does_not_count_this_node_as_a_peer() {
        let (_dir, store) = store();
        configure_replica(&store, "media");
        let root = store.ingest_bytes(b"the last copy", 0).unwrap();
        store.pin(&root, &media(), 1).unwrap();
        store
            .set_config("self_origin_id", &origin().canonical())
            .unwrap();

        // This node advertises what it holds like any other origin. A provider
        // count that included itself would answer "does anyone else have this?"
        // with "I do", and a replica asked not to be the last holder would
        // always find one holder left — itself.
        store
            .put_provider(&root, &origin(), &synch_core::BlobAd::complete(13))
            .unwrap();
        assert_eq!(
            store
                .schedule_stale_releases_above(&media(), 500, 1)
                .unwrap(),
            0,
            "its own advertisement must not satisfy the floor"
        );
        assert_eq!(
            store.held_back_by_replication_floor(&media(), 1).unwrap(),
            1,
            "and the status report must say the object is being held back"
        );

        // A second, foreign holder is what the floor is actually asking for.
        store
            .put_provider(
                &root,
                &origin_named("elsewhere"),
                &synch_core::BlobAd::complete(13),
            )
            .unwrap();
        assert_eq!(
            store
                .schedule_stale_releases_above(&media(), 500, 1)
                .unwrap(),
            1
        );
        assert_eq!(
            store.held_back_by_replication_floor(&media(), 1).unwrap(),
            0
        );
    }

    #[test]
    fn a_withdrawn_durable_claim_becomes_a_want_again() {
        let (_dir, store) = store();
        let root = synch_core::Hash::new(b"in the bucket, until it was not");
        // The shape a cloud replica's holding takes once its cache is dropped:
        // durable, no local bytes.
        store.record_remote_durable_blob(&root, 4096, 1).unwrap();
        store
            .put_entry(
                &origin(),
                "media",
                "held.bin",
                &synch_core::FileEntry::file(4096, 1, root, 1),
            )
            .unwrap();
        store.pin(&root, &media(), 1).unwrap();
        store.pin(&root, &PinHolder::Operator, 1).unwrap();

        // The backend answers NotFound for a content address. That is a
        // statement about the bytes, unlike `entries` merely not naming a root,
        // and it is the one case where absence of bytes is evidence.
        assert!(store.heal_missing_durable_blob(&root).unwrap());

        // The replica's claim must not outlive the bytes it promised: both
        // staging paths skip a root this holder already pins, so a pin left
        // standing over a deleted row is one no sweep could ever re-want, and
        // the node would advertise coverage it does not have for ever.
        let pins = store.pins_for(&root).unwrap();
        assert_eq!(pins.len(), 1, "only the operator's own pin survives");
        assert_eq!(pins[0].holder, PinHolder::Operator);
        let wants = store.wants_of(&media()).unwrap();
        assert_eq!(wants.len(), 1, "and the replica wants it again");
        assert_eq!(wants[0].size, 4096, "at the size its entry knows");
    }

    #[test]
    fn a_withdrawn_claim_is_re_wanted_even_when_cache_residue_survives() {
        let (_dir, store) = store();
        let payload = crate::testutil::data(120_000);
        let root = synch_core::Hash::new(&payload);
        store
            .record_remote_durable_blob(&root, payload.len() as u64, 1)
            .unwrap();
        store
            .put_entry(
                &origin(),
                "media",
                "big.bin",
                &synch_core::FileEntry::file(payload.len() as u64, 1, root, 1),
            )
            .unwrap();
        store.pin(&root, &media(), 1).unwrap();

        // A cloud replica reaches this state routinely: the cache LRU clears a
        // durable row, and any later ranged read writes a partial bitmap back.
        // The row therefore survives the heal's delete — which is what made
        // gating the pin conversion on that delete leave the claim standing
        // over bytes that are neither complete nor durable.
        store
            .conn()
            .execute(
                "UPDATE blobs SET complete = 0, bitmap = X'01' WHERE root = ?1",
                params![root.as_bytes().to_vec()],
            )
            .unwrap();

        assert!(store.heal_missing_durable_blob(&root).unwrap());
        assert!(
            store.pins_for(&root).unwrap().is_empty(),
            "the claim must not outlive the durable promise it was made about"
        );
        let wants = store.wants_of(&media()).unwrap();
        assert_eq!(wants.len(), 1, "and the replica must want it again");
        assert_eq!(wants[0].size, payload.len() as u64);
    }

    #[test]
    fn a_withdrawn_claim_is_re_wanted_even_when_no_entry_names_the_root() {
        let (_dir, store) = store();
        let root = synch_core::Hash::new(b"a superseded version an archive still holds");
        store.record_remote_durable_blob(&root, 4096, 1).unwrap();
        store.pin(&root, &media(), 1).unwrap();

        // No entry names it — a `forever` replica's pins over superseded roots
        // stand for ever by design, and nothing else in the tree points at
        // them. The size is still known from this node's own row, and
        // `blob_providers` survives independently of `entries`, so the object
        // may well still be fetchable. Dropping the claim quietly here would
        // lose precisely the objects that policy is bought to keep.
        assert!(store.heal_missing_durable_blob(&root).unwrap());
        assert!(store.pins_for(&root).unwrap().is_empty());
        let wants = store.wants_of(&media()).unwrap();
        assert_eq!(wants.len(), 1);
        assert_eq!(wants[0].size, 4096);
    }

    #[test]
    fn one_space_with_a_backlog_does_not_starve_another() {
        let (_dir, store) = store();
        for id in ["archive", "docs"] {
            configure_replica(&store, id);
        }
        let archive = PinHolder::Replica("archive".into());
        let docs = PinHolder::Replica("docs".into());

        // `archive` is bootstrapping: many old wants. `docs` was added after,
        // so every want it has is newer than all of them.
        for i in 0..50u8 {
            store
                .stage_want(
                    &synch_core::Hash::new(&[i, 1]),
                    &archive,
                    10,
                    None,
                    i as i64,
                )
                .unwrap();
        }
        store
            .stage_want(&synch_core::Hash::new(b"docs one"), &docs, 10, None, 9_000)
            .unwrap();

        // The caller admits the first `limit` rows and no more, so membership in
        // the whole window proves nothing: under a concatenation `docs` sits at
        // the end of a 33-row window and is never reached. Assert on the prefix
        // the fetch loop actually takes.
        let limit = 4;
        let batch = store
            .wants_to_attempt(1_000_000, 60, 3600, limit, 0)
            .unwrap();
        let admitted: Vec<&PinHolder> = batch.iter().take(limit).map(|w| &w.holder).collect();
        assert!(
            admitted.contains(&&docs),
            "a space added after a large backlog must get a turn inside the first \
             {limit} wants, or it fetches nothing until the backlog drains — \
             months, at four a pass. Admitted: {admitted:?}"
        );
    }

    #[test]
    fn more_spaces_than_slots_still_all_get_served() {
        let (_dir, store) = store();
        // Six spaces, four slots: with no rotation the first four in id order
        // take every slot for ever and the last two wait out their backlogs.
        // The two-space test cannot see this, because with spaces <= slots the
        // property holds trivially.
        let ids = ["a", "b", "c", "d", "e", "f"];
        for (n, id) in ids.iter().enumerate() {
            configure_replica(&store, id);
            store
                .stage_want(
                    &synch_core::Hash::new(id.as_bytes()),
                    &PinHolder::Replica(id.to_string()),
                    10,
                    None,
                    n as i64,
                )
                .unwrap();
        }

        let limit = 4;
        let mut served: std::collections::HashSet<String> = std::collections::HashSet::new();
        for pass in 0..ids.len() {
            let batch = store
                .wants_to_attempt(1_000_000, 60, 3600, limit, pass)
                .unwrap();
            for want in batch.iter().take(limit) {
                served.insert(want.holder.space().unwrap().to_string());
            }
        }
        assert_eq!(
            served.len(),
            ids.len(),
            "every space must lead the interleave within one turn of the list; \
             served: {served:?}"
        );
    }

    #[test]
    fn candidate_work_is_bounded_globally_across_holders() {
        let (_dir, store) = store();
        for id in ["a", "b", "c", "d", "e", "f"] {
            configure_replica(&store, id);
            let holder = PinHolder::Replica(id.to_string());
            for n in 0..20u8 {
                store
                    .stage_want(
                        &synch_core::Hash::new(&[id.as_bytes()[0], n]),
                        &holder,
                        10,
                        None,
                        i64::from(n),
                    )
                    .unwrap();
            }
        }

        let limit = 2;
        let batch = store
            .wants_to_attempt(1_000_000, 60, 3600, limit, 0)
            .unwrap();
        let mut holders: Vec<&PinHolder> = Vec::new();
        for want in &batch {
            if !holders.contains(&&want.holder) {
                holders.push(&want.holder);
            }
        }
        assert!(
            batch.len() <= limit * RARITY_WINDOW + holders.len(),
            "candidate rows must be linear in the holder count plus the global window"
        );
        assert_eq!(holders.len(), 6, "every ready holder must remain visible");
    }

    #[test]
    fn empty_holders_do_not_hide_ready_work_outside_the_slot_count() {
        let (_dir, store) = store();
        for id in ["a", "b", "c"] {
            configure_replica(&store, id);
        }
        let ready = PinHolder::Replica("c".to_string());
        let root = synch_core::Hash::new(b"ready behind two empty holders");
        store.stage_want(&root, &ready, 10, None, 1).unwrap();

        let batch = store.wants_to_attempt(1_000_000, 60, 3600, 2, 0).unwrap();
        assert!(
            batch.iter().any(|want| want.root == root),
            "empty holders inside the nominal slot count must not postpone a ready holder"
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
    fn source_and_replica_rows_are_independent() {
        let (_dir, store) = store();
        store
            .put_source("media", crate::SourceKind::Filesystem, Some("/srv/media"))
            .unwrap();
        store
            .put_replica(&crate::ReplicaRow {
                space: "media".into(),
                retention: ReplicaPolicy::Current,
                grace: Some(60),
                budget: None,
                checkout_path: None,
            })
            .unwrap();
        assert!(store.remove_source("media").unwrap());
        let replica = store.replica("media").unwrap().unwrap();
        assert_eq!(replica.retention, ReplicaPolicy::Current);
        assert_eq!(replica.grace_secs(), 60);
    }
}
