//! The two-slot heads table and the head history (§10, §4.4).

use iroh_base::Signature;
use rusqlite::{params, OptionalExtension, Row};
use synch_core::{Hash, OriginId, SignedHead};

use crate::{
    db::{hash_column, key_column, origin_column, Store, Txn},
    error::{Result, StoreError},
};

/// Which of the two durable head slots per origin (§5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// Fully materialized, servable, backs `entries`.
    Complete,
    /// A fetch in progress; never advertised as servable.
    Pending,
}

impl Slot {
    /// The `slot` column value.
    pub fn as_str(self) -> &'static str {
        match self {
            Slot::Complete => "complete",
            Slot::Pending => "pending",
        }
    }
}

/// A stored head, with the bookkeeping columns §10 keeps alongside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredHead {
    /// The head itself.
    pub head: SignedHead,
    /// When the head was received, in unix nanoseconds.
    pub received_at: i64,
    /// When the `signed_by ↔ origin` binding was checked (§4.4).
    pub verified_at: i64,
}

/// The raw column tuple of a `heads` row.
type HeadRow = (String, u64, Vec<u8>, i64, Vec<u8>, Vec<u8>, i64, i64);

fn head_from_row(row: &Row<'_>) -> rusqlite::Result<HeadRow> {
    Ok((
        row.get(0)?,
        row.get::<_, i64>(1)? as u64,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

fn build_head(
    origin: String,
    seq: u64,
    root: Vec<u8>,
    created_at: i64,
    signed_by: Vec<u8>,
    sig: Vec<u8>,
) -> Result<SignedHead> {
    let sig: [u8; 64] = sig
        .try_into()
        .map_err(|_| StoreError::column("heads.sig", "not 64 bytes"))?;
    Ok(SignedHead {
        origin: origin_column(origin, "heads.origin_id")?,
        seq,
        root: hash_column(root, "heads.root")?,
        created_at,
        signed_by: key_column(signed_by, "heads.signed_by")?,
        sig: Signature::from_bytes(&sig),
    })
}

/// The columns of a head, joined from the pointer to the signature it names.
///
/// `heads` holds `(seq, root)` and the bookkeeping times; the signed head those
/// identify lives once, in `head_history`. The join is what makes "the current
/// head" and "the retained history" one fact instead of two copies that have to
/// be kept in step (§10, v11).
const HEAD_JOIN: &str = "SELECT h.origin_id, h.seq, h.root, hh.created_at, hh.signed_by, hh.sig,
        h.received_at, h.verified_at
 FROM heads h
 JOIN head_history hh
   ON hh.origin_id = h.origin_id AND hh.seq = h.seq AND hh.root = h.root";

fn head_in(
    conn: &rusqlite::Connection,
    origin: &OriginId,
    slot: Slot,
) -> Result<Option<StoredHead>> {
    let row = conn
        .query_row(
            &format!("{HEAD_JOIN} WHERE h.origin_id = ?1 AND h.slot = ?2"),
            params![origin.canonical(), slot.as_str()],
            head_from_row,
        )
        .optional()?;
    let Some((origin, seq, root, created_at, signed_by, sig, received_at, verified_at)) = row
    else {
        return Ok(None);
    };
    Ok(Some(StoredHead {
        head: build_head(origin, seq, root, created_at, signed_by, sig)?,
        received_at,
        verified_at,
    }))
}

impl Store {
    /// Reads one head slot.
    pub fn head(&self, origin: &OriginId, slot: Slot) -> Result<Option<StoredHead>> {
        head_in(&self.conn(), origin, slot)
    }

    /// The complete (materialized, servable) head for an origin.
    pub fn complete_head(&self, origin: &OriginId) -> Result<Option<SignedHead>> {
        Ok(self.head(origin, Slot::Complete)?.map(|s| s.head))
    }

    /// The pending (fetch in progress) head for an origin.
    pub fn pending_head(&self, origin: &OriginId) -> Result<Option<SignedHead>> {
        Ok(self.head(origin, Slot::Pending)?.map(|s| s.head))
    }

    /// The `(seq, root)` ordering key currently held for an origin.
    ///
    /// This is what the §5.2 acceptance rule compares against: the *best* of the
    /// two slots, so a head already being fetched is not fetched again and a
    /// head older than an in-progress target is not adopted.
    pub fn head_floor(&self, origin: &OriginId) -> Result<Option<(u64, Hash)>> {
        let complete = self.complete_head(origin)?.map(|h| (h.seq, h.root));
        let pending = self.pending_head(origin)?.map(|h| (h.seq, h.root));
        Ok(best_floor(complete, pending))
    }

    /// Every slot for every origin.
    pub fn all_heads(&self, slot: Slot) -> Result<Vec<StoredHead>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "{HEAD_JOIN} WHERE h.slot = ?1 ORDER BY h.origin_id"
        ))?;
        let rows = stmt.query_map(params![slot.as_str()], head_from_row)?;
        let mut out = Vec::new();
        for row in rows {
            let (origin, seq, root, created_at, signed_by, sig, received_at, verified_at) = row?;
            out.push(StoredHead {
                head: build_head(origin, seq, root, created_at, signed_by, sig)?,
                received_at,
                verified_at,
            });
        }
        Ok(out)
    }

    /// Writes a head into a slot.
    ///
    /// The caller must have verified the signature *and* the binding first
    /// (§4.4); `verified_at` records when the binding check happened, so
    /// history signed by since-retired keys stays valid.
    pub fn put_head(
        &self,
        slot: Slot,
        head: &SignedHead,
        received_at: i64,
        verified_at: i64,
    ) -> Result<()> {
        let conn = self.conn();
        put_head_in(&conn, slot, head, received_at, verified_at)
    }

    /// Clears a head slot.
    pub fn clear_head(&self, origin: &OriginId, slot: Slot) -> Result<()> {
        self.conn().execute(
            "DELETE FROM heads WHERE origin_id = ?1 AND slot = ?2",
            params![origin.canonical(), slot.as_str()],
        )?;
        Ok(())
    }

    /// Records a head in `head_history`, keeping its signature.
    ///
    /// `now` is when this node received the head, which is what retention
    /// measures age from (§5.4).
    pub fn record_history(&self, head: &SignedHead, now: i64) -> Result<()> {
        let conn = self.conn();
        record_history_in(&conn, head, now)
    }

    /// How many distinct roots an origin has retained at one seq.
    ///
    /// Two is equivocation and is evidence worth keeping (§4.4). An unbounded
    /// number is a member signing forever at one seq, which retention alone
    /// cannot clear: same-seq forks are *exempt* from `root_retention` until the
    /// origin publishes past that seq, and an attacker simply never does. Every
    /// row is verified and bound, so nothing upstream rejects them, and
    /// `equivocations()` re-reads the whole set per pair, so `doctor` and each
    /// GC pass go quadratic in the storm. What bounds the width is
    /// [`Txn::trim_forks`], which *evicts* the lowest-ordered rows at a seq
    /// rather than refusing the head that would widen it — acceptance is the
    /// one thing convergence rests on and may never depend on how many roots
    /// happened to arrive first.
    pub fn fork_width(&self, origin: &OriginId, seq: u64) -> Result<usize> {
        Ok(self.conn().query_row(
            "SELECT COUNT(*) FROM head_history WHERE origin_id = ?1 AND seq = ?2",
            params![origin.canonical(), seq as i64],
            |row| row.get::<_, i64>(0),
        )? as usize)
    }

    /// The retained history for an origin, newest first.
    pub fn head_history(&self, origin: &OriginId) -> Result<Vec<SignedHead>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT origin_id, seq, root, created_at, signed_by, sig FROM head_history
             WHERE origin_id = ?1 ORDER BY seq DESC, root DESC",
        )?;
        let rows = stmt.query_map(params![origin.canonical()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as u64,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (origin, seq, root, created_at, signed_by, sig) = row?;
            out.push(build_head(origin, seq, root, created_at, signed_by, sig)?);
        }
        Ok(out)
    }

    /// Every origin that has published two different roots at the same seq.
    ///
    /// Equivocation only harms the equivocator's own published view, but it is
    /// reported loudly (§4.4) with both signed heads retained as proof.
    pub fn equivocations(&self) -> Result<Vec<Equivocation>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT origin_id, seq, COUNT(DISTINCT root) AS roots FROM head_history
             GROUP BY origin_id, seq HAVING roots > 1 ORDER BY origin_id, seq",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        })?;
        let mut pairs = Vec::new();
        for row in rows {
            let (origin, seq) = row?;
            pairs.push((origin_column(origin, "head_history.origin_id")?, seq));
        }
        drop(stmt);
        drop(conn);

        let mut out = Vec::new();
        for (origin, seq) in pairs {
            let heads: Vec<SignedHead> = self
                .head_history(&origin)?
                .into_iter()
                .filter(|h| h.seq == seq)
                .collect();
            out.push(Equivocation { origin, seq, heads });
        }
        Ok(out)
    }

    /// Every origin that has retained history.
    pub fn history_origins(&self) -> Result<Vec<OriginId>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT DISTINCT origin_id FROM head_history ORDER BY origin_id")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(origin_column(row?, "head_history.origin_id")?);
        }
        Ok(out)
    }

    /// Prunes one origin's retained history to the `root_retention` window
    /// (§5.4), keeping what the design says must survive it.
    ///
    /// Three exemptions, and they are the whole point of the rule:
    ///
    /// - **The current heads.** The complete and pending heads' rows are what
    ///   `synch log` reads the present from and what GC marks the live trie
    ///   from; retention is about *old* roots.
    /// - **Same-seq fork evidence.** Two roots signed at one seq are provable
    ///   equivocation (§4.4) and the fork side of someone's recovery (§3.4),
    ///   surfaced by `synch doctor` on every node. Those rows outlive ordinary
    ///   retention until the origin has published past the forked seq *and*
    ///   the head that did so is itself older than retention — at which point
    ///   the fork is history that the cluster has visibly moved beyond.
    /// - **Anything newer than `before`**, which is the retention window
    ///   itself.
    ///
    /// "Published past the forked seq" is read off the *retained history*, not
    /// off the complete slot, and that is the difference between a bounded rule
    /// and an open one. Reading it off the complete head asked whether the head
    /// this node holds *now* is older than retention, so any origin publishing
    /// once per `root_retention` pinned every fork row it had ever signed —
    /// and every trie node reachable from those roots, since retained roots are
    /// GC mark roots. It was open at the other end too: a fork at a seq *above*
    /// the complete head never satisfied `current_seq > seq`, so an origin
    /// signing two roots at each of a thousand far-future seqs and serving none
    /// of the tries made every one of those rows permanent, `trust rm` and all.
    /// A retained head at a *higher* seq is the same proof that the origin
    /// moved on, it is what an origin flooding future seqs supplies by the
    /// thousand, and only the single highest forked seq is left without one.
    ///
    /// Fork evidence goes all at once or not at all: a seq pruned down to one
    /// root is a row that no longer proves anything, so a forked seq is taken
    /// only when every root at it is prunable — none of them current, all of
    /// them past the window — and the row that proves the origin moved past it
    /// waits for the fork rather than being taken ahead of them.
    /// [`Txn::trim_forks`] bounds the width of a fork on the way in; this
    /// bounds how long one lives.
    ///
    /// Age is `recorded_at`: when *this node* took the row. `created_at` is
    /// signed but is the signer's own unclamped choice, so keying retention on
    /// it would let an origin date a head at the end of time and make both the
    /// row and every trie node reachable from its root permanent here (§5.4).
    ///
    /// Returns how many rows were dropped.
    pub fn prune_history_before(&self, origin: &OriginId, before: i64) -> Result<usize> {
        // Reads and deletes in one immediate transaction, over one snapshot:
        // deciding what is doomed outside it lets a writer on the blocking pool
        // make a row current in between, and the row `heads` points at would go
        // with the rest of the pass.
        self.with_immediate_tx(|tx| {
            let complete = head_in(tx, origin, Slot::Complete)?;
            let pending = head_in(tx, origin, Slot::Pending)?;
            // One snapshot for the whole decision, so a fork and the rows that
            // prove the origin moved past it are judged against the same set.
            let receipts = history_receipts_in(tx, origin)?;
            let is_current = |seq: u64, root: &Hash| {
                [
                    complete.as_ref().map(|c| &c.head),
                    pending.as_ref().map(|p| &p.head),
                ]
                .into_iter()
                .flatten()
                .any(|h| h.seq == seq && h.root == *root)
            };
            // A seq with more than one retained root is a fork, and every side
            // of it is evidence. The exemption lifts for a forked seq only when
            // the origin is on record past it — a retained row at a higher seq,
            // itself older than the window — and every root at the seq can go
            // in the same pass, so the proof is never left half standing.
            let forked = forked_seqs_in(tx, origin)?;
            // The highest seq the origin is on record at with a row older than
            // the window: every forked seq below it has been published past.
            let moved_past_below = receipts
                .iter()
                .filter(|(_, _, recorded_at)| *recorded_at < before)
                .map(|(seq, _, _)| *seq)
                .max();
            // The seqs holding a root this pass may not take — current, or
            // still inside the window — which is what makes their fork
            // all-or-nothing.
            let pinned: std::collections::HashSet<u64> = receipts
                .iter()
                .filter(|(seq, root, recorded_at)| *recorded_at >= before || is_current(*seq, root))
                .map(|(seq, _, _)| *seq)
                .collect();
            let expired = |seq: u64| {
                moved_past_below.is_some_and(|highest| seq < highest) && !pinned.contains(&seq)
            };
            // While a fork is exempt, so is the lowest head the origin is on
            // record at above it. That row is the *proof* the origin moved past
            // the fork, and it is older than the window, so an ordinary pass
            // would take it — leaving a fork that nothing can ever retire,
            // which is the shape of the bug this rule replaces. It stays until
            // the fork it speaks about can go with it.
            let witnesses: std::collections::HashSet<u64> = forked
                .iter()
                .copied()
                .filter(|seq| !expired(*seq))
                .filter_map(|seq| {
                    receipts
                        .iter()
                        .filter(|(s, _, recorded_at)| *s > seq && *recorded_at < before)
                        .map(|(s, _, _)| *s)
                        .min()
                })
                .collect();

            let mut pruned = 0;
            for (seq, root, recorded_at) in &receipts {
                let (seq, recorded_at) = (*seq, *recorded_at);
                if recorded_at >= before {
                    continue;
                }
                if is_current(seq, root) {
                    continue;
                }
                if forked.contains(&seq) && !expired(seq) {
                    continue;
                }
                if witnesses.contains(&seq) {
                    continue;
                }
                // The exemption again, as a condition of the delete rather
                // than of the decision: a row a slot points at is not deletable
                // from here whatever this pass concluded.
                pruned += tx.execute(
                    "DELETE FROM head_history
                      WHERE origin_id = ?1 AND seq = ?2 AND root = ?3
                        AND NOT EXISTS (
                              SELECT 1 FROM heads h
                               WHERE h.origin_id = ?1 AND h.seq = ?2 AND h.root = ?3)",
                    params![origin.canonical(), seq as i64, root.as_bytes().to_vec()],
                )?;
            }
            Ok(pruned)
        })
    }

    /// The roots that GC must mark from: every origin's complete and pending
    /// heads plus retained history roots (§5.4).
    ///
    /// Pending heads must be in the mark set or GC would eat an in-progress
    /// bootstrap.
    pub fn retained_roots(&self) -> Result<Vec<Hash>> {
        let conn = self.conn();
        // One table, not a union across two. `put_head` writes the signature to
        // `head_history` before the slot points at it, so every current head's
        // root is here by construction rather than by coincidence.
        let mut stmt = conn.prepare("SELECT DISTINCT root FROM head_history")?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(hash_column(row?, "heads.root")?);
        }
        Ok(out)
    }
}

impl Txn<'_> {
    /// Reads one head slot inside the transaction.
    pub fn head(&self, origin: &OriginId, slot: Slot) -> Result<Option<StoredHead>> {
        head_in(self.conn(), origin, slot)
    }

    /// The complete head, read inside the transaction.
    pub fn complete_head(&self, origin: &OriginId) -> Result<Option<SignedHead>> {
        Ok(self.head(origin, Slot::Complete)?.map(|s| s.head))
    }

    /// The pending head, read inside the transaction.
    pub fn pending_head(&self, origin: &OriginId) -> Result<Option<SignedHead>> {
        Ok(self.head(origin, Slot::Pending)?.map(|s| s.head))
    }

    /// The `(seq, root)` ordering key currently held, read inside the
    /// transaction.
    ///
    /// The acceptance rule reads this and then writes what it read, so it has
    /// to see the same snapshot the write lands in: split across two lock
    /// acquisitions, two concurrent offers both read the same floor, both
    /// decide they beat it, and the lower one wins the race to the slot.
    pub fn head_floor(&self, origin: &OriginId) -> Result<Option<(u64, Hash)>> {
        let complete = self.complete_head(origin)?.map(|h| (h.seq, h.root));
        let pending = self.pending_head(origin)?.map(|h| (h.seq, h.root));
        Ok(best_floor(complete, pending))
    }

    /// Writes a head into a slot, inside the transaction.
    ///
    /// The caller must have verified the signature *and* the binding first
    /// (§4.4), exactly as for [`Store::put_head`].
    pub fn put_head(
        &self,
        slot: Slot,
        head: &SignedHead,
        received_at: i64,
        verified_at: i64,
    ) -> Result<()> {
        put_head_in(self.conn(), slot, head, received_at, verified_at)
    }

    /// Clears a head slot, inside the transaction.
    pub fn clear_head(&self, origin: &OriginId, slot: Slot) -> Result<()> {
        self.conn().execute(
            "DELETE FROM heads WHERE origin_id = ?1 AND slot = ?2",
            params![origin.canonical(), slot.as_str()],
        )?;
        Ok(())
    }

    /// Records a head in `head_history`, inside the transaction.
    pub fn record_history(&self, head: &SignedHead, now: i64) -> Result<()> {
        record_history_in(self.conn(), head, now)
    }

    /// How many distinct roots this origin has retained at one seq, inside the
    /// transaction. See [`Store::fork_width`].
    pub fn fork_width(&self, origin: &OriginId, seq: u64) -> Result<usize> {
        Ok(self.conn().query_row(
            "SELECT COUNT(*) FROM head_history WHERE origin_id = ?1 AND seq = ?2",
            params![origin.canonical(), seq as i64],
            |row| row.get::<_, i64>(0),
        )? as usize)
    }

    /// Bounds the retained fork at one seq to `keep` roots, evicting the
    /// lowest-ordered ones, and reports how many rows went.
    ///
    /// A retention bound, never an acceptance rule. Same-seq forks are exempt
    /// from `root_retention` until the origin publishes past the forked seq, so
    /// an origin signing forever at one seq would otherwise buy permanent
    /// growth on every peer. Refusing the incoming head instead is what the
    /// acceptance rule may not do: which roots a peer saw first would then
    /// decide which head it holds, and two honest peers fed the same set in
    /// different orders would settle on different heads and refuse each other
    /// forever. Evicting keeps the *greatest* `keep` roots at the seq, which is
    /// the same set on every peer whatever the arrival order, and always leaves
    /// the two that prove the equivocation (§4.4) as long as `keep >= 2`.
    ///
    /// A row a slot points at is never evicted: since v11 `heads` names a
    /// `head_history` row and every head read joins the two, so a slot whose row
    /// went would be a head that can no longer be read. Same guard, and for the
    /// same reason, as [`Store::prune_history_before`]'s.
    pub fn trim_forks(&self, origin: &OriginId, seq: u64, keep: usize) -> Result<usize> {
        Ok(self.conn().execute(
            "DELETE FROM head_history
              WHERE origin_id = ?1 AND seq = ?2
                AND root NOT IN (
                      SELECT root FROM head_history
                       WHERE origin_id = ?1 AND seq = ?2
                       ORDER BY root DESC LIMIT ?3)
                AND NOT EXISTS (
                      SELECT 1 FROM heads h
                       WHERE h.origin_id = ?1 AND h.seq = ?2
                         AND h.root = head_history.root)",
            params![origin.canonical(), seq as i64, keep as i64],
        )?)
    }
}

/// A same-seq fork by one origin, with both signed heads as proof.
#[derive(Debug, Clone)]
pub struct Equivocation {
    /// The equivocating origin.
    pub origin: OriginId,
    /// The seq at which two different roots were signed.
    pub seq: u64,
    /// The conflicting heads, retained with their signatures.
    pub heads: Vec<SignedHead>,
}

/// The greater of the two slots' ordering keys, which is what the §5.2
/// acceptance rule compares against: a head already being fetched is not
/// fetched again, and a head older than an in-progress target is not adopted.
fn best_floor(complete: Option<(u64, Hash)>, pending: Option<(u64, Hash)>) -> Option<(u64, Hash)> {
    match (complete, pending) {
        (None, p) => p,
        (c, None) => c,
        (Some(c), Some(p)) => Some(if (p.0, p.1 .0) > (c.0, c.1 .0) { p } else { c }),
    }
}

/// Every retained row for an origin as `(seq, root, recorded_at)`.
///
/// What retention reads: the signature and the signed time are of no interest to
/// it, and the time it does need is not on [`SignedHead`].
fn history_receipts_in(
    conn: &rusqlite::Connection,
    origin: &OriginId,
) -> Result<Vec<(u64, Hash, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT seq, root, recorded_at FROM head_history
         WHERE origin_id = ?1 ORDER BY seq DESC, root DESC",
    )?;
    let rows = stmt.query_map(params![origin.canonical()], |row| {
        Ok((
            row.get::<_, i64>(0)? as u64,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (seq, root, recorded_at) = row?;
        out.push((seq, hash_column(root, "head_history.root")?, recorded_at));
    }
    Ok(out)
}

/// The seqs at which an origin has more than one retained root.
fn forked_seqs_in(conn: &rusqlite::Connection, origin: &OriginId) -> Result<Vec<u64>> {
    let mut stmt = conn.prepare(
        "SELECT seq FROM head_history WHERE origin_id = ?1
         GROUP BY seq HAVING COUNT(DISTINCT root) > 1",
    )?;
    let rows = stmt.query_map(params![origin.canonical()], |row| {
        Ok(row.get::<_, i64>(0)? as u64)
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn put_head_in(
    conn: &rusqlite::Connection,
    slot: Slot,
    head: &SignedHead,
    received_at: i64,
    verified_at: i64,
) -> Result<()> {
    // The signature goes to `head_history` and the slot points at it. Writing
    // it here is what makes the pointer sound for *every* caller, so no caller
    // has to remember to record history alongside — which is what the old
    // record-on-arrival-and-again-on-displacement pair of rules was doing by
    // hand, redundantly, at seven call sites.
    record_history_in(conn, head, received_at)?;
    conn.execute(
        "INSERT INTO heads (origin_id, slot, seq, root, received_at, verified_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(origin_id, slot) DO UPDATE SET
           seq = excluded.seq, root = excluded.root,
           received_at = excluded.received_at, verified_at = excluded.verified_at",
        params![
            head.origin.canonical(),
            slot.as_str(),
            head.seq as i64,
            head.root.as_bytes().to_vec(),
            received_at,
            verified_at,
        ],
    )?;
    Ok(())
}

fn record_history_in(
    conn: &rusqlite::Connection,
    head: &SignedHead,
    recorded_at: i64,
) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO head_history
           (origin_id, seq, root, created_at, signed_by, sig, recorded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            head.origin.canonical(),
            head.seq as i64,
            head.root.as_bytes().to_vec(),
            head.created_at,
            head.signed_by.as_bytes().to_vec(),
            head.sig.to_bytes().to_vec(),
            recorded_at,
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;

    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path()).unwrap();
        (dir, s)
    }

    fn origin() -> OriginId {
        OriginId::named("nas", "x.example").unwrap()
    }

    #[test]
    fn head_slots_round_trip() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        let head = SignedHead::sign(&key, origin(), 4, Hash::new(b"r"), 99);
        store.put_head(Slot::Complete, &head, 1, 2).unwrap();

        let stored = store.head(&origin(), Slot::Complete).unwrap().unwrap();
        assert_eq!(stored.head, head);
        assert_eq!(stored.received_at, 1);
        assert_eq!(stored.verified_at, 2);
        // The signature survives the round trip through SQLite.
        stored.head.verify_signature().unwrap();
        assert_eq!(store.pending_head(&origin()).unwrap(), None);
    }

    #[test]
    fn head_floor_is_the_best_of_both_slots() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        assert_eq!(store.head_floor(&origin()).unwrap(), None);

        let complete = SignedHead::sign(&key, origin(), 3, Hash([1u8; 32]), 0);
        store.put_head(Slot::Complete, &complete, 0, 0).unwrap();
        assert_eq!(
            store.head_floor(&origin()).unwrap(),
            Some((3, Hash([1u8; 32])))
        );

        let pending = SignedHead::sign(&key, origin(), 5, Hash([2u8; 32]), 0);
        store.put_head(Slot::Pending, &pending, 0, 0).unwrap();
        assert_eq!(
            store.head_floor(&origin()).unwrap(),
            Some((5, Hash([2u8; 32])))
        );
    }

    #[test]
    fn equivocation_is_detected_with_both_proofs() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        let a = SignedHead::sign(&key, origin(), 7, Hash([1u8; 32]), 0);
        let b = SignedHead::sign(&key, origin(), 7, Hash([2u8; 32]), 0);
        let c = SignedHead::sign(&key, origin(), 8, Hash([3u8; 32]), 0);
        for h in [&a, &b, &c] {
            store.record_history(h, 0).unwrap();
        }
        let found = store.equivocations().unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].seq, 7);
        assert_eq!(found[0].heads.len(), 2);
        for h in &found[0].heads {
            h.verify_signature().unwrap();
        }
    }

    #[test]
    fn history_pruning_and_retained_roots() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        for seq in 1..=5u64 {
            let h = SignedHead::sign(&key, origin(), seq, Hash([seq as u8; 32]), 0);
            // Received in seq order, which is what retention reads.
            store.record_history(&h, seq as i64).unwrap();
        }
        let head = SignedHead::sign(&key, origin(), 6, Hash([6u8; 32]), 0);
        store.put_head(Slot::Complete, &head, 10, 0).unwrap();
        let pending = SignedHead::sign(&key, origin(), 7, Hash([7u8; 32]), 0);
        store.put_head(Slot::Pending, &pending, 10, 0).unwrap();

        // Seven distinct roots: five recorded directly, plus the two the slots
        // point at — which `put_head` retains, so they are here by
        // construction rather than needing the union `retained_roots` used to
        // take across both tables.
        let roots = store.retained_roots().unwrap();
        assert_eq!(roots.len(), 7);
        assert!(roots.contains(&Hash([6u8; 32])));
        // Pending heads must be in the mark set (§5.4).
        assert!(roots.contains(&Hash([7u8; 32])));

        // A horizon past the first three drops them; seqs 4 and 5 remain, as do
        // the two the slots point at.
        assert_eq!(store.prune_history_before(&origin(), 4).unwrap(), 3);
        assert_eq!(store.head_history(&origin()).unwrap().len(), 4);
    }

    /// A row a slot points at is never pruned, whatever the horizon says.
    ///
    /// `heads` names a `head_history` row and every head read joins the two, so
    /// the row behind a slot is exempt — checked once when the doomed set is
    /// chosen, and again as a condition of the delete.
    #[test]
    fn a_row_a_slot_points_at_survives_every_prune() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        let complete = SignedHead::sign(&key, origin(), 3, Hash([3u8; 32]), 0);
        let pending = SignedHead::sign(&key, origin(), 4, Hash([4u8; 32]), 0);
        // Recorded long before any horizon this test uses.
        store.put_head(Slot::Complete, &complete, 1, 1).unwrap();
        store.put_head(Slot::Pending, &pending, 1, 1).unwrap();
        store
            .record_history(&SignedHead::sign(&key, origin(), 1, Hash([1u8; 32]), 0), 1)
            .unwrap();

        assert_eq!(store.prune_history_before(&origin(), i64::MAX).unwrap(), 1);
        assert_eq!(
            store.complete_head(&origin()).unwrap(),
            Some(complete),
            "the current head is still readable"
        );
        assert_eq!(store.pending_head(&origin()).unwrap(), Some(pending));
        // And a second pass over the same horizon finds nothing left to take.
        assert_eq!(store.prune_history_before(&origin(), i64::MAX).unwrap(), 0);
        assert_eq!(store.head_history(&origin()).unwrap().len(), 2);
    }

    #[test]
    fn v11_carries_every_head_signature_across_the_rebuild() {
        // The migration drops the signature columns from `heads`, so it has to
        // move them into `head_history` first or the rebuild silently loses the
        // ability to verify the current head. Built by replaying the chain up
        // to v10 and shaping the old table by hand, so this exercises the
        // migration rather than the code that now writes the new shape.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(crate::db::DB_FILE);
        let key = SecretKey::generate();
        let complete = SignedHead::sign(&key, origin(), 4, Hash([4u8; 32]), 44);
        let pending = SignedHead::sign(&key, origin(), 5, Hash([5u8; 32]), 55);
        {
            let mut conn = rusqlite::Connection::open(&path).unwrap();
            crate::db::migrate(&mut conn, &crate::schema::MIGRATIONS[..10]).unwrap();
            // The v10 shape: signatures copied into `heads`, nothing in history.
            conn.execute_batch(
                "DROP TABLE heads;
                 CREATE TABLE heads (
                   origin_id TEXT NOT NULL, slot TEXT NOT NULL, seq INTEGER NOT NULL,
                   root BLOB NOT NULL, created_at INTEGER NOT NULL, signed_by BLOB NOT NULL,
                   sig BLOB NOT NULL, received_at INTEGER NOT NULL, verified_at INTEGER NOT NULL,
                   PRIMARY KEY (origin_id, slot));",
            )
            .unwrap();
            for (slot, head) in [("complete", &complete), ("pending", &pending)] {
                conn.execute(
                    "INSERT INTO heads (origin_id, slot, seq, root, created_at, signed_by, sig,
                                        received_at, verified_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, 2)",
                    params![
                        head.origin.canonical(),
                        slot,
                        head.seq as i64,
                        head.root.as_bytes().to_vec(),
                        head.created_at,
                        head.signed_by.as_bytes().to_vec(),
                        head.sig.to_bytes().to_vec(),
                    ],
                )
                .unwrap();
            }
        }

        let store = Store::open(dir.path()).unwrap();
        let read_complete = store.complete_head(&origin()).unwrap().unwrap();
        assert_eq!(read_complete, complete);
        read_complete
            .verify_signature()
            .expect("the signature survived the rebuild");
        let read_pending = store.pending_head(&origin()).unwrap().unwrap();
        assert_eq!(read_pending, pending);
        read_pending.verify_signature().unwrap();

        // Both roots are now markable from the one table GC reads.
        let roots = store.retained_roots().unwrap();
        assert!(roots.contains(&complete.root) && roots.contains(&pending.root));
    }

    #[test]
    fn all_heads_lists_every_origin() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        for name in ["nas", "laptop", "vps"] {
            let o = OriginId::named(name, "x.example").unwrap();
            let h = SignedHead::sign(&key, o, 1, Hash::new(name.as_bytes()), 0);
            store.put_head(Slot::Complete, &h, 0, 0).unwrap();
        }
        assert_eq!(store.all_heads(Slot::Complete).unwrap().len(), 3);
        assert_eq!(store.all_heads(Slot::Pending).unwrap().len(), 0);
    }

    #[test]
    fn clearing_a_slot() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        let h = SignedHead::sign(&key, origin(), 1, Hash::EMPTY, 0);
        store.put_head(Slot::Pending, &h, 0, 0).unwrap();
        store.clear_head(&origin(), Slot::Pending).unwrap();
        assert_eq!(store.pending_head(&origin()).unwrap(), None);
    }
}
