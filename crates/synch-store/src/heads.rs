//! The two-slot heads table and the head history (§10, §4.4).

use iroh_base::Signature;
use rusqlite::{params, OptionalExtension, Row};
use synch_core::{Hash, OriginId, SignedHead};

use crate::{
    db::{hash_column, key_column, origin_column, Store},
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

impl Store {
    /// Reads one head slot.
    pub fn head(&self, origin: &OriginId, slot: Slot) -> Result<Option<StoredHead>> {
        let conn = self.conn();
        let row = conn
            .query_row(
                "SELECT origin_id, seq, root, created_at, signed_by, sig, received_at, verified_at
                 FROM heads WHERE origin_id = ?1 AND slot = ?2",
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
        Ok(match (complete, pending) {
            (None, p) => p,
            (c, None) => c,
            (Some(c), Some(p)) => Some(if (p.0, p.1 .0) > (c.0, c.1 .0) { p } else { c }),
        })
    }

    /// Every slot for every origin.
    pub fn all_heads(&self, slot: Slot) -> Result<Vec<StoredHead>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT origin_id, seq, root, created_at, signed_by, sig, received_at, verified_at
             FROM heads WHERE slot = ?1 ORDER BY origin_id",
        )?;
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

    /// Promotes the pending head to complete, atomically (§5.2).
    ///
    /// The displaced complete head is retained in `head_history` with its
    /// signature, as provable history and fork evidence (§4.4, §3.4).
    pub fn promote_pending(&self, origin: &OriginId, now: i64) -> Result<Option<SignedHead>> {
        let Some(pending) = self.head(origin, Slot::Pending)? else {
            return Ok(None);
        };
        let displaced = self.complete_head(origin)?;
        self.transaction(|tx| {
            if let Some(old) = &displaced {
                record_history_in(tx, old)?;
            }
            put_head_in(tx, Slot::Complete, &pending.head, pending.received_at, now)?;
            tx.execute(
                "DELETE FROM heads WHERE origin_id = ?1 AND slot = 'pending'",
                params![origin.canonical()],
            )?;
            Ok(())
        })?;
        Ok(Some(pending.head))
    }

    /// Records a head in `head_history`, keeping its signature.
    pub fn record_history(&self, head: &SignedHead) -> Result<()> {
        let conn = self.conn();
        record_history_in(&conn, head)
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
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as u64,
                row.get::<_, i64>(2)? as usize,
            ))
        })?;
        let mut pairs = Vec::new();
        for row in rows {
            let (origin, seq, count) = row?;
            pairs.push((origin_column(origin, "head_history.origin_id")?, seq, count));
        }
        drop(stmt);
        drop(conn);

        let mut out = Vec::new();
        for (origin, seq, _count) in pairs {
            let heads: Vec<SignedHead> = self
                .head_history(&origin)?
                .into_iter()
                .filter(|h| h.seq == seq)
                .collect();
            out.push(Equivocation { origin, seq, heads });
        }
        Ok(out)
    }

    /// Deletes history entries older than `keep_seq` for an origin, leaving the
    /// retention window (§5.4).
    pub fn prune_history(&self, origin: &OriginId, keep_from_seq: u64) -> Result<usize> {
        Ok(self.conn().execute(
            "DELETE FROM head_history WHERE origin_id = ?1 AND seq < ?2",
            params![origin.canonical(), keep_from_seq as i64],
        )?)
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
    /// Age is the head's own `created_at`, which is the only time this table
    /// carries. For this node's own history that is this node's clock; for a
    /// replicated origin it is the origin's, which is the same member-supplied
    /// metadata §8 and §12 already accept for `mtime_ns`.
    ///
    /// Returns how many rows were dropped.
    pub fn prune_history_before(&self, origin: &OriginId, before: i64) -> Result<usize> {
        let complete = self.complete_head(origin)?;
        let pending = self.pending_head(origin)?;
        let current_seq = complete.as_ref().map(|h| h.seq).unwrap_or(0);
        let current_created = complete.as_ref().map(|h| h.created_at).unwrap_or(i64::MIN);
        // A seq with more than one retained root is a fork, and both sides of
        // it are evidence.
        let forked: Vec<u64> = self
            .equivocations()?
            .into_iter()
            .filter(|e| &e.origin == origin)
            .map(|e| e.seq)
            .collect();
        let moved_past_forks = current_created < before;

        let mut doomed = Vec::new();
        for head in self.head_history(origin)? {
            if head.created_at >= before {
                continue;
            }
            let is_current = [complete.as_ref(), pending.as_ref()]
                .into_iter()
                .flatten()
                .any(|h| h.seq == head.seq && h.root == head.root);
            if is_current {
                continue;
            }
            if forked.contains(&head.seq) && !(current_seq > head.seq && moved_past_forks) {
                continue;
            }
            doomed.push((head.seq, head.root));
        }

        let pruned = doomed.len();
        self.transaction(|tx| {
            for (seq, root) in &doomed {
                tx.execute(
                    "DELETE FROM head_history WHERE origin_id = ?1 AND seq = ?2 AND root = ?3",
                    params![origin.canonical(), *seq as i64, root.as_bytes().to_vec()],
                )?;
            }
            Ok(())
        })?;
        Ok(pruned)
    }

    /// The roots that GC must mark from: every origin's complete and pending
    /// heads plus retained history roots (§5.4).
    ///
    /// Pending heads must be in the mark set or GC would eat an in-progress
    /// bootstrap.
    pub fn retained_roots(&self) -> Result<Vec<Hash>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT root FROM heads UNION SELECT root FROM head_history")?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(hash_column(row?, "heads.root")?);
        }
        Ok(out)
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

fn put_head_in(
    conn: &rusqlite::Connection,
    slot: Slot,
    head: &SignedHead,
    received_at: i64,
    verified_at: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO heads (origin_id, slot, seq, root, created_at, signed_by, sig, received_at, verified_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(origin_id, slot) DO UPDATE SET
           seq = excluded.seq, root = excluded.root, created_at = excluded.created_at,
           signed_by = excluded.signed_by, sig = excluded.sig,
           received_at = excluded.received_at, verified_at = excluded.verified_at",
        params![
            head.origin.canonical(),
            slot.as_str(),
            head.seq as i64,
            head.root.as_bytes().to_vec(),
            head.created_at,
            head.signed_by.as_bytes().to_vec(),
            head.sig.to_bytes().to_vec(),
            received_at,
            verified_at,
        ],
    )?;
    Ok(())
}

fn record_history_in(conn: &rusqlite::Connection, head: &SignedHead) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO head_history (origin_id, seq, root, created_at, signed_by, sig)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            head.origin.canonical(),
            head.seq as i64,
            head.root.as_bytes().to_vec(),
            head.created_at,
            head.signed_by.as_bytes().to_vec(),
            head.sig.to_bytes().to_vec(),
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
    fn promotion_retains_the_displaced_head_as_evidence() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        let old = SignedHead::sign(&key, origin(), 1, Hash([1u8; 32]), 0);
        let new = SignedHead::sign(&key, origin(), 2, Hash([2u8; 32]), 0);
        store.put_head(Slot::Complete, &old, 0, 0).unwrap();
        store.put_head(Slot::Pending, &new, 0, 0).unwrap();

        let promoted = store.promote_pending(&origin(), 10).unwrap().unwrap();
        assert_eq!(promoted, new);
        assert_eq!(store.complete_head(&origin()).unwrap(), Some(new));
        assert_eq!(store.pending_head(&origin()).unwrap(), None);

        let history = store.head_history(&origin()).unwrap();
        assert_eq!(history, vec![old.clone()]);
        // Retained with its signature: provable history, not just a hash.
        history[0].verify_signature().unwrap();
    }

    #[test]
    fn promotion_without_a_pending_head_is_a_no_op() {
        let (_d, store) = store();
        assert!(store.promote_pending(&origin(), 0).unwrap().is_none());
    }

    #[test]
    fn equivocation_is_detected_with_both_proofs() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        let a = SignedHead::sign(&key, origin(), 7, Hash([1u8; 32]), 0);
        let b = SignedHead::sign(&key, origin(), 7, Hash([2u8; 32]), 0);
        let c = SignedHead::sign(&key, origin(), 8, Hash([3u8; 32]), 0);
        for h in [&a, &b, &c] {
            store.record_history(h).unwrap();
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
            store.record_history(&h).unwrap();
        }
        let head = SignedHead::sign(&key, origin(), 6, Hash([6u8; 32]), 0);
        store.put_head(Slot::Complete, &head, 0, 0).unwrap();
        let pending = SignedHead::sign(&key, origin(), 7, Hash([7u8; 32]), 0);
        store.put_head(Slot::Pending, &pending, 0, 0).unwrap();

        let roots = store.retained_roots().unwrap();
        assert_eq!(roots.len(), 7);
        assert!(roots.contains(&Hash([6u8; 32])));
        // Pending heads must be in the mark set (§5.4).
        assert!(roots.contains(&Hash([7u8; 32])));

        assert_eq!(store.prune_history(&origin(), 4).unwrap(), 3);
        assert_eq!(store.head_history(&origin()).unwrap().len(), 2);
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
