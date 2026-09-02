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

/// The complete slots a rebuild can work from, and the rows it cannot read.
///
/// Both halves, because a rebuild has to do the origins it can *and* say which
/// it could not: reporting success having silently skipped one is what
/// `repair rebuild-views` exists to rule out, and failing outright on the first bad
/// row rebuilds nothing at all.
#[derive(Debug, Default)]
pub struct CompleteRoots {
    /// The `(origin, root)` pairs that read back cleanly.
    pub roots: Vec<(OriginId, Hash)>,
    /// The `origin_id` text of every row that did not, as stored.
    pub unreadable: Vec<String>,
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

fn all_heads_in(conn: &rusqlite::Connection, slot: Slot) -> Result<Vec<StoredHead>> {
    let mut stmt = conn.prepare(&format!(
        "{HEAD_JOIN} WHERE h.slot = ?1 ORDER BY h.origin_id"
    ))?;
    let rows = stmt.query_map(params![slot.as_str()], head_from_row)?;
    let mut out = Vec::new();
    for row in rows {
        let (origin, seq, root, created_at, signed_by, sig, received_at, verified_at) = row?;
        match build_head(origin.clone(), seq, root, created_at, signed_by, sig) {
            Ok(head) => out.push(StoredHead {
                head,
                received_at,
                verified_at,
            }),
            Err(e) => tracing::warn!(
                origin,
                seq,
                slot = slot.as_str(),
                error = %e,
                "skipping a head row that cannot be read; this origin cannot sync until \
                 the row is repaired"
            ),
        }
    }
    Ok(out)
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
        head_floor_in(&self.conn(), origin)
    }

    /// Every origin whose complete trie this node holds.
    ///
    /// The candidate list for reading what other origins publish about
    /// themselves — a manifest, a space record, a replication claim. Wider than
    /// the origins with `entries`, deliberately: a node that publishes no files
    /// still publishes records about itself, and a dedicated replica is exactly
    /// that shape.
    pub fn origins_with_complete_heads(&self) -> Result<Vec<OriginId>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT origin_id FROM heads WHERE slot = 'complete' ORDER BY origin_id")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(
                row?.parse()
                    .map_err(|_| StoreError::column("heads.origin_id", "unparseable origin"))?,
            );
        }
        Ok(out)
    }

    /// The origin of some head this node cannot yet materialize, if any.
    ///
    /// `Node::view_state`'s first question, asked per `replica ls` and per
    /// status poll. It only ever needed one row, and reaching it through
    /// [`Store::all_heads`] built every pending head — a `head_history` join
    /// and a signature parsed apiece — to look at the first
    /// (`docs/CLOUD-DATAPLANE.md` §7.1a).
    ///
    /// Reading `heads` alone is also the honest form of the question, and in
    /// the one direction it must not fail in. A pending row means this node
    /// holds no trie for that origin, whatever state the row is in; but
    /// `all_heads` skips a row whose signature will not parse, and its join
    /// drops one whose `head_history` row has gone. Both used to read as
    /// "nothing pending", which reports a view as complete that is not.
    pub fn pending_head_origin(&self) -> Result<Option<OriginId>> {
        let conn = self.conn();
        conn.query_row(
            "SELECT origin_id FROM heads WHERE slot = 'pending' ORDER BY origin_id LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|origin| {
            origin
                .parse()
                .map_err(|_| StoreError::column("heads.origin_id", "unparseable origin"))
        })
        .transpose()
    }

    /// A bound origin, other than `own`, whose complete trie this node does not
    /// hold — if there is one.
    ///
    /// `Node::view_state`'s second question, and the expensive half of it: it
    /// materialized every binding and then asked [`Store::complete_head`] per
    /// row, so ten thousand bindings meant ten thousand point reads, each
    /// joining `head_history` and parsing a signature, to establish that the
    /// answer was `None` (`docs/CLOUD-DATAPLANE.md` §7.1a). The `NOT EXISTS`
    /// seeks `heads`' primary key, and stops at the first origin that fails.
    ///
    /// Every binding is considered, live or expired, exactly as before. An
    /// expired row is a trust decision that has lapsed but not yet been swept
    /// — `expire_bindings` deletes it on the next maintenance pass — and
    /// treating it as absent here would report the view complete in the window
    /// between the lapse and the sweep.
    ///
    /// On the `heads` side this reads the slot alone where the loop read the
    /// head through [`Store::complete_head`], which joins `head_history` and
    /// parses the signature. The two differ only on a complete row whose
    /// history row is gone or will not parse — the loop called that missing
    /// (or failed outright), this calls it held. That row cannot arise from
    /// pruning, which exempts the rows the slots point at, so it is a repair
    /// case, and what it reaches is a status line rather than a release.
    pub fn bound_origin_without_complete_head(&self, own: &OriginId) -> Result<Option<OriginId>> {
        let conn = self.conn();
        conn.query_row(
            "SELECT b.origin_id FROM bindings b
             WHERE b.origin_id <> ?1
               AND NOT EXISTS (SELECT 1 FROM heads h
                               WHERE h.origin_id = b.origin_id AND h.slot = 'complete')
             ORDER BY b.origin_id LIMIT 1",
            params![own.canonical()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|origin| {
            origin
                .parse()
                .map_err(|_| StoreError::column("bindings.origin_id", "unparseable origin"))
        })
        .transpose()
    }

    /// Every slot for every origin.
    ///
    /// A row that will not build is skipped, not propagated. This is the bulk
    /// listing the maintenance sweep and `repair rebuild-views` walk. §12's rule is
    /// that a record this node cannot read fails its own origin and no other; a
    /// point read still reports the failure for that origin.
    ///
    /// One variant is *not* contained, and saying so here is the honest version
    /// of the claim: a `root` that is not a hash also breaks `gc`'s mark set,
    /// which reads `head_history` directly and rightly refuses to proceed —
    /// skipping a root there would delete live trie nodes. So a bad root still
    /// stops garbage collection node-wide until it is repaired. Skipping it here
    /// buys the rest of the maintenance pass, not GC.
    pub fn all_heads(&self, slot: Slot) -> Result<Vec<StoredHead>> {
        all_heads_in(&self.conn(), slot)
    }

    /// The `(origin, root)` of every complete slot, without decoding signatures.
    ///
    /// What a rebuild needs, and all it needs. Going through [`Store::all_heads`]
    /// made it depend on `head_history` joining and on every signature parsing,
    /// neither of which it uses — so a row with an unreadable `sig` was silently
    /// absent from the listing and the rebuild reported success having skipped
    /// that origin entirely, which is the one outcome `repair rebuild-views` exists
    /// to rule out. Reading `heads` alone also drops the join, so a row is only
    /// unreadable here if its own two columns are — and such a row is returned in
    /// `unreadable` for the caller to name, not propagated.
    pub fn complete_slot_roots(&self) -> Result<CompleteRoots> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT origin_id, root FROM heads WHERE slot = ?1 ORDER BY origin_id")?;
        let rows = stmt.query_map(params![Slot::Complete.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut found = CompleteRoots::default();
        for row in rows {
            let (origin, root) = row?;
            // Per row, because the caller rebuilds per origin. Propagating the
            // first bad row rebuilt *nothing* — the whole vector is materialized
            // before the caller starts — which is worse than the failure it
            // replaced and contradicts `rebuild_views`' promise that one origin's
            // failure does not stop the others.
            match (
                origin_column(origin.clone(), "heads.origin_id"),
                hash_column(root, "heads.root"),
            ) {
                (Ok(origin), Ok(root)) => found.roots.push((origin, root)),
                (Err(e), _) | (_, Err(e)) => {
                    tracing::warn!(origin, error = %e, "a complete head row cannot be read");
                    found.unreadable.push(origin);
                }
            }
        }
        Ok(found)
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

    /// Restarts the pending slot's staleness clock, if it still holds
    /// `(seq, root)`.
    ///
    /// Called when a fetch commits something, which is the one event that
    /// distinguishes "this slot is being filled" from "this slot is pinned by a
    /// head nobody serves". Without it the slot's clock would only ever be set
    /// when the slot went from empty to occupied, and a trie larger than
    /// `pending_head_ttl` takes to fetch would be swept mid-transfer.
    ///
    /// Named, for the same reason [`Store::clear_head_at`] is. A fetch reads the
    /// pending head once and then spends many round trips on that root, while
    /// `HeadPush` writes the slot from the blocking pool throughout — so by the
    /// time a batch commits, the slot may hold a *different* head. Touching
    /// whatever is there turns progress on the head the fetch is about into an
    /// extension of the sweep deadline for the head it is not, which is the
    /// wedge the slot-scoped clock exists to break: an unservable head that
    /// keeps being re-stamped by a fetch of something else never ages out.
    ///
    /// Returns whether the named head was still there to touch.
    pub fn touch_pending_at(
        &self,
        origin: &OriginId,
        seq: u64,
        root: &Hash,
        now: i64,
    ) -> Result<bool> {
        let touched = self.conn().execute(
            "UPDATE heads SET received_at = ?4
              WHERE origin_id = ?1 AND slot = 'pending' AND seq = ?2 AND root = ?3",
            params![
                origin.canonical(),
                seq as i64,
                root.as_bytes().to_vec(),
                now
            ],
        )?;
        Ok(touched > 0)
    }

    /// Clears a head slot only if it still holds `(seq, root)`.
    ///
    /// Abandonment is a decision about *one* head, and the two places that
    /// make it — a fetch that gave up after several round trips, and the
    /// maintenance sweep, which walks a trie before it decides — reach their
    /// verdict on a snapshot taken long before the delete. `clear_head` deletes
    /// whatever occupies the slot, so a newer head that a concurrent
    /// `offer_head` installed in the gap went with it: the serve side's
    /// `HeadPush` runs on the blocking pool while a fetch is between round
    /// trips, and the slot is written under a per-statement lock, so the two
    /// interleave freely. The head is recoverable — a peer holding it complete
    /// re-offers it on the next round — but only after a delay the caller never
    /// intended.
    ///
    /// Naming the head being condemned makes the decision and the delete one
    /// step, which is what [`crate::Txn`]'s own `clear_head` gets for free by
    /// reading and writing inside one transaction.
    ///
    /// Returns whether the slot was cleared.
    pub fn clear_head_at(
        &self,
        origin: &OriginId,
        slot: Slot,
        seq: u64,
        root: &Hash,
    ) -> Result<bool> {
        let cleared = self.conn().execute(
            "DELETE FROM heads
              WHERE origin_id = ?1 AND slot = ?2 AND seq = ?3 AND root = ?4",
            params![
                origin.canonical(),
                slot.as_str(),
                seq as i64,
                root.as_bytes().to_vec()
            ],
        )?;
        Ok(cleared > 0)
    }

    /// The seq this node's next head for `origin` must carry.
    ///
    /// One function, because "what comes next" is one rule and it had three
    /// writers restating it. `publish` and the key rotation in `activate` both
    /// derived it from the **complete slot alone**, and `try_promote` carried a
    /// ten-line comment explaining that it therefore could not trust "pending
    /// is always greater than complete" and had to re-check the ordering itself
    /// — a downstream reader defending against an invariant with no owner.
    ///
    /// What the complete slot alone misses:
    ///
    /// - **The pending slot.** A peer's copy of one of our own heads — signed
    ///   by a key of ours that is still bound, which is exactly the §3.4
    ///   recovery shape — sits there for the length of a fetch. Publishing
    ///   `complete.seq + 1` against it mints a second root at a seq this
    ///   origin has already signed.
    /// - **Retained history.** A database restored from a backup still has a
    ///   complete head, so `recovery_state` does not call it recovery (§3.4
    ///   covers key loss, not a rolled-back store) and nothing stops it
    ///   publishing straight into seqs it used before the restore. Every head
    ///   a peer has relayed back to us since is in `head_history`, verified and
    ///   bound, and that is the highest seq this node can prove its origin
    ///   reached.
    ///
    /// Self-equivocation is not a theoretical harm: both roots are valid and
    /// bound, so every peer takes the greater one under the §5.2 rule, and if
    /// that is the *older* root this node's own `entries` are rolled back to it
    /// on every peer that adopted it.
    ///
    /// The publishing floor (§3.4) is applied here too, so recovery's "resume
    /// above what peers saw" and this rule cannot disagree.
    pub fn next_own_seq(&self, origin: &OriginId) -> Result<u64> {
        next_own_seq_in(&self.conn(), origin)
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
    /// `doctor`'s equivocation report costs the retained rows. What bounds the
    /// width is
    /// [`Txn::trim_forks`], which *evicts* the lowest-ordered rows at a seq
    /// rather than refusing the head that would widen it — acceptance is the
    /// one thing convergence rests on and may never depend on how many roots
    /// happened to arrive first.
    pub fn fork_width(&self, origin: &OriginId, seq: u64) -> Result<usize> {
        fork_width_in(&self.conn(), origin, seq)
    }

    /// True if `root` is a root this node holds as a head — current, pending,
    /// or retained history.
    ///
    /// What makes a claimed *position* mean anything (§5.5). A position is
    /// only ever "where a node sits in some trie", so the trie has to be one
    /// this node vouches for: given an arbitrary root, the empty path resolves
    /// to that root itself and every position below it is whatever the caller
    /// chose, which would make authorization-by-position authorize nothing.
    /// Roots reached this way are ones some origin signed and this node
    /// verified, so the positions in them are real.
    ///
    /// `head_history` alone answers it: since v11 the `heads` slots point at a
    /// history row rather than carrying their own signature, so every root
    /// either slot names is here, and so is every root retained for a laggard.
    ///
    /// `except` names origins whose roots do not count — the asking peer's
    /// own. Signing a head is not the same as being vouched for: a delegate
    /// publishes its own trie, and this node records that root in
    /// `head_history` as soon as the signature and the delegated binding
    /// verify. A root the *asker* authored is exactly "a root of the caller's
    /// choosing" that the paragraph above rules out — it can place any node
    /// hash it has heard of at any position it likes, then ask for that
    /// position and be handed the node. What makes a position real is that
    /// someone else laid it out.
    pub fn is_head_root(&self, root: &Hash, except: &[OriginId]) -> Result<bool> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT origin_id FROM head_history WHERE root = ?1")?;
        let mut rows = stmt.query_map(params![root.as_bytes().to_vec()], |row| {
            row.get::<_, String>(0)
        })?;
        let excluded: Vec<String> = except.iter().map(|o| o.canonical()).collect();
        rows.try_fold(false, |seen, row| Ok(seen || !excluded.contains(&row?)))
    }

    /// The origins this node holds `root` as a verified head of, in any slot
    /// or in the retained history.
    ///
    /// What a responder needs to decide whose trie a request is walking: a
    /// confined origin's root is served only with provenance
    /// (`NodeStore::owns_node`), and the same root may in principle stand in
    /// more than one origin's history.
    pub fn head_root_origins(&self, root: &Hash) -> Result<Vec<OriginId>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT DISTINCT origin_id FROM head_history WHERE root = ?1")?;
        let rows = stmt.query_map(params![root.as_bytes().to_vec()], |row| {
            row.get::<_, String>(0)
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(origin_column(row?, "head_history.origin_id")?);
        }
        Ok(out)
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
    /// One ordered scan, not a full history read per forked pair. The pairs are
    /// found by a `GROUP BY` and the heads by a join against the same grouping,
    /// so the whole report costs the forked rows rather than the forked rows
    /// times the origin's entire history. `trim_forks` bounds the *width* of one
    /// seq's fork and nothing bounds how many seqs are forked, so the quadratic
    /// version grew with what an equivocating member chose to publish.
    pub fn equivocations(&self) -> Result<Vec<Equivocation>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT h.origin_id, h.seq, h.root, h.created_at, h.signed_by, h.sig
               FROM head_history h
               JOIN (SELECT origin_id, seq FROM head_history
                      GROUP BY origin_id, seq
                     HAVING COUNT(DISTINCT root) > 1) f
                 ON f.origin_id = h.origin_id AND f.seq = h.seq
              ORDER BY h.origin_id, h.seq, h.root",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as u64,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })?;

        let mut out: Vec<Equivocation> = Vec::new();
        for row in rows {
            let (origin, seq, root, created_at, signed_by, sig) = row?;
            let head = build_head(origin, seq, root, created_at, signed_by, sig)?;
            match out.last_mut() {
                Some(last) if last.origin == head.origin && last.seq == seq => {
                    last.heads.push(head)
                }
                _ => out.push(Equivocation {
                    origin: head.origin.clone(),
                    seq,
                    heads: vec![head],
                }),
            }
        }
        Ok(out)
    }

    /// Every origin that has retained history.
    pub fn history_origins(&self) -> Result<Vec<OriginId>> {
        self.history_origins_matching("", params![])
    }

    /// The origins holding at least one retained root older than `before`.
    ///
    /// Which is to say: the only origins [`Store::prune_history_before`] can
    /// take a row from, since every one of its deletions requires
    /// `recorded_at < before`. The maintenance pass asks with this rather than
    /// with [`Store::history_origins`] because pruning opens an *immediate*
    /// transaction per origin — it has to, to decide and delete over one
    /// snapshot — and on a replica of ten thousand origins that was ten
    /// thousand write-lock acquisitions every five minutes to delete nothing,
    /// in front of every other tenant's store work on the shard
    /// (`docs/CLOUD-DATAPLANE.md` §7.1a). In a settled steady state this
    /// returns empty and the pass costs one read.
    pub fn history_origins_before(&self, before: i64) -> Result<Vec<OriginId>> {
        self.history_origins_matching("WHERE recorded_at < ?1", params![before])
    }

    fn history_origins_matching(
        &self,
        filter: &str,
        args: impl rusqlite::Params,
    ) -> Result<Vec<OriginId>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT DISTINCT origin_id FROM head_history {filter} ORDER BY origin_id"
        ))?;
        let rows = stmt.query_map(args, |row| row.get::<_, String>(0))?;
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
    /// and an open one. Reading it off the complete head asks whether the head
    /// this node holds *now* is older than retention, so any origin publishing
    /// once per `root_retention` pins every fork row it has ever signed — and
    /// every trie node reachable from those roots, since retained roots are GC
    /// mark roots. It is open at the other end too: a fork at a seq *above* the
    /// complete head never satisfies `current_seq > seq`, so an origin signing
    /// two roots at each of a thousand far-future seqs and serving none of the
    /// tries makes every one of those rows permanent, `trust rm` and all.
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
            // The top of the retained history, which this pass may never take.
            //
            // `next_own_seq` reads `MAX(seq)` over `heads ∪ head_history`, so
            // this row is how far the origin is known to have got. Pruning it
            // *lowers* that ceiling — and for this node's own origin that means
            // re-publishing seqs it has already used, which is equivocation by an
            // honest node: peers holding the older head reject the new one as
            // `NotNewer`, so its data stops propagating, and the duplicate seqs
            // are retained as proof against it.
            //
            // The window that gets there is ordinary. A restored backup adopts a
            // relayed head of its own origin at the seq it really reached (§3.4),
            // which is exactly what defends the ceiling; if that head's trie is
            // never served, `sweep_pending_heads` clears the slot after
            // `pending_head_ttl` and the history row is all that is left. Seven
            // days later this pass would take it.
            //
            // One row per origin is the whole cost, and it is the row that
            // carries a fact nothing else records.
            let ceiling = receipts.iter().map(|(seq, _, _)| *seq).max();
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
            // would take it — leaving a fork that nothing can ever retire. It
            // stays until the fork it speaks about can go with it.
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
                if Some(seq) == ceiling {
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
    ///
    /// One implementation, shared with the sweep, because there were two — this
    /// one and a byte-identical private copy in `gc`, with the sweep executing
    /// the copy and the sweep's own test asserting on this one. A rule verified
    /// against a version production does not run is not verified.
    #[cfg(test)]
    pub(crate) fn retained_roots(&self) -> Result<Vec<Hash>> {
        crate::gc::retained_roots_in(&self.conn())
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
        head_floor_in(self.conn(), origin)
    }

    /// The seq this node's next head for `origin` must carry, read inside the
    /// transaction that will write it.
    ///
    /// See [`Store::next_own_seq`] for why this is one function and not a rule
    /// each writer restates.
    pub fn next_own_seq(&self, origin: &OriginId) -> Result<u64> {
        next_own_seq_in(self.conn(), origin)
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

    /// Every head in a slot, inside the transaction.
    ///
    /// The transactional twin of [`Store::all_heads`], for the one caller that
    /// has to read the set and rewrite it atomically: moving the read scope
    /// demotes every foreign complete head, and a head promoted between the
    /// read and the write would keep a completeness claim made under a scope
    /// that has gone.
    pub fn all_heads(&self, slot: Slot) -> Result<Vec<StoredHead>> {
        all_heads_in(self.conn(), slot)
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
        fork_width_in(self.conn(), origin, seq)
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
    /// forever. Evicting keeps the *greatest* `keep` roots at the seq, and
    /// always leaves the two that prove the equivocation (§4.4) as long as
    /// `keep >= 2`.
    ///
    /// A row a slot points at is never evicted: since v11 `heads` names a
    /// `head_history` row and every head read joins the two, so a slot whose row
    /// went would be a head that can no longer be read. Same guard, and for the
    /// same reason, as [`Store::prune_history_before`]'s.
    ///
    /// That guard is also the one way the retained set is *not* identical on
    /// every peer: it is the greatest `keep` roots plus whatever a slot still
    /// names, and which roots reached a slot depends on the order they arrived
    /// in. The deviation is bounded by the number of slots, so a peer retains at
    /// most `keep + 2` roots at a seq and the retention bound holds. Nothing
    /// reads across it — `head_floor` reads `heads`, never this table — so head
    /// selection stays order-independent; what can differ between two peers is a
    /// `doctor` fork line and one root's subtree staying in the GC mark set.
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
    // has to remember to record history alongside — a rule that would
    // otherwise have to be kept by hand, redundantly, at every call site.
    record_history_in(conn, head, received_at)?;
    // A `seq` past `i64::MAX` would bind as a negative integer and invert every
    // SQL ordering over `heads` and `head_history` — silently, and for good,
    // since the row it corrupts is the one head selection reads. Nothing
    // honest reaches it (`record_observed_head` refuses such a claim and the
    // publish floor is capped), so this is the backstop that keeps the column's
    // domain equal to the type's.
    let seq = i64::try_from(head.seq)
        .map_err(|_| StoreError::column("heads.seq", "past the representable range"))?;
    // `received_at` on the pending slot ages the *slot*, not the head in it.
    //
    // Occupying an empty slot starts the clock; adopting a newer head into an
    // occupied one inherits it; `touch_pending_at` restarts it when a fetch
    // actually makes progress, so a large trie that is genuinely arriving is
    // not swept out from under itself.
    conn.execute(
        "INSERT INTO heads (origin_id, slot, seq, root, received_at, verified_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(origin_id, slot) DO UPDATE SET
           seq = excluded.seq, root = excluded.root,
           received_at = CASE
             WHEN excluded.slot = ?7 THEN heads.received_at
             ELSE excluded.received_at
           END,
           verified_at = excluded.verified_at",
        params![
            head.origin.canonical(),
            slot.as_str(),
            seq,
            head.root.as_bytes().to_vec(),
            received_at,
            verified_at,
            Slot::Pending.as_str(),
        ],
    )?;
    Ok(())
}

/// The one implementation behind [`Store::head_floor`] and [`Txn::head_floor`].
fn head_floor_in(conn: &rusqlite::Connection, origin: &OriginId) -> Result<Option<(u64, Hash)>> {
    let complete = head_in(conn, origin, Slot::Complete)?.map(|s| (s.head.seq, s.head.root));
    let pending = head_in(conn, origin, Slot::Pending)?.map(|s| (s.head.seq, s.head.root));
    Ok(best_floor(complete, pending))
}

/// The one implementation behind [`Store::fork_width`] and [`Txn::fork_width`].
fn fork_width_in(conn: &rusqlite::Connection, origin: &OriginId, seq: u64) -> Result<usize> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM head_history WHERE origin_id = ?1 AND seq = ?2",
        params![origin.canonical(), seq as i64],
        |row| row.get::<_, i64>(0),
    )? as usize)
}

/// The one implementation behind [`Store::next_own_seq`] and
/// [`Txn::next_own_seq`], so the two scopes cannot drift.
fn next_own_seq_in(conn: &rusqlite::Connection, origin: &OriginId) -> Result<u64> {
    // The highest seq this node can prove the origin reached, from every place
    // that records one: both slots, and the retained history behind them.
    let highest: i64 = conn
        .query_row(
            "SELECT MAX(seq) FROM (
             SELECT seq FROM heads        WHERE origin_id = ?1
             UNION ALL
             SELECT seq FROM head_history WHERE origin_id = ?1
         )",
            params![origin.canonical()],
            |row| row.get::<_, Option<i64>>(0),
        )?
        .unwrap_or(0);
    let floor = crate::recovery::publish_floor_in(conn)?.unwrap_or(0);
    Ok((highest.max(0) as u64).saturating_add(1).max(floor))
}

/// Records a head's signature, refusing a second signature over one
/// `(origin, seq, root)`.
///
/// The row is keyed by `(origin_id, seq, root)` and `signed_by`/`sig`/
/// `created_at` are not in the key, so `INSERT OR IGNORE` silently kept the
/// *first* signature and dropped the incoming one. Since v11 `heads` holds only
/// `(seq, root)` and every head read joins the two, so the slot then read back
/// as a head nobody put there: a different signer, a different `created_at`, and
/// a `verified_at` recording a binding check that was made about the *other*
/// head. `heads_for` would hand peers that head, and if its signer had since
/// been unbound every peer would reject it as `Unbound` — with the origin
/// blamed.
///
/// Ed25519 is deterministic, so an origin re-signing the same root at the same
/// seq produces the same bytes and lands in the no-op case. Anything else is two
/// keys claiming one point of an origin's history, which is not a thing to store
/// quietly under whichever arrived first.
fn record_history_in(
    conn: &rusqlite::Connection,
    head: &SignedHead,
    recorded_at: i64,
) -> Result<()> {
    let seq = i64::try_from(head.seq)
        .map_err(|_| StoreError::column("head_history.seq", "past the representable range"))?;
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO head_history
           (origin_id, seq, root, created_at, signed_by, sig, recorded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            head.origin.canonical(),
            seq,
            head.root.as_bytes().to_vec(),
            head.created_at,
            head.signed_by.as_bytes().to_vec(),
            head.sig.to_bytes().to_vec(),
            recorded_at,
        ],
    )?;
    if inserted > 0 {
        return Ok(());
    }
    // A row was already there. It has to be the same head, or the pointer the
    // slot is about to write means something other than what the caller
    // verified.
    let (signed_by, sig, created_at): (Vec<u8>, Vec<u8>, i64) = conn.query_row(
        "SELECT signed_by, sig, created_at FROM head_history
          WHERE origin_id = ?1 AND seq = ?2 AND root = ?3",
        params![head.origin.canonical(), seq, head.root.as_bytes().to_vec()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let same = signed_by == head.signed_by.as_bytes()
        && sig == head.sig.to_bytes()
        && created_at == head.created_at;
    if !same {
        return Err(StoreError::invalid(format!(
            "{} already retains a different signature at seq {} over root {}",
            head.origin, head.seq, head.root
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;
    use synch_core::{Hash, OriginId};

    use super::*;
    use crate::testutil::{origin, origin_named, sign_head, store};

    /// The pruning pre-filter never hides an origin that had a row to lose.
    ///
    /// `maintenance_pass` asks `history_origins_before` instead of
    /// `history_origins` so it does not open a write transaction per origin to
    /// conclude there was nothing to prune. That is only sound if the two
    /// disagree exactly where pruning is a no-op, so the claim is checked
    /// against pruning itself rather than argued: every origin the filter drops
    /// must prune nothing, and every origin it keeps must be one the unfiltered
    /// listing had too.
    #[test]
    fn the_pruning_prefilter_hides_only_origins_with_nothing_to_prune() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        // Six origins recorded across the window: three well before the
        // horizon, three after it, so the filter has both to sort.
        for (i, recorded_at) in [10, 20, 30, 5_000, 6_000, 7_000].into_iter().enumerate() {
            let o = OriginId::named(&format!("n{i}"), "x.example").unwrap();
            // Two roots apiece, so an origin has something left to prune after
            // the exemption for the highest seq it is on record at.
            for seq in 1..=3 {
                let head =
                    SignedHead::sign(&key, o.clone(), seq, Hash::new(&[i as u8, seq as u8]), 0);
                store
                    .record_history(&head, recorded_at + seq as i64)
                    .unwrap();
            }
        }

        let before = 1_000;
        let all = store.history_origins().unwrap();
        let candidates = store.history_origins_before(before).unwrap();
        assert_eq!(all.len(), 6);
        assert_eq!(candidates.len(), 3, "only the aged origins are candidates");
        assert!(
            candidates.iter().all(|o| all.contains(o)),
            "the filter must narrow the listing, never add to it"
        );

        // The claim that matters: what it dropped had nothing to give.
        for origin in all.iter().filter(|o| !candidates.contains(o)) {
            assert_eq!(
                store.prune_history_before(origin, before).unwrap(),
                0,
                "{origin} was filtered out but had rows to prune"
            );
        }
        // And what it kept did — otherwise the assertion above is satisfied by
        // a filter that keeps everything, or by a pass that prunes nothing.
        let pruned: usize = candidates
            .iter()
            .map(|o| store.prune_history_before(o, before).unwrap())
            .sum();
        assert!(pruned > 0, "the aged origins should have lost rows");
    }

    #[test]
    fn head_slots_round_trip() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        let head = SignedHead::sign(&key, origin(), 4, Hash::new(b"r"), 99);
        store.put_head(Slot::Complete, &head, 1, 2).unwrap();

        let stored = store.head(&origin(), Slot::Complete).unwrap().unwrap();
        assert_eq!(stored.head, head);
        assert_eq!((stored.received_at, stored.verified_at), (1, 2));
        // The signature survives the SQLite round trip through the HEAD_JOIN.
        stored.head.verify_signature().unwrap();
        assert_eq!(store.pending_head(&origin()).unwrap(), None);

        // The listing names every origin's slot.
        for name in ["laptop", "vps"] {
            let o = OriginId::named(name, "x.example").unwrap();
            let h = SignedHead::sign(&key, o, 1, Hash([1u8; 32]), 0);
            store.put_head(Slot::Complete, &h, 0, 0).unwrap();
        }
        assert_eq!(store.all_heads(Slot::Complete).unwrap().len(), 3);
        assert_eq!(store.all_heads(Slot::Pending).unwrap().len(), 0);

        // Clearing a slot only takes the named head.
        let pending = sign_head(&key, 1, 9);
        store.put_head(Slot::Pending, &pending, 0, 0).unwrap();
        assert!(!store
            .clear_head_at(&origin(), Slot::Pending, 1, &Hash([8u8; 32]))
            .unwrap());
        assert!(store.pending_head(&origin()).unwrap().is_some());
        assert!(store
            .clear_head_at(&origin(), Slot::Pending, 1, &Hash([9u8; 32]))
            .unwrap());
        assert_eq!(store.pending_head(&origin()).unwrap(), None);
    }

    #[test]
    fn head_floor_is_the_best_of_both_slots() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        assert_eq!(store.head_floor(&origin()).unwrap(), None);

        store
            .put_head(Slot::Complete, &sign_head(&key, 3, 1), 0, 0)
            .unwrap();
        assert_eq!(
            store.head_floor(&origin()).unwrap(),
            Some((3, Hash([1u8; 32])))
        );

        store
            .put_head(Slot::Pending, &sign_head(&key, 5, 2), 0, 0)
            .unwrap();
        assert_eq!(
            store.head_floor(&origin()).unwrap(),
            Some((5, Hash([2u8; 32])))
        );
    }

    #[test]
    fn equivocation_is_detected_with_both_proofs() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        for h in [
            sign_head(&key, 7, 1),
            sign_head(&key, 7, 2),
            sign_head(&key, 8, 3),
        ] {
            store.record_history(&h, 0).unwrap();
        }
        let found = store.equivocations().unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].seq, 7);
        assert_eq!(found[0].heads.len(), 2);
        // The evidence is the signatures: both retained heads verify.
        for h in &found[0].heads {
            h.verify_signature().unwrap();
        }
    }

    /// Pruning reports what it took, and what the slots point at survives
    /// every horizon: `put_head` retains its roots by construction, and
    /// `heads` names a `head_history` row, so taking it would make a head
    /// unreadable.
    #[test]
    fn pruning_keeps_the_slot_rows_and_their_roots() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        for seq in 1..=5u64 {
            // Received in seq order, which is what retention reads.
            store
                .record_history(&sign_head(&key, seq, seq as u8), seq as i64)
                .unwrap();
        }
        let complete = sign_head(&key, 6, 6);
        let pending = sign_head(&key, 7, 7);
        store.put_head(Slot::Complete, &complete, 10, 0).unwrap();
        store.put_head(Slot::Pending, &pending, 10, 0).unwrap();

        // Seven distinct roots: five recorded directly, plus the two the slots
        // point at, which `put_head` retains by construction.
        let roots = store.retained_roots().unwrap();
        assert_eq!(roots.len(), 7);
        assert!(roots.contains(&Hash([6u8; 32])));

        // A horizon past the first three drops them; seqs 4 and 5 remain, as
        // do the two the slots point at.
        assert_eq!(store.prune_history_before(&origin(), 4).unwrap(), 3);
        assert_eq!(store.head_history(&origin()).unwrap().len(), 4);

        // A horizon past everything leaves only the slot rows: both heads
        // still answer, and a second pass finds nothing left to take.
        assert_eq!(store.prune_history_before(&origin(), i64::MAX).unwrap(), 2);
        assert_eq!(store.complete_head(&origin()).unwrap(), Some(complete));
        assert_eq!(store.pending_head(&origin()).unwrap(), Some(pending));
        assert_eq!(store.head_history(&origin()).unwrap().len(), 2);
        assert_eq!(store.prune_history_before(&origin(), i64::MAX).unwrap(), 0);
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

    /// A rebuild sees the rows it can read and is told about the ones it cannot.
    ///
    /// Both halves matter and neither had a test: skipping a row silently is what
    /// lets `repair rebuild-views` report success having rebuilt nothing for an
    /// origin, and propagating instead rebuilt nothing for *any* origin, because
    /// the whole list is materialized before the caller starts.
    #[test]
    fn complete_slot_roots_separates_the_readable_from_the_unreadable() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        let good = SignedHead::sign(&key, origin(), 1, Hash::EMPTY, 0);
        store.put_head(Slot::Complete, &good, 0, 0).unwrap();

        let found = store.complete_slot_roots().unwrap();
        assert_eq!(found.roots, [(origin(), Hash::EMPTY)]);
        assert!(found.unreadable.is_empty());

        // A root that is not a hash — the shape a corrupted row has, and the one
        // a rebuild cannot do anything with.
        let broken = OriginId::named("broken", "x.example").unwrap();
        store
            .conn()
            .execute(
                "INSERT INTO heads (origin_id, slot, seq, root, received_at, verified_at)
                 VALUES (?1, 'complete', 1, ?2, 0, 0)",
                rusqlite::params![broken.canonical(), vec![0u8; 31]],
            )
            .unwrap();

        let found = store.complete_slot_roots().unwrap();
        assert_eq!(
            found.roots,
            [(origin(), Hash::EMPTY)],
            "the readable row is still returned"
        );
        assert_eq!(
            found.unreadable,
            [broken.canonical()],
            "and the unreadable one is named rather than propagated or dropped"
        );
    }

    /// A binding with no head, and a plain one, so the anti-join has both.
    fn bind(store: &Store, origin: &OriginId, expires_at: Option<i64>) {
        store
            .put_binding(&crate::Binding {
                origin: origin.clone(),
                node_id: SecretKey::generate().public(),
                source: crate::BindingSource::Dns,
                domain: Some("x.example".to_string()),
                issuer: None,
                spaces: Vec::new(),
                note: None,
                added_at: 0,
                expires_at,
            })
            .unwrap();
    }

    /// The indexed answer is the one the listing-and-looking loop gave.
    ///
    /// `Node::view_state` used to materialize every binding and ask
    /// `complete_head` per row. The rewrite has to agree with that everywhere,
    /// not merely on the empty case that a replica in good health is in — so
    /// the old loop is written out here and the two are held against each
    /// other over a table with every shape in it: an origin with a complete
    /// head, one with only a pending head, one with no head at all, one bound
    /// twice, and this node's own origin, which is exempt.
    #[test]
    fn the_bound_origin_without_a_head_is_the_one_the_loop_found() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        let own = origin_named("self");

        // `synced` has a complete head; `pending-only` has a head this node
        // cannot materialize; `never` and `also-never` have none. `own` has
        // none either, and must be skipped for being this node's own.
        let synced = origin_named("synced");
        store
            .put_head(
                Slot::Complete,
                &SignedHead::sign(&key, synced.clone(), 1, Hash::EMPTY, 0),
                0,
                0,
            )
            .unwrap();
        let pending_only = origin_named("pending-only");
        store
            .put_head(
                Slot::Pending,
                &SignedHead::sign(&key, pending_only.clone(), 1, Hash::new(b"p"), 0),
                0,
                0,
            )
            .unwrap();
        let never = origin_named("never");
        let also_never = origin_named("also-never");
        for o in [&own, &synced, &pending_only, &never, &also_never] {
            bind(&store, o, None);
        }
        // Bound twice, which is ordinary: one origin, two device keys.
        bind(&store, &never, Some(i64::MAX));

        // The loop this replaced, verbatim in shape.
        let by_loop = |own: &OriginId| -> Option<OriginId> {
            store
                .bindings()
                .unwrap()
                .into_iter()
                .filter(|b| b.origin != *own)
                .find(|b| store.complete_head(&b.origin).unwrap().is_none())
                .map(|b| b.origin)
        };

        // `also-never` sorts first of the two that qualify, and a pending head
        // is not a complete one, so `pending-only` qualifies as well.
        let found = store.bound_origin_without_complete_head(&own).unwrap();
        assert_eq!(found, Some(also_never.clone()));
        assert_eq!(found, by_loop(&own), "the index and the loop must agree");

        // Give every qualifying origin a complete head and the answer goes to
        // `None` — which reports the view complete, so it has to be reached
        // only when it is true.
        for o in [&also_never, &never, &pending_only] {
            store
                .put_head(
                    Slot::Complete,
                    &SignedHead::sign(&key, o.clone(), 1, Hash::EMPTY, 0),
                    0,
                    0,
                )
                .unwrap();
        }
        assert_eq!(
            store.bound_origin_without_complete_head(&own).unwrap(),
            None
        );
        assert_eq!(by_loop(&own), None);

        // The exemption is for this node's own origin and nothing else: ask as
        // some other node and `self` is just another bound origin with no head.
        let elsewhere = origin_named("elsewhere");
        assert_eq!(
            store
                .bound_origin_without_complete_head(&elsewhere)
                .unwrap(),
            Some(own.clone())
        );
        assert_eq!(by_loop(&elsewhere), Some(own));
    }

    /// A pending head is reported however damaged its row is.
    ///
    /// This is the direction the question must not fail in: a pending slot
    /// means this node holds no trie for that origin, and answering "nothing
    /// pending" reports a view as complete that is not. `all_heads` — which
    /// `view_state` used to ask — skips a row whose signature will not parse
    /// and joins away one whose `head_history` row has gone, so both read as
    /// nothing pending. Reading `heads` alone is why they no longer do.
    #[test]
    fn a_pending_head_is_reported_even_when_its_row_will_not_build() {
        let (_d, store) = store();
        let key = SecretKey::generate();
        assert_eq!(store.pending_head_origin().unwrap(), None);

        // A complete head is not a pending one.
        store
            .put_head(
                Slot::Complete,
                &SignedHead::sign(&key, origin(), 1, Hash::EMPTY, 0),
                0,
                0,
            )
            .unwrap();
        assert_eq!(store.pending_head_origin().unwrap(), None);

        let stuck = origin_named("stuck");
        let head = SignedHead::sign(&key, stuck.clone(), 1, Hash::new(b"p"), 0);
        store.put_head(Slot::Pending, &head, 0, 0).unwrap();
        assert_eq!(store.pending_head_origin().unwrap(), Some(stuck.clone()));

        // The history row this slot points at, gone — a repair case, and the
        // one `all_heads`' join silently drops.
        store
            .conn()
            .execute(
                "DELETE FROM head_history WHERE origin_id = ?1",
                rusqlite::params![stuck.canonical()],
            )
            .unwrap();
        assert!(
            store.all_heads(Slot::Pending).unwrap().is_empty(),
            "the listing loses it, which is the reason this query does not use it"
        );
        assert_eq!(
            store.pending_head_origin().unwrap(),
            Some(stuck),
            "the slot is still occupied, so the view is still incomplete"
        );
    }
}
