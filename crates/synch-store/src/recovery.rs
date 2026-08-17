//! What peers advertise for an origin, and this node's publishing floor (§3.4).
//!
//! A node that lost its key and its database keeps its `OriginId` but starts
//! with an empty `heads` table. Peers still hold heads for that origin, signed
//! by the lost key — which is no longer bound, so those heads can never be
//! accepted (§4.4). Their *existence* is still the only evidence of how far the
//! origin had got, and it arrives for free in the `Hello` summary every peer
//! already sends (§5.1).
//!
//! This module stores that evidence and nothing else. Nothing here is used as a
//! head, no signature is trusted, and the two writes it offers — the observed
//! head per origin and the publishing floor — are ordinary durable records.

use rusqlite::{params, OptionalExtension};
use synch_core::{Hash, NodeId, OriginId};

use crate::{
    db::{hash_column, key_column, origin_column, Store},
    error::{Result, StoreError},
};

/// The config key holding this node's publishing floor.
const FLOOR_KEY: &str = "publish_floor";

/// The highest head a peer has advertised for one origin (§3.4 step 2).
///
/// This is an observation, not a head: it carries no signature and grants no
/// trust. It records that *some* peer claimed an origin had reached this
/// `(seq, root)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedHead {
    /// The origin the summary was about.
    pub origin: OriginId,
    /// The highest seq advertised for it.
    pub seq: u64,
    /// The root advertised at that seq.
    pub root: Hash,
    /// Whether the advertiser said it could serve that trie.
    pub complete: bool,
    /// The peer that made the claim, when it is known.
    ///
    /// Detection rests on unauthenticated summaries — deliberately, since the
    /// true heads are signed by the lost key and cannot validate — so within
    /// the §12 trust stance any member could assert a huge seq and hold a fresh
    /// node in recovery. The attribution is what lets an operator judge the
    /// claim (§3.4).
    pub claimed_by: Option<NodeId>,
    /// When the advertisement was seen, in unix nanoseconds.
    pub observed_at: i64,
}

impl Store {
    /// Records a peer's `Hello` summary for an origin.
    ///
    /// Keeps the greatest `(seq, root)` ever seen, by the same lexicographic
    /// order the acceptance rule uses (§5.2), and returns whether this
    /// observation advanced it.
    pub fn record_observed_head(
        &self,
        origin: &OriginId,
        seq: u64,
        root: &Hash,
        complete: bool,
        claimed_by: Option<&NodeId>,
        now: i64,
    ) -> Result<bool> {
        // The seq is stored as SQLite's signed 64-bit integer and the
        // "keep the greatest" guard below is SQL, so it compares *signed* while
        // every Rust reader of this column compares unsigned. A seq at or above
        // 2^63 therefore stored negative and inverted the ordering in both
        // directions — and §3.4 deliberately does not authenticate the
        // summaries this comes from, so the value is any member's to choose.
        // Downstream it feeds `recovery_state`, which can pin a fresh node in
        // recovery, and then `raise_publish_floor`, which is durable and only
        // ever rises: a floor set from a bogus claim is a node that can never
        // publish an acceptable head again.
        //
        // Refused rather than clamped: a real head cannot have this seq, so the
        // claim is not something to record a rounded-down version of.
        if seq > i64::MAX as u64 {
            return Err(StoreError::invalid(format!(
                "a peer advertised head seq {seq} for {origin}, which is past the representable range"
            )));
        }
        let changed = self.conn().execute(
            "INSERT INTO observed_heads (origin_id, seq, root, complete, claimed_by, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(origin_id) DO UPDATE SET
               seq = excluded.seq, root = excluded.root,
               complete = excluded.complete, claimed_by = excluded.claimed_by,
               observed_at = excluded.observed_at
             WHERE excluded.seq > observed_heads.seq
                OR (excluded.seq = observed_heads.seq AND excluded.root > observed_heads.root)",
            params![
                origin.canonical(),
                seq as i64,
                root.as_bytes().to_vec(),
                complete as i64,
                claimed_by.map(|k| k.as_bytes().to_vec()),
                now,
            ],
        )?;
        Ok(changed > 0)
    }

    /// The highest head any peer has advertised for an origin.
    pub fn observed_head(&self, origin: &OriginId) -> Result<Option<ObservedHead>> {
        let conn = self.conn();
        let row = conn
            .query_row(
                "SELECT origin_id, seq, root, complete, claimed_by, observed_at
                 FROM observed_heads WHERE origin_id = ?1",
                params![origin.canonical()],
                observed_from_row,
            )
            .optional()?;
        row.map(build_observed).transpose()
    }

    /// Every origin some peer has advertised a head for.
    pub fn observed_heads(&self) -> Result<Vec<ObservedHead>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT origin_id, seq, root, complete, claimed_by, observed_at FROM observed_heads
             ORDER BY origin_id",
        )?;
        let rows = stmt.query_map([], observed_from_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(build_observed(row?)?);
        }
        Ok(out)
    }

    /// The seq this node may not publish below (§3.4 step 3).
    pub fn publish_floor(&self) -> Result<Option<u64>> {
        match self.config(FLOOR_KEY)? {
            None => Ok(None),
            Some(text) => text
                .parse::<u64>()
                .map(Some)
                .map_err(|_| StoreError::column("config.publish_floor", text)),
        }
    }

    /// Raises the publishing floor, returning the floor now in force.
    ///
    /// The floor only ever moves up: lowering it could hand out a seq an
    /// earlier publish already used, which is exactly the collision the gap
    /// exists to avoid.
    pub fn raise_publish_floor(&self, seq: u64) -> Result<u64> {
        let effective = self.publish_floor()?.unwrap_or(0).max(seq);
        self.set_config(FLOOR_KEY, &effective.to_string())?;
        Ok(effective)
    }
}

/// The raw column tuple of an `observed_heads` row.
type ObservedRow = (String, i64, Vec<u8>, i64, Option<Vec<u8>>, i64);

fn observed_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ObservedRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

fn build_observed(row: ObservedRow) -> Result<ObservedHead> {
    let (origin, seq, root, complete, claimed_by, observed_at) = row;
    Ok(ObservedHead {
        origin: origin_column(origin, "observed_heads.origin_id")?,
        seq: seq as u64,
        root: hash_column(root, "observed_heads.root")?,
        complete: complete != 0,
        claimed_by: claimed_by
            .map(|bytes| key_column(bytes, "observed_heads.claimed_by"))
            .transpose()?,
        observed_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        (dir, store)
    }

    fn origin() -> OriginId {
        OriginId::named("nas", "x.example").unwrap()
    }

    #[test]
    fn observations_keep_the_greatest_seq_root() {
        let (_d, store) = store();
        assert_eq!(store.observed_head(&origin()).unwrap(), None);

        assert!(store
            .record_observed_head(&origin(), 5, &Hash([1u8; 32]), true, None, 10)
            .unwrap());
        // A lower seq from another peer does not lower the observation.
        assert!(!store
            .record_observed_head(&origin(), 3, &Hash([9u8; 32]), true, None, 11)
            .unwrap());
        assert_eq!(store.observed_head(&origin()).unwrap().unwrap().seq, 5);

        // Same seq, greater root wins — the same lexicographic order the
        // acceptance rule uses (§5.2).
        assert!(store
            .record_observed_head(&origin(), 5, &Hash([2u8; 32]), false, None, 12)
            .unwrap());
        let observed = store.observed_head(&origin()).unwrap().unwrap();
        assert_eq!(observed.root, Hash([2u8; 32]));
        assert!(!observed.complete);
        assert_eq!(observed.observed_at, 12);

        assert!(store
            .record_observed_head(&origin(), 9, &Hash([0u8; 32]), true, None, 13)
            .unwrap());
        assert_eq!(store.observed_head(&origin()).unwrap().unwrap().seq, 9);
    }

    #[test]
    fn observations_are_per_origin() {
        let (_d, store) = store();
        let laptop = OriginId::named("laptop", "x.example").unwrap();
        store
            .record_observed_head(&origin(), 4, &Hash::EMPTY, true, None, 0)
            .unwrap();
        store
            .record_observed_head(&laptop, 7, &Hash::EMPTY, true, None, 0)
            .unwrap();
        let all = store.observed_heads().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(store.observed_head(&laptop).unwrap().unwrap().seq, 7);
    }

    #[test]
    fn the_publishing_floor_only_rises() {
        let (_d, store) = store();
        assert_eq!(store.publish_floor().unwrap(), None);
        assert_eq!(store.raise_publish_floor(1_001).unwrap(), 1_001);
        assert_eq!(store.raise_publish_floor(500).unwrap(), 1_001);
        assert_eq!(store.publish_floor().unwrap(), Some(1_001));
        assert_eq!(store.raise_publish_floor(2_000).unwrap(), 2_000);
    }

    #[test]
    fn the_floor_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = Store::open(dir.path()).unwrap();
            store.raise_publish_floor(4_242).unwrap();
        }
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.publish_floor().unwrap(), Some(4_242));
    }

    #[test]
    fn a_corrupt_floor_is_reported_as_a_column_error() {
        let (_d, store) = store();
        store.set_config(FLOOR_KEY, "not a number").unwrap();
        assert!(store.publish_floor().is_err());
    }

    #[test]
    fn an_observation_records_which_peer_claimed_it() {
        // §3.4: detection rests on unauthenticated summaries, so who made the
        // claim is what an operator judges it by.
        let (_d, store) = store();
        let loud = iroh_base::SecretKey::generate().public();
        let quiet = iroh_base::SecretKey::generate().public();

        store
            .record_observed_head(&origin(), 10, &Hash([1u8; 32]), true, Some(&quiet), 1)
            .unwrap();
        assert_eq!(
            store.observed_head(&origin()).unwrap().unwrap().claimed_by,
            Some(quiet)
        );

        // The claimant moves with the claim: whoever asserted the highest seq
        // is the one named.
        store
            .record_observed_head(&origin(), 5_000, &Hash([2u8; 32]), true, Some(&loud), 2)
            .unwrap();
        let observed = store.observed_head(&origin()).unwrap().unwrap();
        assert_eq!(observed.seq, 5_000);
        assert_eq!(observed.claimed_by, Some(loud));

        // A lower claim changes nothing, claimant included.
        store
            .record_observed_head(&origin(), 9, &Hash([3u8; 32]), true, Some(&quiet), 3)
            .unwrap();
        assert_eq!(
            store.observed_head(&origin()).unwrap().unwrap().claimed_by,
            Some(loud)
        );
    }
}
