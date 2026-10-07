//! Cluster-lock state this node keeps across restarts (`docs/LOCKS.md` §9.2).
//!
//! Two things, both local and never replicated: the Lamport clock lock tickets
//! are taken from, and the holds this node itself has. Everything else about a
//! lock — who else claims it, what ended — is soft state the engine keeps in
//! memory and relearns from its peers.

use rusqlite::{params, OptionalExtension};

use crate::{db::Store, error::Result};

/// One hold this node has, as it is persisted (§5).
///
/// Only `lease` and `sticky` holds are written: a `session` hold dies with its
/// client's control stream, and with the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockHoldRow {
    /// The lock's space.
    pub space: String,
    /// The lock's name within the space.
    pub name: String,
    /// The claim's origin, canonically rendered.
    pub origin: String,
    /// The claim's Lamport time.
    pub lamport: u64,
    /// The claim's nonce.
    pub nonce: u64,
    /// The lease observers keep without a renewal.
    pub ttl_ms: u32,
    /// True when the daemon renews until release; false when the client must.
    pub sticky: bool,
    /// Display only: who asked for it.
    pub owner: String,
    /// Opaque: an S3 lock key's body.
    pub payload: Vec<u8>,
    /// The expired claims this one took over from, encoded by the engine.
    pub supersedes: Vec<u8>,
    /// When it was acquired, unix nanoseconds — display only.
    pub acquired_at: i64,
    /// A lease-mode hold's client deadline, unix nanoseconds.
    pub lease_until: Option<i64>,
}

impl Store {
    /// The persisted Lamport clock, zero on a node that never claimed.
    pub fn lock_clock(&self) -> Result<u64> {
        let value: Option<i64> = self
            .conn()
            .query_row("SELECT lamport FROM lock_clock WHERE id = 0", [], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(value.map_or(0, |v| v as u64))
    }

    /// Raises the persisted clock to `lamport`; never lowers it.
    pub fn raise_lock_clock(&self, lamport: u64) -> Result<()> {
        self.conn().execute(
            "INSERT INTO lock_clock (id, lamport) VALUES (0, ?1)
               ON CONFLICT(id) DO UPDATE SET lamport = MAX(lamport, excluded.lamport)",
            params![lamport as i64],
        )?;
        Ok(())
    }

    /// Records a hold, replacing any earlier hold of the same lock.
    pub fn put_lock_hold(&self, row: &LockHoldRow) -> Result<()> {
        self.conn().execute(
            "INSERT INTO lock_holds (space, name, origin, lamport, nonce, ttl_ms, mode, owner,
                                     payload, supersedes, acquired_at, lease_until)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(space, name) DO UPDATE SET
               origin = excluded.origin, lamport = excluded.lamport, nonce = excluded.nonce,
               ttl_ms = excluded.ttl_ms, mode = excluded.mode, owner = excluded.owner,
               payload = excluded.payload, supersedes = excluded.supersedes,
               acquired_at = excluded.acquired_at, lease_until = excluded.lease_until",
            params![
                row.space,
                row.name,
                row.origin,
                row.lamport as i64,
                row.nonce as i64,
                row.ttl_ms,
                if row.sticky { "sticky" } else { "lease" },
                row.owner,
                row.payload,
                row.supersedes,
                row.acquired_at,
                row.lease_until,
            ],
        )?;
        Ok(())
    }

    /// Forgets a hold — only the claim named, so a stale removal cannot take
    /// a newer hold of the same lock with it.
    pub fn remove_lock_hold(
        &self,
        space: &str,
        name: &str,
        lamport: u64,
        nonce: u64,
    ) -> Result<()> {
        self.conn().execute(
            "DELETE FROM lock_holds WHERE space = ?1 AND name = ?2 AND lamport = ?3 AND nonce = ?4",
            params![space, name, lamport as i64, nonce as i64],
        )?;
        Ok(())
    }

    /// Every hold this node has persisted.
    pub fn lock_holds(&self) -> Result<Vec<LockHoldRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT space, name, origin, lamport, nonce, ttl_ms, mode, owner, payload,
                    supersedes, acquired_at, lease_until
               FROM lock_holds ORDER BY space, name",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(LockHoldRow {
                space: r.get(0)?,
                name: r.get(1)?,
                origin: r.get(2)?,
                lamport: r.get::<_, i64>(3)? as u64,
                nonce: r.get::<_, i64>(4)? as u64,
                ttl_ms: r.get(5)?,
                sticky: r.get::<_, String>(6)? == "sticky",
                owner: r.get(7)?,
                payload: r.get(8)?,
                supersedes: r.get(9)?,
                acquired_at: r.get(10)?,
                lease_until: r.get(11)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hold(lamport: u64) -> LockHoldRow {
        LockHoldRow {
            space: "infra".into(),
            name: "state.tflock".into(),
            origin: "nas@x.example".into(),
            lamport,
            nonce: u64::MAX,
            ttl_ms: 30_000,
            sticky: true,
            owner: "AKIA".into(),
            payload: b"{}".to_vec(),
            supersedes: Vec::new(),
            acquired_at: 1,
            lease_until: None,
        }
    }

    #[test]
    fn the_clock_only_rises() {
        let (_dir, store) = crate::testutil::store();
        assert_eq!(store.lock_clock().unwrap(), 0);
        store.raise_lock_clock(7).unwrap();
        store.raise_lock_clock(3).unwrap();
        assert_eq!(store.lock_clock().unwrap(), 7);
    }

    #[test]
    fn a_stale_removal_leaves_a_newer_hold_of_the_same_lock() {
        let (_dir, store) = crate::testutil::store();
        store.put_lock_hold(&hold(1)).unwrap();
        store.put_lock_hold(&hold(2)).unwrap();
        store
            .remove_lock_hold("infra", "state.tflock", 1, u64::MAX)
            .unwrap();
        assert_eq!(store.lock_holds().unwrap(), vec![hold(2)]);
        store
            .remove_lock_hold("infra", "state.tflock", 2, u64::MAX)
            .unwrap();
        assert!(store.lock_holds().unwrap().is_empty());
    }
}
