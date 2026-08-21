//! The clock every trust decision in the store is dated by (§3.2).
//!
//! Trust here is time-bounded: a DNS binding is live until `expires_at`, and
//! `is_live` is `now < expires_at`. That makes the *instant* an input to every
//! authorization decision this node makes, and an input nothing authenticates —
//! it comes from the host's wall clock, which can be unset, stepped, or simply
//! wrong.
//!
//! Two failures follow, and this module closes both.
//!
//! A clock that reads at or before the epoch dates nothing: at zero no expiry
//! has passed, so every binding the node ever stored — every revoked member
//! included — reads as live, and `expire_bindings` deletes nothing. That is
//! refused outright: [`synch_core::clock_is_trusted`] is the gate, and a
//! reading that fails it makes every expiring binding non-live. Static trust is
//! unaffected, because no clock is consulted for it, so a node with no
//! trustworthy clock keeps exactly the trust an operator typed in by hand.
//!
//! And a clock stepped *backwards* — a bad NTP step, a restored VM snapshot —
//! would revive trust that had already lapsed, because the same comparison
//! reads an old instant as "before the expiry". So the highest trustworthy
//! reading this node has seen is persisted, and every reading is floored by it:
//! time can stand still for a trust decision, never run backwards. The floor is
//! advanced from the maintenance pass and from each membership refresh.
//!
//! A large *forward* step is the deliberate remaining exposure. It expires
//! bindings early, which is the fail-closed direction and self-heals: the next
//! successful membership refresh re-establishes them from DNS.

use synch_core::clock_is_trusted;

use rusqlite::OptionalExtension;

use crate::{db::Store, error::Result};

/// The config key holding the monotonic trust-clock floor, in unix
/// nanoseconds.
const CLOCK_FLOOR_KEY: &str = "trust_clock_floor";

/// What the node's clock reads and what trust can be dated by, for
/// `synch doctor` (§3.2, §9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockStatus {
    /// The raw wall-clock reading, in unix nanoseconds.
    pub reading: i64,
    /// The highest trustworthy reading this node has recorded.
    pub floor: i64,
    /// Whether the reading can date a trust decision at all.
    pub trusted: bool,
    /// Whether the reading is behind the recorded floor, i.e. the clock has
    /// been moved backwards since this node last looked.
    pub stepped_back: bool,
}

/// How far past the recorded floor one reading may advance it.
///
/// A day: far more than any scheduled pass needs, and far less than the years a
/// misread clock offers. Bounding the *step* is what keeps one bad reading from
/// pinning the floor permanently, while genuine time still advances every pass.
const MAX_FLOOR_STEP: i64 = 24 * 3600 * 1_000_000_000;

impl Store {
    /// The highest trustworthy clock reading this node has recorded.
    ///
    /// Zero when it has never recorded one, which is a node that has not yet
    /// seen a working clock rather than a node at the epoch.
    pub fn trust_floor(&self) -> Result<i64> {
        Ok(self
            .config(CLOCK_FLOOR_KEY)?
            .and_then(|text| text.parse::<i64>().ok())
            .unwrap_or(0))
    }

    /// The reading a caller should date a decision by: the clock, floored.
    ///
    /// The same value [`Store::read_instant`] returns, and the reason it exists
    /// twice is that a decision taken *inside* a transaction must be dated by
    /// what that transaction can see.
    pub fn read_instant_on(conn: &rusqlite::Connection) -> Result<i64> {
        let floor: Option<String> = conn
            .query_row(
                "SELECT value FROM config WHERE key = ?1",
                rusqlite::params![CLOCK_FLOOR_KEY],
                |row| row.get(0),
            )
            .optional()?;
        let floor = floor.and_then(|text| text.parse::<i64>().ok()).unwrap_or(0);
        Ok(synch_core::now_ns().max(floor))
    }

    /// Records `reading` as the floor when it is trustworthy and higher, and
    /// returns the floor in force afterwards.
    ///
    /// Called from the maintenance pass and from each membership refresh: those
    /// are the two places that run on a schedule and already write, so the
    /// floor advances without putting a write on the connection-accept path.
    ///
    /// The comparison and the write are one statement, because the two callers
    /// run on the same multi-threaded blocking pool and the connection mutex is
    /// released between two acquisitions. Read-then-write let a refresh thread
    /// that read the floor, stalled, and then wrote its own older reading
    /// overwrite a newer one the maintenance pass had just recorded — a floor
    /// that stepped *backwards*, which is the one thing this module exists to
    /// prevent, and a binding whose expiry fell in the gap read live again.
    pub fn advance_trust_floor(&self, reading: i64) -> Result<i64> {
        if !clock_is_trusted(reading) {
            return self.trust_floor();
        }
        // And not arbitrarily far forward in one step.
        //
        // `clock_is_trusted` is a *lower* bound only, so a dead RTC, a restored
        // snapshot or a bad `date` presents a reading years ahead and this
        // records it. Nothing ever lowers the floor and no command resets it, so
        // every later trust decision evaluates at that instant — and
        // `refresh_dns_bindings` stamps `expires_at` from the *floored* instant,
        // so bindings are written already past it and `expire_bindings` deletes
        // nothing. A member the operator then drops from the zone stays trusted
        // on this node indefinitely: §3.2's way of removing a member stops
        // working, and it fails *open*, which is the opposite of what this
        // module's own comment claims the forward direction does.
        //
        // Real time still advances on every pass, so a bounded step loses
        // nothing; it only refuses to take a year in one.
        let floor = self.trust_floor()?;
        if floor > 0 && reading > floor.saturating_add(MAX_FLOOR_STEP) {
            tracing::warn!(
                reading,
                floor,
                "ignoring a clock reading far past the trust floor"
            );
            return Ok(floor);
        }
        self.conn().execute(
            "INSERT INTO config (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value
               WHERE CAST(excluded.value AS INTEGER) > CAST(config.value AS INTEGER)",
            rusqlite::params![CLOCK_FLOOR_KEY, reading.to_string()],
        )?;
        self.trust_floor()
    }

    /// The instant a trust decision is evaluated at: `reading`, floored by
    /// [`Store::trust_floor`].
    ///
    /// An untrustworthy reading is returned unchanged rather than rescued by
    /// the floor — a stored floor is evidence about the past, not a substitute
    /// for knowing what time it is now, and every expiry check refuses an
    /// instant it cannot trust.
    pub fn trust_instant(&self, reading: i64) -> Result<i64> {
        if !clock_is_trusted(reading) {
            return Ok(reading);
        }
        Ok(reading.max(self.trust_floor()?))
    }

    /// What the clock reads and whether trust can be dated by it.
    pub fn clock_status(&self, reading: i64) -> Result<ClockStatus> {
        let floor = self.trust_floor()?;
        Ok(ClockStatus {
            reading,
            floor,
            trusted: clock_is_trusted(reading),
            stepped_back: clock_is_trusted(reading) && reading < floor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synch_core::MIN_TRUSTED_NS;

    use crate::testutil::store;

    #[test]
    fn an_untrustworthy_reading_is_never_rescued_by_the_floor() {
        let (_d, store) = store();
        let good = MIN_TRUSTED_NS + 10_000;
        assert_eq!(store.advance_trust_floor(good).unwrap(), good);
        // A dead-RTC reading stays untrustworthy, whatever the floor says.
        assert_eq!(store.trust_instant(0).unwrap(), 0);
        let status = store.clock_status(0).unwrap();
        assert!(!status.trusted);
        assert_eq!(status.floor, good);
    }

    #[test]
    fn the_floor_is_monotonic_and_only_moves_on_trustworthy_readings() {
        let (_d, store) = store();
        assert_eq!(store.trust_floor().unwrap(), 0);
        // The epoch does not become a floor: it dates nothing.
        assert_eq!(store.advance_trust_floor(0).unwrap(), 0);
        let high = MIN_TRUSTED_NS + 2_000;
        assert_eq!(store.advance_trust_floor(high).unwrap(), high);
        // Trust time can stand still, never run backwards.
        let stepped_back = MIN_TRUSTED_NS + 1_000;
        assert_eq!(store.advance_trust_floor(stepped_back).unwrap(), high);
        assert_eq!(store.trust_instant(stepped_back).unwrap(), high);
        assert!(store.clock_status(stepped_back).unwrap().stepped_back);
        assert_eq!(store.trust_instant(high + 5).unwrap(), high + 5);

        // A reading far past the floor cannot pin it — one wild reading must
        // not jam the floor forever — while ordinary advances still land.
        let day = 24 * 3600 * 1_000_000_000i64;
        assert_eq!(store.advance_trust_floor(high + 400 * day).unwrap(), high);
        assert_eq!(
            store.advance_trust_floor(high + day / 24).unwrap(),
            high + day / 24
        );

        // The floor is a persisted fact, and survives a reopen.
        let dir = tempfile::tempdir().unwrap();
        {
            let store = Store::open(dir.path()).unwrap();
            store.advance_trust_floor(high).unwrap();
        }
        assert_eq!(
            Store::open(dir.path()).unwrap().trust_floor().unwrap(),
            high
        );
    }
}
