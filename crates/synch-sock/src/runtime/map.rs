//! The socket map: the only state two invocations of one socket can share.
//!
//! The guest has no heap and no mutable globals — the data region is read-only
//! after link and the JIT confines every store to the invocation's stack — so a
//! program cannot accumulate anything across invocations by itself. This is
//! where a session table, a nonce cache or a rate-limit counter lives.
//!
//! Memory-only, deliberately: cleared on daemon restart and on re-arm. It is a
//! working set, not a database, and a socket that needs durability has the
//! tree.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::limits::Limits;

/// One socket's map.
#[derive(Debug, Default)]
struct Store {
    entries: HashMap<Vec<u8>, Entry>,
    bytes: usize,
}

#[derive(Debug, Clone)]
struct Entry {
    value: Vec<u8>,
    expires: Option<Instant>,
}

/// Every program version's map, keyed by `<space>/<path>\0<content-root>`.
#[derive(Debug)]
pub(crate) struct SocketMaps {
    inner: Mutex<HashMap<String, Store>>,
    epoch: Instant,
}

impl Default for SocketMaps {
    fn default() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            epoch: Instant::now(),
        }
    }
}

impl SocketMaps {
    /// A fresh, empty set of maps.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(SocketMaps::default())
    }

    /// Drops everything one socket held — what re-arming does.
    ///
    /// A re-arm is a different program, and a session table minted by the old
    /// one is not state the new one agreed to inherit.
    pub(crate) fn clear(&self, socket: &str) {
        let prefix = format!("{socket}\0");
        self.inner
            .lock()
            .expect("socket map")
            .retain(|name, _| !name.starts_with(&prefix));
    }

    /// Reads a key. `None` if absent or expired.
    pub(crate) fn get(&self, socket: &str, key: &[u8], now: Instant) -> Option<Vec<u8>> {
        let mut all = self.inner.lock().expect("socket map");
        let store = all.get_mut(socket)?;
        let entry = store.entries.get(key)?;
        if entry.expires.is_some_and(|at| at <= now) {
            let bytes = key.len() + entry.value.len();
            store.entries.remove(key);
            store.bytes = store.bytes.saturating_sub(bytes);
            return None;
        }
        Some(entry.value.clone())
    }

    /// Inserts or replaces a key.
    ///
    /// A full map fails the write rather than evicting something a live
    /// invocation may be depending on. Expired entries are removed first.
    /// Failing closed is the right default for a
    /// store whose main use is remembering that somebody has already had their
    /// turn.
    pub(crate) fn set(
        &self,
        socket: &str,
        key: &[u8],
        value: &[u8],
        ttl: Option<Duration>,
        now: Instant,
        limits: &Limits,
    ) -> Result<(), ()> {
        let mut all = self.inner.lock().expect("socket map");
        let store = all.entry(socket.to_string()).or_default();
        store.expire(now);
        store.set(key, value, ttl, now, limits)
    }

    /// Removes a key, reporting whether one was there.
    pub(crate) fn delete(&self, socket: &str, key: &[u8]) -> bool {
        let mut all = self.inner.lock().expect("socket map");
        let Some(store) = all.get_mut(socket) else {
            return false;
        };
        match store.entries.remove(key) {
            Some(entry) => {
                store.bytes = store.bytes.saturating_sub(key.len() + entry.value.len());
                true
            }
            None => false,
        }
    }

    /// Adds to a counter, returning the new value.
    ///
    /// Atomic across every worker thread sharing this map.
    pub(crate) fn incr(
        &self,
        socket: &str,
        key: &[u8],
        delta: i64,
        ttl: Option<Duration>,
        now: Instant,
        limits: &Limits,
    ) -> Result<i64, ()> {
        let mut all = self.inner.lock().expect("socket map");
        let store = all.entry(socket.to_string()).or_default();
        store.expire(now);
        let current = store
            .get(key)
            .and_then(|v| v.try_into().ok().map(i64::from_le_bytes))
            .unwrap_or(0);
        let next = current.saturating_add(delta);
        store.set(key, &next.to_le_bytes(), ttl, now, limits)?;
        Ok(next)
    }

    /// A sliding-window rate limit: `Ok(())` if this event is within `limit`
    /// over `window`, `Err(())` if it is not.
    ///
    /// The two-window weighted approximation, which is what a limiter that must
    /// not store one timestamp per event can honestly offer: the previous
    /// window's count is prorated by how much of it still overlaps the last
    /// `window`. Its error is bounded and one-sided in the direction that
    /// matters — it never admits a burst a true sliding window would have
    /// refused — and it costs two integers per key rather than `limit` of them.
    ///
    /// Present at all because a limiter written by hand out of `incr` is
    /// written wrong about half the time: the usual attempt counts into a fixed
    /// window, which lets twice the limit through across a boundary.
    pub(crate) fn rate_limit(
        &self,
        socket: &str,
        key: &[u8],
        limit: u64,
        window: Duration,
        now: Instant,
        limits: &Limits,
    ) -> Result<(), ()> {
        if limit == 0 || window.is_zero() {
            return Err(());
        }
        let elapsed = now.saturating_duration_since(self.epoch).as_nanos() as u64;
        // A width must be positive and fit the division below. The helpers
        // clamp guest durations, but the store is also called directly: a
        // window of 2^58 ms is 15625 * 2^64 ns, which truncates to exactly
        // zero, and `elapsed / 0` would panic on the worker. Saturating to
        // `u64::MAX` keeps a pathologically large window a legal, enormous
        // window instead of a crash.
        let width = u64::try_from(window.as_nanos()).unwrap_or(u64::MAX).max(1);
        let index = elapsed / width;
        let into = elapsed % width;

        let slot = |i: u64| {
            let mut k = Vec::with_capacity(key.len() + 9);
            k.push(b'r');
            k.extend_from_slice(key);
            k.extend_from_slice(&i.to_le_bytes());
            k
        };

        let mut all = self.inner.lock().expect("socket map");
        let store = all.entry(socket.to_string()).or_default();
        store.expire(now);
        let count_of = |k: &[u8]| -> u64 {
            store
                .get(k)
                .and_then(|v| v.try_into().ok().map(u64::from_le_bytes))
                .unwrap_or(0)
        };

        let current = count_of(&slot(index));
        let previous = if index == 0 {
            0
        } else {
            count_of(&slot(index - 1))
        };
        // How much of the previous window is still inside the trailing window.
        let carried = previous.saturating_mul(width - into) / width;

        if current + carried >= limit {
            return Err(());
        }
        // Two windows of TTL, so the previous window is still there to be
        // prorated when the next one starts counting. Saturating: a window
        // large enough to overflow the double must not be a panic.
        store.set(
            &slot(index),
            &(current + 1).to_le_bytes(),
            Some(window.saturating_mul(2)),
            now,
            limits,
        )
    }

    /// How many keys one socket holds.
    #[cfg(test)]
    pub(crate) fn len(&self, socket: &str) -> usize {
        self.inner
            .lock()
            .expect("socket map")
            .get(socket)
            .map(|s| s.entries.len())
            .unwrap_or(0)
    }
}

impl Store {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.entries.get(key).map(|entry| entry.value.clone())
    }

    fn set(
        &mut self,
        key: &[u8],
        value: &[u8],
        ttl: Option<Duration>,
        now: Instant,
        limits: &Limits,
    ) -> Result<(), ()> {
        let incoming = key.len() + value.len();
        if incoming > limits.map_max_bytes {
            return Err(());
        }
        let existing = self.entries.get(key).map(|e| key.len() + e.value.len());
        let projected = self.bytes - existing.unwrap_or(0) + incoming;
        let count = self.entries.len() + usize::from(existing.is_none());
        if projected > limits.map_max_bytes || count > limits.map_max_keys {
            return Err(());
        }
        self.bytes = projected;
        self.entries.insert(
            key.to_vec(),
            Entry {
                value: value.to_vec(),
                expires: ttl.map(|d| now + d),
            },
        );
        Ok(())
    }

    fn expire(&mut self, now: Instant) {
        let mut freed = 0;
        self.entries.retain(|k, v| {
            let live = v.expires.is_none_or(|at| at > now);
            if !live {
                freed += k.len() + v.value.len();
            }
            live
        });
        self.bytes = self.bytes.saturating_sub(freed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOCKET: &str = "code/git.sock";
    const S: &str = "code/git.sock\0root-v1";

    fn limits() -> Limits {
        Limits::default()
    }

    #[test]
    fn a_value_round_trips_and_a_ttl_expires_it() {
        let maps = SocketMaps::new();
        let now = Instant::now();
        maps.set(S, b"k", b"v", Some(Duration::from_secs(1)), now, &limits())
            .unwrap();
        assert_eq!(maps.get(S, b"k", now).as_deref(), Some(&b"v"[..]));
        assert_eq!(
            maps.get(S, b"k", now + Duration::from_secs(2)),
            None,
            "an expired entry was still readable"
        );
    }

    #[test]
    fn maps_are_per_socket() {
        let maps = SocketMaps::new();
        let now = Instant::now();
        maps.set(S, b"k", b"mine", None, now, &limits()).unwrap();
        assert_eq!(maps.get("code/other.sock", b"k", now), None);
        maps.clear(SOCKET);
        assert_eq!(maps.get(S, b"k", now), None, "re-arming kept the old state");
    }

    #[test]
    fn program_versions_have_separate_maps_and_rearm_clears_them_all() {
        let maps = SocketMaps::new();
        let now = Instant::now();
        let v2 = "code/git.sock\0root-v2";
        maps.set(S, b"k", b"old", None, now, &limits()).unwrap();
        maps.set(v2, b"k", b"new", None, now, &limits()).unwrap();

        assert_eq!(maps.get(S, b"k", now).as_deref(), Some(&b"old"[..]));
        assert_eq!(maps.get(v2, b"k", now).as_deref(), Some(&b"new"[..]));

        maps.clear(SOCKET);
        assert_eq!(maps.get(S, b"k", now), None);
        assert_eq!(maps.get(v2, b"k", now), None);
    }

    #[test]
    fn a_counter_accumulates() {
        let maps = SocketMaps::new();
        let now = Instant::now();
        let l = limits();
        assert_eq!(maps.incr(S, b"n", 1, None, now, &l).unwrap(), 1);
        assert_eq!(maps.incr(S, b"n", 4, None, now, &l).unwrap(), 5);
        assert_eq!(maps.incr(S, b"n", -2, None, now, &l).unwrap(), 3);
    }

    #[test]
    fn counters_are_atomic_across_worker_threads() {
        let maps = SocketMaps::new();
        let now = Instant::now();
        let mut workers = Vec::new();
        for _ in 0..8 {
            let maps = maps.clone();
            workers.push(std::thread::spawn(move || {
                let limits = Limits::default();
                for _ in 0..1000 {
                    maps.incr(S, b"n", 1, None, now, &limits).unwrap();
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        let value: [u8; 8] = maps.get(S, b"n", now).unwrap().try_into().unwrap();
        assert_eq!(i64::from_le_bytes(value), 8000);
    }

    #[test]
    fn a_full_map_fails_without_evicting_live_state() {
        let maps = SocketMaps::new();
        let now = Instant::now();
        let l = Limits {
            map_max_keys: 2,
            map_max_bytes: 64,
            ..limits()
        };
        maps.set(S, b"a", b"1", None, now, &l).unwrap();
        maps.set(S, b"b", b"2", None, now, &l).unwrap();
        assert!(maps.set(S, b"c", b"3", None, now, &l).is_err());
        assert_eq!(maps.len(S), 2, "the key cap was exceeded");
        assert_eq!(
            maps.get(S, b"a", now),
            Some(b"1".to_vec()),
            "a failed write evicted live state"
        );

        // A single value larger than the whole budget cannot be made to fit by
        // evicting, so it fails rather than emptying the map trying.
        let big = vec![0u8; 128];
        assert!(maps.set(S, b"big", &big, None, now, &l).is_err());
        assert_eq!(maps.len(S), 2, "a doomed write emptied the map");
    }

    #[test]
    fn a_rate_limit_admits_exactly_its_limit_then_refuses() {
        let maps = SocketMaps::new();
        let epoch = maps.epoch;
        let l = limits();
        let window = Duration::from_millis(1000);
        for i in 0..3 {
            assert!(
                maps.rate_limit(S, b"peer", 3, window, epoch, &l).is_ok(),
                "event {i} was refused inside the limit"
            );
        }
        assert!(maps.rate_limit(S, b"peer", 3, window, epoch, &l).is_err());
    }

    #[test]
    fn a_concurrent_rate_limit_never_over_admits() {
        let maps = SocketMaps::new();
        let now = maps.epoch;
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let mut workers = Vec::new();
        for _ in 0..16 {
            let maps = maps.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                maps.rate_limit(
                    S,
                    b"peer",
                    5,
                    Duration::from_secs(1),
                    now,
                    &Limits::default(),
                )
                .is_ok()
            }));
        }
        let admitted = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, 5);
    }

    #[test]
    fn a_burst_across_a_window_boundary_does_not_get_twice_the_limit() {
        // The failure mode a fixed window has and this one must not: spend the
        // whole limit at the end of one window, then again at the start of the
        // next, for 2x the limit inside one window's width.
        let maps = SocketMaps::new();
        let epoch = maps.epoch;
        let l = limits();
        let window = Duration::from_millis(1000);

        let late = epoch + Duration::from_millis(900);
        for _ in 0..3 {
            maps.rate_limit(S, b"peer", 3, window, late, &l).unwrap();
        }
        // 100 ms later a new fixed window would start and admit three more.
        let just_after = epoch + Duration::from_millis(1000);
        assert!(
            maps.rate_limit(S, b"peer", 3, window, just_after, &l)
                .is_err(),
            "a boundary crossing admitted a second full limit"
        );

        // A full window later the earlier spend has aged out.
        let much_later = epoch + Duration::from_millis(2000);
        assert!(maps
            .rate_limit(S, b"peer", 3, window, much_later, &l)
            .is_ok());
    }

    #[test]
    fn a_zero_limit_refuses_everything() {
        let maps = SocketMaps::new();
        let now = Instant::now();
        assert!(maps
            .rate_limit(S, b"k", 0, Duration::from_secs(1), now, &limits())
            .is_err());
    }
}
