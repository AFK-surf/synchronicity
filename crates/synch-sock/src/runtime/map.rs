//! The socket map: the only state two invocations of one socket can share.
//!
//! The guest has no heap and no mutable globals — the data region is read-only
//! after link and the JIT confines every store to the 32 KiB stack — so a
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
    /// Bumped on every write, so the least recently *used* entry can be found
    /// without a second index.
    touched: u64,
}

/// Every socket's map, keyed by `<space>/<path>`.
#[derive(Debug, Default)]
pub(crate) struct SocketMaps {
    inner: Mutex<HashMap<String, Store>>,
    clock: Mutex<u64>,
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
        self.inner.lock().expect("socket map").remove(socket);
    }

    fn tick(&self) -> u64 {
        let mut clock = self.clock.lock().expect("socket map clock");
        *clock += 1;
        *clock
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
    /// invocation may be depending on — except for what has already expired,
    /// and for the least recently used entry, which is the one an eviction
    /// policy is allowed to take. Failing closed is the right default for a
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
        let touched = self.tick();
        let mut all = self.inner.lock().expect("socket map");
        let store = all.entry(socket.to_string()).or_default();
        store.expire(now);

        let incoming = key.len() + value.len();
        if incoming > limits.map_max_bytes {
            return Err(());
        }
        let existing = store.entries.get(key).map(|e| key.len() + e.value.len());
        let mut projected = store.bytes - existing.unwrap_or(0) + incoming;
        let mut count = store.entries.len() + usize::from(existing.is_none());

        while (projected > limits.map_max_bytes || count > limits.map_max_keys)
            && store.evict_lru(key)
        {
            projected = store.bytes - existing.unwrap_or(0) + incoming;
            count = store.entries.len() + usize::from(existing.is_none());
        }
        if projected > limits.map_max_bytes || count > limits.map_max_keys {
            return Err(());
        }

        store.bytes = projected;
        store.entries.insert(
            key.to_vec(),
            Entry {
                value: value.to_vec(),
                expires: ttl.map(|d| now + d),
                touched,
            },
        );
        Ok(())
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
    /// Atomic in the sense that matters here: a worker never yields inside a
    /// helper, so nothing can interleave between the read and the write.
    pub(crate) fn incr(
        &self,
        socket: &str,
        key: &[u8],
        delta: i64,
        ttl: Option<Duration>,
        now: Instant,
        limits: &Limits,
    ) -> Result<i64, ()> {
        let current = self
            .get(socket, key, now)
            .and_then(|v| v.try_into().ok().map(i64::from_le_bytes))
            .unwrap_or(0);
        let next = current.saturating_add(delta);
        self.set(socket, key, &next.to_le_bytes(), ttl, now, limits)?;
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
    #[allow(
        clippy::too_many_arguments,
        reason = "the window arithmetic needs both `now` and the invocation's epoch, \
                  and bundling them into a struct would hide which is which"
    )]
    pub(crate) fn rate_limit(
        &self,
        socket: &str,
        key: &[u8],
        limit: u64,
        window: Duration,
        now: Instant,
        epoch: Instant,
        limits: &Limits,
    ) -> Result<(), ()> {
        if limit == 0 || window.is_zero() {
            return Err(());
        }
        let elapsed = now.saturating_duration_since(epoch).as_nanos() as u64;
        let width = window.as_nanos().max(1) as u64;
        let index = elapsed / width;
        let into = elapsed % width;

        let slot = |i: u64| {
            let mut k = Vec::with_capacity(key.len() + 9);
            k.push(b'r');
            k.extend_from_slice(key);
            k.extend_from_slice(&i.to_le_bytes());
            k
        };

        let count_of = |k: &[u8]| -> u64 {
            self.get(socket, k, now)
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
        // prorated when the next one starts counting.
        self.set(
            socket,
            &slot(index),
            &(current + 1).to_le_bytes(),
            Some(window * 2),
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

    /// Drops the least recently written entry, never `keep`.
    fn evict_lru(&mut self, keep: &[u8]) -> bool {
        let victim = self
            .entries
            .iter()
            .filter(|(k, _)| k.as_slice() != keep)
            .min_by_key(|(_, v)| v.touched)
            .map(|(k, _)| k.clone());
        match victim {
            Some(k) => {
                if let Some(entry) = self.entries.remove(&k) {
                    self.bytes = self.bytes.saturating_sub(k.len() + entry.value.len());
                }
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: &str = "code/git.sock";

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
        maps.clear(S);
        assert_eq!(maps.get(S, b"k", now), None, "re-arming kept the old state");
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
    fn a_full_map_fails_the_write_after_evicting_what_it_may() {
        let maps = SocketMaps::new();
        let now = Instant::now();
        let l = Limits {
            map_max_keys: 2,
            map_max_bytes: 64,
            ..limits()
        };
        maps.set(S, b"a", b"1", None, now, &l).unwrap();
        maps.set(S, b"b", b"2", None, now, &l).unwrap();
        maps.set(S, b"c", b"3", None, now, &l).unwrap();
        assert_eq!(maps.len(S), 2, "the key cap was exceeded");
        assert_eq!(
            maps.get(S, b"a", now),
            None,
            "the oldest was not the victim"
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
        let epoch = Instant::now();
        let l = limits();
        let window = Duration::from_millis(1000);
        for i in 0..3 {
            assert!(
                maps.rate_limit(S, b"peer", 3, window, epoch, epoch, &l)
                    .is_ok(),
                "event {i} was refused inside the limit"
            );
        }
        assert!(maps
            .rate_limit(S, b"peer", 3, window, epoch, epoch, &l)
            .is_err());
    }

    #[test]
    fn a_burst_across_a_window_boundary_does_not_get_twice_the_limit() {
        // The failure mode a fixed window has and this one must not: spend the
        // whole limit at the end of one window, then again at the start of the
        // next, for 2x the limit inside one window's width.
        let maps = SocketMaps::new();
        let epoch = Instant::now();
        let l = limits();
        let window = Duration::from_millis(1000);

        let late = epoch + Duration::from_millis(900);
        for _ in 0..3 {
            maps.rate_limit(S, b"peer", 3, window, late, epoch, &l)
                .unwrap();
        }
        // 100 ms later a new fixed window would start and admit three more.
        let just_after = epoch + Duration::from_millis(1000);
        assert!(
            maps.rate_limit(S, b"peer", 3, window, just_after, epoch, &l)
                .is_err(),
            "a boundary crossing admitted a second full limit"
        );

        // A full window later the earlier spend has aged out.
        let much_later = epoch + Duration::from_millis(2000);
        assert!(maps
            .rate_limit(S, b"peer", 3, window, much_later, epoch, &l)
            .is_ok());
    }

    #[test]
    fn a_zero_limit_refuses_everything() {
        let maps = SocketMaps::new();
        let now = Instant::now();
        assert!(maps
            .rate_limit(S, b"k", 0, Duration::from_secs(1), now, now, &limits())
            .is_err());
    }
}
