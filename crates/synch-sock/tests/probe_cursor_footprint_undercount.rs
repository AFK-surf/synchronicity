//! Probe: `sy_list_open` charges the footprint the cursor really occupies
//! (finding 5, fixed `2026-08-28`).
//!
//! Before the fix, the meter charged only the sum of name *bytes* while the
//! runtime retained a `Vec<String>` — 24 bytes of `String` header per entry
//! plus a heap allocation per name. Measured against a counting allocator, a
//! listing of 65 536 fifteen-byte names held ~2.8 MiB of host memory against
//! a ~0.98 MiB charge, so the documented 1 MiB per-invocation footprint was
//! enforced against a number ~2.7x smaller than reality.
//!
//! The fix charges each entry at `len + CURSOR_ENTRY_OVERHEAD` (32) — the
//! charge and the release both go through `CursorSlot::footprint` — and the
//! engine's own listing cap uses the same accounting, so it never
//! materializes a listing the runtime will refuse.
//!
//! Asserted fixed behavior: a listing whose real footprint exceeds the 1 MiB
//! budget is refused with `SY_ELIMIT` instead of being granted at a quarter
//! of its true cost, and a listing that fits is still served.

#![cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64"))
)]

mod harness;

use std::sync::Arc;

use harness::{compile, peer};
use synch_sock::{DuplexStream, EffectivePolicy, HostError, ObjectInfo, SocketHost};

/// A tree with one directory: `big/` holds the full 65 536-entry listing the
/// engine's own caps allow (65536 rows, crates/synch-engine/src/sockets.rs);
/// `small/` holds a hundred.
struct DirTree {
    big: usize,
    small: usize,
}

#[async_trait::async_trait]
impl SocketHost for DirTree {
    fn open(&self, _origin: Option<&str>, _path: &str) -> Result<ObjectInfo, HostError> {
        Err(HostError::NotFound)
    }
    fn open_root(&self, _root: &synch_core::Hash) -> Result<ObjectInfo, HostError> {
        Err(HostError::NotFound)
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>, HostError> {
        let n = if prefix == "big/" {
            self.big
        } else {
            self.small
        };
        Ok((0..n).map(|i| format!("{prefix}entry-{i:05}")).collect())
    }
    async fn pread(&self, _root: synch_core::Hash, _offset: u64, _len: u64) -> Result<Vec<u8>, HostError> {
        Err(HostError::NotFound)
    }
}

/// Opens a cursor over `PREFIX` and returns its handle (negative = errno).
const OPEN_CURSOR: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  return sy_list_open(SY_STR(PREFIX));
}
"#;

async fn run_list(elf: &[u8], host: Arc<dyn SocketHost>) -> i64 {
    let harness = harness::Harness::new();
    let (mine, theirs) = tokio::io::duplex(64 * 1024);
    let (their_r, their_w) = tokio::io::split(theirs);
    let mut inv = harness.invocation(
        elf,
        DuplexStream::new(their_r, their_w),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );
    inv.host = host;
    // The guest returns its handle immediately and reads nothing; keep the
    // caller half alive so dropping it is not what ends the run.
    std::mem::forget(mine);
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        harness.pool.run(inv),
    )
    .await
    .expect("the invocation finished")
    .expect("the invocation ran");
    match outcome.status {
        synch_core::SockStatus::Ok(n) => n,
        other => panic!("guest did not return a status: {other:?}"),
    }
}

#[tokio::test]
async fn an_oversized_listing_is_refused_not_undercounted() {
    let big_src = OPEN_CURSOR.replace("PREFIX", "\"big/\"");
    let small_src = OPEN_CURSOR.replace("PREFIX", "\"small/\"");
    let big = compile(&big_src, "open-big.c");
    let small = compile(&small_src, "open-small.c");

    // 65 536 x (15 bytes + 32 overhead) = 3.08 MiB of real footprint — well
    // past the 1 MiB budget. The meter must refuse the cursor, not grant it
    // at ~0.98 MiB of charge.
    let big_host: Arc<dyn SocketHost> = Arc::new(DirTree {
        big: 65_536,
        small: 100,
    });
    let handle = run_list(&big, big_host).await;
    // SY_ELIMIT = -7: a documented bound was hit.
    assert_eq!(
        handle, -7,
        "a listing whose real footprint exceeds the 1 MiB budget must be \
         refused with SY_ELIMIT, got {handle}"
    );

    // A listing that fits (100 x 47 bytes = 4.7 KiB) is still served.
    let small_host: Arc<dyn SocketHost> = Arc::new(DirTree {
        big: 65_536,
        small: 100,
    });
    let handle = run_list(&small, small_host).await;
    assert!(
        handle >= 0,
        "a small listing must still be served, got {handle}"
    );
}
