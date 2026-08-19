//! The write path descends on the heap, so a deep tree cannot abort the daemon.
//!
//! `insert` accepts keys up to `MAX_KEY_LEN` — 4 096 bytes, 8 192 nibbles (§12)
//! — and `insert_at`/`remove_at` used to recurse one frame per trie level. All
//! store work runs on `spawn_blocking`, whose stacks are 2 MiB by default and
//! which nothing in the workspace resizes, so a directory tree about five
//! hundred levels deep — a 4 013-byte key, inside the bound — overflowed the
//! stack. A stack overflow aborts the process; it cannot be caught, so the
//! daemon died mid-publish, and because the publisher restages a failed batch
//! the next start did it again.
//!
//! These run under a stack no larger than the blocking pool's, so a regression
//! aborts this test rather than passing quietly.

use synch_core::{Hash, MAX_KEY_LEN};
use synch_mpt::{MemStore, Trie};

/// tokio's default `spawn_blocking` stack, which is where every store
/// operation in the daemon actually runs.
const BLOCKING_POOL_STACK: usize = 2 * 1024 * 1024;

fn on_a_blocking_pool_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(BLOCKING_POOL_STACK)
        .spawn(f)
        .expect("spawn")
        .join()
        .expect("the write path must not overflow the stack");
}

/// A nested-directory key with a sibling at every level, which is what forces a
/// branch per level rather than one compressed extension.
fn nested(levels: usize, leaf: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut path = String::from("f:sp");
    for i in 0..levels {
        path.push_str(&format!("/d{i:03}"));
        keys.push(format!("{path}/sib"));
    }
    keys.push(format!("{path}/{leaf}"));
    keys
}

/// Insert, read, and remove every key on a blocking-pool-sized stack; the
/// descent is what overflowed, so reaching the final `Hash::EMPTY` proves the
/// whole write path survives the depth.
fn exercise_deep(keys: &[String]) {
    let store = MemStore::new();
    let trie = Trie::new(&store);
    assert!(
        keys.iter().all(|k| k.len() <= MAX_KEY_LEN),
        "the corpus stays inside the key bound the API accepts"
    );

    let mut root = Hash::EMPTY;
    for key in keys {
        root = trie.insert(root, key.as_bytes(), b"v").unwrap();
    }
    assert_eq!(trie.iter(root).unwrap().len(), keys.len());

    // Reads and removals descend the same depth.
    for key in keys {
        assert_eq!(
            trie.get(root, key.as_bytes()).unwrap().as_deref(),
            Some(&b"v"[..])
        );
    }
    for key in keys {
        root = trie.remove(root, key.as_bytes()).unwrap();
    }
    assert_eq!(root, Hash::EMPTY, "removing everything empties the trie");
}

#[test]
fn a_deep_tree_inserts_and_removes_without_overflowing() {
    let keys = nested(600, "leaf");
    on_a_blocking_pool_stack(move || exercise_deep(&keys));
}

/// The longest key the API accepts, branching at every nibble — the worst case
/// the bound permits.
#[test]
fn a_maximal_key_depth_inserts_and_removes_without_overflowing() {
    let base = vec![b'a'; MAX_KEY_LEN];
    // Siblings force a branch node every few bytes, giving ~1 000 branch
    // levels — twice the depth that used to overflow — without paying for
    // one at every one of the 4 096 positions.
    let mut keys: Vec<String> = (16..MAX_KEY_LEN)
        .step_by(4)
        .map(|cut| {
            let mut sib = base[..cut].to_vec();
            sib.push(b'z');
            String::from_utf8(sib).unwrap()
        })
        .collect();
    keys.push(String::from_utf8(base).unwrap());
    on_a_blocking_pool_stack(move || exercise_deep(&keys));
}
