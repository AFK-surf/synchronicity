//! The write path descends on the heap, so a deep tree cannot abort the daemon.
//! `insert` accepts keys up to `MAX_KEY_LEN` (4 096 bytes, 8 192 nibbles, §12),
//! and all store work runs on `spawn_blocking` stacks of 2 MiB. These tests use
//! a stack no larger than the blocking pool's.

use synch_core::{Hash, MAX_KEY_LEN};
use synch_mpt::{MemStore, Trie};

/// tokio's default `spawn_blocking` stack, where every daemon store op runs.
const BLOCKING_POOL_STACK: usize = 2 * 1024 * 1024;

fn on_a_blocking_pool_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(BLOCKING_POOL_STACK)
        .spawn(f)
        .expect("spawn")
        .join()
        .expect("the write path must not overflow the stack");
}

/// Insert and remove every key on a blocking-pool-sized stack: the descent is
/// what overflowed, so reaching `Hash::EMPTY` proves the whole path survives.
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

    for key in keys {
        root = trie.remove(root, key.as_bytes()).unwrap();
    }
    assert_eq!(root, Hash::EMPTY, "removing everything empties the trie");
}

/// The longest key the API accepts, branching at every nibble — the worst case
/// the bound permits.
#[test]
fn a_maximal_key_depth_inserts_and_removes_without_overflowing() {
    let base = vec![b'a'; MAX_KEY_LEN];
    // Siblings force a branch every few bytes, giving ~1 000 branch levels
    // without paying for all 4 096.
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
