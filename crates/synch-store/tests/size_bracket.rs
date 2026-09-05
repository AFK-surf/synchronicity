//! A wrong size inside one power-of-two bracket verifies against the tree, and
//! must not be allowed to brick the root. DESIGN.md / `docs/DELTA-SYNC.md` §6
//! claim "anything that changes the group count changes the tree's shape, so
//! no proof or slice for it would verify" — false: bao splits at the largest
//! power of two below the chunk count, so 20 groups and 24 both split at 16
//! and share the left subtree. Nothing here is forged — the slice is an honest
//! provider's `encode_slice`; only the `size` the victim is told is wrong,
//! which `FileEntry.size` lets any origin publish. The lie still lands
//! (nothing rejects it at write time) but must not stick: the honest writer
//! takes the row back and the bitmap restarts.

use synch_core::{ChunkRanges, CHUNK_GROUP_SIZE};
use synch_store::Store;

#[test]
fn failed_verification_preserves_committed_groups_across_reopen() {
    let bytes: Vec<u8> = (0..20 * CHUNK_GROUP_SIZE + 17)
        .map(|i| (i % 251) as u8)
        .collect();
    let provider_dir = tempfile::tempdir().unwrap();
    let provider = Store::open(provider_dir.path()).unwrap();
    let root = provider.ingest_bytes(&bytes, 0).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let fetcher = Store::open(dir.path()).unwrap();
    let first = ChunkRanges::single(0, 4);
    let (encoded, served) = provider.encode_slice(&root, &first).unwrap();
    fetcher
        .write_slice(&root, bytes.len() as u64, &served, &encoded, 0)
        .unwrap();
    let before = fetcher.blob(&root).unwrap().unwrap();

    // A late failure can follow several successful verified writes, but must
    // not advance claims or corrupt an already advertised group/outboard.
    let all = ChunkRanges::single(0, 21);
    let (mut encoded, served) = provider.encode_slice(&root, &all).unwrap();
    *encoded.last_mut().unwrap() ^= 0xff;
    assert!(fetcher
        .write_slice(&root, bytes.len() as u64, &served, &encoded, 0)
        .is_err());
    drop(fetcher);
    let fetcher = Store::open(dir.path()).unwrap();
    let after = fetcher.blob(&root).unwrap().unwrap();
    assert_eq!(after.size, before.size);
    assert_eq!(after.verified_groups(), before.verified_groups());
    assert!(!after.complete);
    assert_eq!(fetcher.read_range(&root, 0, 100).unwrap(), bytes[..100]);
    let (encoded, served) = fetcher.encode_slice(&root, &first).unwrap();
    let verifier_dir = tempfile::tempdir().unwrap();
    let verifier = Store::open(verifier_dir.path()).unwrap();
    verifier
        .write_slice(&root, bytes.len() as u64, &served, &encoded, 0)
        .unwrap();

    // The failed attempt does not poison later honest completion.
    let (encoded, served) = provider.encode_slice(&root, &all).unwrap();
    fetcher
        .write_slice(&root, bytes.len() as u64, &served, &encoded, 0)
        .unwrap();
    assert_eq!(fetcher.read_all(&root).unwrap(), bytes);
}

#[test]
fn a_size_lie_inside_one_power_of_two_bracket_does_not_brick_the_root() {
    let true_size = 20 * CHUNK_GROUP_SIZE;
    let lie_size = 24 * CHUNK_GROUP_SIZE;

    let honest_dir = tempfile::tempdir().unwrap();
    let honest = Store::open(honest_dir.path()).unwrap();
    let bytes: Vec<u8> = (0..true_size).map(|i| (i % 251) as u8).collect();
    let root = honest.ingest_bytes(&bytes, 0).unwrap();

    let left = ChunkRanges::single(0, 16);
    let (encoded, served) = honest.encode_slice(&root, &left).unwrap();
    assert_eq!(served, left);

    let victim_dir = tempfile::tempdir().unwrap();
    let victim = Store::open(victim_dir.path()).unwrap();

    // The lie verifies — that is the part no local check can prevent.
    victim
        .write_slice(&root, lie_size, &served, &encoded, 0)
        .expect("a slice over the shared left subtree verifies under either size");
    assert_eq!(victim.blob(&root).unwrap().unwrap().size, lie_size);

    // An honest writer with the true size is accepted rather than refused forever;
    // the bitmap restarts because the group count moved.
    let (rest_encoded, rest_served) = honest
        .encode_slice(&root, &ChunkRanges::single(0, 20))
        .unwrap();
    victim
        .write_slice(&root, true_size, &rest_served, &rest_encoded, 0)
        .expect("the honest writer must take the row back");

    let row = victim.blob(&root).unwrap().unwrap();
    assert_eq!(row.size, true_size, "the true size wins");
    assert!(row.complete, "and the object completes");
    assert_eq!(victim.read_all(&root).unwrap(), bytes);

    // Once the final group is held the size is attested, and a differing
    // claim is refused — which stops the yielding above from churning.
    let (encoded, served) = honest
        .encode_slice(&root, &ChunkRanges::single(0, 16))
        .unwrap();
    let err = victim
        .write_slice(&root, lie_size, &served, &encoded, 0)
        .expect_err("a complete object's size is attested and cannot be re-claimed");
    assert!(err.to_string().contains("size mismatch"), "{err}");
}
