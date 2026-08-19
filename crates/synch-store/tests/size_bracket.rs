//! A wrong size inside one power-of-two bracket verifies against the tree,
//! and must not be allowed to brick the root.
//!
//! DESIGN.md and `docs/DELTA-SYNC.md` §6 both rest on the claim that
//! "anything that changes the object's group count changes the shape of its
//! tree, so no proof or slice for it would verify". That is false. bao splits
//! at the largest power of two below the chunk count, so 20 groups and 24
//! groups *both* split at 16: their left subtrees are the same tree, and the
//! right sibling's chaining value is supplied by the encoder as opaque bytes
//! that join to the true root either way.
//!
//! Nothing here is forged — the slice comes from a fully honest provider's
//! `encode_slice`. Only the `size` the victim is told is wrong, and that comes
//! from `FileEntry.size`, which any origin publishes for itself.
//!
//! The lie still lands (it verifies, so nothing can reject it at write time),
//! but it must not stick: bits held under an *unattested* size are themselves
//! only a claim, so the honest writer takes the row and the bitmap restarts.

use synch_core::{group_count, ChunkRanges, CHUNK_GROUP_SIZE};
use synch_store::Store;

#[test]
fn a_size_lie_inside_one_power_of_two_bracket_does_not_brick_the_root() {
    let true_size = 20 * CHUNK_GROUP_SIZE;
    let lie_size = 24 * CHUNK_GROUP_SIZE;
    assert_eq!(group_count(true_size), 20);
    assert_eq!(group_count(lie_size), 24);
    // The premise: both sizes split at the same place, so the left subtree is
    // shared and a slice over it verifies under either.
    assert_eq!(
        group_count(true_size).next_power_of_two() / 2,
        group_count(lie_size).next_power_of_two() / 2
    );

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

    // An honest writer with the true size is accepted rather than refused
    // forever, and the bitmap restarts because the group count moved.
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
    // claim is refused — which is what stops the yielding above from churning.
    let (encoded, served) = honest
        .encode_slice(&root, &ChunkRanges::single(0, 16))
        .unwrap();
    let err = victim
        .write_slice(&root, lie_size, &served, &encoded, 0)
        .expect_err("a complete object's size is attested and cannot be re-claimed");
    assert!(err.to_string().contains("size mismatch"), "{err}");
}
