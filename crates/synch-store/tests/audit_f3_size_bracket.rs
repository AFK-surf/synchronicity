//! Audit finding F3 — a wrong size inside one power-of-two bracket verifies
//! against the tree, and permanently bricks the root.
//!
//! DESIGN.md and `docs/DELTA-SYNC.md` §6 both rest on the claim that "anything
//! that changes the object's group count changes the shape of its tree, so no
//! proof or slice for it would verify". bao splits at the largest power of two
//! below the chunk count, so 20 groups and 24 groups *both* split at 16: their
//! left subtrees are the same tree, and the right sibling's chaining value is
//! supplied by the encoder as opaque bytes that join to the true root either
//! way.
//!
//! Nothing in this test is forged — the slice comes from a fully honest
//! provider's `encode_slice`. Only the `size` the victim was told is wrong, and
//! that comes from `FileEntry.size`, which any origin publishes for itself.
//! `settle_size` rule 3 then refuses every honest writer for good.
//!
//! The existing `cas.rs` tests only exercise lies *inside the last group*,
//! which do not change the group count.
//!
//! THIS TEST ASSERTS THE DEFECT AS IT STANDS. When rule 3 stops treating held
//! groups as evidence for a group count, the first `write_slice` should be
//! refused (or the honest writer accepted) — invert accordingly.

use synch_core::{group_count, ChunkRanges, CHUNK_GROUP_SIZE};
use synch_store::Store;

#[test]
fn a_size_lie_inside_one_power_of_two_bracket_verifies_and_bricks_the_root() {
    // 20 groups and 24 groups both split at 16, so their left subtrees are the
    // same tree. The design says a wrong group count cannot survive the tree.
    let true_size = 20 * CHUNK_GROUP_SIZE;
    let lie_size = 24 * CHUNK_GROUP_SIZE;
    assert_eq!(group_count(true_size), 20);
    assert_eq!(group_count(lie_size), 24);

    let honest_dir = tempfile::tempdir().unwrap();
    let honest = Store::open(honest_dir.path()).unwrap();
    let bytes: Vec<u8> = (0..true_size).map(|i| (i % 251) as u8).collect();
    let root = honest.ingest_bytes(&bytes, 0).unwrap();

    // An honest provider serves the left half. Nothing here is forged.
    let left = ChunkRanges::single(0, 16);
    let (encoded, served) = honest.encode_slice(&root, &left).unwrap();
    assert_eq!(served, left);

    let victim_dir = tempfile::tempdir().unwrap();
    let victim = Store::open(victim_dir.path()).unwrap();

    // The victim fetches under an entry that overstates the size.
    let written = victim.write_slice(&root, lie_size, &served, &encoded, 0);
    assert!(
        written.is_ok(),
        "the lie should have failed verification, but: {written:?}"
    );
    let row = victim.blob(&root).unwrap().unwrap();
    assert_eq!(row.size, lie_size, "the wrong size is now recorded");
    assert!(!row.complete);

    // Now an honest writer arrives with the true size and the rest of the object.
    let (rest_encoded, rest_served) = honest
        .encode_slice(&root, &ChunkRanges::single(16, 20))
        .unwrap();
    let honest_write = victim.write_slice(&root, true_size, &rest_served, &rest_encoded, 0);
    assert!(
        honest_write.is_err(),
        "expected the honest writer to be refused"
    );
    eprintln!("honest writer refused: {}", honest_write.unwrap_err());

    // And the object can never be read or completed.
    assert!(victim.read_all(&root).is_err());
}
