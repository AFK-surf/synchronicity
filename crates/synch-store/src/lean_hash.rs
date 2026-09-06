//! Raw BLAKE3 primitives for the staged Lean ingestion interpreter.
//! No subtree traversal, Bao layout, I/O or CAS policy is implemented here.
//! Remove the staging-only dead-code allowance when the complete command uses
//! these services; this module is intentionally not a public Rust hash facade.
#![cfg_attr(not(test), allow(dead_code))]

use crate::{Result, StoreError};

/// Exactly one unkeyed cryptographic chunk, never a subtree. The pinned guts
/// API is necessary here: hazmat's HasherExt accepts byte offsets instead of
/// the full chunk-counter domain and rejects empty non-root chunks, although
/// both are well-defined primitive inputs in the Lean capability contract.
#[allow(deprecated)]
pub(crate) fn chunk(counter: u64, root: bool, bytes: &[u8]) -> Result<[u8; 32]> {
    if bytes.len() > 1024 || (root && counter != 0) {
        return Err(StoreError::invalid("invalid BLAKE3 chunk primitive input"));
    }
    let mut state = blake3::guts::ChunkState::new(counter);
    state.update(bytes);
    Ok(*state.finalize(root).as_bytes())
}

/// One unkeyed parent compression over two chaining values. Lean determines
/// their order, tree position and whether ROOT applies.
pub(crate) fn parent(root: bool, left: &[u8], right: &[u8]) -> Result<[u8; 32]> {
    let left: &[u8; 32] = left
        .try_into()
        .map_err(|_| StoreError::invalid("invalid BLAKE3 parent left width"))?;
    let right: &[u8; 32] = right
        .try_into()
        .map_err(|_| StoreError::invalid("invalid BLAKE3 parent right width"))?;
    Ok(if root {
        *blake3::hazmat::merge_subtrees_root(left, right, blake3::hazmat::Mode::Hash).as_bytes()
    } else {
        blake3::hazmat::merge_subtrees_non_root(left, right, blake3::hazmat::Mode::Hash)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake3::hazmat::HasherExt;

    #[test]
    fn root_chunk_matches_standard_empty_and_abc_vectors() {
        for (bytes, expected) in [
            (
                &b""[..],
                "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            ),
            (
                &b"abc"[..],
                "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
            ),
        ] {
            assert_eq!(
                blake3::Hash::from(chunk(0, true, bytes).unwrap())
                    .to_hex()
                    .as_str(),
                expected
            );
        }
    }

    #[test]
    fn malformed_primitive_inputs_return_errors_without_panicking() {
        assert!(chunk(0, true, &[0; 1025]).is_err());
        assert!(chunk(0, false, &[0; 1025]).is_err());
        assert!(chunk(1, true, b"abc").is_err());
        for width in [0, 31, 33, 64] {
            assert!(parent(false, &vec![0; width], &[0; 32]).is_err());
            assert!(parent(true, &[0; 32], &vec![0; width]).is_err());
        }
    }

    #[test]
    fn nonroot_chunks_match_pinned_hazmat_at_distinct_counters() {
        for counter in [0, 1, 16, 255, u64::MAX / 1024] {
            for length in [1, 63, 64, 65, 1023, 1024] {
                let bytes: Vec<u8> = (0..length).map(|n| (n % 251) as u8).collect();
                let expected = blake3::Hasher::new()
                    .set_input_offset(counter * 1024)
                    .update(&bytes)
                    .finalize_non_root();
                assert_eq!(chunk(counter, false, &bytes).unwrap(), expected);
            }
        }
        assert_ne!(
            chunk(0, false, b"abc").unwrap(),
            chunk(1, false, b"abc").unwrap()
        );
    }

    #[test]
    fn empty_nonroot_and_full_counter_domain_are_supported() {
        assert_ne!(chunk(0, false, b"").unwrap(), chunk(0, true, b"").unwrap());
        assert_ne!(
            chunk(0, false, b"").unwrap(),
            chunk(u64::MAX, false, b"").unwrap()
        );
        assert_ne!(
            chunk(u64::MAX - 1, false, &[7; 1024]).unwrap(),
            chunk(u64::MAX, false, &[7; 1024]).unwrap()
        );
    }

    #[test]
    fn parent_primitives_match_pinned_guts_and_root_hash() {
        let left_bytes = [41; 1024];
        let right_bytes = [42; 1024];
        let left = chunk(0, false, &left_bytes).unwrap();
        let right = chunk(1, false, &right_bytes).unwrap();
        for root in [false, true] {
            #[allow(deprecated)]
            let expected = blake3::guts::parent_cv(&left.into(), &right.into(), root);
            assert_eq!(parent(root, &left, &right).unwrap(), *expected.as_bytes());
        }
        let input = [&left_bytes[..], &right_bytes[..]].concat();
        assert_eq!(
            parent(true, &left, &right).unwrap(),
            *blake3::hash(&input).as_bytes()
        );
        assert_ne!(
            parent(true, &left, &right).unwrap(),
            parent(true, &right, &left).unwrap()
        );
    }
}
