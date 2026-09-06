//! Serving slices and proofs through the Lean domain program. Lean reads the
//! row and decides which groups of what was asked for this node holds and how
//! much of that one exchange carries; this module is the Bao service that
//! encodes exactly those groups, and the diagnostics of a refusal.

use synch_core::{ChunkRanges, Hash};
use synch_verified::cas;

use crate::{
    lean_bao::{pairs_of, ranges_of, Bao},
    lean_diagnostics, Result, Store, StoreError,
};

fn error(root: &Hash, error: cas::ServeError<StoreError>) -> StoreError {
    use cas::{OperationError, ServeDomainError as Domain, ServeError};
    match error {
        ServeError::Operation(OperationError::Host(error)) => error,
        ServeError::Operation(_) => StoreError::invalid("invalid native serve-operation protocol"),
        ServeError::Domain(Domain::MissingBlob) => StoreError::MissingBlob(*root),
        ServeError::Domain(Domain::Malformed) => {
            StoreError::Decode("invalid local blob metadata".into())
        }
        ServeError::Domain(Domain::ColumnType {
            index,
            column,
            actual,
        }) => lean_diagnostics::column_type(index, column, actual),
        ServeError::Domain(Domain::Column { column, reason }) => match column.as_str() {
            "blobs.root" => StoreError::column("blobs.root", reason),
            _ => StoreError::invalid("unknown native serve error column"),
        },
        // A truncated walk is a refused request, not a partial answer. The
        // requester sizes its window from `proof_nodes_upper_bound` so that a
        // provider holding everything it asked for still fits the budget, and
        // the walk covers `requested ∩ what we hold`, a subset of that.
        // Overrunning therefore means the request was not sized by a
        // conforming requester, and the answer is to say so rather than to
        // serve a prefix.
        ServeError::Domain(Domain::OverBudget { level, budget }) => StoreError::Verification {
            root: *root,
            reason: format!(
                "a proof over these ranges at level {level} exceeds the {budget}-node budget; \
                 the requester must split the request"
            ),
        },
    }
}

pub(crate) fn encode_slice(
    store: &Store,
    root: &Hash,
    requested: &ChunkRanges,
) -> Result<(Vec<u8>, ChunkRanges)> {
    let mut storage = crate::lean_storage::Session::new(store);
    let mut bao = Bao::new(store);
    let (encoded, served) = cas::encode_slice(
        &mut storage,
        &mut bao,
        root.as_bytes(),
        &pairs_of(requested),
    )
    .map_err(|failure| error(root, failure))?;
    Ok((encoded, ranges_of(&served)))
}

pub(crate) fn encode_proof(
    store: &Store,
    root: &Hash,
    requested: &ChunkRanges,
    level: u8,
    budget: u64,
) -> Result<(Vec<u8>, ChunkRanges)> {
    let mut storage = crate::lean_storage::Session::new(store);
    let mut bao = Bao::new(store);
    let (encoded, served) = cas::encode_proof(
        &mut storage,
        &mut bao,
        root.as_bytes(),
        &pairs_of(requested),
        level,
        budget,
    )
    .map_err(|failure| error(root, failure))?;
    Ok((encoded, ranges_of(&served)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{data, store};
    use synch_core::{group_count, GroupRange, MAX_PROOF_NODES};
    use synch_verified::host;

    /// The Bao service is asked only for groups the row holds, and a slice
    /// window never exceeds one exchange.
    struct Observed<'a> {
        inner: Bao<'a>,
        asked: Vec<Vec<(u64, u64)>>,
    }
    impl host::Bao for Observed<'_> {
        type Error = StoreError;
        fn encode_slice(
            &mut self,
            root: &[u8],
            size: u64,
            inline: Option<&[u8]>,
            spans: &[(u64, u64)],
        ) -> Result<Vec<u8>> {
            self.asked.push(spans.to_vec());
            self.inner.encode_slice(root, size, inline, spans)
        }
        fn encode_proof(
            &mut self,
            root: &[u8],
            size: u64,
            spans: &[(u64, u64)],
            level: u64,
            budget: u64,
        ) -> Result<Option<Vec<u8>>> {
            self.asked.push(spans.to_vec());
            self.inner.encode_proof(root, size, spans, level, budget)
        }
        fn decode_inline(
            &mut self,
            root: &[u8],
            size: u64,
            inline: Option<&[u8]>,
            spans: &[(u64, u64)],
            input: &[u8],
        ) -> Result<Vec<u8>> {
            self.inner.decode_inline(root, size, inline, spans, input)
        }
        fn decode_slice(
            &mut self,
            root: &[u8],
            size: u64,
            spans: &[(u64, u64)],
            input: &[u8],
        ) -> Result<()> {
            self.inner.decode_slice(root, size, spans, input)
        }
        fn flush_object(&mut self, root: &[u8]) -> Result<()> {
            self.inner.flush_object(root)
        }
        fn trim_object(&mut self, root: &[u8], size: u64) -> Result<()> {
            self.inner.trim_object(root, size)
        }
        fn write_proof(
            &mut self,
            root: &[u8],
            size: u64,
            spans: &[(u64, u64)],
            level: u64,
            input: &[u8],
        ) -> Result<(bool, Vec<(u64, u64, Vec<u8>, bool)>)> {
            self.inner.write_proof(root, size, spans, level, input)
        }
        fn promote_run(
            &mut self,
            donor: &[u8],
            root: &[u8],
            size: u64,
            start: u64,
            groups: u64,
            cv: &[u8],
        ) -> Result<bool> {
            self.inner.promote_run(donor, root, size, start, groups, cv)
        }
    }

    #[test]
    fn a_slice_is_asked_only_for_held_groups_within_the_window() {
        let (_dir, store) = store();
        let groups = synch_core::MAX_SLICE_GROUPS + 20;
        let payload = data((groups * 16384) as usize);
        let root = store.ingest_bytes(&payload, 0).unwrap();
        let mut observed = Observed {
            inner: Bao::new(&store),
            asked: vec![],
        };
        let mut storage = crate::lean_storage::Session::new(&store);
        let (encoded, served) = cas::encode_slice(
            &mut storage,
            &mut observed,
            root.as_bytes(),
            &[(3, 5), (5, 6), (7, u64::MAX)],
        )
        .unwrap();
        let expected = vec![(3, 6), (7, 7 + synch_core::MAX_SLICE_GROUPS - 3)];
        assert_eq!(served, expected);
        assert_eq!(observed.asked, vec![expected]);
        assert!(!encoded.is_empty());
        // An empty window asks the service nothing and serves nothing.
        let mut storage = crate::lean_storage::Session::new(&store);
        let (encoded, served) = cas::encode_slice(
            &mut storage,
            &mut observed,
            root.as_bytes(),
            &[(groups, groups + 5)],
        )
        .unwrap();
        assert!(encoded.is_empty() && served.is_empty());
        assert_eq!(observed.asked.len(), 1);
    }

    #[test]
    fn a_partial_row_serves_only_what_its_bitmap_covers() {
        let (_dir, store) = store();
        let payload = data(20 * 16384);
        let root = store.ingest_bytes(&payload, 0).unwrap();
        store
            .conn()
            .execute(
                "UPDATE blobs SET complete = 0, bitmap = ?2 WHERE root = ?1",
                rusqlite::params![
                    root.as_bytes().as_slice(),
                    crate::cas::ranges_to_blob(&ChunkRanges::from_ranges([
                        GroupRange::new(2, 6),
                        GroupRange::new(10, 30)
                    ]))
                ],
            )
            .unwrap();
        let all = ChunkRanges::single(0, group_count(payload.len() as u64));
        let (_, served) = store.encode_slice(&root, &all).unwrap();
        assert_eq!(
            served,
            ChunkRanges::from_ranges([GroupRange::new(2, 6), GroupRange::new(10, 20)])
        );
        let (_, served) = store.encode_proof(&root, &all, 0, MAX_PROOF_NODES).unwrap();
        assert_eq!(
            served,
            ChunkRanges::from_ranges([GroupRange::new(2, 6), GroupRange::new(10, 20)])
        );
    }

    #[test]
    fn a_missing_row_and_an_over_budget_proof_are_refused_whole() {
        let (_dir, store) = store();
        let absent = Hash::new(b"absent");
        assert!(matches!(
            store.encode_slice(&absent, &ChunkRanges::single(0, 1)),
            Err(StoreError::MissingBlob(root)) if root == absent
        ));
        let payload = data(64 * 16384);
        let root = store.ingest_bytes(&payload, 0).unwrap();
        let all = ChunkRanges::single(0, 64);
        let failure = store.encode_proof(&root, &all, 0, 3).unwrap_err();
        assert!(
            matches!(failure, StoreError::Verification { root: at, ref reason }
                if at == root && reason.contains("3-node budget")),
            "{failure}"
        );
        // A single-group object has no interior nodes to prove.
        let small = store.ingest_bytes(&data(100), 0).unwrap();
        let (encoded, served) = store
            .encode_proof(&small, &ChunkRanges::single(0, 1), 0, MAX_PROOF_NODES)
            .unwrap();
        assert!(encoded.is_empty());
        assert_eq!(served, ChunkRanges::single(0, 1));
    }
}
