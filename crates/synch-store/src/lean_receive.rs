//! Receiving through the Lean domain program: a verified slice, a tree proof
//! and the promotion of a donor's bytes. Lean owns the write lease, the size
//! refusal, the row read, the inline-versus-file policy, the order of flush
//! and commit and the settlement of what was received; this module binds the
//! Bao service and the lease, and names the diagnostics.

use synch_core::{ChunkRanges, Cv, Hash};
use synch_verified::cas;

use crate::{
    lean_bao::{pairs_of, ranges_of, Bao},
    lean_diagnostics,
    lean_resources::Leases,
    proof::{Donor, Proven, ProvenSubtree},
    Result, Store, StoreError,
};

fn error(error: cas::ReceiveError<StoreError>) -> StoreError {
    use cas::{OperationError, ReceiveDomainError as Domain, ReceiveError};
    match error {
        ReceiveError::Operation(OperationError::Host(error)) => error,
        ReceiveError::Operation(_) => {
            StoreError::invalid("invalid native receive-operation protocol")
        }
        ReceiveError::Domain(Domain::Malformed) => StoreError::Decode("invalid blob claim".into()),
        ReceiveError::Domain(Domain::ColumnType {
            index,
            column,
            actual,
        }) => lean_diagnostics::column_type(index, column, actual),
        ReceiveError::Domain(Domain::Column { column, reason }) => match column.as_str() {
            "blobs.root" => StoreError::column("blobs.root", reason),
            _ => StoreError::invalid("unknown native receive error column"),
        },
        ReceiveError::Domain(Domain::SizeMismatch {
            root,
            recorded,
            offered,
        }) => StoreError::Verification {
            root: Hash::from_slice(&root).expect("typed digest width"),
            reason: format!("size mismatch: have {recorded}, offered {offered}"),
        },
    }
}

fn tier(store: &Store) -> cas::IngestTier {
    if store.complete_is_durable() {
        cas::IngestTier::Local
    } else {
        cas::IngestTier::Cache
    }
}

pub(crate) fn write_slice(
    store: &Store,
    root: &Hash,
    size: u64,
    served: &ChunkRanges,
    encoded: &[u8],
    now: i64,
) -> Result<ChunkRanges> {
    let mut storage = crate::lean_storage::Session::new(store);
    let mut bao = Bao::new(store);
    let mut leases = Leases::new(store);
    let written = cas::write_slice(
        &mut storage,
        cas::ReceiveResources {
            bao: &mut bao,
            leases: &mut leases,
        },
        root.as_bytes(),
        size,
        &pairs_of(served),
        encoded,
        now,
        tier(store),
    )
    .map_err(error)?;
    Ok(ranges_of(&written))
}

pub(crate) fn write_proof(
    store: &Store,
    root: &Hash,
    size: u64,
    served: &ChunkRanges,
    level: u8,
    encoded: &[u8],
    now: i64,
) -> Result<Proven> {
    let mut storage = crate::lean_storage::Session::new(store);
    let mut bao = Bao::new(store);
    let mut leases = Leases::new(store);
    let proven = cas::write_proof(
        &mut storage,
        cas::ReceiveResources {
            bao: &mut bao,
            leases: &mut leases,
        },
        root.as_bytes(),
        size,
        &pairs_of(served),
        level,
        encoded,
        now,
        tier(store),
    )
    .map_err(error)?;
    let subtrees = proven
        .into_iter()
        .map(|subtree| {
            Ok(ProvenSubtree {
                start: subtree.start,
                groups: subtree.groups,
                cv: Cv(<[u8; 32]>::try_from(subtree.cv.as_slice())
                    .map_err(|_| StoreError::invalid("a chaining value is 32 bytes"))?),
                whole: subtree.whole,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Proven {
        root: *root,
        size,
        subtrees,
    })
}

pub(crate) fn promote(
    store: &Store,
    donor: &Donor,
    proven: &Proven,
    now: i64,
) -> Result<ChunkRanges> {
    let mut storage = crate::lean_storage::Session::new(store);
    let mut bao = Bao::new(store);
    let mut leases = Leases::new(store);
    let subtrees: Vec<cas::ProvenSubtree> = proven
        .subtrees
        .iter()
        .map(|subtree| cas::ProvenSubtree {
            start: subtree.start,
            groups: subtree.groups,
            cv: subtree.cv.as_bytes().to_vec(),
            whole: subtree.whole,
        })
        .collect();
    let promoted = cas::promote(
        &mut storage,
        cas::ReceiveResources {
            bao: &mut bao,
            leases: &mut leases,
        },
        donor.root().as_bytes(),
        proven.root.as_bytes(),
        proven.size,
        &subtrees,
        now,
        tier(store),
    )
    .map_err(error)?;
    Ok(ranges_of(&promoted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{data, store};
    use synch_core::{group_count, MAX_PROOF_NODES};
    use synch_verified::host;

    /// Every Bao request and every lease the receive makes, in order.
    struct Observed<'a> {
        inner: Bao<'a>,
        trace: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
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
            self.trace.borrow_mut().push(format!("inline {spans:?}"));
            self.inner.decode_inline(root, size, inline, spans, input)
        }
        fn decode_slice(
            &mut self,
            root: &[u8],
            size: u64,
            spans: &[(u64, u64)],
            input: &[u8],
        ) -> Result<()> {
            self.trace.borrow_mut().push(format!("decode {spans:?}"));
            self.inner.decode_slice(root, size, spans, input)
        }
        fn flush_object(&mut self, root: &[u8]) -> Result<()> {
            self.trace.borrow_mut().push("flush".into());
            self.inner.flush_object(root)
        }
        fn trim_object(&mut self, root: &[u8], size: u64) -> Result<()> {
            self.trace.borrow_mut().push(format!("trim {size}"));
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
            self.trace.borrow_mut().push(format!("proof {spans:?}"));
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
            self.trace
                .borrow_mut()
                .push(format!("run {start}+{groups}"));
            self.inner.promote_run(donor, root, size, start, groups, cv)
        }
    }
    struct ObservedLeases<'a> {
        inner: Leases<'a>,
        trace: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    }
    impl host::Lease for ObservedLeases<'_> {
        type Error = StoreError;
        fn acquire(&mut self, space: &str, key: &[u8]) -> Result<u64> {
            self.trace.borrow_mut().push("acquire".into());
            self.inner.acquire(space, key)
        }
        fn order(&mut self, space: &str) -> Result<u64> {
            self.trace.borrow_mut().push("order".into());
            self.inner.order(space)
        }
        fn release(&mut self, token: u64) -> Result<()> {
            self.trace.borrow_mut().push("release".into());
            self.inner.release(token)
        }
    }

    fn observed(
        store: &Store,
        encoded: &[u8],
        served: &ChunkRanges,
        root: &Hash,
        size: u64,
    ) -> (Result<Vec<(u64, u64)>>, Vec<String>) {
        let trace = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut storage = crate::lean_storage::Session::new(store);
        let mut bao = Observed {
            inner: Bao::new(store),
            trace: trace.clone(),
        };
        let mut leases = ObservedLeases {
            inner: Leases::new(store),
            trace: trace.clone(),
        };
        let result = cas::write_slice(
            &mut storage,
            cas::ReceiveResources {
                bao: &mut bao,
                leases: &mut leases,
            },
            root.as_bytes(),
            size,
            &pairs_of(served),
            encoded,
            0,
            cas::IngestTier::Local,
        )
        .map_err(error);
        let trace = trace.borrow().clone();
        (result, trace)
    }

    #[test]
    fn a_slice_is_decoded_flushed_then_committed_under_the_lease() {
        let (_dir, provider) = store();
        let (_dir2, fetcher) = store();
        let payload = data(5 * 16384 + 7);
        let root = provider.ingest_bytes(&payload, 0).unwrap();
        let size = payload.len() as u64;
        let first = ChunkRanges::single(0, 3);
        let (encoded, served) = provider.encode_slice(&root, &first).unwrap();
        let (written, trace) = observed(&fetcher, &encoded, &served, &root, size);
        assert_eq!(written.unwrap(), vec![(0, 3)]);
        assert_eq!(trace, ["acquire", "decode [(0, 3)]", "flush", "release"]);
        let row = fetcher.blob(&root).unwrap().unwrap();
        assert!(!row.complete);
        assert_eq!(row.verified_groups(), first);
        assert!(!fetcher.is_being_written(&root));

        // The rest completes the object, which trims it to its settled size.
        let rest = ChunkRanges::single(3, group_count(size));
        let (encoded, served) = provider.encode_slice(&root, &rest).unwrap();
        let (written, trace) = observed(&fetcher, &encoded, &served, &root, size);
        assert_eq!(written.unwrap(), vec![(3, 6)]);
        assert_eq!(
            trace,
            [
                "acquire",
                "decode [(3, 6)]",
                "flush",
                &format!("trim {size}"),
                "release"
            ]
        );
        assert!(fetcher.blob(&root).unwrap().unwrap().complete);
        assert_eq!(fetcher.read_all(&root).unwrap(), payload);

        // A complete row is left alone before anything is decoded.
        let (written, trace) = observed(&fetcher, &encoded, &served, &root, size);
        assert!(written.unwrap().is_empty());
        assert_eq!(trace, ["acquire", "release"]);
    }

    #[test]
    fn a_small_object_is_decoded_inline_and_a_bad_slice_leaves_no_row() {
        let (_dir, provider) = store();
        let (_dir2, fetcher) = store();
        let payload = data(1000);
        let root = provider.ingest_bytes(&payload, 0).unwrap();
        let all = ChunkRanges::single(0, 1);
        let (encoded, served) = provider.encode_slice(&root, &all).unwrap();
        let (written, trace) = observed(&fetcher, &encoded, &served, &root, 1000);
        assert_eq!(written.unwrap(), vec![(0, 1)]);
        assert_eq!(trace, ["acquire", "inline [(0, 1)]", "release"]);
        assert_eq!(fetcher.read_all(&root).unwrap(), payload);

        let (_dir3, victim) = store();
        let mut tampered = encoded.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let (written, trace) = observed(&victim, &tampered, &served, &root, 1000);
        assert!(matches!(written, Err(StoreError::Verification { .. })));
        assert_eq!(trace, ["acquire", "inline [(0, 1)]", "release"]);
        assert!(victim.blob(&root).unwrap().is_none());
        assert!(!victim.is_being_written(&root));
        assert!(victim.conn().is_autocommit());
    }

    #[test]
    fn a_proof_records_a_held_nothing_row_and_promotion_asks_only_eligible_runs() {
        let (_dir, provider) = store();
        let (_dir2, fetcher) = store();
        let old = data(8 * 16384);
        let mut new = old.clone();
        new[2 * 16384 + 5] ^= 0xff;
        let old_root = fetcher.ingest_bytes(&old, 0).unwrap();
        let new_root = provider.ingest_bytes(&new, 0).unwrap();
        let size = new.len() as u64;
        let all = ChunkRanges::single(0, 8);
        let (encoded, served) = provider
            .encode_proof(&new_root, &all, 0, MAX_PROOF_NODES)
            .unwrap();
        let trace = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut storage = crate::lean_storage::Session::new(&fetcher);
        let mut bao = Observed {
            inner: Bao::new(&fetcher),
            trace: trace.clone(),
        };
        let mut leases = ObservedLeases {
            inner: Leases::new(&fetcher),
            trace: trace.clone(),
        };
        let proven = cas::write_proof(
            &mut storage,
            cas::ReceiveResources {
                bao: &mut bao,
                leases: &mut leases,
            },
            new_root.as_bytes(),
            size,
            &pairs_of(&served),
            0,
            &encoded,
            0,
            cas::IngestTier::Local,
        )
        .unwrap();
        assert_eq!(proven.len(), 8);
        assert_eq!(
            trace.borrow().as_slice(),
            ["acquire", "proof [(0, 8)]", "flush", "release"]
        );
        let row = fetcher.blob(&new_root).unwrap().unwrap();
        assert!(!row.complete && row.verified_groups().is_empty());

        trace.borrow_mut().clear();
        let mut storage = crate::lean_storage::Session::new(&fetcher);
        let promoted = cas::promote(
            &mut storage,
            cas::ReceiveResources {
                bao: &mut bao,
                leases: &mut leases,
            },
            old_root.as_bytes(),
            new_root.as_bytes(),
            size,
            &proven,
            0,
            cas::IngestTier::Local,
        )
        .unwrap();
        // Every group but the changed one comes from the donor.
        assert_eq!(promoted, vec![(0, 2), (3, 8)]);
        let runs: Vec<String> = trace
            .borrow()
            .iter()
            .filter(|step| step.starts_with("run"))
            .cloned()
            .collect();
        assert_eq!(runs.len(), 8, "{:?}", trace.borrow());
        assert_eq!(trace.borrow().first().map(String::as_str), Some("acquire"));
        let tail: Vec<String> = trace.borrow().iter().rev().take(2).cloned().collect();
        assert_eq!(tail, ["release", "flush"]);
        let row = fetcher.blob(&new_root).unwrap().unwrap();
        assert_eq!(
            row.verified_groups(),
            ChunkRanges::from_ranges([
                synch_core::GroupRange::new(0, 2),
                synch_core::GroupRange::new(3, 8)
            ])
        );

        // A second promotion asks about nothing already held.
        trace.borrow_mut().clear();
        let mut storage = crate::lean_storage::Session::new(&fetcher);
        let again = cas::promote(
            &mut storage,
            cas::ReceiveResources {
                bao: &mut bao,
                leases: &mut leases,
            },
            old_root.as_bytes(),
            new_root.as_bytes(),
            size,
            &proven,
            0,
            cas::IngestTier::Local,
        )
        .unwrap();
        assert!(again.is_empty());
        assert_eq!(trace.borrow().as_slice(), ["acquire", "run 2+1", "release"]);
    }
}
