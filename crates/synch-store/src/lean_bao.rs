//! The Bao tree as the host service Lean's CAS commands direct: slice and
//! proof encodings of exactly the groups a program names, decodes of received
//! encodings into an object's files, and the compare-then-copy of a donor's
//! run. A trust assumption on `bao-tree`/`blake3`, exercised only for what
//! the program asked; which groups, in what order, and what is committed are
//! the program's.

use std::fs::File;

use bao_tree::io::{outboard::PreOrderOutboard, sync::encode_ranges};
use synch_core::{ChunkRanges, Cv, GroupRange, Hash, PROOF_NODE_LEN};
use synch_verified::host;

use crate::{
    cas::{to_bao_ranges, DataFile},
    proof::{load_from_outboard, walk_proof, Promotion},
    Result, Store, StoreError,
};

pub(crate) struct Bao<'a> {
    store: &'a Store,
    promotion: Promotion,
}

impl<'a> Bao<'a> {
    pub(crate) fn new(store: &'a Store) -> Self {
        Self {
            store,
            promotion: Promotion::default(),
        }
    }
}

pub(crate) fn ranges_of(spans: &[(u64, u64)]) -> ChunkRanges {
    ChunkRanges::from_ranges(
        spans
            .iter()
            .map(|&(start, end)| GroupRange::new(start, end)),
    )
}

pub(crate) fn pairs_of(ranges: &ChunkRanges) -> Vec<(u64, u64)> {
    ranges.ranges.iter().map(|r| (r.start, r.end)).collect()
}

fn root_of(root: &[u8]) -> Result<Hash> {
    Hash::from_slice(root).map_err(|error| StoreError::invalid(error.to_string()))
}

impl host::Bao for Bao<'_> {
    type Error = StoreError;

    fn encode_slice(
        &mut self,
        root: &[u8],
        size: u64,
        inline: Option<&[u8]>,
        spans: &[(u64, u64)],
    ) -> Result<Vec<u8>> {
        let root = root_of(root)?;
        let tree = Store::tree(size);
        let bao_ranges = to_bao_ranges(&ranges_of(spans));
        let mut encoded = Vec::new();
        let root_hash = blake3::Hash::from_bytes(root.0);
        match inline {
            Some(data) => {
                let outboard = PreOrderOutboard {
                    root: root_hash,
                    tree,
                    data: Vec::<u8>::new(),
                };
                encode_ranges(data, outboard, &bao_ranges, &mut encoded)
            }
            None => {
                // Both files are read positionally, never slurped. An outboard
                // is 1/256 of its object, so reading it whole costs 40 MB on a
                // 10 GB object, and this runs once per served window (§6.4).
                // What each call actually touches is the sibling hashes on the
                // path to the requested groups.
                let data = File::open(self.store.blob_path(&root))?;
                let outboard = PreOrderOutboard {
                    root: root_hash,
                    tree,
                    data: DataFile(File::open(self.store.outboard_path(&root))?),
                };
                encode_ranges(DataFile(data), outboard, &bao_ranges, &mut encoded)
            }
        }
        .map_err(|error| StoreError::invalid(format!("encode slice: {error}")))?;
        Ok(encoded)
    }

    fn encode_proof(
        &mut self,
        root: &[u8],
        size: u64,
        spans: &[(u64, u64)],
        level: u64,
        budget: u64,
    ) -> Result<Option<Vec<u8>>> {
        let root = root_of(root)?;
        let level =
            u8::try_from(level).map_err(|_| StoreError::invalid("proof level exceeds one byte"))?;
        let wanted = ranges_of(spans);
        // The outboard is read positionally, one node at a time, never
        // slurped: the span-level round over a 100 GB object touches a few
        // thousand of its nodes, where the outboard as a whole is hundreds of
        // megabytes. The budget is checked before each node is loaded, so an
        // over-budget request costs at most `budget` loads.
        let outboard = PreOrderOutboard {
            root: blake3::Hash::from_bytes(root.0),
            tree: Store::tree(size),
            data: DataFile(File::open(self.store.outboard_path(&root))?),
        };
        let (proof, truncated) = walk_proof(&root, size, &wanted, level, budget, false, |node| {
            load_from_outboard(&outboard, &root, node)
        })?;
        if truncated.is_some() {
            return Ok(None);
        }
        let mut encoded = Vec::with_capacity(proof.nodes.len() * PROOF_NODE_LEN);
        for (_, pair) in &proof.nodes {
            encoded.extend_from_slice(pair);
        }
        Ok(Some(encoded))
    }

    fn decode_inline(
        &mut self,
        root: &[u8],
        size: u64,
        inline: Option<&[u8]>,
        spans: &[(u64, u64)],
        input: &[u8],
    ) -> Result<Vec<u8>> {
        let root = root_of(root)?;
        self.store
            .decode_inline(&root, size, inline, &ranges_of(spans), input)
    }

    fn decode_slice(
        &mut self,
        root: &[u8],
        size: u64,
        spans: &[(u64, u64)],
        input: &[u8],
    ) -> Result<()> {
        let root = root_of(root)?;
        self.store
            .decode_slice_into_files(&root, size, &ranges_of(spans), input)
    }

    fn flush_object(&mut self, root: &[u8]) -> Result<()> {
        let root = root_of(root)?;
        self.store.flush_promotion(&mut self.promotion)?;
        self.store.flush_object(&root)
    }

    fn trim_object(&mut self, root: &[u8], size: u64) -> Result<()> {
        let root = root_of(root)?;
        self.store.trim_to_size(
            &root,
            crate::cas::Commit {
                size,
                complete: true,
            },
        );
        Ok(())
    }

    fn write_proof(
        &mut self,
        root: &[u8],
        size: u64,
        spans: &[(u64, u64)],
        level: u64,
        input: &[u8],
    ) -> Result<(bool, Vec<(u64, u64, Vec<u8>, bool)>)> {
        let root = root_of(root)?;
        let level =
            u8::try_from(level).map_err(|_| StoreError::invalid("proof level exceeds one byte"))?;
        let (wrote, proven) =
            self.store
                .verify_proof_into_outboard(&root, size, &ranges_of(spans), level, input)?;
        Ok((
            wrote,
            proven
                .into_iter()
                .map(|subtree| {
                    (
                        subtree.start,
                        subtree.groups,
                        subtree.cv.as_bytes().to_vec(),
                        subtree.whole,
                    )
                })
                .collect(),
        ))
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
        let donor = root_of(donor)?;
        let root = root_of(root)?;
        let cv = Cv(<[u8; 32]>::try_from(cv)
            .map_err(|_| StoreError::invalid("a chaining value is 32 bytes"))?);
        self.store
            .promote_run(&mut self.promotion, &donor, &root, size, start, groups, &cv)
    }
}
