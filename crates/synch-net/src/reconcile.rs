//! The §5.2 reconciliation algorithm.
//!
//! ```text
//! verify sig(H) under H.signed_by; check H.signed_by is bound to O (else ignore)
//! check (H.seq, H.root) > (local.seq, local.root) lexicographically (else ignore)
//! record H as pending_head(O)                            // durable
//! frontier ← { H.root }
//! while frontier ≠ ∅:
//!     want ← { h ∈ frontier : h ∉ trie_nodes }           // structural sharing
//!     if want = ∅: break
//!     nodes ← GetNodes(want)
//!     verify each node hashes to its requested hash      // reject & disconnect
//!     store nodes; frontier ← their children ∪ value hashes
//! atomically: set complete_head(O) ← H; clear pending
//! re-materialize changed leaves from the node-level diff
//! ```

use std::sync::Arc;

use synch_core::{now_ns, HeadSummary, OriginId, SignedHead, MAX_BATCH};
use synch_mpt::{Trie, TrieNode};
use synch_store::{Slot, Store};

use crate::{error::NetError, mpt::MptClient};

/// How many full fetch rounds may make no progress before the pending head is
/// abandoned and head selection re-runs (§5.2).
pub const MAX_UNPRODUCTIVE_ROUNDS: u32 = 3;

/// What happened when a head was offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadOutcome {
    /// The signature did not verify.
    BadSignature,
    /// The signer has no live binding to the claimed origin (§3.1).
    ///
    /// Trie heads whose signing key is not bound to the claimed origin are
    /// ignored even if relayed by a trusted peer.
    Unbound,
    /// The head is not strictly greater than what we already hold.
    NotNewer,
    /// The head was adopted as pending and its trie must be fetched.
    Pending,
    /// The head was adopted and its trie was already present, so the complete
    /// slot flipped immediately.
    Completed,
}

impl HeadOutcome {
    /// True if the head was adopted in either slot.
    pub fn accepted(&self) -> bool {
        matches!(self, HeadOutcome::Pending | HeadOutcome::Completed)
    }
}

/// What happened when a pending head's trie was fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    /// There was no pending head to fetch.
    Idle,
    /// The trie is now complete and the head flipped.
    Completed,
    /// Progress was made but the trie is still incomplete.
    Partial,
    /// Every candidate persistently returned `missing`; the pending head was
    /// abandoned and head selection re-runs (§5.2).
    Abandoned,
}

/// Reconciliation over one node's store.
#[derive(Debug, Clone)]
pub struct Syncer {
    store: Arc<Store>,
}

impl Syncer {
    /// Binds a syncer to a store.
    pub fn new(store: Arc<Store>) -> Self {
        Syncer { store }
    }

    /// The store this syncer reconciles into.
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The head summaries this node advertises in `Hello` (§5.1).
    ///
    /// `complete` means "I hold the full trie under this root and can serve
    /// it"; a signed head alone proves nothing about that, so the flag is
    /// computed from the local trie, never assumed.
    pub fn local_summaries(&self) -> Result<Vec<HeadSummary>, NetError> {
        let trie = Trie::new(self.store.as_ref());
        let mut out = Vec::new();
        for stored in self.store.all_heads(Slot::Complete)? {
            let head = stored.head;
            let complete = trie.is_complete(head.root)?;
            out.push(HeadSummary {
                origin: head.origin,
                seq: head.seq,
                root: head.root,
                complete,
            });
        }
        // A pending head is advertised too — as strictly not complete — so a
        // peer learns the newer head exists without being told we can serve it.
        for stored in self.store.all_heads(Slot::Pending)? {
            let head = stored.head;
            match out.iter_mut().find(|s| s.origin == head.origin) {
                Some(existing) if (head.seq, head.root.0) > (existing.seq, existing.root.0) => {
                    existing.seq = head.seq;
                    existing.root = head.root;
                    existing.complete = false;
                }
                Some(_) => {}
                None => out.push(HeadSummary {
                    origin: head.origin,
                    seq: head.seq,
                    root: head.root,
                    complete: false,
                }),
            }
        }
        out.sort_by(|a, b| a.origin.cmp(&b.origin));
        Ok(out)
    }

    /// Offers a head for adoption, applying the full §5.2 acceptance rule.
    pub fn offer_head(&self, head: &SignedHead, now: i64) -> Result<HeadOutcome, NetError> {
        // 1. The signature must verify under the key that claims to have made it.
        if head.verify_signature().is_err() {
            return Ok(HeadOutcome::BadSignature);
        }
        // 2. That key must be bound to the claimed origin, right now.
        if !self.store.is_bound(&head.origin, &head.signed_by, now)? {
            return Ok(HeadOutcome::Unbound);
        }
        // Verified heads are provable history and fork evidence even when they
        // lose the ordering comparison, so they are retained either way (§4.4).
        self.store.record_history(head)?;

        // 3. (seq, root) must be strictly greater, lexicographically. Strictly
        //    greater on seq alone would not converge: two peers receiving
        //    different same-seq heads in different orders would diverge
        //    permanently.
        let floor = self.store.head_floor(&head.origin)?;
        if !head.supersedes(floor.as_ref()) {
            return Ok(HeadOutcome::NotNewer);
        }

        self.store.put_head(Slot::Pending, head, now, now)?;
        if self.try_promote(&head.origin, now)? {
            Ok(HeadOutcome::Completed)
        } else {
            Ok(HeadOutcome::Pending)
        }
    }

    /// Flips the pending head to complete if its whole trie is present,
    /// re-materializing the derived views from the node-level diff.
    pub fn try_promote(&self, origin: &OriginId, now: i64) -> Result<bool, NetError> {
        let Some(pending) = self.store.pending_head(origin)? else {
            return Ok(false);
        };
        let trie = Trie::new(self.store.as_ref());
        if !trie.is_complete(pending.root)? {
            return Ok(false);
        }
        let old_root = self
            .store
            .complete_head(origin)?
            .map(|h| h.root)
            .unwrap_or(synch_core::Hash::EMPTY);
        self.store.promote_pending(origin, now)?;
        self.store
            .materialize_diff(origin, old_root, pending.root)?;
        tracing::debug!(origin = %origin, seq = pending.seq, "head flipped to complete");
        Ok(true)
    }

    /// Fetches the pending head's trie from `client`, verifying every node
    /// against the hash it was requested by.
    ///
    /// Nodes are content-addressed, so `client` need not be the origin, nor
    /// even the peer that told us about the head: any peer advertising a
    /// complete head for the origin at or above this seq will do.
    pub async fn fetch_pending(
        &self,
        client: &MptClient,
        origin: &OriginId,
    ) -> Result<FetchOutcome, NetError> {
        let Some(pending) = self.store.pending_head(origin)? else {
            return Ok(FetchOutcome::Idle);
        };
        let mut unproductive = 0u32;
        loop {
            let trie = Trie::new(self.store.as_ref());
            let missing = trie.missing(pending.root, MAX_BATCH)?;
            if missing.is_empty() {
                break;
            }

            let mut learned = 0usize;
            if !missing.nodes.is_empty() {
                let response = client.get_nodes(&missing.nodes).await?;
                for (hash, bytes) in &response.nodes {
                    // Verify each node against the hash it was requested by. A
                    // malicious or corrupt peer can withhold, never inject.
                    let actual = TrieNode::hash_of_encoded(bytes)
                        .map_err(|_| NetError::NodeHashMismatch { expected: *hash })?;
                    if actual != *hash {
                        return Err(NetError::NodeHashMismatch { expected: *hash });
                    }
                    if !missing.nodes.contains(hash) {
                        return Err(NetError::Unexpected(format!(
                            "peer served unrequested trie node {hash}"
                        )));
                    }
                    synch_mpt::NodeStore::put_node(self.store.as_ref(), hash, bytes)?;
                    learned += 1;
                }
            }
            if !missing.values.is_empty() {
                let response = client.get_values(&missing.values).await?;
                for (hash, bytes) in &response.values {
                    let actual = synch_core::Hash::new(bytes);
                    if actual != *hash {
                        return Err(NetError::ValueHashMismatch { expected: *hash });
                    }
                    synch_mpt::NodeStore::put_value(self.store.as_ref(), hash, bytes)?;
                    learned += 1;
                }
            }

            if learned == 0 {
                unproductive += 1;
                if unproductive >= MAX_UNPRODUCTIVE_ROUNDS {
                    // No wedging on unservable heads: abandon the pending head
                    // and let head selection re-run. Structural sharing makes
                    // the restart cost proportional to what actually changed.
                    tracing::warn!(
                        origin = %origin,
                        seq = pending.seq,
                        "abandoning pending head: providers persistently missing nodes"
                    );
                    self.store.clear_head(origin, Slot::Pending)?;
                    return Ok(FetchOutcome::Abandoned);
                }
            } else {
                unproductive = 0;
            }
        }

        if self.try_promote(origin, now_ns())? {
            Ok(FetchOutcome::Completed)
        } else {
            Ok(FetchOutcome::Partial)
        }
    }

    /// Runs one full `Hello` push-pull exchange with a peer, then fetches
    /// whatever it advertised that we do not have (§5.2, §5.3).
    pub async fn sync_with(&self, client: &MptClient) -> Result<SyncReport, NetError> {
        let ours = self.local_summaries()?;
        let store = self.store.clone();

        let mut report = SyncReport::default();
        let theirs = client
            .head_exchange(ours.clone(), |theirs| {
                // Push: heads we hold that the peer does not.
                let mut push = Vec::new();
                for summary in &ours {
                    let peer = theirs.iter().find(|t| t.origin == summary.origin);
                    let newer = match peer {
                        None => true,
                        Some(peer) => summary.order_key() > peer.order_key(),
                    };
                    if newer {
                        if let Ok(Some(head)) = store.complete_head(&summary.origin) {
                            if (head.seq, head.root.0) == summary.order_key() {
                                push.push(head);
                            }
                        }
                    }
                }
                // Pull: origins where the peer is ahead of us.
                let mut want = Vec::new();
                for summary in theirs {
                    let ours_for = ours.iter().find(|o| o.origin == summary.origin);
                    let newer = match ours_for {
                        None => true,
                        Some(mine) => summary.order_key() > mine.order_key(),
                    };
                    if newer {
                        want.push(summary.origin.clone());
                    }
                }
                (push, want)
            })
            .await?;

        report.heads_pushed = theirs.pushed;
        for head in theirs.received {
            let outcome = self.offer_head(&head, now_ns())?;
            match outcome {
                HeadOutcome::Pending => {
                    report.heads_accepted += 1;
                    match self.fetch_pending(client, &head.origin).await? {
                        FetchOutcome::Completed => report.tries_completed += 1,
                        FetchOutcome::Abandoned => report.heads_abandoned += 1,
                        _ => {}
                    }
                }
                HeadOutcome::Completed => {
                    report.heads_accepted += 1;
                    report.tries_completed += 1;
                }
                HeadOutcome::BadSignature | HeadOutcome::Unbound => report.heads_rejected += 1,
                HeadOutcome::NotNewer => {}
            }
        }

        // A head can arrive by reactive push (§5.3) long before its trie does.
        // Such a head sits in the pending slot and is *not* newer than what we
        // hold, so the exchange above will not have asked for it — but §5.2
        // says its nodes may be fetched from any peer advertising a complete
        // head for that origin at or above its seq. Do exactly that here, which
        // is what turns "I heard about it" into "I can serve it".
        for stored in self.store.all_heads(Slot::Pending)? {
            let pending = stored.head;
            let servable = theirs.summaries.iter().any(|summary| {
                summary.origin == pending.origin
                    && summary.complete
                    && summary.order_key() >= (pending.seq, pending.root.0)
            });
            if !servable {
                continue;
            }
            match self.fetch_pending(client, &pending.origin).await? {
                FetchOutcome::Completed => report.tries_completed += 1,
                FetchOutcome::Abandoned => report.heads_abandoned += 1,
                _ => {}
            }
        }
        Ok(report)
    }
}

/// What one exchange achieved, for logging and tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Heads we pushed to the peer.
    pub heads_pushed: usize,
    /// Heads the peer sent that we adopted.
    pub heads_accepted: usize,
    /// Heads the peer sent that failed verification or the binding check.
    pub heads_rejected: usize,
    /// Tries that became complete during this exchange.
    pub tries_completed: usize,
    /// Pending heads abandoned because nobody could serve their nodes.
    pub heads_abandoned: usize,
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;
    use synch_core::{file_key, FileEntry, Hash, OriginId, SignedHead};
    use synch_store::{Binding, BindingSource};

    use super::*;

    fn setup() -> (tempfile::TempDir, Arc<Store>, SecretKey, OriginId) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let key = SecretKey::generate();
        let origin = OriginId::named("nas", "x.example").unwrap();
        store
            .put_binding(&Binding {
                origin: origin.clone(),
                node_id: key.public(),
                source: BindingSource::Static,
                domain: None,
                note: None,
                added_at: 0,
                expires_at: None,
            })
            .unwrap();
        (dir, store, key, origin)
    }

    fn publish(store: &Store, files: &[&str]) -> Hash {
        let trie = Trie::new(store);
        let mut root = Hash::EMPTY;
        for path in files {
            let entry = FileEntry::file(7, 0, Hash::new(path.as_bytes()), 1);
            root = trie
                .insert(
                    root,
                    &file_key("s", path).unwrap(),
                    &postcard::to_stdvec(&entry).unwrap(),
                )
                .unwrap();
        }
        root
    }

    #[test]
    fn a_head_with_a_present_trie_completes_immediately() {
        let (_d, store, key, origin) = setup();
        let root = publish(&store, &["a", "b"]);
        let syncer = Syncer::new(store.clone());
        let head = SignedHead::sign(&key, origin.clone(), 1, root, 0);
        assert_eq!(syncer.offer_head(&head, 0).unwrap(), HeadOutcome::Completed);
        assert_eq!(store.complete_head(&origin).unwrap(), Some(head));
        assert_eq!(
            store
                .list_entries(Some(&origin), "s", "", None, None)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn a_head_with_a_missing_trie_stays_pending() {
        let (_d, store, key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        let head = SignedHead::sign(&key, origin.clone(), 1, Hash::new(b"unknown root"), 0);
        assert_eq!(syncer.offer_head(&head, 0).unwrap(), HeadOutcome::Pending);
        assert_eq!(store.pending_head(&origin).unwrap(), Some(head));
        // The complete slot is untouched while a fetch is in progress.
        assert_eq!(store.complete_head(&origin).unwrap(), None);
    }

    #[test]
    fn a_forged_signature_is_rejected() {
        let (_d, store, key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        let mut head = SignedHead::sign(&key, origin.clone(), 1, Hash::EMPTY, 0);
        head.seq = 99;
        assert_eq!(
            syncer.offer_head(&head, 0).unwrap(),
            HeadOutcome::BadSignature
        );
        assert_eq!(store.complete_head(&origin).unwrap(), None);
        assert!(store.head_history(&origin).unwrap().is_empty());
    }

    #[test]
    fn an_unbound_signer_is_rejected_even_when_the_signature_verifies() {
        // §3.2: heads whose signing key is not bound to the claimed origin are
        // ignored even if relayed by a trusted peer.
        let (_d, store, _key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        let stranger = SecretKey::generate();
        let head = SignedHead::sign(&stranger, origin.clone(), 1, Hash::EMPTY, 0);
        head.verify_signature().unwrap();
        assert_eq!(syncer.offer_head(&head, 0).unwrap(), HeadOutcome::Unbound);
        assert_eq!(store.complete_head(&origin).unwrap(), None);
    }

    #[test]
    fn an_expired_binding_no_longer_admits_heads() {
        let (_d, store, _k, origin) = setup();
        let rotated = SecretKey::generate();
        store
            .put_binding(&Binding {
                origin: origin.clone(),
                node_id: rotated.public(),
                source: BindingSource::Dns,
                domain: Some("x.example".into()),
                note: None,
                added_at: 0,
                expires_at: Some(100),
            })
            .unwrap();
        let syncer = Syncer::new(store.clone());
        let head = SignedHead::sign(&rotated, origin.clone(), 1, Hash::EMPTY, 0);
        assert_eq!(
            syncer.offer_head(&head, 50).unwrap(),
            HeadOutcome::Completed
        );
        let later = SignedHead::sign(&rotated, origin, 2, Hash::new(b"x"), 0);
        assert_eq!(
            syncer.offer_head(&later, 200).unwrap(),
            HeadOutcome::Unbound
        );
    }

    #[test]
    fn the_seq_root_rule_accepts_equal_seq_greater_root() {
        // Strictly-greater-on-seq alone would not converge: two peers receiving
        // different same-seq heads in different orders would diverge forever.
        let (_d, store, key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        let low = SignedHead::sign(&key, origin.clone(), 1, Hash([1u8; 32]), 0);
        let high = SignedHead::sign(&key, origin.clone(), 1, Hash([2u8; 32]), 0);

        assert!(syncer.offer_head(&low, 0).unwrap().accepted());
        assert!(syncer.offer_head(&high, 0).unwrap().accepted());
        assert_eq!(
            store.head_floor(&origin).unwrap().unwrap().1,
            Hash([2u8; 32])
        );
        // And the reverse order converges to the same head.
        assert_eq!(syncer.offer_head(&low, 0).unwrap(), HeadOutcome::NotNewer);
    }

    #[test]
    fn same_seq_forks_are_both_retained_as_evidence() {
        let (_d, store, key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        syncer
            .offer_head(
                &SignedHead::sign(&key, origin.clone(), 1, Hash([1u8; 32]), 0),
                0,
            )
            .unwrap();
        syncer
            .offer_head(
                &SignedHead::sign(&key, origin.clone(), 1, Hash([2u8; 32]), 0),
                0,
            )
            .unwrap();
        let equivocations = store.equivocations().unwrap();
        assert_eq!(equivocations.len(), 1);
        assert_eq!(equivocations[0].heads.len(), 2);
        for head in &equivocations[0].heads {
            head.verify_signature().unwrap();
        }
    }

    #[test]
    fn older_heads_are_ignored() {
        let (_d, store, key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        let new = SignedHead::sign(&key, origin.clone(), 5, Hash([5u8; 32]), 0);
        syncer.offer_head(&new, 0).unwrap();
        let old = SignedHead::sign(&key, origin.clone(), 4, Hash([9u8; 32]), 0);
        assert_eq!(syncer.offer_head(&old, 0).unwrap(), HeadOutcome::NotNewer);
        assert_eq!(store.head_floor(&origin).unwrap().unwrap().0, 5);
    }

    #[test]
    fn summaries_report_completeness_honestly() {
        let (_d, store, key, origin) = setup();
        let syncer = Syncer::new(store.clone());
        let root = publish(&store, &["a"]);
        syncer
            .offer_head(&SignedHead::sign(&key, origin.clone(), 1, root, 0), 0)
            .unwrap();
        let summaries = syncer.local_summaries().unwrap();
        assert_eq!(summaries.len(), 1);
        assert!(summaries[0].complete);

        // A pending head for an unknown root shows up as explicitly incomplete.
        syncer
            .offer_head(
                &SignedHead::sign(&key, origin, 2, Hash::new(b"unknown"), 0),
                0,
            )
            .unwrap();
        let summaries = syncer.local_summaries().unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].seq, 2);
        assert!(!summaries[0].complete);
    }
}
