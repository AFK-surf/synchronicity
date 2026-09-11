//! The bindings table: `OriginId → device key`, with source and validity (§3.1).
//!
//! Every trust check and every head verification goes through here — nothing in
//! the durable data model references a bare device key as an identity.

use rusqlite::params;
use synch_core::{NodeId, OriginId};
use synch_mpt::Scope;

use crate::{db::Store, error::Result};

/// Where a binding came from (§3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingSource {
    /// Explicitly added with `synch trust add`; never expires.
    Static,
    /// Learned from a DNSSEC-validated TXT record; expires on TTL + grace.
    Dns,
    /// Materialized from a `d:` record in a rooted origin's trie (§3.5).
    ///
    /// Never a source a delegation may itself be honored from: that is the
    /// whole of the one-level property, and it is a lookup rather than a
    /// claim — the native authorization operation checks the issuer lookup.
    Delegated,
}

impl BindingSource {
    /// The `source` column value.
    pub fn as_str(self) -> &'static str {
        match self {
            BindingSource::Static => "static",
            BindingSource::Dns => "dns",
            BindingSource::Delegated => "delegated",
        }
    }
}

/// What an origin is permitted to publish, as `try_promote` asks it (§3.5).
///
/// Three answers, not two. Collapsing "no live binding" into "unrestricted" is
/// a fail-open in the worst place: a delegated origin whose head was refused
/// for a scope violation sits in the pending slot, and the moment its
/// delegation lapses or is revoked the origin has no live binding at all — so
/// the very act of revoking would promote the head that revocation exists to
/// keep out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishScope {
    /// No live binding: nothing this origin published may be promoted.
    Untrusted,
    /// A live rooted binding: the origin may publish anything.
    Unrestricted,
    /// Live delegations only: confined to these spaces.
    Confined(Vec<String>),
}

/// Publication authority, its actual trie grant, and provenance from one snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionAuthority {
    /// Whether this origin may publish, including any confined spaces.
    pub publication: PublishScope,
    /// Exact trie grant built from the same authority observation.
    pub trie_scope: Scope,
    /// Origin required to have vouched for fetched trie nodes, if any.
    pub provenance: Option<OriginId>,
}

/// A binding's dated and effective status, evaluated by the native projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingStatus {
    /// The stored binding.
    pub binding: Binding,
    /// Whether the binding's own expiry is live at the trusted instant.
    pub dated_live: bool,
    /// Whether the binding is live including its issuer cascade.
    pub live: bool,
}

/// An `OriginId → device key` binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The origin the key is bound to.
    pub origin: OriginId,
    /// The bound device key.
    pub node_id: NodeId,
    /// Where the binding came from.
    pub source: BindingSource,
    /// The membership domain, for DNS bindings.
    pub domain: Option<String>,
    /// The origin that vouched for this key, for delegated bindings.
    pub issuer: Option<OriginId>,
    /// The spaces a delegated binding covers read-write (§3.5).
    pub spaces: Vec<String>,
    /// The spaces a delegated binding covers read-only (§3.5): served like
    /// `spaces`, and refused at head promotion like a space outside the grant.
    pub read_only: Vec<String>,
    /// A user note, for static bindings.
    pub note: Option<String>,
    /// When the binding was added, in unix nanoseconds.
    pub added_at: i64,
    /// When the binding expires, in unix nanoseconds. `None` for static.
    pub expires_at: Option<i64>,
}

/// Renders a delegated binding's space list for the `spaces` column.
///
/// Newline-separated: `validate_space` forbids control characters, so no valid
/// id can contain the separator and no escaping is needed.
pub(crate) fn encode_spaces(spaces: &[String]) -> String {
    spaces.join("\n")
}

/// Inserts or refreshes a binding on whichever connection is handed in.
fn put_binding_in(conn: &rusqlite::Connection, binding: &Binding) -> Result<()> {
    let list = |spaces: &[String]| match spaces.is_empty() {
        true => None,
        false => Some(encode_spaces(spaces)),
    };
    conn.execute(
        "INSERT INTO bindings (origin_id, node_id, source, domain, issuer, spaces, read_only, note, added_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(origin_id, node_id, source, domain, issuer) DO UPDATE SET
           spaces = excluded.spaces,
           read_only = excluded.read_only,
           note = COALESCE(excluded.note, bindings.note),
           expires_at = excluded.expires_at",
        params![
            binding.origin.canonical(),
            binding.node_id.as_bytes().to_vec(),
            binding.source.as_str(),
            binding.domain.as_deref().unwrap_or(""),
            binding
                .issuer
                .as_ref()
                .map(|o| o.canonical())
                .unwrap_or_default(),
            list(&binding.spaces),
            list(&binding.read_only),
            binding.note,
            binding.added_at,
            binding.expires_at,
        ],
    )?;
    Ok(())
}

impl crate::db::Txn<'_> {
    /// Publication authority and provenance judged from the same snapshot as
    /// the head flip. A revoked issuer or changed binding cannot be hidden by
    /// an earlier read outside this transaction.
    pub fn promotion_authority(&self, origin: &OriginId, now: i64) -> Result<PromotionAuthority> {
        crate::lean_authorization::origin_authority_on(self.conn(), origin, now, true)
    }

    /// The scope one origin's leaves may be materialized under, inside the
    /// transaction.
    ///
    /// [`Store::materialization_scope`]: the read scope for a foreign origin,
    /// and always the whole keyspace for this node's own, whose trie it built
    /// and therefore holds whole.
    pub fn materialization_scope(&self, origin: &OriginId) -> Result<Scope> {
        crate::lean_authorization::materialization_scope_on(self.conn(), origin, true)
    }

    /// The read scope this node is confined to, inside the transaction.
    ///
    /// Promotion reads it to scope the materialization diff the same way the
    /// fetch that filled the trie was scoped (§5.5).
    pub fn local_trie_scope(&self) -> Result<Scope> {
        crate::lean_authorization::local_scope_on(self.conn(), true)
    }

    /// Removes one binding, inside the transaction.
    pub fn remove_binding(
        &self,
        origin: &OriginId,
        node_id: &NodeId,
        source: BindingSource,
    ) -> Result<bool> {
        let n = self.conn().execute(
            "DELETE FROM bindings WHERE origin_id = ?1 AND node_id = ?2 AND source = ?3",
            params![
                origin.canonical(),
                node_id.as_bytes().to_vec(),
                source.as_str()
            ],
        )?;
        Ok(n > 0)
    }

    /// Inserts or refreshes a binding, inside the transaction.
    ///
    /// A key rotation writes the incoming key's self-binding and the two key
    /// states together: a binding without the state change is a key the node
    /// trusts but will not sign with, and the reverse is a key it signs with
    /// and cannot verify after a restart.
    pub fn put_binding(&self, binding: &Binding) -> Result<()> {
        put_binding_in(self.conn(), binding)
    }
}

impl Store {
    /// Dated and effective binding statuses from one native projection.
    pub fn binding_statuses(&self, now: i64) -> Result<Vec<BindingStatus>> {
        crate::lean_authorization::binding_statuses(self, now)
    }

    /// Whether the peer has a rooted live binding, using an indexed native read.
    pub fn is_rooted_key(&self, key: &NodeId, now: i64) -> Result<bool> {
        Ok(crate::lean_authorization::peer_authority(self, key, now)?.rooted)
    }

    /// Whether this DNS domain is the key's sole dated hint source.
    pub fn sole_dns_hint_source(&self, key: &NodeId, domain: &str, now: i64) -> Result<bool> {
        crate::lean_authorization::sole_dns_hint_source(self, key, domain, now)
    }

    /// Inserts or refreshes a binding.
    pub fn put_binding(&self, binding: &Binding) -> Result<()> {
        put_binding_in(&self.conn(), binding)
    }

    /// Removes one binding.
    pub fn remove_binding(
        &self,
        origin: &OriginId,
        node_id: &NodeId,
        source: BindingSource,
    ) -> Result<bool> {
        let n = self.conn().execute(
            "DELETE FROM bindings WHERE origin_id = ?1 AND node_id = ?2 AND source = ?3",
            params![
                origin.canonical(),
                node_id.as_bytes().to_vec(),
                source.as_str()
            ],
        )?;
        Ok(n > 0)
    }

    /// Removes one key's bindings for an origin, whatever their source.
    ///
    /// This is `trust rm <origin> --key <key>`: after a rotation window
    /// closes, the retired key's binding is the one thing left to clean up,
    /// and removing the whole origin to get at it threw away the new key too.
    pub fn remove_key_binding(&self, origin: &OriginId, node_id: &NodeId) -> Result<bool> {
        let n = self.conn().execute(
            "DELETE FROM bindings WHERE origin_id = ?1 AND node_id = ?2",
            params![origin.canonical(), node_id.as_bytes().to_vec()],
        )?;
        Ok(n > 0)
    }

    /// Removes every binding for an origin.
    pub fn remove_origin_bindings(&self, origin: &OriginId) -> Result<usize> {
        Ok(self.conn().execute(
            "DELETE FROM bindings WHERE origin_id = ?1",
            params![origin.canonical()],
        )?)
    }

    /// Every binding, live or expired.
    pub fn bindings(&self) -> Result<Vec<Binding>> {
        crate::lean_authorization::bindings(
            self,
            synch_verified::authorization::BindingSelection::All,
            false,
            0,
        )
    }

    /// Every binding for one origin.
    pub fn bindings_for_origin(&self, origin: &OriginId) -> Result<Vec<Binding>> {
        crate::lean_authorization::bindings(
            self,
            crate::lean_authorization::for_origin(origin),
            false,
            0,
        )
    }

    /// Every binding that names a device key.
    pub fn bindings_for_key(&self, node_id: &NodeId) -> Result<Vec<Binding>> {
        crate::lean_authorization::bindings(
            self,
            crate::lean_authorization::for_key(node_id),
            false,
            0,
        )
    }

    /// Every binding that is live at `now`, cascade included.
    ///
    /// The single place liveness is decided, because a delegated binding
    /// cannot answer for itself: the native dated check is only one part; whether it
    /// counts also depends on *another* row — the issuing origin's own
    /// binding. Derived trust must not outlive its source, so
    /// `synch trust rm nas` and `nas`'s TXT record lapsing each cut off
    /// `nas`'s delegates in the same instant they cut off `nas`.
    ///
    /// Evaluated on read rather than stamped on write, because the issuer's
    /// binding can lapse at any time and nothing would come along to restamp
    /// the rows that depend on it. A delegated row that slipped past on the
    /// dated check alone is exactly the cascade hole, and it would pass every
    /// test that never revokes an issuer.
    pub fn live_bindings(&self, now: i64) -> Result<Vec<Binding>> {
        crate::lean_authorization::bindings(
            self,
            synch_verified::authorization::BindingSelection::All,
            true,
            now,
        )
    }

    /// The live bindings naming one device key, cascade included.
    ///
    /// The same answer [`Store::live_bindings`] would give about this key,
    /// reached through `bindings_by_key` instead of by materializing the table.
    /// Every question below that is *about one key* goes through this, and the
    /// hot ones are hot indeed: `is_trusted_key` is the connection-accept gate
    /// and the per-dial trust check, `scope_for_key` runs per request and
    /// `publish_scope_of_key` per slice. Answering any of them from a
    /// whole-table read made each cost `O(bindings)` on a node that holds ten
    /// thousand of them (`docs/CLOUD-DATAPLANE.md` §7.1a).
    pub fn live_bindings_for_key(&self, node_id: &NodeId, now: i64) -> Result<Vec<Binding>> {
        crate::lean_authorization::bindings(
            self,
            crate::lean_authorization::for_key(node_id),
            true,
            now,
        )
    }

    /// The live bindings for one origin, cascade included.
    ///
    /// `origin_id` leads the primary key, so this is the same index seek
    /// [`Self::live_bindings_for_key`] is, asked the other way round.
    pub fn live_bindings_for_origin(&self, origin: &OriginId, now: i64) -> Result<Vec<Binding>> {
        crate::lean_authorization::bindings(
            self,
            crate::lean_authorization::for_origin(origin),
            true,
            now,
        )
    }

    /// The origins a device key is currently bound to.
    ///
    /// A key may hold several origins only in malformed configurations; §3.2
    /// asks `synch doctor` to report exactly that, so this returns all of them.
    pub fn live_origins_for_key(&self, node_id: &NodeId, now: i64) -> Result<Vec<OriginId>> {
        Ok(self
            .live_bindings_for_key(node_id, now)?
            .into_iter()
            .filter(|b| &b.node_id == node_id)
            .map(|b| b.origin)
            .collect())
    }

    /// True if `node_id` is currently bound to `origin`.
    ///
    /// This is the second half of head validity (§4.4): a signature that
    /// verifies under an unbound key is not a valid head.
    pub fn is_bound(&self, origin: &OriginId, node_id: &NodeId, now: i64) -> Result<bool> {
        crate::lean_authorization::bound(self, origin, node_id, now)
    }

    /// True if a device key has *any* live binding.
    ///
    /// This is the connection-accept gate (§3.2): connections from device keys
    /// with no live binding are closed immediately after the QUIC handshake.
    pub fn is_trusted_key(&self, node_id: &NodeId, now: i64) -> Result<bool> {
        crate::lean_authorization::trusted_key(self, node_id, now)
    }

    /// Every origin with at least one live binding.
    pub fn trusted_origins(&self, now: i64) -> Result<Vec<OriginId>> {
        crate::lean_authorization::trusted_origins(self, now)
    }

    /// Every device key with at least one live binding, for dialing.
    ///
    /// Read once per reactive push and once per anti-entropy round, so it is
    /// the one whole-set question on a hot path. It answers in SQL rather than
    /// by filtering [`Store::live_bindings`]: at ten thousand bindings that
    /// built ten thousand `Binding` values — parsing an origin, a key and a
    /// space list apiece — to return a column of keys
    /// (`docs/CLOUD-DATAPLANE.md` §7.1a).
    pub fn trusted_keys(&self, now: i64) -> Result<Vec<NodeId>> {
        crate::lean_authorization::trusted_keys(self, now)
    }

    /// The live device keys currently bound to an origin, for dialing (§3.3).
    pub fn keys_for_origin(&self, origin: &OriginId, now: i64) -> Result<Vec<NodeId>> {
        Ok(self
            .live_bindings_for_origin(origin, now)?
            .into_iter()
            .map(|b| b.node_id)
            .collect())
    }

    /// What part of the keyspace a peer may be served (§5.5).
    ///
    /// [`Scope::full`] whenever the key holds any live *rooted* binding — a
    /// rooted member is unrestricted by construction — and otherwise the union
    /// of the space lists every live delegation of that key carries. Two
    /// rooted origins may each delegate the same key, and each vouches
    /// independently, so their grants add rather than conflict.
    ///
    /// A key with no live binding at all gets the scope of an empty space list
    /// — `m:self` and the public `d:` namespace, and no file data. It will have
    /// been refused at accept long before this is asked, so the case is
    /// unreachable rather than permissive.
    pub fn scope_for_key(&self, node_id: &NodeId, now: i64) -> Result<Scope> {
        Ok(self.scope_for_key_with_origins(node_id, now)?.0)
    }

    /// As [`Self::scope_for_key`], and the origins that key speaks for.
    ///
    /// The origins are what makes a claimed position mean anything: a root the
    /// asking peer signed itself is a root of its own choosing, so it does not
    /// vouch for the positions in it (`Store::is_head_root`). Taken from the
    /// same `live_bindings` read, because the caller needs both.
    pub fn scope_for_key_with_origins(
        &self,
        node_id: &NodeId,
        now: i64,
    ) -> Result<(Scope, Vec<OriginId>)> {
        let answer = crate::lean_authorization::peer_authority(self, node_id, now)?;
        Ok((answer.serving, answer.origins))
    }

    /// The scope a device key may read under (§3.5).
    ///
    /// The content half of scope: object roots carry no space, so a delegated
    /// peer's entitlement to bytes is decided against this list.
    pub fn publish_scope_of_key(&self, node_id: &NodeId, now: i64) -> Result<PublishScope> {
        Ok(self.publish_scope_of_key_with_origins(node_id, now)?.0)
    }

    /// As [`Self::publish_scope_of_key`], and the origins that key speaks for.
    ///
    /// The origins are what the content half of the scope needs: an entry
    /// naming an object is title to its bytes only if some origin *other than
    /// the requester* published it (`Store::content_in_spaces`). Returned from
    /// the same `live_bindings` read rather than a second one, because this
    /// runs once per slice.
    pub fn publish_scope_of_key_with_origins(
        &self,
        node_id: &NodeId,
        now: i64,
    ) -> Result<(PublishScope, Vec<OriginId>)> {
        let answer = crate::lean_authorization::peer_authority(self, node_id, now)?;
        Ok((answer.publication, answer.origins))
    }

    /// The spaces a delegated origin may publish into, or `None` when the
    /// origin is rooted and may publish anything.
    ///
    /// This is the publish-scope question (§3.5), asked of the *origin* whose
    /// trie is being materialized rather than of a connection's peer key.
    pub fn publish_scope(&self, origin: &OriginId, now: i64) -> Result<PublishScope> {
        crate::lean_authorization::origin_publication(self, origin, now)
    }

    /// The origin whose provenance a walk over `origin`'s trie must carry, if
    /// any (§5.5).
    ///
    /// `None` for this node's own origin, whose trie it built, and for an
    /// origin holding a live rooted binding, which may reference any node it
    /// likes: it can read everything, so nothing it publishes leaks. `Some`
    /// for everything else — a confined origin, and an origin with no live
    /// binding at all, which is judged as strictly as a confined one rather
    /// than as an unrestricted one.
    pub fn provenance_owner(&self, origin: &OriginId, now: i64) -> Result<Option<OriginId>> {
        self.with_connection_scope(|conn| {
            Ok(
                crate::lean_authorization::origin_authority_on(conn, origin, now, false)?
                    .provenance,
            )
        })
    }

    /// The scope this node itself may read, as last declared by a peer (§5.5).
    ///
    /// `None` — the default — is the whole keyspace. A delegated node cannot
    /// derive this locally before it has synced anything: its scope lives in
    /// the delegating origin's trie, which it needs the scope to read. So the
    /// value is learned from the `Hello` of whichever peer is serving it, and
    /// held here because the fetch walk, promotion and the head summaries all
    /// have to agree about it.
    ///
    /// Read-only. [`Store::set_read_scope`] is the one thing that moves it,
    /// because moving it discards everything derived under the old value — and
    /// the claim that used to stand here, that "adopting a peer's word costs
    /// nothing … a wrong value can only make this node ask for less than it is
    /// entitled to", is exactly what that discarding disproves. Asking for less
    /// is free only while nothing durable is derived from it.
    pub fn local_scope(&self) -> Result<Option<Vec<String>>> {
        crate::lean_authorization::local_spaces(self)
    }

    /// True when this node holds a live *rooted* binding for one of its own
    /// keys in an origin other than its own (§5.5).
    ///
    /// This is the locally materialized shape of a promotion: the issuer's
    /// zone names the key as a full member, and the resolver wrote that down
    /// as a rooted binding. It is what lets the delegate tell "promoted"
    /// from "grant lapsed next to an operator's local `trust add`" — a peer
    /// declaration alone cannot, because any rooted binding produces the
    /// same `Unrestricted` wire value.
    pub fn own_rooted_in_foreign_origin(&self, now: i64) -> Result<bool> {
        Ok(crate::lean_authorization::local_authority(self, now)?.rooted_elsewhere)
    }

    /// The origins that have delegated to *this* node (§3.5); empty if it is
    /// not a delegate.
    ///
    /// A delegation names a device key, so this matches every key that is this
    /// node's — its origin's, and every `device_keys` row, because a record
    /// naming a key mid-rotation still confines the node holding it.
    pub fn own_issuers(&self, now: i64) -> Result<Vec<OriginId>> {
        Ok(crate::lean_authorization::local_authority(self, now)?.issuers)
    }

    /// The spaces this node's own live delegations grant it, or `None` when
    /// no live `d:` record names it (§5.5).
    ///
    /// The read scope is derived from this rather than from a peer's
    /// declaration: the grant is the record every member reads identically
    /// out of the issuer's trie, so a node's view of itself cannot depend on
    /// which peer it happens to be talking to — and a peer's word can never
    /// widen it. `None` covers both the never-a-delegate and the revoked
    /// states; the caller tells them apart by what it already holds.
    pub fn own_grant(&self, now: i64) -> Result<Option<Vec<String>>> {
        Ok(crate::lean_authorization::local_authority(self, now)?.grant)
    }

    /// The part of [`Store::own_grant`] this node may read but not publish
    /// into (§3.5): the spaces every issuer that grants them grants read-only.
    ///
    /// Empty when the node is not a delegate, and when every space it holds
    /// is read-write. A source registered for one of these publishes into a
    /// space every member refuses, so the engine refuses it first, at the
    /// point the operator can still choose a replica instead.
    pub fn own_read_only(&self, now: i64) -> Result<Vec<String>> {
        Ok(crate::lean_authorization::local_authority(self, now)?.read_only)
    }

    /// Why this node must not pull metadata from `peer`, or `None` if it may
    /// (§5.5).
    ///
    /// A delegate holds every foreign trie in part, so only a node holding one
    /// whole can serve it: pulling from another delegate yields a trie short in
    /// exactly the spaces that peer was not granted, which nothing downstream
    /// can tell from a trie still arriving. A delegate therefore syncs only
    /// with full members of its own issuer's cluster — which is also what keeps
    /// the read scope a single node-wide value, since every peer it can reach
    /// reads the same `d:` record and declares the same answer.
    ///
    /// A node that is not a delegate is unrestricted. Content is unaffected:
    /// it is content-addressed and hash-verified, so bytes come from anyone
    /// (§6).
    /// Asked once per outgoing metadata dial, so the "not a delegate" answer
    /// is reached without reading a row that is not about this node: a hosted
    /// replica holds ten thousand bindings and is nobody's delegate, and
    /// deciding that from a whole-table scan is what made one reactive push
    /// quadratic in the membership (`docs/CLOUD-DATAPLANE.md` §7.1a).
    pub fn refuse_metadata_sync(&self, peer: &NodeId, now: i64) -> Result<Option<String>> {
        crate::lean_authorization::metadata_peer(self, peer, now)
    }

    /// Sets the read scope and, if it moved, discards everything derived under
    /// the old one (§5.5). Returns whether it moved.
    ///
    /// The scope decides what a fetch asks for, what `is_complete_scoped`
    /// counts as whole, and what `materialize_diff` walks. Nothing reconciles
    /// rows built under one scope with a walk under another: the promotion diff
    /// prunes at equal node hashes, so it can neither reach what a narrower
    /// walk skipped nor remove what a wider one covered — and where the newly
    /// admitted subtree also changed, it descends into an old root with no node
    /// there and raises `MissingNode`, which reads as the origin's fault.
    ///
    /// So nothing is reconciled. `entries`, `blob_providers` and the delegated
    /// bindings are derived state, and derived state whose premise changed is
    /// thrown away: the rows go, the boundaries go, and every foreign complete
    /// head drops back to pending. The promotion that follows finds no complete
    /// head, so its diff runs from `Hash::EMPTY` — a full materialization that
    /// touches the stale root not at all.
    ///
    /// An unchanged scope costs one comparison; a changed one costs a
    /// re-materialization of every foreign origin. Trie nodes are
    /// content-addressed and are not discarded, so the only bytes refetched are
    /// what the new scope adds. This node's own origin is never touched: it
    /// built that trie and there is nobody to refetch it from.
    pub fn set_read_scope(&self, spaces: Option<&[String]>) -> Result<bool> {
        self.set_read_scope_at(spaces, synch_core::now_ns())
    }

    /// Timestamped implementation of [`Store::set_read_scope`].  Maintenance
    /// supplies the same clock reading it uses to age pending heads, so a head
    /// demoted by this scope transition cannot be swept immediately using the
    /// age it accumulated under the old scope.
    fn set_read_scope_at(&self, spaces: Option<&[String]>, now: i64) -> Result<bool> {
        crate::lean_authorization::change_scope(self, spaces, now)
    }

    /// Realigns the read scope with the live grant, and returns whether it
    /// moved (§5.5).
    ///
    /// The delegate a lapsed grant named is cut off at the connection gate
    /// the moment its binding dies — no peer's declaration ever reaches it
    /// again — so the maintenance pass is where the clock drives the derived
    /// views away: the same destructive move `adopt_scope` makes for a moved
    /// grant, applied to the one that expired. A grant that expires wholly
    /// collapses the scope to the empty one; one that expires among several
    /// narrows the scope to the grants that remain; a grant materialized
    /// since the last pass widens it. A fresh node (no grant, no confined
    /// scope) is left alone.
    pub fn collapse_grantless_scope(&self, now: i64) -> Result<bool> {
        let grant = self.own_grant(now)?;
        match (self.local_scope()?, grant) {
            // A live grant is the authoritative scope: a grant materialized
            // since the last pass widens, one that shrank narrows.
            (Some(spaces), Some(grant)) if spaces != grant => {
                self.set_read_scope_at(Some(&grant), now)
            }
            // No grant left: a confined scope collapses to the empty one —
            // `m:self` and the `d:` namespace, no file data — not to `None`,
            // which would read as unrestricted.
            (Some(spaces), None) if !spaces.is_empty() => self.set_read_scope_at(Some(&[]), now),
            _ => Ok(false),
        }
    }

    /// The scope one origin's leaves may be materialized under.
    ///
    /// [`Store::local_trie_scope`] for a foreign origin, whose trie this node
    /// holds only as far as it was served — but always [`Scope::full`] for this
    /// node's *own* origin, whose trie it built and therefore holds whole.
    /// Scoping the local publish would silently drop every record outside the
    /// read scope from the derived views, `b:` above all: a delegate would stop
    /// advertising the content it holds, so no member could fetch from it, and
    /// its own retired ads would never be swept.
    pub fn materialization_scope(&self, origin: &OriginId) -> Result<Scope> {
        self.with_connection_scope(|conn| {
            crate::lean_authorization::materialization_scope_on(conn, origin, false)
        })
    }

    /// True if this store holds any delegation row at all.
    ///
    /// One indexed existence check, for hot paths that would otherwise read the
    /// whole bindings table to discover that nothing is delegated.
    pub fn has_delegations(&self) -> Result<bool> {
        crate::lean_authorization::has_delegations(self)
    }

    /// The read scope as the trie walk wants it.
    pub fn local_trie_scope(&self) -> Result<Scope> {
        self.with_connection_scope(|conn| crate::lean_authorization::local_scope_on(conn, false))
    }

    /// Every live delegation, for `delegate ls` and `doctor`.
    pub fn delegations(&self, now: i64) -> Result<Vec<Binding>> {
        crate::lean_authorization::bindings(
            self,
            synch_verified::authorization::BindingSelection::Delegated,
            true,
            now,
        )
    }

    /// Every delegation row, live or not, for reporting what has lapsed.
    pub fn all_delegations(&self) -> Result<Vec<Binding>> {
        crate::lean_authorization::bindings(
            self,
            synch_verified::authorization::BindingSelection::Delegated,
            false,
            0,
        )
    }

    /// Replaces the whole DNS binding set for one domain, in one transaction.
    ///
    /// Bindings that disappear from DNS are *not* deleted here: they keep their
    /// existing expiry so they lapse after `dns_trust_grace` rather than being
    /// yanked on a single propagation glitch (§3.2).
    pub fn refresh_dns_bindings(&self, domain: &str, bindings: &[Binding]) -> Result<()> {
        self.with_tx(|tx| {
            for binding in bindings {
                tx.execute(
                    // The conflict target includes the domain, because that is
                    // what a DNS binding's identity is: an `id=`-less record
                    // binds `OriginId::Key(nk)`, which names no domain. It
                    // includes the issuer too, which is `''` here: a DNS
                    // binding is vouched for by nobody, and the column is in
                    // the key for the same reason the domain is.
                    "INSERT INTO bindings (origin_id, node_id, source, domain, issuer, spaces, note, added_at, expires_at)
                     VALUES (?1, ?2, 'dns', ?3, '', NULL, NULL, ?4, ?5)
                     ON CONFLICT(origin_id, node_id, source, domain, issuer) DO UPDATE SET
                       expires_at = excluded.expires_at",
                    params![
                        binding.origin.canonical(),
                        binding.node_id.as_bytes().to_vec(),
                        domain,
                        binding.added_at,
                        binding.expires_at,
                    ],
                )?;
            }
            Ok(())
        })
    }

    /// Drops every binding one zone vouched for, now rather than at expiry.
    ///
    /// For leaving a zone: those bindings are trusted *because* that zone said
    /// so, and waiting out `dns_trust_grace` would leave its members dialable
    /// for hours after the operator said otherwise.
    pub fn drop_dns_bindings(&self, domain: &str) -> Result<usize> {
        Ok(self.conn().execute(
            "DELETE FROM bindings WHERE source = 'dns' AND domain = ?1",
            params![domain],
        )?)
    }

    /// Deletes DNS bindings whose expiry has passed, returning how many went.
    ///
    /// Nothing is deleted at an instant no expiry can be compared against (see
    /// [`crate::clock`]): the native liveness operation has already stopped honoring
    /// every DNS binding on such a node, so trust is withdrawn without the
    /// deletion, and a clock that gets fixed costs one refresh rather than a
    /// re-resolution of every domain from nothing.
    pub fn expire_bindings(&self, now: i64) -> Result<usize> {
        crate::lean_authorization::expire_dns(self, now)
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;
    use synch_core::MIN_TRUSTED_NS;

    use super::*;
    use crate::{testutil::store, StoreError};

    /// A trustworthy instant, `secs` seconds into the trusted era: a clock
    /// reading below [`MIN_TRUSTED_NS`] dates nothing (see [`crate::clock`]).
    fn at(secs: i64) -> i64 {
        MIN_TRUSTED_NS + secs * 1_000_000_000
    }

    #[test]
    fn widening_the_scope_forgets_the_boundaries_the_old_one_drew() {
        use synch_mpt::NodeStore;

        let (_dir, store) = store();
        let withheld = synch_core::Hash::new(b"a subtree the narrow grant withheld");
        let at = [6u8, 6, 3, 10];
        store.set_read_scope(Some(&["photos".to_string()])).unwrap();
        store.note_redacted(&withheld, &at).unwrap();
        assert!(store.is_redacted(&withheld, Some(&at)).unwrap());

        // Re-declaring the same scope changes nothing, so the boundary stands.
        assert!(!store.set_read_scope(Some(&["photos".to_string()])).unwrap());
        assert!(store.is_redacted(&withheld, Some(&at)).unwrap());

        // Widening it does. The same node now sits at a position this node is
        // entitled to, and a boundary left over from the narrow grant would
        // make the walk skip it forever — reporting a trie complete that it
        // does not hold, with nothing to notice.
        assert!(store
            .set_read_scope(Some(&["photos".to_string(), "finance".to_string()]))
            .unwrap());
        assert!(
            !store.is_redacted(&withheld, None).unwrap(),
            "a boundary outlived the scope that drew it"
        );
    }

    /// Moving the scope demotes a foreign complete head to pending — but never
    /// over a newer head already pending there. `put_head` replaces the slot,
    /// so the demotion used to drop the newer head to history and lower the
    /// floor to the older one.
    #[test]
    fn moving_the_scope_never_demotes_over_a_newer_pending_head() {
        use crate::heads::Slot;
        use crate::testutil::{origin, sign_head};
        use synch_core::Hash;

        let (_dir, store) = store();
        let key = SecretKey::generate();
        let complete = sign_head(&key, 5, 5);
        let pending = sign_head(&key, 7, 7);
        store.put_head(Slot::Complete, &complete, 100, 100).unwrap();
        store.put_head(Slot::Pending, &pending, 200, 200).unwrap();

        assert!(store
            .set_read_scope_at(Some(&["photos".to_string()]), at(20))
            .unwrap());
        assert_eq!(store.complete_head(&origin()).unwrap(), None);
        assert_eq!(
            store.pending_head(&origin()).unwrap(),
            Some(pending),
            "the newer pending head survived the demotion"
        );
        assert_eq!(
            store
                .head(&origin(), Slot::Pending)
                .unwrap()
                .unwrap()
                .received_at,
            at(20),
            "scope-invalidated pending work gets a fresh retry window"
        );
        assert_eq!(
            store.head_floor(&origin()).unwrap(),
            Some((7, Hash([7u8; 32])))
        );

        // With nothing newer pending, the complete head is what gets demoted.
        let later = sign_head(&key, 9, 9);
        store.put_head(Slot::Complete, &later, 300, 300).unwrap();
        store
            .clear_head_at(&origin(), Slot::Pending, 7, &Hash([7u8; 32]))
            .unwrap();
        assert!(store
            .set_read_scope_at(Some(&["photos".to_string(), "finance".to_string()]), at(30),)
            .unwrap());
        assert_eq!(store.complete_head(&origin()).unwrap(), None);
        assert_eq!(store.pending_head(&origin()).unwrap(), Some(later));
        assert_eq!(
            store
                .head(&origin(), Slot::Pending)
                .unwrap()
                .unwrap()
                .received_at,
            at(30),
            "a newly demoted head is not born with its old complete-slot age"
        );
    }

    #[test]
    fn moving_the_scope_requeues_every_foreign_origin() {
        use crate::heads::Slot;
        use crate::testutil::origin_named;
        use synch_core::{Hash, SignedHead};

        let (_dir, store) = store();
        let key = SecretKey::generate();
        let first = origin_named("first");
        let second = origin_named("second");
        let first_complete = SignedHead::sign(&key, first.clone(), 5, Hash([5; 32]), 0);
        let first_pending = SignedHead::sign(&key, first.clone(), 7, Hash([7; 32]), 0);
        let second_complete = SignedHead::sign(&key, second.clone(), 9, Hash([9; 32]), 0);
        store
            .put_head(Slot::Complete, &first_complete, at(1), at(1))
            .unwrap();
        store
            .put_head(Slot::Pending, &first_pending, at(2), at(2))
            .unwrap();
        store
            .put_head(Slot::Complete, &second_complete, at(3), at(3))
            .unwrap();

        assert!(store
            .set_read_scope_at(Some(&["photos".to_string()]), at(20))
            .unwrap());

        for (origin, expected) in [(&first, &first_pending), (&second, &second_complete)] {
            assert_eq!(store.complete_head(origin).unwrap(), None);
            assert_eq!(store.pending_head(origin).unwrap().as_ref(), Some(expected));
            assert_eq!(
                store
                    .head(origin, Slot::Pending)
                    .unwrap()
                    .unwrap()
                    .received_at,
                at(20)
            );
        }
    }

    #[test]
    fn malformed_scope_change_rolls_back_the_scope_and_demotions() {
        let (_dir, store) = store();
        store.set_read_scope(Some(&["photos".to_string()])).unwrap();
        let before = store.local_scope().unwrap();
        let origin = crate::testutil::origin_named("malformed");
        let key = SecretKey::generate();
        {
            let conn = store.conn();
            conn.execute_batch(
                "CREATE TEMP TABLE heads (
                   origin_id, slot, seq, root, received_at, verified_at);
                 CREATE TEMP TABLE head_history (
                   origin_id, seq, root, created_at, signed_by, sig, recorded_at);",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO heads VALUES (?1, 'complete', 1, X'01', 0, 0)",
                params![origin.canonical()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO head_history VALUES (?1, 1, X'01', 0, ?2, zeroblob(64), 0)",
                params![origin.canonical(), key.public().as_bytes().to_vec()],
            )
            .unwrap();
        }

        assert!(store
            .set_read_scope_at(Some(&["finance".to_string()]), at(30))
            .is_err());
        assert_eq!(store.local_scope().unwrap(), before);
        assert!(store.conn().is_autocommit());
    }

    fn binding(origin: OriginId, key: NodeId, expires: Option<i64>) -> Binding {
        Binding {
            origin,
            node_id: key,
            source: if expires.is_some() {
                BindingSource::Dns
            } else {
                BindingSource::Static
            },
            domain: None,
            issuer: None,
            spaces: Vec::new(),
            read_only: Vec::new(),
            note: None,
            added_at: 0,
            expires_at: expires,
        }
    }

    /// A delegation of `spaces` from `issuer` to `subject`, live a millennium.
    fn delegation(subject: NodeId, issuer: OriginId, spaces: &[&str]) -> Binding {
        scoped_delegation(subject, issuer, spaces, &[])
    }

    /// As [`delegation`], with `read_only` granted read alone.
    fn scoped_delegation(
        subject: NodeId,
        issuer: OriginId,
        spaces: &[&str],
        read_only: &[&str],
    ) -> Binding {
        Binding {
            origin: OriginId::Key(subject),
            node_id: subject,
            source: BindingSource::Delegated,
            domain: None,
            issuer: Some(issuer),
            spaces: spaces.iter().map(|s| s.to_string()).collect(),
            read_only: read_only.iter().map(|s| s.to_string()).collect(),
            note: None,
            added_at: at(0),
            expires_at: Some(at(1000)),
        }
    }

    /// A read-only space is one grant with two answers (§3.5): the serve and
    /// content gates count it — the subject is served the space and fetches
    /// its bytes exactly as a read-write one — while the publication
    /// authority its own heads are judged by does not, so a key granted only
    /// read-only spaces is confined to none and still trusted.
    #[test]
    fn a_read_only_space_is_served_and_fetched_but_never_published() {
        let (_d, store) = store();
        let issuer_key = SecretKey::generate().public();
        let subject = SecretKey::generate().public();
        let issuer = OriginId::named("nas", "x.example").unwrap();
        store
            .put_binding(&binding(issuer.clone(), issuer_key, None))
            .unwrap();
        store
            .put_binding(&scoped_delegation(
                subject,
                issuer.clone(),
                &["photos"],
                &["docs"],
            ))
            .unwrap();
        let path = |bytes: &[u8]| synch_mpt::Nibbles::from_bytes(bytes).as_slice().to_vec();

        // Read: both spaces, in the trie served and in the content gate.
        let served = store.scope_for_key(&subject, at(10)).unwrap();
        assert!(served.prefixes().unwrap().contains(&path(b"f:docs/")));
        assert!(served.prefixes().unwrap().contains(&path(b"f:photos/")));
        assert!(served.exact().contains(&path(b"m:space/docs")));
        assert_eq!(
            store.publish_scope_of_key(&subject, at(10)).unwrap(),
            PublishScope::Confined(vec!["docs".to_string(), "photos".to_string()])
        );
        assert_eq!(
            store
                .socket_scope_for_key(&subject, at(10))
                .unwrap()
                .unwrap()
                .1,
            Some(vec!["docs".to_string(), "photos".to_string()])
        );

        // Publish: the read-write space alone, in the answer and in the keys
        // the promotion scope check walks.
        assert_eq!(
            store
                .publish_scope(&OriginId::Key(subject), at(10))
                .unwrap(),
            PublishScope::Confined(vec!["photos".to_string()])
        );
        let authority = store
            .transaction::<_, StoreError>(|tx| {
                tx.promotion_authority(&OriginId::Key(subject), at(10))
            })
            .unwrap();
        assert!(authority
            .trie_scope
            .prefixes()
            .unwrap()
            .contains(&path(b"f:photos/")));
        assert!(!authority
            .trie_scope
            .prefixes()
            .unwrap()
            .contains(&path(b"f:docs/")));
        assert!(!authority
            .trie_scope
            .exact()
            .contains(&path(b"m:space/docs")));
        // Replicating a read-only space is holding its content, which the
        // grant permits, so the claim that says so is publishable.
        assert!(authority.trie_scope.exact().contains(&path(b"r:docs")));

        // Read-only alone is still a live, confined binding — not "no
        // binding", which would refuse the `b:` ads the subject may publish.
        let reader = SecretKey::generate().public();
        store
            .put_binding(&scoped_delegation(reader, issuer, &[], &["docs"]))
            .unwrap();
        assert!(store.is_trusted_key(&reader, at(10)).unwrap());
        assert_eq!(
            store.publish_scope(&OriginId::Key(reader), at(10)).unwrap(),
            PublishScope::Confined(Vec::new())
        );
        assert_eq!(
            store.publish_scope_of_key(&reader, at(10)).unwrap(),
            PublishScope::Confined(vec!["docs".to_string()])
        );
    }

    /// Grants add across issuers (§3.5): a space one issuer grants read-only
    /// and another read-write is read-write, and the node's own view of what
    /// it may not publish into says so.
    #[test]
    fn a_read_write_grant_from_a_second_issuer_lifts_read_only() {
        let (_d, store) = store();
        let own = SecretKey::generate();
        store.set_self_origin(&OriginId::Key(own.public())).unwrap();
        store
            .add_device_key(&own, crate::KeyState::Active, 1)
            .unwrap();
        let nas = OriginId::named("nas", "x.example").unwrap();
        let vps = OriginId::named("vps", "x.example").unwrap();
        for issuer in [&nas, &vps] {
            store
                .put_binding(&binding(
                    issuer.clone(),
                    SecretKey::generate().public(),
                    None,
                ))
                .unwrap();
        }
        store
            .put_binding(&scoped_delegation(
                own.public(),
                nas.clone(),
                &["photos"],
                &["docs", "finance"],
            ))
            .unwrap();
        assert_eq!(
            store.own_grant(at(10)).unwrap(),
            Some(vec![
                "docs".to_string(),
                "finance".to_string(),
                "photos".to_string()
            ])
        );
        assert_eq!(
            store.own_read_only(at(10)).unwrap(),
            vec!["docs".to_string(), "finance".to_string()]
        );

        store
            .put_binding(&scoped_delegation(own.public(), vps, &["docs"], &[]))
            .unwrap();
        assert_eq!(
            store.own_read_only(at(10)).unwrap(),
            vec!["finance".to_string()],
            "a read-write grant from any issuer is read-write"
        );
        assert_eq!(
            store
                .publish_scope(&OriginId::Key(own.public()), at(10))
                .unwrap(),
            PublishScope::Confined(vec!["docs".to_string(), "photos".to_string()])
        );

        // Withdrawing the read-write issuer puts the space back to read-only.
        store.remove_origin_bindings(&nas).unwrap();
        assert_eq!(store.own_read_only(at(10)).unwrap(), Vec::<String>::new());
        assert_eq!(
            store.own_grant(at(10)).unwrap(),
            Some(vec!["docs".to_string()])
        );
    }

    #[test]
    fn promotion_uses_permission_changes_inside_its_transaction() {
        let (_d, store) = store();
        let issuer_key = SecretKey::generate().public();
        let issuer = OriginId::Key(issuer_key);
        let subject = SecretKey::generate().public();
        let origin = OriginId::Key(subject);
        store
            .put_binding(&binding(issuer.clone(), issuer_key, None))
            .unwrap();
        store
            .put_binding(&binding(origin.clone(), subject, None))
            .unwrap();
        store
            .put_binding(&delegation(subject, issuer.clone(), &["photos"]))
            .unwrap();
        assert_eq!(
            store.publish_scope(&origin, at(0)).unwrap(),
            PublishScope::Unrestricted
        );

        store
            .transaction::<_, StoreError>(|txn| {
                txn.remove_binding(&origin, &subject, BindingSource::Static)?;
                txn.set_config("local_scope", "photos")?;
                assert_eq!(
                    {
                        let authority = txn.promotion_authority(&origin, at(0))?;
                        (authority.publication, authority.provenance)
                    },
                    (
                        PublishScope::Confined(vec!["photos".into()]),
                        Some(origin.clone())
                    )
                );
                assert_eq!(
                    txn.materialization_scope(&origin)?,
                    Scope::of(&synch_core::ScopeKeys {
                        prefixes: vec![b"d:".to_vec(), b"f:photos/".to_vec()],
                        exact: vec![
                            b"m:self".to_vec(),
                            b"m:space/photos".to_vec(),
                            b"r:photos".to_vec()
                        ]
                    })
                );
                // Revoking the issuer in this same snapshot also revokes its
                // delegate, without waiting for a later binding sweep.
                txn.remove_binding(&issuer, &issuer_key, BindingSource::Static)?;
                assert_eq!(
                    {
                        let authority = txn.promotion_authority(&origin, at(0))?;
                        (authority.publication, authority.provenance)
                    },
                    (PublishScope::Untrusted, Some(origin.clone()))
                );
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn promotion_dates_authority_with_its_transaction_clock_floor() {
        let (_d, store) = store();
        let issuer_key = SecretKey::generate().public();
        let issuer = OriginId::Key(issuer_key);
        let subject = SecretKey::generate().public();
        let origin = OriginId::Key(subject);
        store
            .put_binding(&binding(issuer.clone(), issuer_key, Some(at(10))))
            .unwrap();
        store
            .put_binding(&delegation(subject, issuer, &["photos"]))
            .unwrap();
        assert!(matches!(
            store.publish_scope(&origin, at(0)).unwrap(),
            PublishScope::Confined(_)
        ));
        store
            .transaction::<_, StoreError>(|txn| {
                txn.set_config("trust_clock_floor", &at(10).to_string())?;
                assert_eq!(
                    {
                        let authority = txn.promotion_authority(&origin, at(0))?;
                        (authority.publication, authority.provenance)
                    },
                    (PublishScope::Untrusted, Some(origin.clone()))
                );
                // Being this node's own origin removes the provenance requirement,
                // but does not turn expired publishing authority into permission.
                txn.set_self_origin(&origin)?;
                assert_eq!(
                    {
                        let authority = txn.promotion_authority(&origin, at(0))?;
                        (authority.publication, authority.provenance)
                    },
                    (PublishScope::Untrusted, None)
                );
                assert_eq!(txn.materialization_scope(&origin)?, Scope::full());
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn static_bindings_never_expire() {
        let (_d, store) = store();
        let k1 = SecretKey::generate().public();
        let k2 = SecretKey::generate().public();
        let origin = OriginId::named("nas", "x.example").unwrap();
        store
            .put_binding(&binding(origin.clone(), k1, None))
            .unwrap();
        store
            .put_binding(&binding(OriginId::Key(k2), k2, None))
            .unwrap();

        assert!(store.is_bound(&origin, &k1, i64::MAX).unwrap());
        assert!(store.is_trusted_key(&k1, i64::MAX).unwrap());
        assert_eq!(store.expire_bindings(i64::MAX).unwrap(), 0);
        assert!(store.is_trusted_key(&k1, i64::MAX).unwrap());

        // Both queries see both static bindings, expiry sweep or not.
        assert_eq!(store.trusted_origins(at(0)).unwrap().len(), 2);
        assert_eq!(store.trusted_keys(at(0)).unwrap().len(), 2);
    }

    #[test]
    fn dns_bindings_expire() {
        let (_d, store) = store();
        let key = SecretKey::generate().public();
        let origin = OriginId::named("nas", "x.example").unwrap();
        store
            .put_binding(&binding(origin.clone(), key, Some(at(100))))
            .unwrap();

        assert!(store.is_bound(&origin, &key, at(50)).unwrap());
        assert!(!store.is_bound(&origin, &key, at(100)).unwrap());
        assert!(!store.is_trusted_key(&key, at(150)).unwrap());
        assert_eq!(store.expire_bindings(at(150)).unwrap(), 1);
        assert!(store.bindings().unwrap().is_empty());
    }

    /// M3: at the epoch no expiry has passed, so every stored binding reads
    /// live and nothing is ever reaped — an undatable clock has to withdraw
    /// DNS trust instead, leaving static trust alone.
    #[test]
    fn an_undatable_clock_honors_no_dns_binding_and_deletes_none() {
        let (_d, store) = store();
        let dns_key = SecretKey::generate().public();
        let static_key = SecretKey::generate().public();
        let origin = OriginId::named("nas", "x.example").unwrap();
        store
            .put_binding(&binding(origin.clone(), dns_key, Some(at(100))))
            .unwrap();
        store
            .put_binding(&binding(origin.clone(), static_key, None))
            .unwrap();

        for undatable in [0, MIN_TRUSTED_NS - 1] {
            assert!(
                !store.is_bound(&origin, &dns_key, undatable).unwrap(),
                "a dns binding must not be live at {undatable}"
            );
            assert!(!store.is_trusted_key(&dns_key, undatable).unwrap());
            assert!(store
                .keys_for_origin(&origin, undatable)
                .unwrap()
                .contains(&static_key));
            assert!(store.is_bound(&origin, &static_key, undatable).unwrap());
            assert_eq!(store.expire_bindings(undatable).unwrap(), 0);
        }
        // Both bindings are still on disk, so fixing the clock costs one
        // refresh rather than a domain re-resolution from nothing.
        assert_eq!(store.bindings().unwrap().len(), 2);
        assert!(store.is_bound(&origin, &dns_key, at(50)).unwrap());
    }

    /// The mirror image: an older instant reads as "before the expiry", so a
    /// restored snapshot would hand back lapsed trust — the persisted floor
    /// keeps trust time from running backwards.
    #[test]
    fn a_backwards_clock_step_cannot_revive_an_expired_binding() {
        let (_d, store) = store();
        let key = SecretKey::generate().public();
        let origin = OriginId::named("nas", "x.example").unwrap();
        store
            .put_binding(&binding(origin.clone(), key, Some(at(100))))
            .unwrap();
        store.advance_trust_floor(at(200)).unwrap();

        assert!(!store.is_bound(&origin, &key, at(50)).unwrap());
        assert!(!store.is_trusted_key(&key, at(50)).unwrap());
        assert!(store.live_origins_for_key(&key, at(50)).unwrap().is_empty());
        assert!(store.trusted_origins(at(50)).unwrap().is_empty());
        assert_eq!(store.expire_bindings(at(50)).unwrap(), 1);
    }

    #[test]
    fn rotation_window_binds_two_keys() {
        let (_d, store) = store();
        let old = SecretKey::generate().public();
        let new = SecretKey::generate().public();
        let origin = OriginId::named("nas", "x.example").unwrap();
        store
            .put_binding(&binding(origin.clone(), old, Some(at(100))))
            .unwrap();
        store
            .put_binding(&binding(origin.clone(), new, Some(at(200))))
            .unwrap();

        let keys = store.keys_for_origin(&origin, at(50)).unwrap();
        assert_eq!(keys.len(), 2);
        // After the old key's grace lapses, only the new key holds the origin.
        let keys = store.keys_for_origin(&origin, at(150)).unwrap();
        assert_eq!(keys, vec![new]);
        assert!(!store.is_bound(&origin, &old, at(150)).unwrap());
        assert!(store.is_bound(&origin, &new, at(150)).unwrap());
    }

    /// §3.2 malformed-set rule: the store surfaces the ambiguity rather than
    /// silently picking one origin.
    #[test]
    fn a_key_may_be_reported_under_two_origins() {
        let (_d, store) = store();
        let key = SecretKey::generate().public();
        let a = OriginId::named("nas", "x.example").unwrap();
        let b = OriginId::named("laptop", "x.example").unwrap();
        store.put_binding(&binding(a.clone(), key, None)).unwrap();
        store.put_binding(&binding(b.clone(), key, None)).unwrap();
        let mut origins = store.live_origins_for_key(&key, at(0)).unwrap();
        origins.sort();
        assert_eq!(origins, vec![b, a]);
    }

    #[test]
    fn dns_refresh_extends_expiry() {
        let (_d, store) = store();
        let key = SecretKey::generate().public();
        let origin = OriginId::named("nas", "x.example").unwrap();
        let mut b = binding(origin.clone(), key, Some(at(100)));
        b.domain = Some("x.example".into());
        store
            .refresh_dns_bindings("x.example", &[b.clone()])
            .unwrap();
        assert!(!store.is_bound(&origin, &key, at(150)).unwrap());

        b.expires_at = Some(at(500));
        store.refresh_dns_bindings("x.example", &[b]).unwrap();
        assert!(store.is_bound(&origin, &key, at(150)).unwrap());
        assert_eq!(store.bindings_for_origin(&origin).unwrap().len(), 1);
    }

    #[test]
    fn removal() {
        let (_d, store) = store();
        let key = SecretKey::generate().public();
        let origin = OriginId::named("nas", "x.example").unwrap();
        store
            .put_binding(&binding(origin.clone(), key, None))
            .unwrap();
        assert!(store
            .remove_binding(&origin, &key, BindingSource::Static)
            .unwrap());
        assert!(!store
            .remove_binding(&origin, &key, BindingSource::Static)
            .unwrap());

        store
            .put_binding(&binding(origin.clone(), key, None))
            .unwrap();
        assert_eq!(store.remove_origin_bindings(&origin).unwrap(), 1);
    }

    /// Derived trust cannot outlive its source (§3.5): every query routes
    /// through `live_bindings` so they all agree.
    #[test]
    fn a_delegation_dies_with_its_issuer() {
        let (_d, store) = store();
        let issuer_key = SecretKey::generate().public();
        let subject = SecretKey::generate().public();
        let issuer = OriginId::named("nas", "x.example").unwrap();
        store
            .put_binding(&binding(issuer.clone(), issuer_key, None))
            .unwrap();
        store
            .put_binding(&delegation(subject, issuer.clone(), &["photos"]))
            .unwrap();

        // While the issuer is rooted, the delegate is trusted and scoped.
        assert!(store.is_trusted_key(&subject, at(10)).unwrap());
        assert_eq!(
            store.publish_scope_of_key(&subject, at(10)).unwrap(),
            PublishScope::Confined(vec!["photos".to_string()])
        );
        assert!(!store.scope_for_key(&subject, at(10)).unwrap().is_full());

        // Remove the issuer's own binding and the delegation goes with it, in
        // the same instant, with nothing having rewritten the delegated row.
        store.remove_origin_bindings(&issuer).unwrap();
        assert!(!store.is_trusted_key(&subject, at(10)).unwrap());
        assert!(!store
            .is_bound(&OriginId::Key(subject), &subject, at(10))
            .unwrap());
        assert!(!store.trusted_keys(at(10)).unwrap().contains(&subject));
        assert!(store.delegations(at(10)).unwrap().is_empty());
        // The row is still there — it is derived from a trie and only a trie
        // may remove it — it simply is not live.
        assert_eq!(store.all_delegations().unwrap().len(), 1);
    }

    /// A delegation cannot be the source of another (§3.5): depth 2 fails on
    /// lookup because the named issuer holds no rooted binding.
    #[test]
    fn a_delegated_binding_is_never_rooted() {
        let (_d, store) = store();
        let first = SecretKey::generate().public();
        let second = SecretKey::generate().public();
        let delegate = OriginId::Key(first);
        store
            .put_binding(&delegation(
                first,
                OriginId::named("nas", "x.example").unwrap(),
                &["photos"],
            ))
            .unwrap();
        store
            .put_binding(&delegation(second, delegate, &["photos"]))
            .unwrap();
        assert!(!store.is_trusted_key(&second, at(10)).unwrap());
    }

    /// Real native projections report the exact identities that remain trusted
    /// after issuer expiration, including an undatable wall-clock reading.
    #[test]
    fn native_trust_projection_reports_expiry_and_issuer_revocation() {
        let (_d, store) = store();
        let rooted = OriginId::named("nas", "x.example").unwrap();
        let lapsing = OriginId::named("vps", "x.example").unwrap();
        let rooted_key = SecretKey::generate().public();
        let lapsing_key = SecretKey::generate().public();
        let statically = SecretKey::generate().public();
        let vouched = SecretKey::generate().public();
        let orphaned = SecretKey::generate().public();
        let issuerless = SecretKey::generate().public();

        store
            .put_binding(&binding(rooted.clone(), rooted_key, Some(at(1000))))
            .unwrap();
        store
            .put_binding(&binding(lapsing.clone(), lapsing_key, Some(at(100))))
            .unwrap();
        store
            .put_binding(&binding(
                OriginId::named("box", "x.example").unwrap(),
                statically,
                None,
            ))
            .unwrap();
        store
            .put_binding(&delegation(vouched, rooted, &["photos"]))
            .unwrap();
        store
            .put_binding(&delegation(orphaned, lapsing, &["docs"]))
            .unwrap();
        let mut no_issuer = delegation(issuerless, OriginId::Key(rooted_key), &["docs"]);
        no_issuer.issuer = None;
        store.put_binding(&no_issuer).unwrap();

        let nas = OriginId::named("nas", "x.example").unwrap();
        let vps = OriginId::named("vps", "x.example").unwrap();
        let box_origin = OriginId::named("box", "x.example").unwrap();
        for (now, mut keys, mut origins) in [
            (
                at(50),
                vec![rooted_key, lapsing_key, statically, vouched, orphaned],
                vec![
                    nas.clone(),
                    vps,
                    box_origin.clone(),
                    OriginId::Key(vouched),
                    OriginId::Key(orphaned),
                ],
            ),
            (
                at(500),
                vec![rooted_key, statically, vouched],
                vec![nas, box_origin.clone(), OriginId::Key(vouched)],
            ),
            (at(5000), vec![statically], vec![box_origin.clone()]),
            (0, vec![statically], vec![box_origin]),
        ] {
            keys.sort_by_key(|key| *key.as_bytes());
            origins.sort();
            assert_eq!(store.trusted_keys(now).unwrap(), keys, "keys at {now}");
            assert_eq!(
                store.trusted_origins(now).unwrap(),
                origins,
                "origins at {now}"
            );
        }
    }

    /// The delegate-to-delegate rule (§5.5), and the cascade under it.
    ///
    /// Untested until now, and the two reads it is built from were rewritten
    /// from whole-table scans into index seeks to stop one reactive push
    /// costing `O(peers × bindings)` (`docs/CLOUD-DATAPLANE.md` §7.1a). What
    /// has to survive that is every answer, so all five are asserted here —
    /// including the one the rewrite could most easily have lost, which is the
    /// cascade: a delegation whose issuer's own binding has lapsed makes this
    /// node nobody's delegate, and a node that is nobody's delegate refuses
    /// nobody.
    #[test]
    fn a_delegate_syncs_metadata_only_within_its_own_cluster() {
        let (_d, store) = store();
        let own = SecretKey::generate().public();
        store.set_self_origin(&OriginId::Key(own)).unwrap();

        let issuer = OriginId::named("nas", "x.example").unwrap();
        let issuer_key = SecretKey::generate().public();
        let sibling = OriginId::named("vps", "x.example").unwrap();
        let sibling_key = SecretKey::generate().public();
        let stranger = OriginId::named("nas", "other.example").unwrap();
        let stranger_key = SecretKey::generate().public();
        let untrusted = SecretKey::generate().public();
        for (origin, key) in [
            (&issuer, issuer_key),
            (&sibling, sibling_key),
            (&stranger, stranger_key),
        ] {
            store
                .put_binding(&binding(origin.clone(), key, Some(at(1000))))
                .unwrap();
        }

        // A node that is nobody's delegate is unrestricted, whoever it dials.
        // This is the case every hosted replica is in, and the one the dial
        // path pays for on every push.
        for peer in [&issuer_key, &stranger_key, &untrusted] {
            assert_eq!(store.refuse_metadata_sync(peer, at(10)).unwrap(), None);
        }

        // Now this node is `nas`'s delegate.
        store
            .put_binding(&delegation(own, issuer.clone(), &["photos"]))
            .unwrap();
        assert_eq!(store.own_issuers(at(10)).unwrap(), vec![issuer.clone()]);

        // Its own issuer, and a full member of the same cluster: both fine.
        assert_eq!(
            store.refuse_metadata_sync(&issuer_key, at(10)).unwrap(),
            None
        );
        assert_eq!(
            store.refuse_metadata_sync(&sibling_key, at(10)).unwrap(),
            None
        );
        // A full member of a *different* cluster, and a key bound to nothing:
        // both refused, for different stated reasons.
        assert!(store
            .refuse_metadata_sync(&stranger_key, at(10))
            .unwrap()
            .is_some_and(|why| why.contains("different cluster")));
        assert!(store
            .refuse_metadata_sync(&untrusted, at(10))
            .unwrap()
            .is_some_and(|why| why.contains("not a full member")));

        // The cascade: once `nas`'s own binding lapses, the delegation it
        // issued names nothing that vouches for it, so this node is nobody's
        // delegate again — and refuses nobody again, including the stranger it
        // refused a moment ago.
        assert!(store.own_issuers(at(2000)).unwrap().is_empty());
        assert_eq!(
            store.refuse_metadata_sync(&stranger_key, at(2000)).unwrap(),
            None
        );
    }

    /// Two rooted origins may each delegate the same key, and each vouches
    /// independently.
    #[test]
    fn delegations_from_two_issuers_add_and_are_removed_separately() {
        let (_d, store) = store();
        let subject = SecretKey::generate().public();
        let mut issuers = Vec::new();
        for (name, space) in [("nas", "photos"), ("vps", "docs")] {
            let key = SecretKey::generate().public();
            let origin = OriginId::named(name, "x.example").unwrap();
            store
                .put_binding(&binding(origin.clone(), key, None))
                .unwrap();
            store
                .put_binding(&delegation(subject, origin.clone(), &[space]))
                .unwrap();
            issuers.push(origin);
        }
        // Both statements stand: `issuer` is part of the row's identity, so
        // the second did not overwrite the first.
        assert_eq!(
            store.publish_scope_of_key(&subject, at(10)).unwrap(),
            PublishScope::Confined(vec!["docs".to_string(), "photos".to_string()])
        );
        // Withdrawing one leaves the other, rather than cutting the key off.
        store.remove_origin_bindings(&issuers[0]).unwrap();
        assert_eq!(
            store.publish_scope_of_key(&subject, at(10)).unwrap(),
            PublishScope::Confined(vec!["docs".to_string()])
        );
        assert!(store.is_trusted_key(&subject, at(10)).unwrap());
    }

    /// An undatable clock honors no delegation, exactly as it honors no DNS
    /// binding.
    #[test]
    fn a_delegation_needs_a_clock_that_can_date_it() {
        let (_d, store) = store();
        let issuer_key = SecretKey::generate().public();
        let subject = SecretKey::generate().public();
        let issuer = OriginId::named("nas", "x.example").unwrap();
        store
            .put_binding(&binding(issuer.clone(), issuer_key, None))
            .unwrap();
        store
            .put_binding(&delegation(subject, issuer, &["photos"]))
            .unwrap();
        assert!(store.is_trusted_key(&subject, at(10)).unwrap());
        // At the epoch nothing has expired, which is precisely why an instant
        // no build could produce must date nothing at all.
        assert!(!store.is_trusted_key(&subject, 0).unwrap());
        // Static trust consults no clock and is the escape hatch.
        assert!(store.is_trusted_key(&issuer_key, 0).unwrap());
    }

    /// The scope a node reads under is learned, and changing it is reported.
    #[test]
    fn the_local_read_scope_round_trips() {
        let (_d, store) = store();
        assert_eq!(store.local_scope().unwrap(), None);
        assert!(store.local_trie_scope().unwrap().is_full());

        assert!(store.set_read_scope(Some(&["photos".to_string()])).unwrap());
        assert!(!store.set_read_scope(Some(&["photos".to_string()])).unwrap());
        assert_eq!(
            store.local_scope().unwrap(),
            Some(vec!["photos".to_string()])
        );
        assert!(!store.local_trie_scope().unwrap().is_full());

        assert!(store.set_read_scope(None).unwrap());
        assert!(store.local_trie_scope().unwrap().is_full());
    }
}
