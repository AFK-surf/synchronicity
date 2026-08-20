//! The bindings table: `OriginId → device key`, with source and validity (§3.1).
//!
//! Every trust check and every head verification goes through here — nothing in
//! the durable data model references a bare device key as an identity.

use rusqlite::{params, OptionalExtension};
use synch_core::{NodeId, OriginId};
use synch_mpt::Scope;

use crate::{
    db::{key_column, origin_column, Store},
    error::{Result, StoreError},
};

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
    /// claim — see [`BindingSource::is_rooted`].
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

    /// True if trust from this source is rooted in this node's own operator or
    /// in a DNSSEC-validated zone, rather than derived from another origin.
    ///
    /// Only a rooted binding qualifies its holder to delegate (§3.5). Because
    /// a delegation only ever produces a `Delegated` binding, a delegate's own
    /// `d:` records are read by nobody, and depth 2 fails on a lookup here
    /// rather than on anything a publisher could assert.
    pub fn is_rooted(self) -> bool {
        match self {
            BindingSource::Static | BindingSource::Dns => true,
            BindingSource::Delegated => false,
        }
    }

    /// Parses the `source` column value.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "static" => Ok(BindingSource::Static),
            "dns" => Ok(BindingSource::Dns),
            "delegated" => Ok(BindingSource::Delegated),
            other => Err(StoreError::column("bindings.source", other)),
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
    /// The spaces a delegated binding covers (§3.5).
    pub spaces: Vec<String>,
    /// A user note, for static bindings.
    pub note: Option<String>,
    /// When the binding was added, in unix nanoseconds.
    pub added_at: i64,
    /// When the binding expires, in unix nanoseconds. `None` for static.
    pub expires_at: Option<i64>,
}

impl Binding {
    /// True if the binding is live at `now`.
    ///
    /// An expiring binding is live only when `now` is an instant a trust
    /// decision may be dated by ([`synch_core::clock_is_trusted`], and see
    /// [`crate::clock`]): `now < expires_at` is satisfied by every expiry in
    /// the table when `now` is the epoch, so a node whose clock cannot be
    /// trusted must read as holding no DNS trust rather than as holding all of
    /// it. Static bindings consult no clock and are unaffected.
    pub fn is_live(&self, now: i64) -> bool {
        match self.expires_at {
            None => true,
            Some(expiry) => synch_core::clock_is_trusted(now) && now < expiry,
        }
    }

    /// True if this binding is rooted in configuration rather than derived
    /// from another origin's word.
    pub fn is_rooted(&self) -> bool {
        self.source.is_rooted()
    }
}

/// Renders a delegated binding's space list for the `spaces` column.
///
/// Newline-separated: `validate_space` forbids control characters, so no valid
/// id can contain the separator and no escaping is needed.
pub(crate) fn encode_spaces(spaces: &[String]) -> String {
    spaces.join("\n")
}

/// Reads the `spaces` column back, dropping anything that is not a valid id.
pub(crate) fn decode_spaces(text: &str) -> Vec<String> {
    text.split('\n')
        .filter(|s| synch_core::validate_space(s).is_ok())
        .map(str::to_string)
        .collect()
}

/// Inserts or refreshes a binding on whichever connection is handed in.
fn put_binding_in(conn: &rusqlite::Connection, binding: &Binding) -> Result<()> {
    conn.execute(
        "INSERT INTO bindings (origin_id, node_id, source, domain, issuer, spaces, note, added_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(origin_id, node_id, source, domain, issuer) DO UPDATE SET
           spaces = excluded.spaces,
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
            match binding.spaces.is_empty() {
                true => None,
                false => Some(encode_spaces(&binding.spaces)),
            },
            binding.note,
            binding.added_at,
            binding.expires_at,
        ],
    )?;
    Ok(())
}

impl crate::db::Txn<'_> {
    /// The scope one origin's leaves may be materialized under, inside the
    /// transaction.
    ///
    /// [`Store::materialization_scope`]: the read scope for a foreign origin,
    /// and always the whole keyspace for this node's own, whose trie it built
    /// and therefore holds whole.
    pub fn materialization_scope(&self, origin: &OriginId) -> Result<Scope> {
        let own: Option<String> = self
            .conn()
            .query_row(
                "SELECT value FROM config WHERE key = 'self_origin_id'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if own.as_deref() == Some(origin.canonical().as_str()) {
            return Ok(Scope::full());
        }
        self.local_trie_scope()
    }

    /// The read scope this node is confined to, inside the transaction.
    ///
    /// Promotion reads it to scope the materialization diff the same way the
    /// fetch that filled the trie was scoped (§5.5).
    pub fn local_trie_scope(&self) -> Result<Scope> {
        let text: Option<String> = self
            .conn()
            .query_row(
                "SELECT value FROM config WHERE key = ?1",
                rusqlite::params!["local_scope"],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match text.as_deref() {
            None => Scope::full(),
            Some(text) => Scope::of(&synch_core::scope_prefixes(&decode_spaces(text))),
        })
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
        self.query_bindings("", params![])
    }

    /// Every binding for one origin.
    pub fn bindings_for_origin(&self, origin: &OriginId) -> Result<Vec<Binding>> {
        self.query_bindings("WHERE origin_id = ?1", params![origin.canonical()])
    }

    /// Every binding that names a device key.
    pub fn bindings_for_key(&self, node_id: &NodeId) -> Result<Vec<Binding>> {
        self.query_bindings("WHERE node_id = ?1", params![node_id.as_bytes().to_vec()])
    }

    fn query_bindings(&self, filter: &str, args: impl rusqlite::Params) -> Result<Vec<Binding>> {
        let conn = self.conn();
        let sql = format!(
            "SELECT origin_id, node_id, source, domain, issuer, spaces, note, added_at, expires_at
             FROM bindings {filter} ORDER BY origin_id, added_at"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(args, |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<i64>>(8)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (origin, node_id, source, domain, issuer, spaces, note, added_at, expires_at) =
                row?;
            let issuer = match issuer.is_empty() {
                true => None,
                false => Some(origin_column(issuer, "bindings.issuer")?),
            };
            // Newline-separated, which is unambiguous because
            // `validate_space` forbids control characters — and an entry that
            // is not a valid space id is dropped rather than kept, since this
            // column feeds an authorization decision and the fail-closed
            // reading is the only safe one.
            let spaces: Vec<String> = spaces.map(|text| decode_spaces(&text)).unwrap_or_default();
            out.push(Binding {
                origin: origin_column(origin, "bindings.origin_id")?,
                node_id: key_column(node_id, "bindings.node_id")?,
                source: BindingSource::parse(&source)?,
                // '' is how the column spells "no domain": it is part of the
                // key, and SQLite admits no expression in a PRIMARY KEY.
                domain: domain.filter(|d: &String| !d.is_empty()),
                issuer,
                spaces,
                note,
                added_at,
                expires_at,
            });
        }
        Ok(out)
    }

    /// Every binding that is live at `now`, cascade included.
    ///
    /// The single place liveness is decided, because a delegated binding
    /// cannot answer for itself: [`Binding::is_live`] dates it, but whether it
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
        let now = self.trust_instant(now)?;
        let all = self.bindings()?;
        let rooted: std::collections::HashSet<String> = all
            .iter()
            .filter(|b| b.is_rooted() && b.is_live(now))
            .map(|b| b.origin.canonical())
            .collect();
        Ok(all
            .into_iter()
            .filter(|b| b.is_live(now))
            .filter(|b| match (&b.source, &b.issuer) {
                (BindingSource::Delegated, Some(issuer)) => rooted.contains(&issuer.canonical()),
                // A delegated row with no issuer names nothing that could have
                // vouched for it, so nothing has.
                (BindingSource::Delegated, None) => false,
                _ => true,
            })
            .collect())
    }

    /// The origins a device key is currently bound to.
    ///
    /// A key may hold several origins only in malformed configurations; §3.2
    /// asks `synch doctor` to report exactly that, so this returns all of them.
    pub fn live_origins_for_key(&self, node_id: &NodeId, now: i64) -> Result<Vec<OriginId>> {
        Ok(self
            .live_bindings(now)?
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
        Ok(self
            .live_bindings(now)?
            .into_iter()
            .any(|b| &b.origin == origin && &b.node_id == node_id))
    }

    /// True if a device key has *any* live binding.
    ///
    /// This is the connection-accept gate (§3.2): connections from device keys
    /// with no live binding are closed immediately after the QUIC handshake.
    pub fn is_trusted_key(&self, node_id: &NodeId, now: i64) -> Result<bool> {
        Ok(!self.live_origins_for_key(node_id, now)?.is_empty())
    }

    /// Every origin with at least one live binding.
    pub fn trusted_origins(&self, now: i64) -> Result<Vec<OriginId>> {
        let mut out: Vec<OriginId> = self
            .live_bindings(now)?
            .into_iter()
            .map(|b| b.origin)
            .collect();
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Every device key with at least one live binding, for dialing.
    pub fn trusted_keys(&self, now: i64) -> Result<Vec<NodeId>> {
        let mut out: Vec<NodeId> = self
            .live_bindings(now)?
            .into_iter()
            .map(|b| b.node_id)
            .collect();
        out.sort_by_key(|k| *k.as_bytes());
        out.dedup();
        Ok(out)
    }

    /// The live device keys currently bound to an origin, for dialing (§3.3).
    pub fn keys_for_origin(&self, origin: &OriginId, now: i64) -> Result<Vec<NodeId>> {
        Ok(self
            .live_bindings(now)?
            .into_iter()
            .filter(|b| &b.origin == origin)
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
        let live: Vec<Binding> = self
            .live_bindings(now)?
            .into_iter()
            .filter(|b| &b.node_id == node_id)
            .collect();
        let origins: Vec<OriginId> = live.iter().map(|b| b.origin.clone()).collect();
        if live.iter().any(|b| b.is_rooted()) {
            return Ok((Scope::full(), origins));
        }
        let mut spaces: Vec<String> = live.into_iter().flat_map(|b| b.spaces).collect();
        spaces.sort();
        spaces.dedup();
        Ok((Scope::of(&synch_core::scope_prefixes(&spaces)), origins))
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
        let live: Vec<Binding> = self
            .live_bindings(now)?
            .into_iter()
            .filter(|b| &b.node_id == node_id)
            .collect();
        let origins: Vec<OriginId> = live.iter().map(|b| b.origin.clone()).collect();
        // Three-valued for the same reason [`Store::publish_scope`] is. A key
        // with no live binding is distinct from a delegated peer whose grant
        // covers no spaces.
        //
        // Both readings are wrong somewhere. Answering the content gate, the
        // empty list happened to fail closed and was right by luck. Answering
        // "what scope should you read under", it is a live member being told to
        // narrow its view to nothing — which it then remembers, and which stops
        // it materializing every foreign origin it holds.
        if live.is_empty() {
            return Ok((PublishScope::Untrusted, origins));
        }
        // A delegation outranks a local `trust add`, and the order matters.
        //
        // A `d:` record is the cluster's statement about a key, replicated to
        // every member and read identically by all of them; a rooted binding is
        // one operator's local configuration. Letting the local one win made
        // two members of the same cluster answer this question differently for
        // the same key, and since this is what a responder declares in its
        // `Hello`, the delegate reading those declarations flipped between them
        // once per anti-entropy round.
        //
        // Deciding it from the record every member holds makes the answer agree
        // cluster-wide, and it fails closed. Promoting a delegate is therefore
        // revoking its delegation, not rooting its key beside a record that
        // still confines it.
        let delegated: Vec<String> = live
            .iter()
            .filter(|b| b.source == BindingSource::Delegated)
            .flat_map(|b| b.spaces.clone())
            .collect();
        if !delegated.is_empty() {
            let mut spaces = delegated;
            spaces.sort();
            spaces.dedup();
            return Ok((PublishScope::Confined(spaces), origins));
        }
        if live.iter().any(|b| b.is_rooted()) {
            return Ok((PublishScope::Unrestricted, origins));
        }
        let mut spaces: Vec<String> = live.into_iter().flat_map(|b| b.spaces).collect();
        spaces.sort();
        spaces.dedup();
        Ok((PublishScope::Confined(spaces), origins))
    }

    /// The spaces a delegated origin may publish into, or `None` when the
    /// origin is rooted and may publish anything.
    ///
    /// This is the publish-scope question (§3.5), asked of the *origin* whose
    /// trie is being materialized rather than of a connection's peer key.
    pub fn publish_scope(&self, origin: &OriginId, now: i64) -> Result<PublishScope> {
        let live: Vec<Binding> = self
            .live_bindings(now)?
            .into_iter()
            .filter(|b| &b.origin == origin)
            .collect();
        if live.is_empty() {
            return Ok(PublishScope::Untrusted);
        }
        if live.iter().any(|b| b.is_rooted()) {
            return Ok(PublishScope::Unrestricted);
        }
        let mut spaces: Vec<String> = live.into_iter().flat_map(|b| b.spaces).collect();
        spaces.sort();
        spaces.dedup();
        Ok(PublishScope::Confined(spaces))
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
        Ok(self.config("local_scope")?.map(|text| decode_spaces(&text)))
    }

    /// The origins that have delegated to *this* node (§3.5); empty if it is
    /// not a delegate.
    ///
    /// A delegation names a device key, so this matches every key that is this
    /// node's — its origin's, and every `device_keys` row, because a record
    /// naming a key mid-rotation still confines the node holding it.
    pub fn own_issuers(&self, now: i64) -> Result<Vec<OriginId>> {
        let own: Vec<NodeId> = self
            .self_origin()?
            .as_ref()
            .and_then(|o| o.as_key().copied())
            .into_iter()
            .chain(self.device_keys()?.into_iter().map(|k| k.node_id))
            .collect();
        Ok(self
            .live_bindings(now)?
            .into_iter()
            .filter(|b| b.source == BindingSource::Delegated && own.contains(&b.node_id))
            .filter_map(|b| b.issuer)
            .collect())
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
    pub fn refuse_metadata_sync(&self, peer: &NodeId, now: i64) -> Result<Option<String>> {
        let live = self.live_bindings(now)?;
        // The clusters this node is a delegate of. Empty means it is not a
        // delegate at all, and none of this applies to it.
        let issuers = self.own_issuers(now)?;
        if issuers.is_empty() {
            return Ok(None);
        }
        // A peer is a full member exactly where this node holds a *rooted*
        // binding for it: a delegate's binding is `Delegated` by construction,
        // so this one test is the whole of the delegate-to-delegate rule.
        let member_origins: Vec<&OriginId> = live
            .iter()
            .filter(|b| &b.node_id == peer && b.is_rooted())
            .map(|b| &b.origin)
            .collect();
        if member_origins.is_empty() {
            return Ok(Some(
                "this node is a delegate and that peer is not a full member of its cluster".into(),
            ));
        }
        let same_cluster = member_origins.iter().any(|origin| {
            issuers.iter().any(|issuer| {
                *origin == issuer
                    || (origin.domain().is_some() && origin.domain() == issuer.domain())
            })
        });
        match same_cluster {
            true => Ok(None),
            false => Ok(Some(
                "this node is a delegate and that peer belongs to a different cluster".into(),
            )),
        }
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
        let current = self.local_scope()?;
        let next = spaces.map(|s| s.to_vec());
        if current == next {
            return Ok(false);
        }
        // All of it in one transaction, so a crash cannot leave the new scope
        // beside the old scope's rows, its boundaries, or its heads.
        self.transaction(|txn| {
            match &next {
                None => txn.clear_config("local_scope")?,
                Some(spaces) => txn.set_config("local_scope", &encode_spaces(spaces))?,
            }
            // A boundary records where a walk *stopped*, which is a fact about
            // a scope and not about a node: widen the grant and the same node
            // stands at the same position, still marked as a boundary, so the
            // walk skips a subtree this node is now entitled to and
            // `is_complete_scoped` answers complete for a trie it does not
            // hold. Dropped whole rather than re-keyed; one round re-learns any
            // that still stand.
            txn.clear_redacted()?;
            let own: Option<String> = txn
                .conn()
                .query_row(
                    "SELECT value FROM config WHERE key = 'self_origin_id'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            for stored in txn.all_heads(crate::heads::Slot::Complete)? {
                let origin = &stored.head.origin;
                if own.as_deref() == Some(origin.canonical().as_str()) {
                    continue;
                }
                txn.delete_origin_entries(origin)?;
                txn.delete_origin_providers(origin)?;
                txn.delete_origin_delegations(origin)?;
                // Back to pending rather than deleted: the head is still a
                // signed statement this node verified, and demoting it is
                // exactly the claim that changed — this node no longer holds
                // the trie under it, because "holds it whole" is a question
                // about a scope and the scope just moved.
                txn.put_head(
                    crate::heads::Slot::Pending,
                    &stored.head,
                    stored.received_at,
                    stored.verified_at,
                )?;
                txn.clear_head(origin, crate::heads::Slot::Complete)?;
            }
            Ok(true)
        })
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
        match self.self_origin()?.as_ref() == Some(origin) {
            true => Ok(Scope::full()),
            false => self.local_trie_scope(),
        }
    }

    /// True if this store holds any delegation row at all.
    ///
    /// One indexed existence check, for hot paths that would otherwise read the
    /// whole bindings table to discover that nothing is delegated.
    pub fn has_delegations(&self) -> Result<bool> {
        Ok(self.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM bindings WHERE source = 'delegated')",
            [],
            |row| row.get::<_, i64>(0),
        )? == 1)
    }

    /// The read scope as the trie walk wants it.
    pub fn local_trie_scope(&self) -> Result<Scope> {
        Ok(match self.local_scope()? {
            None => Scope::full(),
            Some(spaces) => Scope::of(&synch_core::scope_prefixes(&spaces)),
        })
    }

    /// Every live delegation, for `delegate ls` and `doctor`.
    pub fn delegations(&self, now: i64) -> Result<Vec<Binding>> {
        Ok(self
            .live_bindings(now)?
            .into_iter()
            .filter(|b| b.source == BindingSource::Delegated)
            .collect())
    }

    /// Every delegation row, live or not, for reporting what has lapsed.
    pub fn all_delegations(&self) -> Result<Vec<Binding>> {
        Ok(self
            .bindings()?
            .into_iter()
            .filter(|b| b.source == BindingSource::Delegated)
            .collect())
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
    /// [`crate::clock`]): [`Binding::is_live`] has already stopped honoring
    /// every DNS binding on such a node, so trust is withdrawn without the
    /// deletion, and a clock that gets fixed costs one refresh rather than a
    /// re-resolution of every domain from nothing.
    pub fn expire_bindings(&self, now: i64) -> Result<usize> {
        let now = self.trust_instant(now)?;
        if !synch_core::clock_is_trusted(now) {
            return Ok(0);
        }
        // DNS rows only. A delegated row is a *materialized view* of a `d:`
        // leaf, and materialization only ever applies deltas — so a row
        // deleted out of band here never comes back, because the leaf it was
        // derived from has not changed. A forward clock skew would silently
        // and permanently drop trust the issuer never withdrew. DNS rows are
        // re-inserted by the refresh loop, which is what makes deleting them
        // safe; nothing re-derives these. They stop counting the instant they
        // date-lapse, and go when the record that made them does.
        Ok(self.conn().execute(
            "DELETE FROM bindings
             WHERE source = 'dns' AND expires_at IS NOT NULL AND expires_at <= ?1",
            params![now],
        )?)
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;
    use synch_core::MIN_TRUSTED_NS;

    use super::*;
    use crate::testutil::store;

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
        store.set_read_scope(Some(&["photos".to_string()])).unwrap();
        store.note_redacted(&withheld).unwrap();
        assert!(store.is_redacted(&withheld).unwrap());

        // Re-declaring the same scope changes nothing, so the boundary stands.
        assert!(!store.set_read_scope(Some(&["photos".to_string()])).unwrap());
        assert!(store.is_redacted(&withheld).unwrap());

        // Widening it does. The same node now sits at a position this node is
        // entitled to, and a boundary left over from the narrow grant would
        // make the walk skip it forever — reporting a trie complete that it
        // does not hold, with nothing to notice.
        assert!(store
            .set_read_scope(Some(&["photos".to_string(), "finance".to_string()]))
            .unwrap());
        assert!(
            !store.is_redacted(&withheld).unwrap(),
            "a boundary outlived the scope that drew it"
        );
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
            note: None,
            added_at: 0,
            expires_at: expires,
        }
    }

    /// A delegation of `spaces` from `issuer` to `subject`, live a millennium.
    fn delegation(subject: NodeId, issuer: OriginId, spaces: &[&str]) -> Binding {
        Binding {
            origin: OriginId::Key(subject),
            node_id: subject,
            source: BindingSource::Delegated,
            domain: None,
            issuer: Some(issuer),
            spaces: spaces.iter().map(|s| s.to_string()).collect(),
            note: None,
            added_at: at(0),
            expires_at: Some(at(1000)),
        }
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
        assert!(!BindingSource::Delegated.is_rooted());
        assert!(!store.is_trusted_key(&second, at(10)).unwrap());
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
