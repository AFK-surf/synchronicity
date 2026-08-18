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
    /// The read scope this node is confined to, inside the transaction.
    ///
    /// Promotion reads it to scope the materialization diff the same way the
    /// fetch that filled the trie was scoped (§8).
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

    /// Materializes one `d:` leaf into a delegated binding, inside the
    /// transaction that is promoting the issuer's head.
    ///
    /// Part of the same write as the head flip and the `entries` delta, for
    /// the reason §5.2 gives about materialization generally: a crash between
    /// them would leave this node's trust table disagreeing with the trie it
    /// is derived from.
    pub fn put_delegation(
        &self,
        issuer: &OriginId,
        subject: &NodeId,
        delegation: &synch_core::Delegation,
        now: i64,
    ) -> Result<()> {
        put_binding_in(
            self.conn(),
            &Binding {
                origin: OriginId::Key(*subject),
                node_id: *subject,
                source: BindingSource::Delegated,
                domain: None,
                issuer: Some(issuer.clone()),
                spaces: delegation.spaces.clone(),
                note: delegation.note.clone(),
                added_at: now,
                expires_at: Some(delegation.not_after),
            },
        )
    }

    /// Drops the delegated binding one issuer made for one subject.
    ///
    /// Revocation is deletion: the `d:` key vanishes from the issuer's next
    /// root, the diff surfaces it here, and the binding goes with it. Only
    /// this issuer's row is touched — another origin's delegation of the same
    /// key is a separate statement and stands.
    pub fn remove_delegation(&self, issuer: &OriginId, subject: &NodeId) -> Result<bool> {
        let n = self.conn().execute(
            "DELETE FROM bindings WHERE origin_id = ?1 AND node_id = ?2
               AND source = 'delegated' AND issuer = ?3",
            params![
                OriginId::Key(*subject).canonical(),
                subject.as_bytes().to_vec(),
                issuer.canonical()
            ],
        )?;
        Ok(n > 0)
    }

    /// Drops every delegation an issuer has made, for when its whole trie goes.
    pub fn remove_delegations_by(&self, issuer: &OriginId) -> Result<usize> {
        Ok(self.conn().execute(
            "DELETE FROM bindings WHERE source = 'delegated' AND issuer = ?1",
            params![issuer.canonical()],
        )?)
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

    /// What part of the keyspace a peer may be served (§8).
    ///
    /// [`Scope::full`] whenever the key holds any live *rooted* binding — a
    /// rooted member is unrestricted by construction — and otherwise the union
    /// of the space lists every live delegation of that key carries. Two
    /// rooted origins may each delegate the same key, and each vouches
    /// independently, so their grants add rather than conflict.
    ///
    /// A key with no live binding at all gets a scope that admits nothing.
    /// It will have been refused at accept long before this is asked, and a
    /// scope is the wrong place to discover it.
    pub fn scope_for_key(&self, node_id: &NodeId, now: i64) -> Result<Scope> {
        let live: Vec<Binding> = self
            .live_bindings(now)?
            .into_iter()
            .filter(|b| &b.node_id == node_id)
            .collect();
        if live.iter().any(|b| b.is_rooted()) {
            return Ok(Scope::full());
        }
        let mut spaces: Vec<String> = live.into_iter().flat_map(|b| b.spaces).collect();
        spaces.sort();
        spaces.dedup();
        Ok(Scope::of(&synch_core::scope_prefixes(&spaces)))
    }

    /// The spaces a device key is confined to, or `None` when the key holds a
    /// rooted binding and is confined to nothing.
    ///
    /// The content half of scope (§7): object roots carry no space, so a
    /// delegated peer's entitlement to bytes is decided against this list.
    pub fn publish_scope_of_key(&self, node_id: &NodeId, now: i64) -> Result<Option<Vec<String>>> {
        let live: Vec<Binding> = self
            .live_bindings(now)?
            .into_iter()
            .filter(|b| &b.node_id == node_id)
            .collect();
        if live.iter().any(|b| b.is_rooted()) {
            return Ok(None);
        }
        let mut spaces: Vec<String> = live.into_iter().flat_map(|b| b.spaces).collect();
        spaces.sort();
        spaces.dedup();
        Ok(Some(spaces))
    }

    /// The spaces a delegated origin may publish into, or `None` when the
    /// origin is rooted and may publish anything.
    ///
    /// This is the publish-scope question (§7), asked of the *origin* whose
    /// trie is being materialized rather than of a connection's peer key.
    pub fn publish_scope(&self, origin: &OriginId, now: i64) -> Result<Option<Vec<String>>> {
        let live: Vec<Binding> = self
            .live_bindings(now)?
            .into_iter()
            .filter(|b| &b.origin == origin)
            .collect();
        if live.is_empty() || live.iter().any(|b| b.is_rooted()) {
            return Ok(None);
        }
        let mut spaces: Vec<String> = live.into_iter().flat_map(|b| b.spaces).collect();
        spaces.sort();
        spaces.dedup();
        Ok(Some(spaces))
    }

    /// The scope this node itself may read, as last declared by a peer (§8).
    ///
    /// `None` — the default — is the whole keyspace. A delegated node cannot
    /// derive this locally before it has synced anything: its scope lives in
    /// the delegating origin's trie, which it needs the scope to read. So the
    /// value is learned from the `Hello` of whichever peer is serving it, and
    /// held here because the fetch walk, promotion and the head summaries all
    /// have to agree about it.
    ///
    /// Adopting a peer's word costs nothing: every responder enforces the same
    /// scope on every request independently, so a wrong value can only make
    /// this node ask for less than it is entitled to.
    pub fn local_scope(&self) -> Result<Option<Vec<String>>> {
        Ok(self.config("local_scope")?.map(|text| decode_spaces(&text)))
    }

    /// Records the scope a peer declared, when it differs from what is held.
    ///
    /// Returns true if the value changed, which is the caller's cue that
    /// anything derived from the old scope — a memoized completeness answer
    /// above all — is now answering the wrong question.
    pub fn set_local_scope(&self, scope: Option<&[String]>) -> Result<bool> {
        let current = self.local_scope()?;
        let next = scope.map(|s| s.to_vec());
        if current == next {
            return Ok(false);
        }
        match next {
            None => self.clear_config("local_scope")?,
            Some(spaces) => self.set_config("local_scope", &encode_spaces(&spaces))?,
        }
        Ok(true)
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
                    // binds `OriginId::Key(nk)`, which names no domain, so two
                    // membership domains publishing one key used to write one
                    // row and the last writer owned its `domain` column. It
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
        Ok(self.conn().execute(
            "DELETE FROM bindings WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now],
        )?)
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;
    use synch_core::MIN_TRUSTED_NS;

    use super::*;

    /// A trustworthy instant, `secs` seconds into the trusted era.
    ///
    /// Expiries are compared against a clock, and a clock reading below
    /// [`MIN_TRUSTED_NS`] dates nothing (see [`crate::clock`]) — so a test that
    /// wants a binding to be live has to say when.
    fn at(secs: i64) -> i64 {
        MIN_TRUSTED_NS + secs * 1_000_000_000
    }

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        (dir, store)
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

    #[test]
    fn static_bindings_never_expire() {
        let (_d, store) = store();
        let key = SecretKey::generate().public();
        let origin = OriginId::named("nas", "x.example").unwrap();
        store
            .put_binding(&binding(origin.clone(), key, None))
            .unwrap();

        assert!(store.is_bound(&origin, &key, i64::MAX).unwrap());
        assert!(store.is_trusted_key(&key, i64::MAX).unwrap());
        assert_eq!(store.expire_bindings(i64::MAX).unwrap(), 0);
        assert!(store.is_trusted_key(&key, i64::MAX).unwrap());
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

    #[test]
    fn an_undatable_clock_honors_no_dns_binding_and_deletes_none() {
        // M3: `is_live` is `now < expires_at` and `expire_bindings` deletes on
        // `expires_at <= now`, so at the epoch every binding this node ever
        // stored reads as live and nothing is ever reaped — a NAS with a dead
        // RTC trusting revoked members forever. A reading that dates nothing
        // has to withdraw DNS trust instead, while leaving static trust (which
        // consults no clock) alone.
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

        for undatable in [0, -1, MIN_TRUSTED_NS - 1] {
            assert!(
                !store.is_bound(&origin, &dns_key, undatable).unwrap(),
                "a dns binding must not be live at {undatable}"
            );
            assert!(!store.is_trusted_key(&dns_key, undatable).unwrap());
            assert!(!store.trusted_keys(undatable).unwrap().contains(&dns_key));
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

    #[test]
    fn a_backwards_clock_step_cannot_revive_an_expired_binding() {
        // The mirror image: the same comparison reads an older instant as
        // "before the expiry", so a bad NTP step or a restored snapshot would
        // hand back trust that had already lapsed. The persisted floor is what
        // makes trust time stand still rather than run backwards.
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
    fn unknown_keys_are_untrusted() {
        let (_d, store) = store();
        let key = SecretKey::generate().public();
        assert!(!store.is_trusted_key(&key, at(0)).unwrap());
        let origin = OriginId::named("nas", "x.example").unwrap();
        assert!(!store.is_bound(&origin, &key, at(0)).unwrap());
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
        // After the old key's record is dropped and its grace lapses, only the
        // new key holds the origin — and no replicated state changed.
        let keys = store.keys_for_origin(&origin, at(150)).unwrap();
        assert_eq!(keys, vec![new]);
        assert!(!store.is_bound(&origin, &old, at(150)).unwrap());
        assert!(store.is_bound(&origin, &new, at(150)).unwrap());
    }

    #[test]
    fn a_key_may_be_reported_under_two_origins() {
        // §3.2 malformed-set rule: the store must surface the ambiguity rather
        // than silently pick one.
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
    fn static_and_dns_bindings_coexist() {
        let (_d, store) = store();
        let key = SecretKey::generate().public();
        let origin = OriginId::named("nas", "x.example").unwrap();
        store
            .put_binding(&binding(origin.clone(), key, None))
            .unwrap();
        store
            .put_binding(&binding(origin.clone(), key, Some(at(10))))
            .unwrap();
        assert_eq!(store.bindings_for_origin(&origin).unwrap().len(), 2);
        // The static one keeps the origin alive after the DNS one lapses.
        store.expire_bindings(at(100)).unwrap();
        assert!(store.is_bound(&origin, &key, at(100)).unwrap());
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

    #[test]
    fn trusted_sets() {
        let (_d, store) = store();
        let k1 = SecretKey::generate().public();
        let k2 = SecretKey::generate().public();
        let a = OriginId::named("a", "x.example").unwrap();
        let b = OriginId::Key(k2);
        store.put_binding(&binding(a.clone(), k1, None)).unwrap();
        store.put_binding(&binding(b.clone(), k2, None)).unwrap();
        assert_eq!(store.trusted_origins(at(0)).unwrap().len(), 2);
        assert_eq!(store.trusted_keys(at(0)).unwrap().len(), 2);
    }
    /// Derived trust cannot outlive its source (§3.5).
    ///
    /// The hole this guards is invisible when it opens: a delegate whose
    /// issuer has been removed keeps syncing, and nothing says why. Every
    /// query has to agree about it, which is why they all route through
    /// `live_bindings`.
    #[test]
    fn a_delegation_dies_with_its_issuer() {
        let (_dir, store) = store();
        let issuer_key = SecretKey::generate().public();
        let subject = SecretKey::generate().public();
        let issuer = OriginId::named("nas", "x.example").unwrap();
        store
            .put_binding(&binding(issuer.clone(), issuer_key, None))
            .unwrap();
        store
            .put_binding(&Binding {
                origin: OriginId::Key(subject),
                node_id: subject,
                source: BindingSource::Delegated,
                domain: None,
                issuer: Some(issuer.clone()),
                spaces: vec!["photos".into()],
                note: None,
                added_at: at(0),
                expires_at: Some(at(1000)),
            })
            .unwrap();

        // While the issuer is rooted, the delegate is trusted and scoped.
        assert!(store.is_trusted_key(&subject, at(10)).unwrap());
        assert_eq!(
            store.publish_scope_of_key(&subject, at(10)).unwrap(),
            Some(vec!["photos".to_string()])
        );
        assert!(!store.scope_for_key(&subject, at(10)).unwrap().is_full());

        // Remove the issuer's own binding and the delegation goes with it, in
        // the same instant, with nothing having rewritten the delegated row.
        store.remove_origin_bindings(&issuer).unwrap();
        assert!(!store.is_trusted_key(&subject, at(10)).unwrap());
        assert!(store
            .is_bound(&OriginId::Key(subject), &subject, at(10))
            .is_ok());
        assert!(!store
            .is_bound(&OriginId::Key(subject), &subject, at(10))
            .unwrap());
        assert!(!store.trusted_keys(at(10)).unwrap().contains(&subject));
        assert!(store.delegations(at(10)).unwrap().is_empty());
        // The row is still there — it is derived from a trie and only a trie
        // may remove it — it simply is not live.
        assert_eq!(store.all_delegations().unwrap().len(), 1);
    }

    /// A delegation cannot be the source of another (§3.5).
    #[test]
    fn a_delegated_binding_is_never_rooted() {
        let (_dir, store) = store();
        let first = SecretKey::generate().public();
        let second = SecretKey::generate().public();
        let delegate = OriginId::Key(first);
        store
            .put_binding(&Binding {
                origin: delegate.clone(),
                node_id: first,
                source: BindingSource::Delegated,
                domain: None,
                issuer: Some(OriginId::named("nas", "x.example").unwrap()),
                spaces: vec!["photos".into()],
                note: None,
                added_at: at(0),
                expires_at: Some(at(1000)),
            })
            .unwrap();
        // A delegation naming a delegate as its issuer is honored by nobody,
        // because the issuer holds no rooted binding — depth 2 fails on a
        // lookup rather than on anything the publisher asserted.
        store
            .put_binding(&Binding {
                origin: OriginId::Key(second),
                node_id: second,
                source: BindingSource::Delegated,
                domain: None,
                issuer: Some(delegate),
                spaces: vec!["photos".into()],
                note: None,
                added_at: at(0),
                expires_at: Some(at(1000)),
            })
            .unwrap();
        assert!(!BindingSource::Delegated.is_rooted());
        assert!(!store.is_trusted_key(&second, at(10)).unwrap());
    }

    /// Two rooted origins may each delegate the same key, and each vouches
    /// independently.
    #[test]
    fn delegations_from_two_issuers_add_and_are_removed_separately() {
        let (_dir, store) = store();
        let subject = SecretKey::generate().public();
        let mut issuers = Vec::new();
        for (name, space) in [("nas", "photos"), ("vps", "docs")] {
            let key = SecretKey::generate().public();
            let origin = OriginId::named(name, "x.example").unwrap();
            store
                .put_binding(&binding(origin.clone(), key, None))
                .unwrap();
            store
                .put_binding(&Binding {
                    origin: OriginId::Key(subject),
                    node_id: subject,
                    source: BindingSource::Delegated,
                    domain: None,
                    issuer: Some(origin.clone()),
                    spaces: vec![space.to_string()],
                    note: None,
                    added_at: at(0),
                    expires_at: Some(at(1000)),
                })
                .unwrap();
            issuers.push(origin);
        }
        // Both statements stand: `issuer` is part of the row's identity, so
        // the second did not overwrite the first.
        assert_eq!(
            store.publish_scope_of_key(&subject, at(10)).unwrap(),
            Some(vec!["docs".to_string(), "photos".to_string()])
        );
        // Withdrawing one leaves the other, rather than cutting the key off.
        store.remove_origin_bindings(&issuers[0]).unwrap();
        assert_eq!(
            store.publish_scope_of_key(&subject, at(10)).unwrap(),
            Some(vec!["docs".to_string()])
        );
        assert!(store.is_trusted_key(&subject, at(10)).unwrap());
    }

    /// An undatable clock honors no delegation, exactly as it honors no DNS
    /// binding.
    #[test]
    fn a_delegation_needs_a_clock_that_can_date_it() {
        let (_dir, store) = store();
        let issuer_key = SecretKey::generate().public();
        let subject = SecretKey::generate().public();
        let issuer = OriginId::named("nas", "x.example").unwrap();
        store
            .put_binding(&binding(issuer.clone(), issuer_key, None))
            .unwrap();
        store
            .put_binding(&Binding {
                origin: OriginId::Key(subject),
                node_id: subject,
                source: BindingSource::Delegated,
                domain: None,
                issuer: Some(issuer),
                spaces: vec!["photos".into()],
                note: None,
                added_at: at(0),
                expires_at: Some(at(1000)),
            })
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
        let (_dir, store) = store();
        assert_eq!(store.local_scope().unwrap(), None);
        assert!(store.local_trie_scope().unwrap().is_full());

        assert!(store
            .set_local_scope(Some(&["photos".to_string()]))
            .unwrap());
        assert!(!store
            .set_local_scope(Some(&["photos".to_string()]))
            .unwrap());
        assert_eq!(
            store.local_scope().unwrap(),
            Some(vec!["photos".to_string()])
        );
        assert!(!store.local_trie_scope().unwrap().is_full());

        assert!(store.set_local_scope(None).unwrap());
        assert!(store.local_trie_scope().unwrap().is_full());
    }
}
