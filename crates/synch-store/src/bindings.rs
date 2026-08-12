//! The bindings table: `OriginId → device key`, with source and validity (§3.1).
//!
//! Every trust check and every head verification goes through here — nothing in
//! the durable data model references a bare device key as an identity.

use rusqlite::params;
use synch_core::{NodeId, OriginId};

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
}

impl BindingSource {
    /// The `source` column value.
    pub fn as_str(self) -> &'static str {
        match self {
            BindingSource::Static => "static",
            BindingSource::Dns => "dns",
        }
    }

    /// Parses the `source` column value.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "static" => Ok(BindingSource::Static),
            "dns" => Ok(BindingSource::Dns),
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
    /// A user note, for static bindings.
    pub note: Option<String>,
    /// When the binding was added, in unix nanoseconds.
    pub added_at: i64,
    /// When the binding expires, in unix nanoseconds. `None` for static.
    pub expires_at: Option<i64>,
}

impl Binding {
    /// True if the binding is live at `now`.
    pub fn is_live(&self, now: i64) -> bool {
        match self.expires_at {
            None => true,
            Some(expiry) => now < expiry,
        }
    }
}

impl Store {
    /// Inserts or refreshes a binding.
    pub fn put_binding(&self, binding: &Binding) -> Result<()> {
        self.conn().execute(
            "INSERT INTO bindings (origin_id, node_id, source, domain, note, added_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(origin_id, node_id, source) DO UPDATE SET
               domain = excluded.domain,
               note = COALESCE(excluded.note, bindings.note),
               expires_at = excluded.expires_at",
            params![
                binding.origin.canonical(),
                binding.node_id.as_bytes().to_vec(),
                binding.source.as_str(),
                binding.domain,
                binding.note,
                binding.added_at,
                binding.expires_at,
            ],
        )?;
        Ok(())
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
            "SELECT origin_id, node_id, source, domain, note, added_at, expires_at
             FROM bindings {filter} ORDER BY origin_id, added_at"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(args, |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Option<i64>>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (origin, node_id, source, domain, note, added_at, expires_at) = row?;
            out.push(Binding {
                origin: origin_column(origin, "bindings.origin_id")?,
                node_id: key_column(node_id, "bindings.node_id")?,
                source: BindingSource::parse(&source)?,
                domain,
                note,
                added_at,
                expires_at,
            });
        }
        Ok(out)
    }

    /// The origins a device key is currently bound to.
    ///
    /// A key may hold several origins only in malformed configurations; §3.2
    /// asks `synch doctor` to report exactly that, so this returns all of them.
    pub fn live_origins_for_key(&self, node_id: &NodeId, now: i64) -> Result<Vec<OriginId>> {
        Ok(self
            .bindings_for_key(node_id)?
            .into_iter()
            .filter(|b| b.is_live(now))
            .map(|b| b.origin)
            .collect())
    }

    /// True if `node_id` is currently bound to `origin`.
    ///
    /// This is the second half of head validity (§4.4): a signature that
    /// verifies under an unbound key is not a valid head.
    pub fn is_bound(&self, origin: &OriginId, node_id: &NodeId, now: i64) -> Result<bool> {
        Ok(self
            .bindings_for_origin(origin)?
            .into_iter()
            .any(|b| &b.node_id == node_id && b.is_live(now)))
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
            .bindings()?
            .into_iter()
            .filter(|b| b.is_live(now))
            .map(|b| b.origin)
            .collect();
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Every device key with at least one live binding, for dialing.
    pub fn trusted_keys(&self, now: i64) -> Result<Vec<NodeId>> {
        let mut out: Vec<NodeId> = self
            .bindings()?
            .into_iter()
            .filter(|b| b.is_live(now))
            .map(|b| b.node_id)
            .collect();
        out.sort_by_key(|k| *k.as_bytes());
        out.dedup();
        Ok(out)
    }

    /// The live device keys currently bound to an origin, for dialing (§3.3).
    pub fn keys_for_origin(&self, origin: &OriginId, now: i64) -> Result<Vec<NodeId>> {
        Ok(self
            .bindings_for_origin(origin)?
            .into_iter()
            .filter(|b| b.is_live(now))
            .map(|b| b.node_id)
            .collect())
    }

    /// Replaces the whole DNS binding set for one domain, in one transaction.
    ///
    /// Bindings that disappear from DNS are *not* deleted here: they keep their
    /// existing expiry so they lapse after `dns_trust_grace` rather than being
    /// yanked on a single propagation glitch (§3.2).
    pub fn refresh_dns_bindings(&self, domain: &str, bindings: &[Binding]) -> Result<()> {
        self.transaction(|tx| {
            for binding in bindings {
                tx.execute(
                    "INSERT INTO bindings (origin_id, node_id, source, domain, note, added_at, expires_at)
                     VALUES (?1, ?2, 'dns', ?3, NULL, ?4, ?5)
                     ON CONFLICT(origin_id, node_id, source) DO UPDATE SET
                       domain = excluded.domain,
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
    pub fn expire_bindings(&self, now: i64) -> Result<usize> {
        Ok(self.conn().execute(
            "DELETE FROM bindings WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now],
        )?)
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;

    use super::*;

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
            .put_binding(&binding(origin.clone(), key, Some(100)))
            .unwrap();

        assert!(store.is_bound(&origin, &key, 50).unwrap());
        assert!(!store.is_bound(&origin, &key, 100).unwrap());
        assert!(!store.is_trusted_key(&key, 150).unwrap());
        assert_eq!(store.expire_bindings(150).unwrap(), 1);
        assert!(store.bindings().unwrap().is_empty());
    }

    #[test]
    fn unknown_keys_are_untrusted() {
        let (_d, store) = store();
        let key = SecretKey::generate().public();
        assert!(!store.is_trusted_key(&key, 0).unwrap());
        let origin = OriginId::named("nas", "x.example").unwrap();
        assert!(!store.is_bound(&origin, &key, 0).unwrap());
    }

    #[test]
    fn rotation_window_binds_two_keys() {
        let (_d, store) = store();
        let old = SecretKey::generate().public();
        let new = SecretKey::generate().public();
        let origin = OriginId::named("nas", "x.example").unwrap();
        store
            .put_binding(&binding(origin.clone(), old, Some(100)))
            .unwrap();
        store
            .put_binding(&binding(origin.clone(), new, Some(200)))
            .unwrap();

        let keys = store.keys_for_origin(&origin, 50).unwrap();
        assert_eq!(keys.len(), 2);
        // After the old key's record is dropped and its grace lapses, only the
        // new key holds the origin — and no replicated state changed.
        let keys = store.keys_for_origin(&origin, 150).unwrap();
        assert_eq!(keys, vec![new]);
        assert!(!store.is_bound(&origin, &old, 150).unwrap());
        assert!(store.is_bound(&origin, &new, 150).unwrap());
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
        let mut origins = store.live_origins_for_key(&key, 0).unwrap();
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
            .put_binding(&binding(origin.clone(), key, Some(10)))
            .unwrap();
        assert_eq!(store.bindings_for_origin(&origin).unwrap().len(), 2);
        // The static one keeps the origin alive after the DNS one lapses.
        store.expire_bindings(100).unwrap();
        assert!(store.is_bound(&origin, &key, 100).unwrap());
    }

    #[test]
    fn dns_refresh_extends_expiry() {
        let (_d, store) = store();
        let key = SecretKey::generate().public();
        let origin = OriginId::named("nas", "x.example").unwrap();
        let mut b = binding(origin.clone(), key, Some(100));
        b.domain = Some("x.example".into());
        store
            .refresh_dns_bindings("x.example", &[b.clone()])
            .unwrap();
        assert!(!store.is_bound(&origin, &key, 150).unwrap());

        b.expires_at = Some(500);
        store.refresh_dns_bindings("x.example", &[b]).unwrap();
        assert!(store.is_bound(&origin, &key, 150).unwrap());
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
        assert_eq!(store.trusted_origins(0).unwrap().len(), 2);
        assert_eq!(store.trusted_keys(0).unwrap().len(), 2);
    }
}
