//! The object store the data plane writes to, and the envelope it writes the
//! database stream in.
//!
//! The CAS is not written through here — each tenant's node owns its own
//! OpenDAL operator rooted at its own prefix, exactly as a serverless daemon
//! does (`docs/SERVERLESS.md` §6). This is the *service's* own client, for the
//! two things no node writes: the database replica streams (§5.3) and the
//! fail-static desired-state cache (§4.2).
//!
//! # Why the database stream is sealed
//!
//! A tenant's database carries its device secret key. The CAS prefix beside it
//! carries content, which the hosting service can read by construction — that
//! is what hosting a replica means, and `docs/CLOUD-DATAPLANE.md` §9 says so
//! plainly. Identities are a different matter: read access to the bucket
//! should not be the ability to *become* a tenant's node. So the database
//! stream is sealed with a key that lives in the environment rather than in
//! the bucket, which is the "protect it separately from the CAS prefix" rule
//! of `docs/SERVERLESS.md` §1 discharged without a second bucket.
//!
//! The seal binds the object's own key as associated data, so a sealed object
//! cannot be moved to another key — swapping one tenant's snapshot for
//! another's, or an old segment for a newer one, fails to open rather than
//! silently restoring the wrong database.

use std::collections::BTreeSet;
use std::sync::Arc;

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};

use crate::error::{DpError, Result};

/// A handle on the service's bucket.
#[derive(Clone)]
pub struct ObjectStore {
    operator: opendal::Operator,
    seal: Option<Arc<LessSafeKey>>,
}

impl std::fmt::Debug for ObjectStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key, and never the operator's options — they carry
        // credentials (`synch_store::cloud::CloudConfig` makes the same
        // choice, for the same reason).
        f.debug_struct("ObjectStore")
            .field("sealed", &self.seal.is_some())
            .finish()
    }
}

impl ObjectStore {
    /// Wraps an operator, sealing writes with `key` when one is given.
    pub fn new(operator: opendal::Operator, key: Option<[u8; 32]>) -> Result<Self> {
        let seal = match key {
            Some(bytes) => {
                let unbound = UnboundKey::new(&AES_256_GCM, &bytes).map_err(|_| DpError::Crypto)?;
                Some(Arc::new(LessSafeKey::new(unbound)))
            }
            None => None,
        };
        Ok(Self { operator, seal })
    }

    /// An in-memory store that seals, for tests that need the real envelope.
    ///
    /// Not `cfg(test)`: the crate's own integration tests are a separate
    /// build and reach this the way any embedder would.
    pub fn memory_sealed() -> Result<Self> {
        let operator = opendal::Operator::from_config(opendal::services::MemoryConfig::default())?;
        Self::new(operator, Some([7u8; 32]))
    }

    /// An in-memory store, for tests.
    #[cfg(test)]
    pub fn memory() -> Result<Self> {
        let operator = opendal::Operator::from_config(opendal::services::MemoryConfig::default())?;
        Self::new(operator, None)
    }

    /// Writes an object, sealing it when this store seals.
    pub async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<()> {
        let body = match &self.seal {
            Some(seal) => self.seal_bytes(seal, key, bytes)?,
            None => bytes,
        };
        self.operator.write(key, body).await?;
        Ok(())
    }

    /// Reads an object, or `None` when it is not there.
    pub async fn get_if_present(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let bytes = match self.operator.read(key).await {
            Ok(buffer) => buffer.to_vec(),
            Err(error) if error.kind() == opendal::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        match &self.seal {
            Some(seal) => self.open_bytes(seal, key, bytes).map(Some),
            None => Ok(Some(bytes)),
        }
    }

    /// Every object key directly under `prefix`.
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let entries = match self.operator.list(prefix).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == opendal::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        Ok(entries
            .into_iter()
            .map(|entry| entry.path().to_string())
            .filter(|path| !path.ends_with('/'))
            .collect())
    }

    /// Every directory name directly under `prefix`.
    ///
    /// Object stores have no directories; OpenDAL synthesizes them from the
    /// common prefixes of a delimited listing, which is exactly what a
    /// generation listing needs.
    pub async fn list_dirs(&self, prefix: &str) -> Result<Vec<String>> {
        let entries = match self.operator.list(prefix).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == opendal::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut names = BTreeSet::new();
        for entry in entries {
            let path = entry.path();
            if let Some(rest) = path.strip_prefix(prefix) {
                let name = rest.trim_end_matches('/');
                if !name.is_empty() && !name.contains('/') {
                    names.insert(name.to_string());
                }
            }
        }
        Ok(names.into_iter().collect())
    }

    /// Removes every object under `prefix`. Used only at offboarding (§6).
    pub async fn remove_prefix(&self, prefix: &str) -> Result<()> {
        self.operator.delete_with(prefix).recursive(true).await?;
        Ok(())
    }

    fn seal_bytes(&self, seal: &LessSafeKey, key: &str, mut bytes: Vec<u8>) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        aws_lc_rs::rand::fill(&mut nonce).map_err(|_| DpError::Crypto)?;
        seal.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(key.as_bytes()),
            &mut bytes,
        )
        .map_err(|_| DpError::Crypto)?;
        let mut out = Vec::with_capacity(NONCE_LEN + bytes.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&bytes);
        Ok(out)
    }

    fn open_bytes(&self, seal: &LessSafeKey, key: &str, bytes: Vec<u8>) -> Result<Vec<u8>> {
        if bytes.len() < NONCE_LEN {
            return Err(DpError::Crypto);
        }
        let (nonce, body) = bytes.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| DpError::Crypto)?;
        let mut body = body.to_vec();
        let plain = seal
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(key.as_bytes()),
                &mut body,
            )
            .map_err(|_| DpError::Crypto)?;
        Ok(plain.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed() -> ObjectStore {
        let operator =
            opendal::Operator::from_config(opendal::services::MemoryConfig::default()).unwrap();
        ObjectStore::new(operator, Some([7u8; 32])).unwrap()
    }

    #[tokio::test]
    async fn a_sealed_object_round_trips() {
        let store = sealed();
        store
            .put("db/a/b/snapshot", b"secret".to_vec())
            .await
            .unwrap();
        let back = store.get_if_present("db/a/b/snapshot").await.unwrap();
        assert_eq!(back.as_deref(), Some(&b"secret"[..]));
    }

    /// The property the associated data buys: an object cannot be moved.
    #[tokio::test]
    async fn a_sealed_object_will_not_open_under_another_key() {
        let store = sealed();
        store
            .put("db/a/b/snapshot", b"secret".to_vec())
            .await
            .unwrap();
        let raw = store
            .operator
            .read("db/a/b/snapshot")
            .await
            .unwrap()
            .to_vec();
        // Put the very same bytes where a different tenant's snapshot goes.
        store
            .operator
            .write("db/other/b/snapshot", raw)
            .await
            .unwrap();
        let error = store
            .get_if_present("db/other/b/snapshot")
            .await
            .unwrap_err();
        assert!(matches!(error, DpError::Crypto), "{error}");
    }

    #[tokio::test]
    async fn a_sealed_object_is_not_plaintext_at_rest() {
        let store = sealed();
        store
            .put("db/a/b/snapshot", b"secret".to_vec())
            .await
            .unwrap();
        let raw = store
            .operator
            .read("db/a/b/snapshot")
            .await
            .unwrap()
            .to_vec();
        assert!(
            !raw.windows(6).any(|window| window == b"secret"),
            "the plaintext should not be readable in the stored object"
        );
    }

    #[tokio::test]
    async fn listing_directories_names_each_generation_once() {
        let store = ObjectStore::memory().unwrap();
        store.put("db/a/b/g1/snapshot", vec![1]).await.unwrap();
        store
            .put("db/a/b/g1/wal/00000000.0.1", vec![1])
            .await
            .unwrap();
        store.put("db/a/b/g2/snapshot", vec![1]).await.unwrap();
        let dirs = store.list_dirs("db/a/b/").await.unwrap();
        assert_eq!(dirs, vec!["g1".to_string(), "g2".to_string()]);
    }
}
