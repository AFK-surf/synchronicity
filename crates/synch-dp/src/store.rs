//! The service's own object-store client.
//!
//! The CAS is not written through here — each tenant's node owns its own
//! OpenDAL operator rooted at its own prefix, exactly as a serverless daemon
//! does (`docs/SERVERLESS.md` §6), and the database replica streams are the
//! replication library's own client. This is for what neither of those
//! writes: the fail-static desired-state cache (§4.2) and the offboarding
//! sweep (§6).
//!
//! # Encryption at rest is not this layer's business
//!
//! Objects are written as they are. A tenant's database stream carries its
//! device secret key and wants protecting, but the place to protect it is the
//! bucket — SSE-KMS, a customer-managed key, whatever the deployment already
//! runs for everything else it keeps there. An envelope invented here would be
//! one more key to rotate, escrow and lose, buying nothing the storage layer
//! does not already do better.

use std::collections::BTreeSet;

use crate::error::Result;

/// A handle on the service's bucket.
#[derive(Clone)]
pub struct ObjectStore {
    operator: opendal::Operator,
}

impl std::fmt::Debug for ObjectStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the operator's options — they carry credentials
        // (`synch_store::cloud::CloudConfig` makes the same choice, for the
        // same reason).
        f.debug_struct("ObjectStore").finish()
    }
}

impl ObjectStore {
    /// Wraps an operator.
    pub fn new(operator: opendal::Operator) -> Self {
        Self { operator }
    }

    /// An in-memory store, for tests.
    ///
    /// Not `cfg(test)`: the crate's own integration tests are a separate build
    /// and reach this the way any embedder would.
    pub fn memory() -> Result<Self> {
        let operator = opendal::Operator::from_config(opendal::services::MemoryConfig::default())?;
        Ok(Self::new(operator))
    }

    /// Writes an object.
    pub async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<()> {
        self.operator.write(key, bytes).await?;
        Ok(())
    }

    /// Reads an object, or `None` when it is not there.
    pub async fn get_if_present(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match self.operator.read(key).await {
            Ok(buffer) => Ok(Some(buffer.to_vec())),
            Err(error) if error.kind() == opendal::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
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
    /// common prefixes of a delimited listing.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_object_round_trips() {
        let store = ObjectStore::memory().unwrap();
        store
            .put("dp/0/desired.json", b"{}".to_vec())
            .await
            .unwrap();
        let back = store.get_if_present("dp/0/desired.json").await.unwrap();
        assert_eq!(back.as_deref(), Some(&b"{}"[..]));
    }

    /// Absence is not an error: a cold start reads the fail-static cache
    /// before anything has written one (§4.2).
    #[tokio::test]
    async fn a_missing_object_is_not_an_error() {
        let store = ObjectStore::memory().unwrap();
        assert!(store
            .get_if_present("dp/0/desired.json")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn a_prefix_sweep_removes_everything_under_it() {
        let store = ObjectStore::memory().unwrap();
        store
            .put("tenants/acme/prod/cas/aa/x", vec![1])
            .await
            .unwrap();
        store
            .put("tenants/acme/prod/cas/bb/y", vec![2])
            .await
            .unwrap();
        store
            .put("tenants/other/prod/cas/aa/z", vec![3])
            .await
            .unwrap();
        store.remove_prefix("tenants/acme/prod/").await.unwrap();
        assert!(store
            .list_dirs("tenants/acme/prod/")
            .await
            .unwrap()
            .is_empty());
        // And only under it: offboarding one tenant must not touch another.
        assert_eq!(
            store.list_dirs("tenants/other/prod/cas/").await.unwrap(),
            vec!["aa".to_string()]
        );
    }
}
