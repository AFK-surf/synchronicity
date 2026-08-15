//! Reading the unified tree (§8).
//!
//! One tree, per space, aggregated from every origin's published paths. The
//! stored and synced model is untouched: this is a read model over `entries`,
//! and nothing here can mutate another origin's assertions.
//!
//! Every read of a bare `<space>/<path>` has to pick one of the versions a path
//! carries, and does it by an explicit policy — `newest`, `origin=<id>`, or
//! `strict`. Selection is presentation, not resolution: the losing versions
//! stay first-class, individually addressable, and marked.

use synch_store::{EntryRow, Selection, VersionPolicy, VersionSet};

use crate::{
    error::{EngineError, Result},
    node::Node,
};

impl Node {
    /// Every version of one path, with its attestors (§8).
    pub fn versions(&self, space: &str, path: &str) -> Result<VersionSet> {
        Ok(self.store().versions_for(space, path)?)
    }

    /// The unified listing under a prefix: one row per path, each carrying its
    /// version count and whether it is divergent.
    pub fn unified_listing(
        &self,
        space: &str,
        prefix: &str,
        start_after: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<VersionSet>> {
        Ok(self
            .store()
            .unified_listing(space, prefix, start_after, limit)?)
    }

    /// Picks the version a policy selects for a path (§8).
    ///
    /// The single entry point every reading surface goes through — `cat`,
    /// `get`, mirrors, the S3 gateway — so that they cannot disagree about what
    /// a policy means.
    pub fn resolve(&self, space: &str, path: &str, policy: &VersionPolicy) -> Result<EntryRow> {
        let set = self.versions(space, path)?;
        self.resolve_set(&set, policy)
    }

    /// The same selection against a version set already in hand, so a listing
    /// pass does not re-query per path.
    pub fn resolve_set(&self, set: &VersionSet, policy: &VersionPolicy) -> Result<EntryRow> {
        match set.select(policy) {
            Selection::Selected(entry) => Ok(*entry),
            Selection::Absent => Err(EngineError::not_found(reference_of(
                policy, &set.space, &set.path,
            ))),
            Selection::Divergent => Err(EngineError::Divergent {
                space: set.space.clone(),
                path: set.path.clone(),
                versions: set.describe(),
            }),
        }
    }
}

/// How a path reads back under a policy: origin-pinned reads name the origin,
/// unified ones do not.
pub fn reference_of(policy: &VersionPolicy, space: &str, path: &str) -> String {
    match policy.pinned_origin() {
        Some(origin) => format!("{origin}:{space}/{path}"),
        None => format!("{space}/{path}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use synch_core::{FileEntry, Hash, OriginId};

    async fn node() -> (tempfile::TempDir, Node) {
        let dir = tempfile::tempdir().unwrap();
        Node::init(dir.path(), None).unwrap();
        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        (dir, node)
    }

    fn origin(name: &str) -> OriginId {
        OriginId::named(name, "x.example").unwrap()
    }

    #[tokio::test]
    async fn resolve_applies_each_policy() {
        let (_d, node) = node().await;
        node.store()
            .put_entry(
                &origin("nas"),
                "media",
                "f",
                &FileEntry::file(1, 500, Hash::new(b"theirs"), 2),
            )
            .unwrap();
        node.store()
            .put_entry(
                &origin("laptop"),
                "media",
                "f",
                &FileEntry::file(1, 100, Hash::new(b"ours"), 1),
            )
            .unwrap();

        assert_eq!(
            node.resolve("media", "f", &VersionPolicy::Newest)
                .unwrap()
                .origin,
            origin("nas")
        );
        assert_eq!(
            node.resolve("media", "f", &VersionPolicy::Origin(origin("laptop")))
                .unwrap()
                .content,
            Some(Hash::new(b"ours"))
        );
        let err = node
            .resolve("media", "f", &VersionPolicy::Strict)
            .unwrap_err();
        assert!(matches!(err, EngineError::Divergent { .. }));
        let text = err.to_string();
        assert!(text.contains("nas@x.example"), "{text}");
        assert!(text.contains("laptop@x.example"), "{text}");

        // An absent path names itself the way the policy addresses it.
        let err = node
            .resolve("media", "absent", &VersionPolicy::Newest)
            .unwrap_err();
        assert!(err.to_string().contains("media/absent"), "{err}");
        let err = node
            .resolve("media", "absent", &VersionPolicy::Origin(origin("nas")))
            .unwrap_err();
        assert!(
            err.to_string().contains("nas@x.example:media/absent"),
            "{err}"
        );
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn the_listing_marks_divergence() {
        let (_d, node) = node().await;
        for (name, content) in [("nas", b"a"), ("laptop", b"b")] {
            node.store()
                .put_entry(
                    &origin(name),
                    "media",
                    "split",
                    &FileEntry::file(1, 0, Hash::new(content), 1),
                )
                .unwrap();
        }
        node.store()
            .put_entry(
                &origin("nas"),
                "media",
                "agreed",
                &FileEntry::file(1, 0, Hash::new(b"same"), 1),
            )
            .unwrap();

        let listing = node.unified_listing("media", "", None, None).unwrap();
        assert_eq!(listing.len(), 2, "one row per path");
        let split = listing.iter().find(|s| s.path == "split").unwrap();
        assert_eq!(split.version_count(), 2);
        assert!(split.is_divergent());
        let agreed = listing.iter().find(|s| s.path == "agreed").unwrap();
        assert!(!agreed.is_divergent());
        node.shutdown().await.unwrap();
    }
}
