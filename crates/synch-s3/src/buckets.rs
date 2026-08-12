//! Bucket mapping: a bucket names a *view* — `<origin>:<space>` (§9.4).
//!
//! Buckets whose origin is the local node are writable; foreign-origin buckets
//! are read-only, because the version model forbids publishing someone else's
//! view (§8).

use std::str::FromStr;

use synch_core::OriginId;
use synch_engine::{EntryRef, Node};

use crate::error::{S3Error, S3Result};

/// The config key holding the bucket map.
const BUCKETS_CONFIG: &str = "s3_buckets";

/// One bucket's mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bucket {
    /// The bucket name.
    pub name: String,
    /// The origin whose published view the bucket serves.
    pub origin: OriginId,
    /// The space within that origin.
    pub space: String,
}

impl Bucket {
    /// True if the bucket maps to the local node's own view, and so is writable.
    pub fn writable_by(&self, node: &Node) -> bool {
        &self.origin == node.origin()
    }
}

/// Validates a bucket name against the S3 naming rules we enforce.
pub fn validate_name(name: &str) -> S3Result<()> {
    let ok = (3..=63).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && !name.starts_with(['-', '.'])
        && !name.ends_with(['-', '.']);
    if ok {
        Ok(())
    } else {
        Err(S3Error::invalid(format!(
            "invalid bucket name {name:?}: 3-63 characters of [a-z0-9.-], \
             not starting or ending with '-' or '.'"
        )))
    }
}

/// Reads the configured buckets.
pub fn load(node: &Node) -> S3Result<Vec<Bucket>> {
    let Some(text) = node.store().config(BUCKETS_CONFIG)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split('\t');
        let (Some(name), Some(origin), Some(space)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let Ok(origin) = OriginId::from_str(origin) else {
            continue;
        };
        out.push(Bucket {
            name: name.to_string(),
            origin,
            space: space.to_string(),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Looks one bucket up.
pub fn find(node: &Node, name: &str) -> S3Result<Bucket> {
    load(node)?
        .into_iter()
        .find(|b| b.name == name)
        .ok_or_else(|| S3Error::no_such_bucket(name))
}

/// Adds or replaces a bucket mapping from an `<origin>:<space>` reference.
pub fn add(node: &Node, name: &str, reference: &str) -> S3Result<Bucket> {
    validate_name(name)?;
    let reference: EntryRef = reference
        .parse()
        .map_err(|e: synch_engine::EngineError| S3Error::invalid(e.to_string()))?;
    let origin = reference
        .origin
        .clone()
        .ok_or_else(|| S3Error::invalid("a bucket needs an explicit <origin>:<space>"))?;
    if !reference.path.is_empty() {
        return Err(S3Error::invalid(
            "a bucket maps to a whole space, not a path within one",
        ));
    }
    let bucket = Bucket {
        name: name.to_string(),
        origin,
        space: reference.space,
    };
    let mut buckets = load(node)?;
    buckets.retain(|b| b.name != bucket.name);
    buckets.push(bucket.clone());
    save(node, &buckets)?;
    Ok(bucket)
}

/// Removes a bucket mapping.
pub fn remove(node: &Node, name: &str) -> S3Result<bool> {
    let mut buckets = load(node)?;
    let before = buckets.len();
    buckets.retain(|b| b.name != name);
    save(node, &buckets)?;
    Ok(buckets.len() != before)
}

fn save(node: &Node, buckets: &[Bucket]) -> S3Result<()> {
    let text = buckets
        .iter()
        .map(|b| format!("{}\t{}\t{}", b.name, b.origin.canonical(), b.space))
        .collect::<Vec<_>>()
        .join("\n");
    node.store().set_config(BUCKETS_CONFIG, &text)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use synch_engine::NodeConfig;

    async fn node() -> (tempfile::TempDir, Node) {
        let dir = tempfile::tempdir().unwrap();
        Node::init(dir.path(), None).unwrap();
        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        (dir, node)
    }

    #[tokio::test]
    async fn buckets_round_trip() {
        let (_d, node) = node().await;
        let reference = format!("{}:media", node.origin().canonical());
        let bucket = add(&node, "my-photos", &reference).unwrap();
        assert_eq!(bucket.space, "media");
        assert!(bucket.writable_by(&node));

        assert_eq!(load(&node).unwrap().len(), 1);
        assert_eq!(find(&node, "my-photos").unwrap(), bucket);
        assert!(find(&node, "absent").is_err());

        assert!(remove(&node, "my-photos").unwrap());
        assert!(!remove(&node, "my-photos").unwrap());
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn foreign_buckets_are_not_writable() {
        let (_d, node) = node().await;
        let bucket = add(&node, "nas-media", "nas@cluster.example:media").unwrap();
        assert!(!bucket.writable_by(&node));
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn rejects_bad_mappings() {
        let (_d, node) = node().await;
        // A bucket maps to a whole space.
        assert!(add(&node, "bad", "nas@cluster.example:media/sub").is_err());
        // And needs an explicit origin.
        assert!(add(&node, "bad", "media").is_err());
        node.shutdown().await.unwrap();
    }

    #[test]
    fn bucket_names_follow_the_s3_rules() {
        assert!(validate_name("my-bucket").is_ok());
        assert!(validate_name("a.b.c").is_ok());
        assert!(validate_name("ab").is_err());
        assert!(validate_name("UPPER").is_err());
        assert!(validate_name("-lead").is_err());
        assert!(validate_name("trail-").is_err());
        assert!(validate_name(&"x".repeat(64)).is_err());
    }
}
