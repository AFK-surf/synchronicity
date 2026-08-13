//! Bucket mapping: a bucket names a space of the unified tree plus a version
//! policy (§9.4).
//!
//! Reads serve the policy-selected version of each key (§8). Writes are always
//! publishes of the *local* node's own view — the version model forbids
//! publishing someone else's — so every bucket is writable, and a bucket that
//! pins a foreign origin is effectively read-only in practice, since reads
//! would not see our writes. The gateway warns about exactly that shape.

use std::str::FromStr;

use synch_engine::{EntryRef, Node, VersionPolicy};

use crate::error::{S3Error, S3Result};

/// The config key holding the bucket map.
const BUCKETS_CONFIG: &str = "s3_buckets";

/// One bucket's mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bucket {
    /// The bucket name.
    pub name: String,
    /// The space of the unified tree the bucket serves.
    pub space: String,
    /// Which version of each path reads return (§8).
    pub policy: VersionPolicy,
}

impl Bucket {
    /// The origin whose view this bucket pins, if it pins one.
    pub fn pinned_origin(&self) -> Option<&synch_core::OriginId> {
        self.policy.pinned_origin()
    }

    /// True if the bucket pins an origin other than the local node's.
    ///
    /// Writes still land — they publish our own view — but reads keep serving
    /// the pinned origin, so what was written will not come back (§9.4).
    pub fn pins_a_foreign_origin(&self, node: &Node) -> bool {
        self.pinned_origin().is_some_and(|o| o != node.origin())
    }

    /// The warning §9.4 asks the gateway to log for such a bucket.
    pub fn foreign_pin_warning(&self, node: &Node) -> Option<String> {
        self.pinned_origin()
            .filter(|o| *o != node.origin())
            .map(|origin| {
                format!(
                    "bucket {} pins {origin}, so writes to it publish {}'s view \
                     and reads keep serving {origin}'s: it is effectively read-only",
                    self.name,
                    node.origin()
                )
            })
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
///
/// Each line is `<bucket>\t<space>\t<policy>`. Databases written before the
/// unified tree stored `<bucket>\t<origin>\t<space>`; migration v5 (§10)
/// rewrites those in place, so nothing here has to guess which shape it is
/// looking at.
pub fn load(node: &Node) -> S3Result<Vec<Bucket>> {
    let Some(text) = node.store().config(BUCKETS_CONFIG)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split('\t');
        let (Some(name), Some(space), Some(policy)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let Ok(policy) = VersionPolicy::from_str(policy) else {
            continue;
        };
        out.push(Bucket {
            name: name.to_string(),
            space: space.to_string(),
            policy,
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

/// Adds or replaces a bucket mapping.
///
/// `reference` is a space — `media` — or the origin-pinned shorthand
/// `<origin>:<space>`, which is the same thing as `--policy origin=<origin>`.
pub fn add(node: &Node, name: &str, reference: &str, policy: Option<&str>) -> S3Result<Bucket> {
    validate_name(name)?;
    let reference: EntryRef = reference
        .parse()
        .map_err(|e: synch_engine::EngineError| S3Error::invalid(e.to_string()))?;
    if !reference.path.is_empty() {
        return Err(S3Error::invalid(
            "a bucket maps to a whole space, not a path within one",
        ));
    }
    let policy = match (&reference.origin, policy) {
        (Some(_), Some(_)) => {
            return Err(S3Error::invalid(
                "the reference already pins an origin; drop --policy or the <origin>: prefix",
            ))
        }
        (Some(origin), None) => VersionPolicy::Origin(origin.clone()),
        (None, Some(text)) => VersionPolicy::from_str(text)
            .map_err(|e: synch_store::StoreError| S3Error::invalid(e.to_string()))?,
        (None, None) => VersionPolicy::Newest,
    };
    let bucket = Bucket {
        name: name.to_string(),
        space: reference.space,
        policy,
    };
    let mut buckets = load(node)?;
    buckets.retain(|b| b.name != bucket.name);
    buckets.push(bucket.clone());
    save(node, &buckets)?;
    if let Some(warning) = bucket.foreign_pin_warning(node) {
        tracing::warn!("{warning}");
    }
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
        .map(|b| format!("{}\t{}\t{}", b.name, b.space, b.policy.render()))
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
        let bucket = add(&node, "my-photos", "media", None).unwrap();
        assert_eq!(bucket.space, "media");
        assert_eq!(bucket.policy, VersionPolicy::Newest);
        assert!(!bucket.pins_a_foreign_origin(&node));

        assert_eq!(load(&node).unwrap().len(), 1);
        assert_eq!(find(&node, "my-photos").unwrap(), bucket);
        assert!(find(&node, "absent").is_err());

        assert!(remove(&node, "my-photos").unwrap());
        assert!(!remove(&node, "my-photos").unwrap());
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_policy_may_be_given_either_way() {
        let (_d, node) = node().await;
        // The shorthand and the flag mean the same thing.
        let shorthand = add(&node, "nas-media", "nas@cluster.example:media", None).unwrap();
        let flagged = add(
            &node,
            "nas-media-2",
            "media",
            Some("origin=nas@cluster.example"),
        )
        .unwrap();
        assert_eq!(shorthand.policy, flagged.policy);
        assert_eq!(shorthand.space, flagged.space);
        assert!(shorthand.pins_a_foreign_origin(&node));
        assert!(shorthand.foreign_pin_warning(&node).is_some());

        let strict = add(&node, "strict-media", "media", Some("strict")).unwrap();
        assert_eq!(strict.policy, VersionPolicy::Strict);
        assert!(strict.foreign_pin_warning(&node).is_none());

        // Pinning our own origin is not foreign, so there is nothing to warn
        // about.
        let ours = add(
            &node,
            "ours",
            &format!("{}:media", node.origin().canonical()),
            None,
        )
        .unwrap();
        assert!(!ours.pins_a_foreign_origin(&node));
        assert!(ours.foreign_pin_warning(&node).is_none());

        // And the mapping survives a reload with its policy intact.
        let loaded = find(&node, "strict-media").unwrap();
        assert_eq!(loaded.policy, VersionPolicy::Strict);
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn rejects_bad_mappings() {
        let (_d, node) = node().await;
        // A bucket maps to a whole space.
        assert!(add(&node, "bad", "nas@cluster.example:media/sub", None).is_err());
        // A pin cannot be given twice, two ways.
        assert!(add(
            &node,
            "bad",
            "nas@cluster.example:media",
            Some("origin=other@cluster.example")
        )
        .is_err());
        // And a policy has to be one of the three.
        assert!(add(&node, "bad", "media", Some("whatever")).is_err());
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
