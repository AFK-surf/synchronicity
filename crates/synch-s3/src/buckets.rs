//! Bucket mapping: a bucket names a space of the unified tree plus a version
//! policy (§9.4).
//!
//! Reads serve the policy-selected version of each key (§8). Writes are always
//! publishes of the *local* node's own view — the version model forbids
//! publishing someone else's — so every bucket is writable, and a bucket that
//! pins a foreign origin is effectively read-only in practice, since reads
//! would not see our writes. The gateway warns about exactly that shape.
//!
//! The map lives in the daemon's `s3.buckets` config value, reached over the
//! control socket, and it is an **append-only log of records**: three
//! tab-separated fields add or replace a bucket, one field removes it, and the
//! last record naming a bucket wins. Nothing rewrites the list in place,
//! because a read-modify-write of the whole list drops whichever concurrent
//! edit commits first — and there is deliberately no limit on how many gateway
//! processes point at one daemon.

use crate::{
    daemon::Daemon,
    error::{S3Error, S3Result},
};

/// The config value holding the bucket map.
pub const BUCKETS_CONFIG: &str = "s3.buckets";

/// Which version of each key a bucket's reads serve (§8).
///
/// The daemon owns what these *mean* — it is the one that resolves a path under
/// one. The gateway recognizes the three spellings so it can tell a foreign
/// origin pin from our own, and passes the text through untouched otherwise.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Policy {
    /// The greatest `(mtime_ns, content_root, origin)`.
    #[default]
    Newest,
    /// Pin to one origin's view.
    Origin(String),
    /// Refuse a divergent key, with `409 Conflict` naming the versions.
    Strict,
}

impl Policy {
    /// Reads the stored and command-line spelling.
    pub fn parse(text: &str) -> S3Result<Policy> {
        match text.trim() {
            "newest" => Ok(Policy::Newest),
            "strict" => Ok(Policy::Strict),
            other => match other.strip_prefix("origin=") {
                Some(origin) if !origin.is_empty() => Ok(Policy::Origin(origin.to_string())),
                _ => Err(S3Error::invalid(format!(
                    "{other:?} is not a version policy: use newest, origin=<id>, or strict"
                ))),
            },
        }
    }

    /// The stored and command-line spelling.
    pub fn render(&self) -> String {
        match self {
            Policy::Newest => "newest".to_string(),
            Policy::Origin(origin) => format!("origin={origin}"),
            Policy::Strict => "strict".to_string(),
        }
    }

    /// The origin this policy pins to, if it pins one.
    pub fn pinned_origin(&self) -> Option<&str> {
        match self {
            Policy::Origin(origin) => Some(origin),
            _ => None,
        }
    }
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render())
    }
}

/// One bucket's mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bucket {
    /// The bucket name.
    pub name: String,
    /// The space of the unified tree the bucket serves.
    pub space: String,
    /// Which version of each path reads return (§8).
    pub policy: Policy,
}

impl Bucket {
    /// The record that adds or replaces this mapping.
    fn record(&self) -> String {
        format!("{}\t{}\t{}", self.name, self.space, self.policy.render())
    }

    /// True if the bucket pins an origin other than the local node's.
    ///
    /// Writes still land — they publish our own view — but reads keep serving
    /// the pinned origin, so what was written will not come back (§9.4).
    pub fn pins_a_foreign_origin(&self, ours: &str) -> bool {
        self.policy.pinned_origin().is_some_and(|o| o != ours)
    }

    /// The warning §9.4 asks the gateway to log for such a bucket.
    pub fn foreign_pin_warning(&self, ours: &str) -> Option<String> {
        self.policy
            .pinned_origin()
            .filter(|o| *o != ours)
            .map(|origin| {
                format!(
                    "bucket {} pins {origin}, so writes to it publish {ours}'s view \
                     and reads keep serving {origin}'s: it is effectively read-only",
                    self.name,
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

/// Folds the append-only record log into the bucket map it describes.
///
/// Later records win, which is what makes both "replace this mapping" and
/// "remove it" expressible without ever rewriting what is already stored. A
/// record nobody can read is skipped rather than fatal: one malformed line
/// must not cost every other bucket its mapping.
pub fn fold(records: &[String]) -> Vec<Bucket> {
    let mut out: Vec<Bucket> = Vec::new();
    for record in records {
        let mut fields = record.split('\t');
        let Some(name) = fields.next().filter(|n| !n.is_empty()) else {
            continue;
        };
        let mapping = match (fields.next(), fields.next()) {
            (Some(space), Some(policy)) => match Policy::parse(policy) {
                Ok(policy) => Some(Bucket {
                    name: name.to_string(),
                    space: space.to_string(),
                    policy,
                }),
                Err(_) => continue,
            },
            // One field alone is a removal: the bucket the record names stops
            // existing from here on.
            (None, _) => None,
            _ => continue,
        };
        out.retain(|b| b.name != name);
        if let Some(bucket) = mapping {
            out.push(bucket);
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Reads the configured buckets from the daemon.
pub async fn load(daemon: &Daemon) -> S3Result<Vec<Bucket>> {
    Ok(fold(&daemon.config(BUCKETS_CONFIG).await?))
}

/// Looks one bucket up.
pub async fn find(daemon: &Daemon, name: &str) -> S3Result<Bucket> {
    load(daemon)
        .await?
        .into_iter()
        .find(|b| b.name == name)
        .ok_or_else(|| S3Error::no_such_bucket(name))
}

/// Adds or replaces a bucket mapping.
///
/// `reference` is a space — `media` — or the origin-pinned shorthand
/// `<origin>:<space>`, which is the same thing as `--policy origin=<origin>`.
pub async fn add(
    daemon: &Daemon,
    name: &str,
    reference: &str,
    policy: Option<&str>,
) -> S3Result<Bucket> {
    validate_name(name)?;
    let (pinned, space) = split_reference(reference)?;
    let policy = match (&pinned, policy) {
        (Some(_), Some(_)) => {
            return Err(S3Error::invalid(
                "the reference already pins an origin; drop --policy or the <origin>: prefix",
            ))
        }
        (Some(origin), None) => Policy::Origin(origin.clone()),
        (None, Some(text)) => Policy::parse(text)?,
        (None, None) => Policy::default(),
    };
    let bucket = Bucket {
        name: name.to_string(),
        space,
        policy,
    };
    // The daemon is the authority on what a space id and an origin are, so the
    // mapping is offered to it before it is stored: an empty listing under this
    // policy means it would work, and anything else comes back as the error a
    // first GET would otherwise have produced days later.
    daemon
        .list(&bucket.space, "", None, 0, &bucket.policy.render())
        .await?;
    daemon.append(BUCKETS_CONFIG, &bucket.record()).await?;
    Ok(bucket)
}

/// Removes a bucket mapping, returning whether it existed.
///
/// Appends a removal record rather than rewriting the list, for the reason the
/// whole log is append-only: two gateways editing one value must not be able to
/// undo each other.
pub async fn remove(daemon: &Daemon, name: &str) -> S3Result<bool> {
    let existed = load(daemon).await?.iter().any(|b| b.name == name);
    if existed {
        daemon.append(BUCKETS_CONFIG, name).await?;
    }
    Ok(existed)
}

/// Splits `<origin>:<space>` into its parts, or takes a bare space.
///
/// A bucket maps to a whole space, so there is no path to confuse the split
/// with: everything before the last colon is the origin, and a key-identified
/// origin's own colon survives it.
fn split_reference(reference: &str) -> S3Result<(Option<String>, String)> {
    let (origin, space) = match reference.rsplit_once(':') {
        Some((origin, space)) => (Some(origin.to_string()), space),
        None => (None, reference),
    };
    if space.contains('/') {
        return Err(S3Error::invalid(
            "a bucket maps to a whole space, not a path within one",
        ));
    }
    synch_core::validate_space(space).map_err(|e| S3Error::invalid(e.to_string()))?;
    if origin.as_deref().is_some_and(str::is_empty) {
        return Err(S3Error::invalid(format!(
            "{reference:?} names no origin before its colon"
        )));
    }
    Ok((origin, space.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|l| l.to_string()).collect()
    }

    #[test]
    fn the_last_record_naming_a_bucket_wins() {
        let buckets = fold(&records(&[
            "photos\tmedia\tnewest",
            "docs\tpapers\tstrict",
            // A replacement for an existing name, appended rather than edited.
            "photos\tmedia\torigin=nas@cluster.example",
        ]));
        assert_eq!(buckets.len(), 2);
        let photos = buckets.iter().find(|b| b.name == "photos").unwrap();
        assert_eq!(
            photos.policy,
            Policy::Origin("nas@cluster.example".to_string())
        );
    }

    #[test]
    fn a_single_field_record_removes_a_bucket() {
        let buckets = fold(&records(&[
            "photos\tmedia\tnewest",
            "docs\tpapers\tstrict",
            "photos",
        ]));
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].name, "docs");
        // And re-adding after a removal brings it back, because the log is
        // read in order and nothing was rewritten.
        let buckets = fold(&records(&[
            "photos\tmedia\tnewest",
            "photos",
            "photos\tother\tstrict",
        ]));
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].space, "other");
    }

    #[test]
    fn an_unreadable_record_costs_only_itself() {
        let buckets = fold(&records(&[
            "photos\tmedia\tnewest",
            "garbage\tmedia\twhatever",
            "\t\t",
            "docs\tpapers\tstrict",
        ]));
        let names: Vec<&str> = buckets.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, vec!["docs", "photos"]);
    }

    /// Databases written before the unified tree stored the bucket map as
    /// `<bucket>\t<space>\t<policy>` in one config row; migration v5 gave every
    /// line its policy and v8 moved the row into the `s3.*` namespace, so what
    /// the log reads back on an upgraded node is exactly a run of add records.
    #[test]
    fn a_migrated_bucket_map_reads_as_add_records() {
        let buckets = fold(&records(&["photos\tmedia\torigin=nas@x.example"]));
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].space, "media");
        assert_eq!(buckets[0].policy.pinned_origin(), Some("nas@x.example"));
    }

    #[test]
    fn policies_round_trip() {
        for text in ["newest", "strict", "origin=nas@cluster.example"] {
            assert_eq!(Policy::parse(text).unwrap().render(), text);
        }
        assert!(Policy::parse("whatever").is_err());
        assert!(Policy::parse("origin=").is_err());
        assert_eq!(Policy::default(), Policy::Newest);
    }

    #[test]
    fn references_split_into_an_origin_and_a_space() {
        assert_eq!(split_reference("media").unwrap(), (None, "media".into()));
        assert_eq!(
            split_reference("nas@cluster.example:media").unwrap(),
            (Some("nas@cluster.example".into()), "media".into())
        );
        // A key-identified origin keeps its own colon.
        assert_eq!(
            split_reference("key:abcdef:media").unwrap(),
            (Some("key:abcdef".into()), "media".into())
        );
        assert!(split_reference("nas@cluster.example:media/sub").is_err());
        assert!(split_reference(":media").is_err());
        assert!(split_reference("").is_err());
    }

    #[test]
    fn a_foreign_pin_is_named_as_one() {
        let ours = "laptop@cluster.example";
        let bucket = Bucket {
            name: "nas-media".into(),
            space: "media".into(),
            policy: Policy::Origin("nas@cluster.example".into()),
        };
        assert!(bucket.pins_a_foreign_origin(ours));
        assert!(bucket
            .foreign_pin_warning(ours)
            .unwrap()
            .contains("read-only"));

        let mine = Bucket {
            policy: Policy::Origin(ours.into()),
            ..bucket.clone()
        };
        assert!(!mine.pins_a_foreign_origin(ours));
        assert!(mine.foreign_pin_warning(ours).is_none());

        let unpinned = Bucket {
            policy: Policy::Strict,
            ..bucket
        };
        assert!(!unpinned.pins_a_foreign_origin(ours));
        assert!(unpinned.foreign_pin_warning(ours).is_none());
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
