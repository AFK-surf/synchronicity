//! Bucket mapping: a bucket names a space, an access mode, and a read view.
//!
//! Read-only buckets may select any view. Read-write buckets require a source
//! and read this node's own origin, so a successful write is immediately
//! visible through the same bucket.
//!
//! The map lives in the daemon's `s3.buckets` config value, reached over the
//! control socket, and it is an **append-only log of records**: four
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
pub(crate) const BUCKETS_CONFIG: &str = "s3.buckets";

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

/// Whether a bucket may publish this node's view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Reads only; any selection policy is allowed.
    ReadOnly,
    /// Reads and writes against this node's own source view.
    ReadWrite,
}

impl Access {
    fn parse(text: &str) -> S3Result<Self> {
        match text {
            "read-only" => Ok(Self::ReadOnly),
            "read-write" => Ok(Self::ReadWrite),
            _ => Err(S3Error::invalid(
                "bucket access must be read-only or read-write",
            )),
        }
    }

    /// The stored spelling.
    pub fn render(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::ReadWrite => "read-write",
        }
    }
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
    /// Whether mutations are accepted.
    pub access: Access,
    /// Which version of each path reads return (§8).
    pub policy: Policy,
}

impl Bucket {
    /// The record that adds or replaces this mapping.
    fn record(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}",
            self.name,
            self.space,
            self.access.render(),
            self.policy.render()
        )
    }

    /// Refuses a mutation before its body is consumed.
    pub fn require_writable(&self) -> S3Result<()> {
        match self.access {
            Access::ReadWrite => Ok(()),
            Access::ReadOnly => Err(S3Error::access_denied(format!(
                "bucket {} is read-only",
                self.name
            ))),
        }
    }
}

/// Validates a bucket name against the S3 naming rules we enforce.
pub(crate) fn validate_name(name: &str) -> S3Result<()> {
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

/// Folds the append-only record log into the bucket map it describes
/// (`record_log`: later records win, a lone name is a removal, a
/// malformed record costs only itself).
pub fn fold(records: &[String]) -> Vec<Bucket> {
    let mut out = crate::record_log::fold(
        records,
        |bucket: &Bucket| &bucket.name,
        |name, rest| {
            let [space, access, policy, ..] = rest else {
                return None;
            };
            Access::parse(access)
                .ok()
                .zip(Policy::parse(policy).ok())
                .map(|(access, policy)| Bucket {
                    name: name.to_string(),
                    space: space.to_string(),
                    access,
                    policy,
                })
        },
    );
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
/// `space` is a namespace id. Read-only selection is supplied independently.
pub async fn add(
    daemon: &Daemon,
    name: &str,
    space: &str,
    access: Access,
    select: Option<&str>,
) -> S3Result<Bucket> {
    validate_name(name)?;
    synch_core::validate_space(space).map_err(|e| S3Error::invalid(e.to_string()))?;
    let policy = match access {
        Access::ReadOnly => select.map(Policy::parse).transpose()?.unwrap_or_default(),
        Access::ReadWrite if select.is_some() => {
            return Err(S3Error::invalid("--select is valid only with --read-only"));
        }
        Access::ReadWrite => {
            if !daemon.has_source(space).await? {
                return Err(S3Error::invalid(format!(
                    "read-write bucket requires a local source for {space}"
                )));
            }
            Policy::Origin(daemon.origin().await?)
        }
    };
    let bucket = Bucket {
        name: name.to_string(),
        space: space.to_string(),
        access,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn records(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|l| l.to_string()).collect()
    }

    /// Every fold rule in one pass: replace, remove, re-add, and a bad record costs only itself.
    #[test]
    fn the_last_record_naming_a_bucket_wins() {
        let buckets = fold(&records(&[
            "photos\tmedia\tread-only\tnewest",
            "docs\tpapers\tread-only\tstrict",
            "photos\tmedia\tread-only\torigin=nas",
            "garbage\tmedia\tread-only\twhatever",
            "\t\t",
            "docs",
            "docs\tother\tread-write\torigin=self",
        ]));
        let names: Vec<&str> = buckets.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, vec!["docs", "photos"]);
        let photos = buckets.iter().find(|b| b.name == "photos").unwrap();
        assert_eq!(photos.policy, Policy::Origin("nas".to_string()));
        let docs = buckets.iter().find(|b| b.name == "docs").unwrap();
        assert_eq!(docs.space, "other");
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
    fn only_read_write_buckets_accept_mutations() {
        let mut bucket = Bucket {
            name: "media".into(),
            space: "media".into(),
            access: Access::ReadOnly,
            policy: Policy::Newest,
        };
        assert!(bucket.require_writable().is_err());
        bucket.access = Access::ReadWrite;
        assert!(bucket.require_writable().is_ok());
    }

    #[test]
    fn bucket_names_follow_the_s3_rules() {
        assert!(validate_name("my-bucket").is_ok());
        assert!(validate_name("a.b.c").is_ok());
        assert!(validate_name("ab").is_err());
        assert!(validate_name("UPPER").is_err());
        assert!(validate_name("-lead").is_err());
        assert!(validate_name(&"x".repeat(64)).is_err());
    }
}
