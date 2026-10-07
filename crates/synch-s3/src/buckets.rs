//! Bucket mapping: a bucket names a space, an access mode, and a read view.
//!
//! Read-only buckets may select any view. Read-write buckets require a source
//! and read this node's own origin, so a successful write is immediately
//! visible through the same bucket.
//!
//! The map lives in the daemon's `s3.buckets` config value, reached over the
//! control socket, and it is an **append-only log of records**: four
//! tab-separated fields add or replace a bucket (a fifth, `no-cache`, marks a
//! bucket whose reads keep no copy of peers' objects), one field removes it, and the
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

/// The record field marking a bucket that keeps no copy of peers' objects.
const NO_CACHE: &str = "no-cache";

/// The record field prefix carrying a bucket's lock-key globs.
const LOCKS: &str = "locks=";

/// Refuses a lock glob the record could not carry or a key could not match.
fn validate_lock_glob(pattern: &str) -> S3Result<()> {
    if pattern.is_empty()
        || pattern.len() > synch_core::MAX_LOCK_NAME_BYTES
        || pattern.contains(',')
        || pattern.chars().any(char::is_control)
    {
        return Err(S3Error::invalid(format!(
            "{pattern:?} is not a lock glob: one pattern per --locks, no commas"
        )));
    }
    Ok(())
}

/// Matches `key` against a glob where `*` is any run of characters, `/`
/// included, and `?` is any one character.
fn glob(pattern: &str, key: &str) -> bool {
    let (p, k): (Vec<char>, Vec<char>) = (pattern.chars().collect(), key.chars().collect());
    let (mut pi, mut ki) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ki < k.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == k[ki]) {
            pi += 1;
            ki += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ki;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ki = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// Which version of each key a bucket's reads serve (§8).
///
/// The daemon owns what these *mean* — it is the one that resolves a path under
/// one. `Own` is resolved against the daemon for every read, so a writable
/// bucket follows node identity adoption instead of pinning the name current
/// when the bucket happened to be created.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Policy {
    /// The greatest `(mtime_ns, content_root, origin)`.
    #[default]
    Newest,
    /// Pin to one origin's view.
    Origin(String),
    /// Refuse a divergent key, with `409 Conflict` naming the versions.
    Strict,
    /// This node's current origin. Stored only for read-write buckets.
    Own,
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
            "own" => Ok(Policy::Own),
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
            Policy::Own => "own".to_string(),
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
    /// Serve peers' objects without keeping a copy (§6.4): content this node
    /// does not already hold is verified in memory and streamed through.
    pub no_cache: bool,
    /// Globs naming the keys that are cluster locks (docs/LOCKS.md §11.1).
    pub locks: Vec<String>,
}

impl Bucket {
    /// The record that adds or replaces this mapping.
    fn record(&self) -> String {
        let record = format!(
            "{}\t{}\t{}\t{}",
            self.name,
            self.space,
            self.access.render(),
            self.policy.render()
        );
        // Appended rather than placed earlier, so a gateway that predates the
        // field still reads the four it knows and serves the bucket cached.
        let mut record = match self.no_cache {
            true => format!("{record}\t{NO_CACHE}"),
            false => record,
        };
        // After `no-cache`, so a gateway that reads only the first option
        // still finds it there.
        if !self.locks.is_empty() {
            record = format!("{record}\t{LOCKS}{}", self.locks.join(","));
        }
        record
    }

    /// Whether `key` is one of this bucket's lock keys.
    pub fn is_lock_key(&self, key: &str) -> bool {
        !key.is_empty() && self.locks.iter().any(|pattern| glob(pattern, key))
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

    /// The daemon version policy for a read performed now.
    pub async fn read_policy(&self, daemon: &Daemon) -> S3Result<String> {
        match &self.policy {
            Policy::Own => Ok(format!("origin={}", daemon.origin().await?)),
            _ => Ok(self.policy.render()),
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
            let [space, access, policy, options @ ..] = rest else {
                return None;
            };
            let no_cache = options.contains(&NO_CACHE);
            let locks: Vec<String> = options
                .iter()
                .find_map(|field| field.strip_prefix(LOCKS))
                .map(|globs| {
                    globs
                        .split(',')
                        .filter(|g| !g.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let (access, policy) = Access::parse(access).ok().zip(Policy::parse(policy).ok())?;
            if matches!((&access, &policy), (Access::ReadWrite, Policy::Own))
                || matches!((&access, &policy), (Access::ReadOnly, p) if !matches!(p, Policy::Own))
            {
                Some(Bucket {
                    name: name.to_string(),
                    space: space.to_string(),
                    access,
                    policy,
                    no_cache,
                    locks,
                })
            } else {
                None
            }
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
    no_cache: bool,
) -> S3Result<Bucket> {
    add_with_locks(daemon, name, space, access, select, no_cache, &[]).await
}

/// As [`add`], declaring the keys matching `locks` cluster locks
/// (docs/LOCKS.md §11.1). A lock is a write, so only a read-write bucket may
/// declare them.
pub async fn add_with_locks(
    daemon: &Daemon,
    name: &str,
    space: &str,
    access: Access,
    select: Option<&str>,
    no_cache: bool,
    locks: &[String],
) -> S3Result<Bucket> {
    validate_name(name)?;
    for pattern in locks {
        validate_lock_glob(pattern)?;
    }
    if !locks.is_empty() && access != Access::ReadWrite {
        return Err(S3Error::invalid("--locks needs a read-write bucket"));
    }
    synch_core::validate_space(space).map_err(|e| S3Error::invalid(e.to_string()))?;
    let policy = match access {
        Access::ReadOnly => {
            let policy = select.map(Policy::parse).transpose()?.unwrap_or_default();
            if policy == Policy::Own {
                return Err(S3Error::invalid("own is reserved for read-write buckets"));
            }
            policy
        }
        Access::ReadWrite if select.is_some() => {
            return Err(S3Error::invalid("--select is valid only with --read-only"));
        }
        Access::ReadWrite => {
            if !daemon.has_source(space).await? {
                return Err(S3Error::invalid(format!(
                    "read-write bucket requires a local source for {space}"
                )));
            }
            Policy::Own
        }
    };
    let bucket = Bucket {
        name: name.to_string(),
        space: space.to_string(),
        access,
        policy,
        no_cache,
        locks: locks.to_vec(),
    };
    // The daemon is the authority on what a space id and an origin are, so the
    // mapping is offered to it before it is stored: an empty listing under this
    // policy means it would work, and anything else comes back as the error a
    // first GET would otherwise have produced days later.
    daemon
        .list(
            &bucket.space,
            "",
            None,
            0,
            &bucket.read_policy(daemon).await?,
        )
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
            "legacy\tmedia\tread-write\torigin=old-name",
            "\t\t",
            "docs",
            "docs\tother\tread-write\town",
        ]));
        let names: Vec<&str> = buckets.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, vec!["docs", "photos"]);
        let photos = buckets.iter().find(|b| b.name == "photos").unwrap();
        assert_eq!(photos.policy, Policy::Origin("nas".to_string()));
        let docs = buckets.iter().find(|b| b.name == "docs").unwrap();
        assert_eq!(docs.space, "other");
        assert_eq!(docs.policy, Policy::Own);
    }

    #[test]
    fn policies_round_trip() {
        for text in ["newest", "strict", "origin=nas@cluster.example", "own"] {
            assert_eq!(Policy::parse(text).unwrap().render(), text);
        }
        assert!(Policy::parse("whatever").is_err());
        assert!(Policy::parse("origin=").is_err());
        assert_eq!(Policy::default(), Policy::Newest);
    }

    /// The no-cache marker rides as a fifth field: it round-trips, and a
    /// record without it reads as an ordinary cached bucket.
    #[test]
    fn a_no_cache_bucket_round_trips_through_its_record() {
        let bucket = Bucket {
            name: "peers".into(),
            space: "media".into(),
            access: Access::ReadOnly,
            policy: Policy::Newest,
            no_cache: true,
            locks: Vec::new(),
        };
        assert_eq!(fold(&[bucket.record()]), vec![bucket]);
        let plain = fold(&records(&["photos\tmedia\tread-only\tnewest"]));
        assert!(!plain[0].no_cache);
    }

    #[test]
    fn only_read_write_buckets_accept_mutations() {
        let mut bucket = Bucket {
            name: "media".into(),
            space: "media".into(),
            access: Access::ReadOnly,
            policy: Policy::Newest,
            no_cache: false,
            locks: Vec::new(),
        };
        assert!(bucket.require_writable().is_err());
        bucket.access = Access::ReadWrite;
        assert!(bucket.require_writable().is_ok());
    }

    /// Lock globs ride after `no-cache`, round-trip, and match whole keys.
    #[test]
    fn lock_keys_round_trip_and_match_whole_keys() {
        let bucket = Bucket {
            name: "tf".into(),
            space: "infra".into(),
            access: Access::ReadWrite,
            policy: Policy::Own,
            no_cache: true,
            locks: vec!["*.tflock".into(), "locks/?".into()],
        };
        assert_eq!(fold(&[bucket.record()]), vec![bucket.clone()]);
        assert!(bucket.is_lock_key("env/prod/terraform.tfstate.tflock"));
        assert!(bucket.is_lock_key("locks/a"));
        assert!(!bucket.is_lock_key("locks/ab"));
        assert!(!bucket.is_lock_key("terraform.tfstate"));
        assert!(!bucket.is_lock_key("x.tflock.bak"));
        assert!(validate_lock_glob("a,b").is_err());
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
