//! What one shard is told, and how it reads it.
//!
//! Everything comes from the environment, because that is what a pod is
//! configured with. Nothing is read from disk: the disk is ephemeral, and a
//! configuration that outlived a reschedule would be a lie.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use crate::error::{DpError, Result};

/// The hosting slot this build claims (`docs/CLOUD-DATAPLANE.md` §3.4).
///
/// One, because v1 hosts every network once. It is a constant rather than a
/// setting so that no deployment can accidentally run two shards claiming the
/// same slot for different networks — redundancy is a *second* slot, which is
/// a design change, not a config change.
pub const SLOT: u32 = 1;

/// The device label for [`SLOT`].
pub fn slot_label() -> String {
    format!("cloud-{SLOT}")
}

/// One shard's settings.
#[derive(Debug, Clone)]
pub struct DpConfig {
    /// Base URL of the control plane, no trailing slash.
    pub control_url: String,
    /// The `synchdp_…` token.
    pub token: String,
    /// Where tenant data directories live, on the pod's ephemeral volume.
    pub base_dir: PathBuf,
    /// This shard's ordinal, and how many there are.
    pub shard: u32,
    /// Total shards. Rendezvous hashing decides which serves which network.
    pub shards: u32,
    /// A name for this pod, for logs and the status heartbeat.
    pub shard_name: String,
    /// How often to poll the control plane.
    pub poll_interval: Duration,
    /// The object store: OpenDAL service and its options.
    pub objects: ObjectConfig,
    /// The key sealing the database streams.
    pub db_key: Option<[u8; 32]>,
    /// Total cache budget across all tenants on this pod.
    pub cache_bytes_total: u64,
    /// How many tenants this pod is sized for. Divides the cache budget.
    pub max_tenants: u64,
    /// Where to serve Prometheus metrics, when asked to.
    pub metrics_addr: Option<String>,
}

/// The object store both the CAS and the database streams live in.
#[derive(Debug, Clone)]
pub struct ObjectConfig {
    /// `s3`, `gcs`, `azblob`, or `memory`.
    pub service: String,
    /// OpenDAL service options, verbatim field names.
    pub options: HashMap<String, String>,
}

impl ObjectConfig {
    /// Builds the operator for the service's own client (database streams and
    /// the desired-state cache), rooted at the bucket.
    pub fn operator(&self) -> Result<opendal::Operator> {
        self.operator_rooted("/")
    }

    /// Builds an operator rooted at `root` — one tenant's CAS prefix.
    pub fn operator_rooted(&self, root: &str) -> Result<opendal::Operator> {
        let mut options = self.options.clone();
        options.insert("root".to_string(), root.to_string());
        let operator = match self.service.as_str() {
            "s3" => opendal::Operator::from_iter::<opendal::services::S3>(options)?,
            "gcs" => opendal::Operator::from_iter::<opendal::services::Gcs>(options)?,
            "azblob" => opendal::Operator::from_iter::<opendal::services::Azblob>(options)?,
            "memory" => opendal::Operator::from_iter::<opendal::services::Memory>(options)?,
            other => {
                return Err(DpError::Config(format!(
                    "unknown object store service `{other}` (s3, gcs, azblob, memory)"
                )))
            }
        };
        Ok(operator
            .layer(opendal::layers::RetryLayer::default())
            .layer(
                opendal::layers::TimeoutLayer::default().with_io_timeout(Duration::from_secs(60)),
            ))
    }

    /// The `CloudConfig` a tenant's node gets, rooted at its own prefix.
    pub fn cloud_config(
        &self,
        root: &str,
        scratch_dir: PathBuf,
        cache_bytes: u64,
    ) -> Result<synch_store::cloud::CloudConfig> {
        let service = match self.service.as_str() {
            "s3" => synch_store::cloud::CloudService::S3,
            "gcs" => synch_store::cloud::CloudService::Gcs,
            "azblob" => synch_store::cloud::CloudService::Azblob,
            "memory" => synch_store::cloud::CloudService::Memory,
            other => {
                return Err(DpError::Config(format!(
                    "unknown object store service `{other}`"
                )))
            }
        };
        let mut options = self.options.clone();
        options.insert("root".to_string(), root.to_string());
        Ok(synch_store::cloud::CloudConfig {
            service,
            options,
            scratch_dir,
            io_timeout: Duration::from_secs(60),
            // The replicate mode of the daemon: acquisition pins, and the pin
            // path finalizes into the cloud store (§4.5). `All` would also
            // make every transient read durable, which is not what a replica
            // promised to keep.
            upload_policy: synch_store::cloud::CloudUploadPolicy::OwnPinned,
            // Always explicit: the Unix free-space default is a single-node
            // policy and thrashes when tenants share a volume (§5.2).
            cache_bytes: Some(cache_bytes),
        })
    }
}

impl DpConfig {
    /// Reads the environment.
    pub fn from_env() -> Result<Self> {
        let control_url = require("SYNCH_DP_CONTROL_URL")?
            .trim_end_matches('/')
            .to_string();
        let token = require("SYNCH_DP_TOKEN")?;
        let base_dir = PathBuf::from(
            std::env::var("SYNCH_DP_BASE_DIR").unwrap_or_else(|_| "/run/synch-dp".to_string()),
        );
        let shard = parse("SYNCH_DP_SHARD", 0)?;
        let shards = parse("SYNCH_DP_SHARDS", 1)?;
        if shards == 0 {
            return Err(DpError::Config("SYNCH_DP_SHARDS must be at least 1".into()));
        }
        if shard >= shards {
            return Err(DpError::Config(format!(
                "SYNCH_DP_SHARD ({shard}) must be below SYNCH_DP_SHARDS ({shards})"
            )));
        }
        let shard_name =
            std::env::var("SYNCH_DP_SHARD_NAME").unwrap_or_else(|_| format!("dp-{}", shard + 1));
        let poll_interval = Duration::from_secs(parse::<u64>("SYNCH_DP_POLL_SECS", 60)?.max(1));

        let service = std::env::var("SYNCH_DP_CAS_BACKEND").unwrap_or_else(|_| "s3".to_string());
        let mut options = HashMap::new();
        collect_options(&service, &mut options);

        let db_key = match std::env::var("SYNCH_DP_DB_KEY") {
            Ok(hex_key) => {
                let bytes = hex::decode(hex_key.trim())
                    .map_err(|_| DpError::Config("SYNCH_DP_DB_KEY must be hex".into()))?;
                let key: [u8; 32] = bytes.try_into().map_err(|_| {
                    DpError::Config("SYNCH_DP_DB_KEY must be 32 bytes (64 hex chars)".into())
                })?;
                Some(key)
            }
            // Refused rather than defaulted: the stream carries device secret
            // keys, and a deployment that has not decided how to protect them
            // should find out now and not after a bucket is readable (§9).
            // `SYNCH_DP_DB_UNSEALED=1` is the explicit way to say "I know",
            // which exists for tests and for a bucket that is already sealed
            // by the provider under a key the operator controls.
            Err(_) if truthy("SYNCH_DP_DB_UNSEALED") => None,
            Err(_) => {
                return Err(DpError::Config(
                    "SYNCH_DP_DB_KEY is required: the database replica stream carries device \
                     secret keys. Set a 32-byte hex key, or SYNCH_DP_DB_UNSEALED=1 to store \
                     them unsealed deliberately."
                        .into(),
                ))
            }
        };

        Ok(Self {
            control_url,
            token,
            base_dir,
            shard,
            shards,
            shard_name,
            poll_interval,
            objects: ObjectConfig { service, options },
            db_key,
            cache_bytes_total: parse("SYNCH_DP_CACHE_BYTES_TOTAL", 64 * 1024 * 1024 * 1024)?,
            max_tenants: parse::<u64>("SYNCH_DP_MAX_TENANTS", 64)?.max(1),
            metrics_addr: std::env::var("SYNCH_DP_METRICS_ADDR").ok(),
        })
    }

    /// The cache each tenant may fill.
    pub fn cache_bytes_per_tenant(&self) -> u64 {
        (self.cache_bytes_total / self.max_tenants).max(1)
    }

    /// Whether this shard serves `network`, by rendezvous hashing.
    ///
    /// No assignment state anywhere: every shard computes the same answer from
    /// the same document, and a shard-count change moves about one in `n` of
    /// the tenants rather than reshuffling all of them.
    pub fn serves(&self, network_key: &str) -> bool {
        if self.shards == 1 {
            return true;
        }
        let mut best = (0u64, 0u32);
        for candidate in 0..self.shards {
            let mut hasher = blake3::Hasher::new();
            hasher.update(network_key.as_bytes());
            hasher.update(&candidate.to_be_bytes());
            let score = u64::from_be_bytes(
                hasher.finalize().as_bytes()[..8]
                    .try_into()
                    .expect("a blake3 digest is 32 bytes"),
            );
            if score > best.0 {
                best = (score, candidate);
            }
        }
        best.1 == self.shard
    }

    /// This tenant's data directory.
    pub fn tenant_dir(&self, org: &str, network: &str) -> PathBuf {
        self.base_dir.join("tenants").join(org).join(network)
    }

    /// This tenant's CAS prefix within the bucket.
    pub fn cas_root(&self, org: &str, network: &str) -> String {
        format!("/tenants/{org}/{network}/")
    }

    /// This tenant's database replica stream prefix.
    pub fn db_prefix(&self, org: &str, network: &str) -> String {
        format!("db/{org}/{network}")
    }

    /// Where the fail-static desired-state cache lives (§4.2).
    pub fn desired_key(&self) -> String {
        format!("dp/{}/desired.json", self.shard)
    }
}

/// Copies the provider's environment into OpenDAL option names.
fn collect_options(service: &str, options: &mut HashMap<String, String>) {
    let pairs: &[(&str, &str)] = match service {
        "s3" => &[
            ("SYNCH_DP_S3_BUCKET", "bucket"),
            ("SYNCH_DP_S3_REGION", "region"),
            ("SYNCH_DP_S3_ENDPOINT", "endpoint"),
            ("SYNCH_DP_S3_ACCESS_KEY_ID", "access_key_id"),
            ("SYNCH_DP_S3_SECRET_ACCESS_KEY", "secret_access_key"),
        ],
        "gcs" => &[
            ("SYNCH_DP_GCS_BUCKET", "bucket"),
            ("SYNCH_DP_GCS_ENDPOINT", "endpoint"),
            ("SYNCH_DP_GCS_CREDENTIAL_PATH", "credential_path"),
        ],
        "azblob" => &[
            ("SYNCH_DP_AZBLOB_CONTAINER", "container"),
            ("SYNCH_DP_AZBLOB_ENDPOINT", "endpoint"),
            ("SYNCH_DP_AZBLOB_ACCOUNT_NAME", "account_name"),
            ("SYNCH_DP_AZBLOB_ACCOUNT_KEY", "account_key"),
        ],
        _ => &[],
    };
    for (env, option) in pairs {
        if let Ok(value) = std::env::var(env) {
            if !value.is_empty() {
                options.insert((*option).to_string(), value);
            }
        }
    }
}

fn require(key: &str) -> Result<String> {
    std::env::var(key).map_err(|_| DpError::Config(format!("{key} is required")))
}

fn parse<T: std::str::FromStr>(key: &str, default: T) -> Result<T> {
    match std::env::var(key) {
        Ok(value) => value
            .trim()
            .parse()
            .map_err(|_| DpError::Config(format!("{key} is not a number: {value}"))),
        Err(_) => Ok(default),
    }
}

fn truthy(key: &str) -> bool {
    matches!(
        std::env::var(key).unwrap_or_default().trim(),
        "1" | "true" | "yes"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(shard: u32, shards: u32) -> DpConfig {
        DpConfig {
            control_url: "https://cp.example".into(),
            token: "synchdp_x".into(),
            base_dir: PathBuf::from("/run/synch-dp"),
            shard,
            shards,
            shard_name: format!("dp-{shard}"),
            poll_interval: Duration::from_secs(60),
            objects: ObjectConfig {
                service: "memory".into(),
                options: HashMap::new(),
            },
            db_key: None,
            cache_bytes_total: 1024,
            max_tenants: 4,
            metrics_addr: None,
        }
    }

    /// Every network is served by exactly one shard — the property that makes
    /// a slot single-writer without any coordination (§7.2).
    #[test]
    fn every_network_lands_on_exactly_one_shard() {
        let shards = 4;
        for n in 0..200 {
            let key = format!("org{n}/net{n}");
            let owners = (0..shards)
                .filter(|shard| config(*shard, shards).serves(&key))
                .count();
            assert_eq!(owners, 1, "{key} had {owners} owners");
        }
    }

    /// A single shard serves everything, so the common deployment needs no
    /// hashing at all.
    #[test]
    fn one_shard_serves_everything() {
        let only = config(0, 1);
        for n in 0..50 {
            assert!(only.serves(&format!("org{n}/net{n}")));
        }
    }

    /// Growing the fleet must move roughly one in n, not reshuffle everything
    /// — that is the whole reason for rendezvous hashing over a modulus.
    #[test]
    fn growing_the_fleet_moves_about_one_in_n() {
        let keys: Vec<String> = (0..600).map(|n| format!("org{n}/net{n}")).collect();
        let owner = |key: &str, shards: u32| -> u32 {
            (0..shards)
                .find(|shard| config(*shard, shards).serves(key))
                .expect("some shard owns it")
        };
        let moved = keys
            .iter()
            .filter(|key| owner(key, 3) != owner(key, 4))
            .count();
        let fraction = moved as f64 / keys.len() as f64;
        // A modulus would move ~3/4 here; rendezvous moves ~1/4.
        assert!(
            fraction > 0.15 && fraction < 0.40,
            "moved {fraction} of tenants growing 3 -> 4 shards"
        );
    }

    #[test]
    fn the_cache_budget_is_split_across_the_shards_capacity() {
        let config = config(0, 1);
        assert_eq!(config.cache_bytes_per_tenant(), 256);
    }

    #[test]
    fn prefixes_are_keyed_by_network_not_by_shard() {
        // §7.2: everything durable about a tenant survives a shard handover
        // because no shard identity appears in any of these.
        let a = config(0, 4);
        let b = config(3, 4);
        assert_eq!(a.cas_root("acme", "prod"), b.cas_root("acme", "prod"));
        assert_eq!(a.db_prefix("acme", "prod"), b.db_prefix("acme", "prod"));
        assert_eq!(a.tenant_dir("acme", "prod"), b.tenant_dir("acme", "prod"));
    }
}
