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
    /// Total cache budget across all tenants on this pod.
    pub cache_bytes_total: u64,
    /// How many tenants this pod is sized for. Divides the cache budget.
    pub max_tenants: u64,
    /// How many distinct CAS objects each tenant fetches concurrently (1-256).
    pub replica_concurrency: usize,
    /// Where to serve Prometheus metrics, when asked to.
    pub metrics_addr: Option<String>,
    /// How each tenant's endpoint is bound.
    ///
    /// The default is an ephemeral port on every interface, which is what a
    /// pod wants. A deployment pins relay URLs or discovery here; a test
    /// makes it loopback so a tenant talks only to the node beside it.
    pub net: synch_net::NetOptions,
    /// How every tenant resolves its membership zone.
    ///
    /// The daemon exposes this as `--doh` / `--dnssec-anchor` / `--rekor`; a
    /// fleet needs it for the same reasons, and additionally because
    /// *identity settles at open* — a tenant whose node cannot resolve its
    /// zone never learns its own name, whatever resolver is installed
    /// afterwards.
    pub dns: synch_net::ResolverOptions,
    /// How old the hosted device key may get before it is rotated (§6).
    pub rotate_after: Duration,
    /// How long the old key stays published after the new one signs.
    pub retire_after: Duration,
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
        // OpenDAL's default features are disabled so dependencies cannot pick
        // a TLS provider for this process. That also disables its pre-main
        // HTTP transport registration, so every shipped constructor must
        // install the enabled reqwest transport explicitly before S3/GCS/Azure
        // is first used. `CloudStore::open` does the same for ordinary nodes.
        opendal::install_default();
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
    /// A configuration for a test or an embedder driving the pieces directly.
    ///
    /// Memory-backed storage, one shard, everything else at its default. The
    /// caller adjusts what it cares about — `net` for a loopback endpoint,
    /// `rotate_after` to make a rotation due.
    pub fn for_test(base_dir: impl Into<PathBuf>, control_url: &str) -> Self {
        Self {
            control_url: control_url.trim_end_matches('/').to_string(),
            token: "synchdp_test".into(),
            base_dir: base_dir.into(),
            shard: 0,
            shards: 1,
            shard_name: "dp-test".into(),
            poll_interval: Duration::from_secs(60),
            objects: ObjectConfig {
                service: "memory".into(),
                options: HashMap::new(),
            },
            cache_bytes_total: 64 * 1024 * 1024,
            max_tenants: 4,
            replica_concurrency: synch_engine::DEFAULT_REPLICA_CONCURRENCY,
            metrics_addr: None,
            net: synch_net::NetOptions::default(),
            dns: synch_net::ResolverOptions::default(),
            rotate_after: crate::rotation::DEFAULT_ROTATE_AFTER,
            retire_after: crate::rotation::DEFAULT_RETIRE_AFTER,
        }
    }

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
        let replica_concurrency = replica_concurrency(
            std::env::var("SYNCH_DP_REPLICA_CONCURRENCY")
                .ok()
                .as_deref(),
        )?;

        Ok(Self {
            control_url,
            token,
            base_dir,
            shard,
            shards,
            shard_name,
            poll_interval,
            objects: ObjectConfig { service, options },
            cache_bytes_total: parse("SYNCH_DP_CACHE_BYTES_TOTAL", 64 * 1024 * 1024 * 1024)?,
            max_tenants: parse::<u64>("SYNCH_DP_MAX_TENANTS", 64)?.max(1),
            replica_concurrency,
            metrics_addr: std::env::var("SYNCH_DP_METRICS_ADDR").ok(),
            net: synch_net::NetOptions::default(),
            dns: synch_net::ResolverOptions {
                doh_url: std::env::var("SYNCH_DP_DOH").ok(),
                trust_anchor: std::env::var("SYNCH_DP_DNSSEC_ANCHOR")
                    .ok()
                    .map(PathBuf::from),
                rekor: Some(parse_rekor()?),
                ..synch_net::ResolverOptions::default()
            },
            // Settable so a test can exercise a rotation without waiting a
            // quarter of a year for one; not documented as an operator knob,
            // because the defaults are the policy (`rotation`).
            rotate_after: Duration::from_secs(parse::<u64>(
                "SYNCH_DP_ROTATE_AFTER_SECS",
                crate::rotation::DEFAULT_ROTATE_AFTER.as_secs(),
            )?),
            retire_after: Duration::from_secs(parse::<u64>(
                "SYNCH_DP_RETIRE_AFTER_SECS",
                crate::rotation::DEFAULT_RETIRE_AFTER.as_secs(),
            )?),
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

    /// Refuses a deployment that cannot replicate tenant databases.
    ///
    /// Asked once at startup rather than discovered one tenant at a time. A
    /// shard whose backend has no replication client would provision nodes,
    /// mint their device keys, get them named in customer zones, and then
    /// lose every one of them on its first reschedule — so the honest
    /// failure is to refuse to start (§5.3).
    pub fn check_db_replication(&self) -> Result<()> {
        self.db_client("preflight", "preflight").map(|_| ())
    }

    /// The replication client for one tenant's database stream.
    ///
    /// `celld-ltx` brings its own storage client rather than OpenDAL, so this
    /// is configured from the same environment as the CAS instead of sharing
    /// its operator. Two clients, one bucket, separate prefixes — which is
    /// what §5.1 already asks for.
    ///
    /// It also brings only two: S3-compatible object storage, and a local
    /// directory. So a GCS or Azure deployment is refused here rather than
    /// handed an S3 client pointed at a bucket that does not exist — the
    /// database stream is the only durable copy of a tenant's identity
    /// (§5.3), and a deployment that cannot write one must fail to start
    /// rather than run and lose it.
    pub fn db_client(&self, org: &str, network: &str) -> Result<crate::dbrepl::DbClient> {
        let options = &self.objects.options;
        let get = |key: &str| options.get(key).cloned().unwrap_or_default();
        match self.objects.service.as_str() {
            "s3" => Ok(crate::dbrepl::DbClient::Objects(Box::new(
                celld_ltx::ObjectStoreClient::new(celld_ltx::ObjectStoreConfig {
                    bucket: get("bucket"),
                    path: self.db_prefix(org, network),
                    region: get("region"),
                    endpoint: get("endpoint"),
                    access_key_id: get("access_key_id"),
                    secret_access_key: get("secret_access_key"),
                    // A custom endpoint is MinIO/R2/Backblaze in practice, and
                    // all of them want path-style addressing; native AWS does
                    // not.
                    force_path_style: !get("endpoint").is_empty(),
                    ..Default::default()
                }),
            ))),
            // The CAS's `memory` service is for tests, and so is this: a
            // directory beside the tenant data rather than inside the bucket.
            // It is named for the CAS backend it accompanies, not for what it
            // does — nothing durable is expected of either.
            "memory" => Ok(crate::dbrepl::DbClient::Files(
                celld_ltx::FileReplicaClient::new(
                    self.db_stream_dir(org, network)
                        .to_string_lossy()
                        .to_string(),
                ),
            )),
            other => Err(DpError::Config(format!(
                "cloud hosting cannot replicate tenant databases to {other}: \
                 the replication library supports S3-compatible storage only, \
                 and a deployment without a database stream would lose every \
                 tenant identity on the first reschedule"
            ))),
        }
    }

    /// Where a `memory`-backed deployment keeps its database streams.
    pub fn db_stream_dir(&self, org: &str, network: &str) -> PathBuf {
        self.base_dir.join("db").join(org).join(network)
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

fn replica_concurrency(value: Option<&str>) -> Result<usize> {
    let value = match value {
        None => return Ok(synch_engine::DEFAULT_REPLICA_CONCURRENCY),
        Some(value) => value,
    };
    match value.trim().parse::<usize>() {
        Ok(0) => Err(DpError::Config(
            "SYNCH_DP_REPLICA_CONCURRENCY must be at least 1".into(),
        )),
        Ok(value) if value > synch_engine::MAX_REPLICA_CONCURRENCY => {
            Err(DpError::Config(format!(
                "SYNCH_DP_REPLICA_CONCURRENCY must be at most {}",
                synch_engine::MAX_REPLICA_CONCURRENCY
            )))
        }
        Ok(value) => Ok(value),
        Err(_) => Err(DpError::Config(format!(
            "SYNCH_DP_REPLICA_CONCURRENCY is not a number: {value}"
        ))),
    }
}

/// Reads the zone-key transparency policy.
///
/// `require` remains the default. `off` exists for private deployments whose
/// DNSSEC root is deliberately not published to the public transparency log,
/// matching the ordinary daemon's explicit `--rekor off` escape hatch.
fn parse_rekor() -> Result<synch_net::RekorPolicy> {
    match std::env::var("SYNCH_DP_REKOR") {
        Err(_) => Ok(synch_net::RekorPolicy::Require),
        Ok(value) if value.eq_ignore_ascii_case("require") => Ok(synch_net::RekorPolicy::Require),
        Ok(value) if value.eq_ignore_ascii_case("off") => Ok(synch_net::RekorPolicy::Off),
        Ok(value) => Err(DpError::Config(format!(
            "SYNCH_DP_REKOR must be `require` or `off`, got `{value}`"
        ))),
    }
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
            cache_bytes_total: 1024,
            max_tenants: 4,
            replica_concurrency: synch_engine::DEFAULT_REPLICA_CONCURRENCY,
            metrics_addr: None,
            net: synch_net::NetOptions::default(),
            dns: synch_net::ResolverOptions::default(),
            rotate_after: crate::rotation::DEFAULT_ROTATE_AFTER,
            retire_after: crate::rotation::DEFAULT_RETIRE_AFTER,
        }
    }

    /// The replication library speaks S3 and local files, and nothing else.
    /// A backend it cannot write is a shard that would mint device keys, get
    /// them named in customer zones, and lose them all on its first
    /// reschedule — so it has to be refused before any of that (§5.3).
    #[test]
    fn a_backend_without_database_replication_refuses_to_start() {
        let mut config = config(0, 1);
        for service in ["s3", "memory"] {
            config.objects.service = service.into();
            assert!(
                config.check_db_replication().is_ok(),
                "{service} should be replicable"
            );
        }
        for service in ["gcs", "azblob"] {
            config.objects.service = service.into();
            let error = config
                .check_db_replication()
                .expect_err("a backend with no replication client must be refused");
            assert!(
                error.to_string().contains(service),
                "the refusal should name the backend: {error}"
            );
        }
    }

    #[test]
    fn replica_concurrency_defaults_to_sixteen_and_is_configurable() {
        assert_eq!(
            replica_concurrency(None).unwrap(),
            synch_engine::DEFAULT_REPLICA_CONCURRENCY
        );
        assert_eq!(replica_concurrency(Some(" 23 ")).unwrap(), 23);
        let too_large = (synch_engine::MAX_REPLICA_CONCURRENCY + 1).to_string();
        for invalid in ["0", "many", &too_large] {
            let error = replica_concurrency(Some(invalid)).unwrap_err();
            assert!(
                error.to_string().contains("SYNCH_DP_REPLICA_CONCURRENCY"),
                "the error should name the setting: {error}"
            );
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
