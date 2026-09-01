//! What one data plane is told, and how it reads it.
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

/// One data plane's settings.
#[derive(Debug, Clone)]
pub struct DpConfig {
    /// Base URL of the control plane, no trailing slash.
    pub control_url: String,
    /// The `synchdp_…` token.
    pub token: String,
    /// Where tenant data directories live, on the pod's ephemeral volume.
    pub base_dir: PathBuf,
    /// A name for this pod, for logs and the status heartbeat.
    ///
    /// A fallback only: the authoritative name is the one the control plane
    /// answers with (`Desired::dp`), because that is the name the assignment
    /// is written against. This is what a log line says before the first poll
    /// succeeds, and what the heartbeat carries if a control plane older than
    /// the assignment work answers without one.
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
    /// How many threads the shared blocking pool gets.
    ///
    /// Configuration rather than a constant in `main` because it is one half
    /// of a pair: every store touch of every tenant crosses this pool (§7.1),
    /// and [`max_inflight_per_tenant`](Self::max_inflight_per_tenant) is
    /// derived from it so that the shard's whole inbound demand has a
    /// ceiling. Two numbers chosen in two places would agree only by
    /// accident.
    pub blocking_threads: usize,
    /// How many inbound peer requests one tenant may have in flight at once.
    ///
    /// The bound that makes tenancy containment structural rather than
    /// social. DESIGN §12 declines per-peer limits deliberately: in an
    /// ordinary cluster every peer that can send a request is an authorized
    /// member, members are extended basic trust not to DoS each other, and a
    /// member behaving abusively is a membership problem whose remedy is
    /// `synch trust rm`. A shard cannot take that stance, because the
    /// membership belonging to org A is not org B's to curate while both
    /// share this process's blocking pool — so what §12 leaves to trust, this
    /// leaves to a semaphore.
    ///
    /// It is not a rate limit and an honest peer never meets it: a request
    /// that waits for a slot waits microseconds, and a tenant's store calls
    /// serialize on that tenant's one connection mutex regardless. What it
    /// removes is one tenant's ability to make its inbound work unbounded.
    pub max_inflight_per_tenant: usize,
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
    /// Memory-backed storage, everything else at its default. The
    /// caller adjusts what it cares about — `net` for a loopback endpoint,
    /// `rotate_after` to make a rotation due.
    pub fn for_test(base_dir: impl Into<PathBuf>, control_url: &str) -> Self {
        Self {
            control_url: control_url.trim_end_matches('/').to_string(),
            token: "synchdp_test".into(),
            base_dir: base_dir.into(),
            shard_name: "dp-test".into(),
            poll_interval: Duration::from_secs(60),
            objects: ObjectConfig {
                service: "memory".into(),
                options: HashMap::new(),
            },
            cache_bytes_total: 64 * 1024 * 1024,
            max_tenants: 4,
            replica_concurrency: synch_engine::DEFAULT_REPLICA_CONCURRENCY,
            blocking_threads: default_blocking_threads(4),
            max_inflight_per_tenant: default_max_inflight(default_blocking_threads(4), 4),
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
        // `SYNCH_DP_SHARD` and `SYNCH_DP_SHARDS` are gone, and their absence
        // is refused loudly rather than ignored. A pod still carrying them
        // was configured for a fleet that divided its own work by hashing;
        // starting anyway would host whatever the control plane assigned this
        // token, which may be a different set entirely, while the operator
        // believes the old arithmetic still holds.
        refuse_retired_sharding(&|key| std::env::var(key).is_ok())?;
        let shard_name = std::env::var("SYNCH_DP_SHARD_NAME").unwrap_or_else(|_| "dp".to_string());
        let poll_interval = Duration::from_secs(parse::<u64>("SYNCH_DP_POLL_SECS", 60)?.max(1));

        let service = std::env::var("SYNCH_DP_CAS_BACKEND").unwrap_or_else(|_| "s3".to_string());
        let mut options = HashMap::new();
        collect_options(&service, &mut options);
        let replica_concurrency = replica_concurrency(
            std::env::var("SYNCH_DP_REPLICA_CONCURRENCY")
                .ok()
                .as_deref(),
        )?;

        let max_tenants = parse::<u64>("SYNCH_DP_MAX_TENANTS", 64)?.max(1);
        let blocking_threads = match std::env::var("SYNCH_DP_BLOCKING_THREADS") {
            Ok(_) => parse::<usize>("SYNCH_DP_BLOCKING_THREADS", 0)?.max(1),
            Err(_) => default_blocking_threads(max_tenants),
        };
        let max_inflight_per_tenant = match std::env::var("SYNCH_DP_MAX_INFLIGHT_PER_TENANT") {
            Ok(_) => parse::<usize>("SYNCH_DP_MAX_INFLIGHT_PER_TENANT", 0)?.max(1),
            Err(_) => default_max_inflight(blocking_threads, max_tenants),
        };
        // Said once, at startup, where an operator who overrode one of the
        // pair can still act on it. Not a refusal: a deployment that knows its
        // tenants are quiet is entitled to oversubscribe, and refusing to boot
        // over a capacity ratio would be the service choosing its own outage.
        if max_inflight_per_tenant.saturating_mul(max_tenants as usize) > blocking_threads {
            tracing::warn!(
                max_inflight_per_tenant,
                max_tenants,
                blocking_threads,
                "this shard's tenants can ask for more concurrent blocking work than the \
                 pool has threads; one tenant's peers can then make another tenant wait"
            );
        }

        Ok(Self {
            control_url,
            token,
            base_dir,
            shard_name,
            poll_interval,
            objects: ObjectConfig { service, options },
            cache_bytes_total: parse("SYNCH_DP_CACHE_BYTES_TOTAL", 64 * 1024 * 1024 * 1024)?,
            max_tenants,
            replica_concurrency,
            blocking_threads,
            max_inflight_per_tenant,
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

    /// This data plane's name for its own cache, derived from its token.
    ///
    /// The cache key cannot be the data plane's *id*, however much it would
    /// prefer to be: the id arrives in the document, and the whole point of
    /// the cache is to be readable on a cold start when the control plane
    /// cannot be reached and no document has arrived. A pod that had to poll
    /// before it could find its own cache would have no fail-static path at
    /// all — which is the one §4.2 exists to provide.
    ///
    /// The token is what a pod does hold before it has spoken to anybody, and
    /// it names exactly one data plane (migration v14), so a fingerprint of it
    /// keys the cache per data plane without the pod having to be told
    /// anything twice. Eight bytes of BLAKE3, hex: the token is not
    /// recoverable from it, and the object sits in a bucket the deployment
    /// already trusts with tenant databases.
    ///
    /// Rotating a data plane's token therefore orphans its cache, and the
    /// next cold start during a control-plane outage has nothing to fall back
    /// on. That is a rare pairing of two rare events, and the alternative —
    /// a second environment variable naming the cache — reintroduces exactly
    /// the misconfiguration this design removed.
    pub fn cache_id(&self) -> String {
        let digest = blake3::hash(self.token.as_bytes());
        hex_of(&digest.as_bytes()[..8])
    }

    /// Where the fail-static desired-state cache lives (§4.2).
    pub fn desired_key(&self) -> String {
        format!("dp/{}/desired.json", self.cache_id())
    }
}

/// Refuses a pod still configured for the sharding this no longer does.
///
/// Silence would be the dangerous answer. A deployment carrying
/// `SYNCH_DP_SHARDS` was dividing the fleet's work by arithmetic each pod did
/// for itself; this build divides it by what the control plane assigned this
/// pod's token, which may be an entirely different set. Starting anyway would
/// host that set correctly while the operator went on believing the old
/// arithmetic held — and the two beliefs disagree most exactly where it hurts,
/// on which pod owns which tenant's database stream.
///
/// Takes the lookup rather than reading the environment, so the rule can be
/// stated in a test without a process-wide mutation racing every other test in
/// the binary.
fn refuse_retired_sharding(present: &dyn Fn(&str) -> bool) -> Result<()> {
    for retired in ["SYNCH_DP_SHARD", "SYNCH_DP_SHARDS"] {
        if present(retired) {
            return Err(DpError::Config(format!(
                "{retired} is no longer read: the control plane assigns \
                 networks to data planes by name now. Register this pod with \
                 `controlplane dataplane register <dp-id>`, mint its key with \
                 `--dp <dp-id>`, and unset {retired}"
            )));
        }
    }
    Ok(())
}

/// Lowercase hex, for the cache key. `hex` is not a dependency of this crate
/// and one byte-to-string loop does not earn one.
fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// How many blocking threads a shard sized for `max_tenants` gets.
///
/// A ceiling, not an allocation: tokio grows the pool on demand and reaps idle
/// threads, so a shard that is quiet costs nothing for a generous one. Floored
/// at the 512 this shipped with and capped so a large `SYNCH_DP_MAX_TENANTS`
/// cannot ask the kernel for an unbounded number of stacks.
///
/// The multiplier is what makes [`default_max_inflight`] able to give every
/// tenant a ceiling it will not meet in ordinary work and still leave half the
/// pool for the work no peer asked for: the reconciler's own passes, the
/// replication tickers, the heartbeats that are the billing record.
fn default_blocking_threads(max_tenants: u64) -> usize {
    let sized = max_tenants.saturating_mul(64);
    sized.clamp(512, 4096) as usize
}

/// The default per-tenant inbound ceiling for a pool of this size.
///
/// Half the pool, shared out. The other half is deliberately not spendable by
/// peers at all: a shard whose every thread is serving inbound requests is a
/// shard that cannot heartbeat, cannot converge, and cannot ship a database
/// tail — so the reconciler would lose its grip on its tenants at exactly the
/// moment one of them is being leaned on.
///
/// The floor is twice `synch_net`'s per-connection stream cap, and that is the
/// number that matters rather than a round one. A slot is held for the whole
/// of a request, the read included, so a peer that opens a stream and then
/// says nothing holds a slot until the 120 s stream timeout expires. One
/// connection can hold eight such streams. A ceiling at or below eight would
/// therefore let a single connection wedge its own tenant's endpoint, which
/// turns a bound meant to contain a tenant into a way to stop one.
///
/// It stays a bound on *this* tenant either way, which is the whole point: a
/// member that stalls streams against its own org's replica is DESIGN §12's
/// membership problem with §12's remedy, and the shard's other tenants —
/// which is what this service owes them — are untouched. The cap at 64 is
/// because more buys a single tenant almost nothing: its store calls
/// serialize on its one connection mutex whatever the ceiling.
fn default_max_inflight(blocking_threads: usize, max_tenants: u64) -> usize {
    let share = (blocking_threads / 2) / (max_tenants.max(1) as usize).max(1);
    share.clamp(MIN_INFLIGHT_PER_TENANT, 64)
}

/// The least a tenant's endpoint may be given.
///
/// Twice `synch_net::serve::MAX_CONCURRENT_STREAMS` — see
/// [`default_max_inflight`] for why that number and not a rounder one.
const MIN_INFLIGHT_PER_TENANT: usize = 16;

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

    fn config() -> DpConfig {
        DpConfig {
            control_url: "https://cp.example".into(),
            token: "synchdp_x".into(),
            base_dir: PathBuf::from("/run/synch-dp"),
            shard_name: "dp".into(),
            poll_interval: Duration::from_secs(60),
            objects: ObjectConfig {
                service: "memory".into(),
                options: HashMap::new(),
            },
            cache_bytes_total: 1024,
            max_tenants: 4,
            replica_concurrency: synch_engine::DEFAULT_REPLICA_CONCURRENCY,
            blocking_threads: 512,
            max_inflight_per_tenant: 8,
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
        let mut config = config();
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

    /// A pod still configured for the old sharding is refused, and told what
    /// to do instead.
    ///
    /// The alternative was ignoring the variables, and it is worse than it
    /// looks: the pod would host exactly what the control plane assigned it
    /// while its operator went on believing a shard count decided that — two
    /// beliefs that disagree precisely about which pod owns which tenant's
    /// database stream.
    #[test]
    fn a_pod_configured_for_the_old_sharding_is_refused() {
        assert!(refuse_retired_sharding(&|_| false).is_ok());
        for retired in ["SYNCH_DP_SHARD", "SYNCH_DP_SHARDS"] {
            let error = refuse_retired_sharding(&|key| key == retired)
                .expect_err("a retired setting must not be ignored");
            let said = error.to_string();
            assert!(said.contains(retired), "the refusal names it: {said}");
            assert!(
                said.contains("dataplane register"),
                "and names the remedy: {said}"
            );
        }
    }

    /// The fail-static cache is this data plane's alone, and it can be found
    /// before the control plane has been reached.
    ///
    /// Both halves matter. Two data planes sharing a bucket must not share a
    /// cache — one would boot into the other's tenant set — and the key
    /// therefore cannot be a constant. But it also cannot be the data plane's
    /// *id*, because the id arrives in the document and the cache exists
    /// precisely for the boot where no document arrives (§4.2). The token is
    /// the one thing a pod holds before it has spoken to anybody, and it names
    /// exactly one data plane.
    #[test]
    fn the_cache_key_is_per_data_plane_and_needs_no_poll_to_derive() {
        let mut one = config();
        one.token = "synchdp_first".into();
        let mut two = config();
        two.token = "synchdp_second".into();
        assert_ne!(one.desired_key(), two.desired_key());
        // Stable across restarts, because it is derived rather than drawn.
        assert_eq!(
            one.desired_key(),
            config_with_token("synchdp_first").desired_key()
        );
        // And it does not carry the token it was derived from.
        assert!(!one.desired_key().contains("synchdp_first"));
    }

    fn config_with_token(token: &str) -> DpConfig {
        let mut config = config();
        config.token = token.into();
        config
    }

    /// The two numbers that bound what a shard's peers can hold agree with
    /// each other at every size.
    ///
    /// This is the tenancy bound, not a tuning preference: a tenant's inbound
    /// requests each occupy a blocking-pool thread, and if the shard's tenants
    /// can collectively ask for more threads than the pool has, one org's
    /// devices can make another org's tenant wait — which is the multi-tenant
    /// failure the ceiling exists to remove. Half the pool, so the work no
    /// peer asked for (the reconcile pass, the replication tickers, the
    /// heartbeats that are the billing record) always has somewhere to run.
    #[test]
    fn a_shards_tenants_cannot_collectively_outbid_its_blocking_pool() {
        for max_tenants in [1u64, 4, 16, 64, 256, 1024, 4096] {
            let threads = default_blocking_threads(max_tenants);
            let each = default_max_inflight(threads, max_tenants);
            assert!(
                each >= MIN_INFLIGHT_PER_TENANT,
                "{max_tenants} tenants: {each} is at or below the per-connection \
                 stream cap, so one connection could wedge its own tenant"
            );
            // The floor is allowed to win on a shard configured for more
            // tenants than its pool can seat — see `default_max_inflight` for
            // why that floor is not negotiable — so the invariant is stated
            // where it can hold: wherever the share is what the arithmetic
            // returned, it fits inside half the pool.
            if each > MIN_INFLIGHT_PER_TENANT {
                assert!(
                    each * max_tenants as usize <= threads / 2,
                    "{max_tenants} tenants x {each} in flight overruns {threads} threads"
                );
            }
        }
        // The shipped default is comfortably inside it.
        let threads = default_blocking_threads(64);
        assert_eq!(default_max_inflight(threads, 64) * 64, threads / 2);
    }

    /// And a deployment that oversubscribes on purpose is told, not refused.
    #[test]
    fn an_oversubscribed_shard_is_still_a_shard() {
        // The clamp is what produces this: 4 096 tenants on 4 096 threads
        // cannot each have a floor's worth, and the honest answer is to run
        // anyway and say so rather than to refuse to boot over a ratio.
        let threads = default_blocking_threads(4096);
        assert_eq!(default_max_inflight(threads, 4096), MIN_INFLIGHT_PER_TENANT);
        assert!(MIN_INFLIGHT_PER_TENANT * 4096 > threads);
    }

    #[test]
    fn the_cache_budget_is_split_across_the_shards_capacity() {
        let config = config();
        assert_eq!(config.cache_bytes_per_tenant(), 256);
    }

    #[test]
    fn prefixes_are_keyed_by_network_not_by_shard() {
        // §7.2: everything durable about a tenant survives a shard handover
        // because no shard identity appears in any of these.
        let a = config();
        let b = config();
        assert_eq!(a.cas_root("acme", "prod"), b.cas_root("acme", "prod"));
        assert_eq!(a.db_prefix("acme", "prod"), b.db_prefix("acme", "prod"));
        assert_eq!(a.tenant_dir("acme", "prod"), b.tenant_dir("acme", "prod"));
    }
}
