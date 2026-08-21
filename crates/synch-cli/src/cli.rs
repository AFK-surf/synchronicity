//! The `synch` command surface (§9.2).

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

/// synchronicity — an omnipresent peer-to-peer file store.
///
/// Every doc comment below is `--help` text first and rustdoc second, so a URL
/// in one is written the way a terminal should print it, without the angle
/// brackets rustdoc wants.
#[allow(rustdoc::bare_urls)]
#[derive(Debug, Parser)]
#[command(name = "synch", version, about, long_about = None)]
pub struct Cli {
    /// The data directory. Defaults to the platform data directory.
    #[arg(long, global = true, env = "SYNCH_DATA_DIR")]
    pub data_dir: Option<PathBuf>,

    /// CAS storage: local disk, S3, Google Cloud Storage, or Azure Blob.
    #[arg(
        long,
        global = true,
        env = "SYNCH_CAS_BACKEND",
        default_value = "local"
    )]
    pub cas_backend: CasBackendArg,

    /// Prefix/root below the selected cloud bucket or container.
    #[arg(long, global = true, env = "SYNCH_CLOUD_ROOT", default_value = "/")]
    pub cloud_root: String,

    /// Which fetched objects are uploaded to the cloud CAS.
    #[arg(
        long,
        global = true,
        env = "SYNCH_CLOUD_UPLOAD",
        default_value = "own+pinned"
    )]
    pub cloud_upload: CloudUploadArg,

    /// Maximum bytes used by the reconstructible cloud read cache. Without a
    /// value, maintenance evicts enough to keep 20% of its filesystem free.
    #[arg(long, global = true, env = "SYNCH_CLOUD_CACHE_BYTES")]
    pub cloud_cache_bytes: Option<u64>,

    /// S3 bucket (also used by compatible endpoints such as MinIO).
    #[arg(long, global = true, env = "SYNCH_S3_BUCKET")]
    pub s3_bucket: Option<String>,

    /// S3 signing region.
    #[arg(long, global = true, env = "SYNCH_S3_REGION")]
    pub s3_region: Option<String>,

    /// S3-compatible endpoint override.
    #[arg(long, global = true, env = "SYNCH_S3_ENDPOINT")]
    pub s3_endpoint: Option<String>,

    /// GCS bucket.
    #[arg(long, global = true, env = "SYNCH_GCS_BUCKET")]
    pub gcs_bucket: Option<String>,

    /// GCS endpoint override (primarily for test/emulator deployments).
    #[arg(long, global = true, env = "SYNCH_GCS_ENDPOINT")]
    pub gcs_endpoint: Option<String>,

    /// GCS service-account credential file.
    #[arg(long, global = true, env = "SYNCH_GCS_CREDENTIAL_PATH")]
    pub gcs_credential_path: Option<PathBuf>,

    /// Azure Blob container.
    #[arg(long, global = true, env = "SYNCH_AZBLOB_CONTAINER")]
    pub azblob_container: Option<String>,

    /// Azure Blob endpoint override (including Azurite).
    #[arg(long, global = true, env = "SYNCH_AZBLOB_ENDPOINT")]
    pub azblob_endpoint: Option<String>,

    /// Azure Storage account name.
    #[arg(long, global = true, env = "SYNCH_AZBLOB_ACCOUNT_NAME")]
    pub azblob_account_name: Option<String>,

    /// Azure Storage account key. Environment use is preferred.
    #[arg(
        long,
        global = true,
        env = "SYNCH_AZBLOB_ACCOUNT_KEY",
        hide_env_values = true
    )]
    pub azblob_account_key: Option<String>,

    /// Bind the endpoint to this address instead of an ephemeral port.
    #[arg(long, global = true)]
    pub bind: Option<String>,

    /// Disable relays and address discovery; reach peers by direct address only.
    #[arg(long, global = true)]
    pub offline: bool,

    /// The DNS-over-HTTP(S) endpoint membership TXT records resolve
    /// through; defaults to https://1.1.1.1/dns-query. http:// is accepted —
    /// answers are DNSSEC-validated in process either way.
    #[arg(long, global = true, env = "SYNCH_DOH", value_name = "URL")]
    pub doh: Option<String>,

    /// Replace the ICANN DNSSEC root trust anchor with this file of DNSKEY
    /// records (zone syntax, as `dig DNSKEY` prints) — for internal
    /// deployments and testing against a self-signed root.
    #[arg(long, global = true, env = "SYNCH_DNSSEC_ANCHOR", value_name = "FILE")]
    pub dnssec_anchor: Option<PathBuf>,

    /// Whether a membership answer additionally requires the zone key that
    /// signed it to carry a verified transparency-log record. The default
    /// is require — the Sigstore production log keys are built in — and
    /// off is a choice to state, not inherit, --dnssec-anchor or not.
    #[arg(long, global = true, env = "SYNCH_REKOR", value_name = "MODE")]
    pub rekor: Option<RekorMode>,

    /// Replace the built-in transparency-log key with this file of log
    /// verification key(s) — PEM PUBLIC KEY blocks, or one base64
    /// SubjectPublicKeyInfo per line — for a self-hosted log. As with
    /// --dnssec-anchor, an override is a different universe: nothing signed
    /// by the built-in log verifies any more.
    #[arg(long, global = true, env = "SYNCH_REKOR_KEY", value_name = "FILE")]
    pub rekor_key: Option<PathBuf>,

    /// Follow this Sigstore TUF repository instead of the official one, so
    /// the transparency-log pin set tracks it (docs/REKOR-ZONE-KEY.md §10).
    /// A mirror knob, not a trust knob: whatever it names, the metadata
    /// fetched under it is verified against the TUF root this build embeds.
    #[arg(long, global = true, env = "SYNCH_TUF", value_name = "URL")]
    pub tuf: Option<String>,

    /// Never contact Sigstore's TUF repository, leaving the pin set frozen
    /// at whatever this node last verified — or at the built-in snapshot.
    /// The cost is a new build the day Sigstore rotates a log (§10.4).
    #[arg(long, global = true, env = "SYNCH_NO_TUF")]
    pub no_tuf: bool,

    /// Dial and listen through this iroh relay server instead of n0's public
    /// relays; repeat for several. A relay forwards encrypted traffic only —
    /// choosing one is an availability decision, not a trust one (§3.3).
    /// Takes effect where the endpoint is bound: `synch daemon run`.
    #[arg(
        long,
        global = true,
        env = "SYNCH_RELAY",
        value_name = "URL",
        value_delimiter = ',',
        conflicts_with = "offline"
    )]
    pub relay: Vec<String>,

    /// Publish and resolve peer addresses through this pkarr relay — a
    /// self-hosted iroh-dns-server such as <https://dns.example.com/pkarr> —
    /// instead of n0's iroh.link. Discovery is addressing, not membership:
    /// it can strand a dial but never redirect one (§3.3). Takes effect
    /// where the endpoint is bound: `synch daemon run`.
    #[arg(
        long,
        global = true,
        env = "SYNCH_DISCOVERY",
        value_name = "URL",
        conflicts_with = "offline"
    )]
    pub discovery: Option<String>,

    /// Also publish and resolve peer addresses on the BitTorrent Mainline
    /// DHT, alongside the pkarr/DNS lookup. The same signed pkarr records,
    /// with no discovery server in the middle, so a node stays dialable when
    /// that server is down or blocked (§3.3). Takes effect where the endpoint
    /// is bound: `synch daemon run`.
    #[arg(long, global = true, env = "SYNCH_DHT", conflicts_with = "offline")]
    pub dht: bool,

    /// Bootstrap the DHT from these nodes instead of mainline's public ones;
    /// repeat for several. Pointing every node at your own bootstrap nodes
    /// gives the deployment a DHT of its own, reaching none of mainline's and
    /// reached by none of them. That covers the DHT leg only — pair it with
    /// --discovery to move the pkarr/DNS leg in house too (§3.3).
    #[arg(
        long,
        global = true,
        env = "SYNCH_DHT_BOOTSTRAP",
        value_name = "HOST:PORT",
        value_delimiter = ',',
        requires = "dht",
        conflicts_with = "offline"
    )]
    pub dht_bootstrap: Vec<String>,

    /// Publish this node's direct IP addresses to the DHT, not just its relay
    /// URLs. The DHT is a public index, so this tells anyone who asks where
    /// the node sits; it is for a node already answering on a public address,
    /// where it buys peers a dial without the relay round trip (§3.3).
    #[arg(
        long,
        global = true,
        env = "SYNCH_DHT_PUBLISH_ADDRS",
        requires = "dht",
        conflicts_with = "offline"
    )]
    pub dht_publish_addrs: bool,

    /// Increase log verbosity.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// The `--rekor` setting: whether zone-key transparency is enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RekorMode {
    /// Discard a validated answer whose zone key has no verified log record.
    Require,
    /// Do not consult the log at all.
    Off,
}

/// The configured CAS backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CasBackendArg {
    /// Durable local filesystem storage.
    Local,
    /// Amazon S3 or a compatible endpoint through OpenDAL.
    S3,
    /// Google Cloud Storage through OpenDAL.
    Gcs,
    /// Azure Blob Storage through OpenDAL.
    Azblob,
}

/// Cloud promotion policy for peer-fetched content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CloudUploadArg {
    /// Upload only content ingested on this node.
    Own,
    /// Also upload anything pinned here.
    #[value(name = "own+pinned")]
    OwnPinned,
    /// Upload every object fetched to completion.
    All,
}

impl From<CloudUploadArg> for synch_store::cloud::CloudUploadPolicy {
    fn from(value: CloudUploadArg) -> Self {
        match value {
            CloudUploadArg::Own => Self::Own,
            CloudUploadArg::OwnPinned => Self::OwnPinned,
            CloudUploadArg::All => Self::All,
        }
    }
}

impl CasBackendArg {
    /// The value persisted in the node database.
    pub fn as_str(self) -> &'static str {
        match self {
            CasBackendArg::Local => "local",
            CasBackendArg::S3 => "s3",
            CasBackendArg::Gcs => "gcs",
            CasBackendArg::Azblob => "azblob",
        }
    }
}

impl From<RekorMode> for synch_net::RekorPolicy {
    fn from(mode: RekorMode) -> Self {
        match mode {
            RekorMode::Require => synch_net::RekorPolicy::Require,
            RekorMode::Off => synch_net::RekorPolicy::Off,
        }
    }
}

/// The top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a device key and database.
    Init {
        /// The membership domain whose zone will name this node. Without it
        /// the device key is the identity and cannot rotate (§3.1).
        #[arg(long)]
        domain: Option<String>,
    },
    /// Print the OriginId, current device key(s), and where the name came from.
    Id,
    /// Device-key rotation.
    Key {
        /// The key subcommand.
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// Run or inspect the daemon.
    Daemon {
        /// The daemon subcommand.
        #[command(subcommand)]
        command: DaemonCommand,
    },
    /// Static membership.
    Trust {
        /// The trust subcommand.
        #[command(subcommand)]
        command: TrustCommand,
    },
    /// Delegate space-restricted access to another node's key.
    Delegate {
        /// The delegate subcommand.
        #[command(subcommand)]
        command: DelegateCommand,
    },
    /// DNSSEC membership domains.
    Domain {
        /// The domain subcommand.
        #[command(subcommand)]
        command: DomainCommand,
    },
    /// Live peers, addresses, last sync, lag.
    Peers,
    /// Run one anti-entropy exchange with every dialable peer, now.
    Sync,
    /// Index a local directory as a space.
    Space {
        /// The space subcommand.
        #[command(subcommand)]
        command: SpaceCommand,
    },
    /// List the unified tree, divergent paths marked with their version count.
    Ls {
        /// `[<origin>:]<space>[/<dir>]`. The origin-prefixed form lists one
        /// origin's view instead of the unified tree.
        reference: String,
        /// Show every version of every path, with its attestors.
        #[arg(long)]
        all: bool,
    },
    /// The version inspector: every version of a path, side by side.
    Status {
        /// `<space>[/<path>]`.
        reference: Option<String>,
    },
    /// Verified streaming read to stdout.
    Cat {
        /// `[<origin>:]<space>/<path>`. The bare form reads the version the
        /// policy selects; the origin-prefixed form pins one origin.
        reference: String,
        /// A byte range, as `START..END`, `START..`, or `..END`.
        #[arg(long)]
        range: Option<String>,
        /// Read this origin's version — the same thing as pinning it in the
        /// reference.
        #[arg(long, value_name = "ORIGIN")]
        from: Option<String>,
        /// Refuse to read a divergent path, and list its versions instead.
        #[arg(long, conflicts_with = "from")]
        strict: bool,
    },
    /// Fetch to a file.
    Get {
        /// `[<origin>:]<space>/<path>`.
        reference: String,
        /// Where to write. Defaults to the entry's file name.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Fetch this origin's version.
        #[arg(long, value_name = "ORIGIN")]
        from: Option<String>,
        /// Refuse to fetch a divergent path, and list its versions instead.
        #[arg(long, conflicts_with = "from")]
        strict: bool,
    },
    /// Adopt a peer's version as this node's own.
    Take {
        /// `<origin>:<space>/<path>`.
        reference: String,
    },
    /// Per-origin publish history for a path.
    Log {
        /// `[<origin>:]<space>/<path>`.
        reference: String,
    },
    /// Show which files differ between two origins' published trees.
    ///
    /// Name-status only (created/modified/deleted), no content is fetched.
    /// Compares this node's own tree against `--to` by default, or two remotes
    /// with `--from`.
    Compare {
        /// `<space>[/<dir>]` — the space, or a directory within it. No origin
        /// prefix: name origins with `--from` and `--to`.
        reference: String,
        /// The origin to compare against. Required.
        #[arg(long, value_name = "ORIGIN")]
        to: String,
        /// The baseline origin. Defaults to this node's own origin.
        #[arg(long, value_name = "ORIGIN")]
        from: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Continuous read-only materialization.
    Mirror {
        /// The mirror subcommand.
        #[command(subcommand)]
        command: MirrorCommand,
    },
    /// Keep content in the local store regardless of policy.
    Pin {
        /// The pin subcommand.
        #[command(subcommand)]
        command: PinCommand,
    },
    /// Resume publishing after key or database loss (§3.4).
    Recover {
        /// How long to collect peer summaries before lifting the publishing
        /// floor: a plain number of seconds, or a duration like `90m`, `1h`,
        /// `2h30m`. Defaults to one hour.
        #[arg(long)]
        wait: Option<String>,
        /// How far above the highest seq any peer advertised publishing
        /// resumes. Defaults to 1000.
        #[arg(long)]
        gap: Option<u64>,
    },
    /// Connectivity, membership, equivocation, and GC report.
    Doctor {
        /// Rebuild the derived views from the authoritative trie.
        #[arg(long)]
        rebuild: bool,
    },
    /// Scan every configured space and publish the result.
    Scan,
    /// The read-only tunnel to the control plane the zone names, on by
    /// default.
    Cloud {
        /// The cloud subcommand.
        #[command(subcommand)]
        command: CloudCommand,
    },
    /// Inspect or migrate the node's content-addressed storage backend.
    Cas {
        /// The CAS subcommand.
        #[command(subcommand)]
        command: CasCommand,
    },
}

/// `synch cas ...`
#[derive(Debug, Subcommand)]
pub enum CasCommand {
    /// Copy and verify every durable object into another backend, then switch.
    /// The daemon must be stopped; rerunning after interruption is safe.
    Migrate {
        /// Destination backend.
        #[arg(long, value_enum)]
        to: CasBackendArg,
    },
}

/// `synch cloud ...`
///
/// The tunnel is on by default: a daemon attaches to the control plane its
/// membership zone names and answers its read requests for every space this
/// node holds. Which spaces a dashboard may browse is not a local question —
/// the org admin's browsing toggle and the RBAC around it decide it on the
/// other end. The only local act is opting out. There is no `--url`: where to
/// attach is read from the same DNSSEC-validated zone that names the
/// membership.
#[derive(Debug, Subcommand)]
pub enum CloudCommand {
    /// Reopen the tunnel after `cloud disable`. It is on by default, so this
    /// is only ever an undo.
    Enable,
    /// Stop answering the control plane and drop any open tunnel.
    Disable,
    /// One line per control-plane endpoint of per membership domain: record
    /// found, attached, last error. An apex names every node of its control
    /// plane and this daemon holds a tunnel to each, so one node being down
    /// is its own line rather than a verdict on the domain.
    Status,
}

/// `synch key ...`
///
/// Rotation is operator-driven end to end (§3.4): the node never polls its own
/// domain and never switches signing keys on its own.
#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// Generate the next device key and print the TXT record to publish.
    Rotate,
    /// Switch signing to a generated key, keeping the old one serving. The
    /// global `--bind` names the new endpoint's HOST:PORT; without it the new
    /// key takes an ephemeral port, and the old address stays with the
    /// retiring endpoint until `key retire` frees it.
    Activate {
        /// The z-base-32 device key to activate.
        key: String,
    },
    /// Drop a retiring key's endpoint and delete its secret.
    Retire {
        /// The z-base-32 device key to delete.
        key: String,
    },
    /// List local device keys.
    Ls,
}

/// `synch daemon ...`
#[derive(Debug, Subcommand)]
pub enum DaemonCommand {
    /// Own the node: serve the control socket and run the anti-entropy,
    /// scanner, watcher, and maintenance loops.
    Run,
    /// Print the running node's current state.
    Status,
    /// Ask the running daemon to shut down.
    Stop,
}

/// `synch trust ...`
#[derive(Debug, Subcommand)]
pub enum TrustCommand {
    /// Trust a device key, or a zone whose members are resolved from DNS
    /// (§3.2).
    Add {
        /// A peer's z-base-32 device key, or a domain such as
        /// `cluster.example` whose member records this node should resolve.
        key: String,
        /// A note for `synch trust ls`.
        #[arg(long)]
        note: Option<String>,
        /// A direct address to remember for dialing.
        #[arg(long)]
        addr: Option<String>,
    },
    /// Remove trust.
    Rm {
        /// The origin to stop trusting, or a trusted zone.
        origin: String,
        /// Drop only this z-base-32 key's binding, keeping the origin's other
        /// keys — the cleanup step after a peer's rotation window closes.
        #[arg(long)]
        key: Option<String>,
    },
    /// List bindings.
    Ls,
}

/// `synch delegate ...`
#[derive(Debug, Subcommand)]
pub enum DelegateCommand {
    /// Delegate a device key into the cluster, confined to the named spaces.
    Add {
        /// The subject's z-base-32 device key.
        key: String,
        /// A space the delegation covers. Repeat for more than one.
        #[arg(long = "space", required = true)]
        spaces: Vec<String>,
        /// How long the delegation lasts, e.g. `7d`. Default 30d.
        #[arg(long)]
        until: Option<String>,
        /// A note for `trust ls` and `doctor`.
        #[arg(long)]
        note: Option<String>,
    },
    /// Withdraw a delegation this node issued.
    Rm {
        /// The subject's z-base-32 device key.
        key: String,
    },
    /// List every delegation this node honors, whoever issued it.
    Ls,
}

/// `synch domain ...`
#[derive(Debug, Subcommand)]
pub enum DomainCommand {
    /// Set the membership domain — the zone that names this node (§3.1).
    /// Takes effect at the next start.
    Set {
        /// The domain, e.g. `cluster.example.com`.
        domain: String,
        /// This node is a delegate: it belongs to the zone but is not named
        /// by it, so no record for its key is expected (§3.5).
        ///
        /// Without this, a zone that answers and does not name this node leaves
        /// the daemon waiting on a reduced socket for a record to appear —
        /// because on a first start that is indistinguishable from a record
        /// that has not propagated yet.
        #[arg(long)]
        delegate: bool,
    },
    /// Drop the membership domain and its bindings. The device key names the
    /// node again at the next start.
    Clear,
    /// Print the membership domain.
    Ls,
    /// Re-resolve the membership domain now.
    Refresh,
}

/// `synch space ...`
#[derive(Debug, Subcommand)]
pub enum SpaceCommand {
    /// Add a path-backed or detached space.
    Add {
        /// The space id.
        id: String,
        /// The local directory. Omit with `--detached`.
        #[arg(required_unless_present = "detached", conflicts_with = "detached")]
        path: Option<PathBuf>,
        /// Publish into the space without a local checkout, scanner, or watcher.
        #[arg(long)]
        detached: bool,
    },
    /// List configured spaces.
    Ls,
    /// Stop indexing a space and unpublish its entries.
    Rm {
        /// The space id.
        id: String,
    },
}

/// `synch mirror ...`
///
/// A mirror materializes one space of the unified tree into a directory under
/// a version policy (§7.2), so it is named by the directory it writes into.
#[derive(Debug, Subcommand)]
pub enum MirrorCommand {
    /// Mirror a space of the unified tree into a local directory.
    Add {
        /// The space id.
        space: String,
        /// The local directory.
        path: PathBuf,
        /// Which version of each path to write: `newest` (default),
        /// `origin=<id>`, or `strict`.
        #[arg(long)]
        policy: Option<String>,
    },
    /// Stop mirroring into a directory.
    Rm {
        /// The local directory.
        path: PathBuf,
    },
    /// List mirrors.
    Ls,
    /// Bring every mirror up to date now.
    Sync,
}

/// `synch pin ...`
#[derive(Debug, Subcommand)]
pub enum PinCommand {
    /// Pin an object root, or the version a path selects.
    Add {
        /// A hex object root, or `<space>/<path>` — whose selected version's
        /// content root is the one pinned (§8).
        target: String,
    },
    /// Unpin an object root, or the version a path selects.
    Rm {
        /// A hex object root, or `<space>/<path>`.
        target: String,
    },
    /// List pinned objects.
    Ls,
}

/// Parses a `--wait` duration: bare seconds, or `<n>d<n>h<n>m<n>s` in any
/// combination (`0`, `45`, `90m`, `1h`, `2h30m`).
///
/// Kept deliberately small: this is the only duration the command surface takes
/// and it does not warrant a dependency.
pub fn parse_duration(text: &str) -> anyhow::Result<std::time::Duration> {
    let text = text.trim();
    if text.is_empty() {
        anyhow::bail!("a duration looks like 30s, 90m, 1h, 2h30m, or a plain number of seconds");
    }
    if let Ok(seconds) = text.parse::<u64>() {
        return Ok(std::time::Duration::from_secs(seconds));
    }
    let mut total: u64 = 0;
    let mut digits = String::new();
    let mut saw_unit = false;
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
            continue;
        }
        let unit = match ch {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            other => anyhow::bail!("{other} is not a duration unit; use s, m, h, or d"),
        };
        let value: u64 = digits
            .parse()
            .map_err(|_| anyhow::anyhow!("{text}: every unit needs a number in front of it"))?;
        total = total
            .checked_add(value.saturating_mul(unit))
            .ok_or_else(|| anyhow::anyhow!("{text} is longer than this program can wait"))?;
        digits.clear();
        saw_unit = true;
    }
    if !saw_unit || !digits.is_empty() {
        anyhow::bail!("{text}: a duration looks like 30s, 90m, 1h, 2h30m, or plain seconds");
    }
    Ok(std::time::Duration::from_secs(total))
}

/// A parsed `--range` argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// The first byte, inclusive.
    pub start: u64,
    /// The last byte, exclusive. `None` means "to the end".
    pub end: Option<u64>,
}

impl ByteRange {
    /// Parses `START..END`, `START..`, `..END`, or `..`.
    pub fn parse(text: &str) -> anyhow::Result<ByteRange> {
        let (start, end) = text
            .split_once("..")
            .ok_or_else(|| anyhow::anyhow!("a range looks like START..END"))?;
        let start = if start.is_empty() { 0 } else { start.parse()? };
        let end = if end.is_empty() {
            None
        } else {
            Some(end.parse()?)
        };
        if let Some(end) = end {
            if end < start {
                anyhow::bail!("range end {end} is before its start {start}");
            }
        }
        Ok(ByteRange { start, end })
    }

    /// How many bytes the range covers, when it is bounded.
    pub fn length(&self) -> Option<u64> {
        self.end.map(|end| end.saturating_sub(self.start))
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn the_command_surface_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn dht_discovery_is_opt_in_and_never_mixes_with_offline() {
        let cli = Cli::parse_from(["synch", "daemon", "run"]);
        assert!(!cli.dht && cli.dht_bootstrap.is_empty());

        // The DHT joins the pkarr/DNS lookup rather than replacing it, so
        // --dht and --discovery are usable together.
        let cli = Cli::try_parse_from(
            "synch daemon run --dht --dht-bootstrap boot1.example:6881,boot2.example:6881 \
             --dht-publish-addrs --discovery https://dns.example.com/pkarr \
             --relay https://relay-a.example.com --relay https://relay-b.example.com"
                .split_whitespace(),
        )
        .unwrap();
        assert!(cli.dht && cli.dht_publish_addrs);
        assert_eq!(
            cli.dht_bootstrap.join(","),
            "boot1.example:6881,boot2.example:6881"
        );
        assert_eq!(
            cli.relay.join(","),
            "https://relay-a.example.com,https://relay-b.example.com"
        );
        assert_eq!(
            cli.discovery.as_deref(),
            Some("https://dns.example.com/pkarr")
        );

        // --offline refuses every network flag rather than quietly ignoring
        // it, the DHT sub-knobs need --dht, cat/get refuse --from with
        // --strict, and cloud enable takes no --space.
        for args in [
            "synch daemon run --offline --dht",
            "synch daemon run --offline --dht-bootstrap boot.example:6881",
            "synch daemon run --offline --dht-publish-addrs",
            "synch daemon run --offline --relay https://r.example.com",
            "synch daemon run --offline --discovery https://d.example.com",
            "synch daemon run --dht-bootstrap boot.example:6881",
            "synch daemon run --dht-publish-addrs",
            "synch cat media/a.txt --from nas@x --strict",
            "synch get media/a.txt --from nas@x --strict",
            "synch cloud enable --space media",
        ] {
            assert!(
                Cli::try_parse_from(args.split_whitespace()).is_err(),
                "{args}"
            );
        }
    }

    #[test]
    fn durations_parse() {
        for (text, secs) in [
            ("0", 0),
            ("45", 45),
            ("30s", 30),
            ("90m", 5_400),
            ("1h", 3_600),
            ("2h30m", 9_000),
            (" 1d ", 86_400),
        ] {
            assert_eq!(
                parse_duration(text).unwrap(),
                std::time::Duration::from_secs(secs),
                "{text}"
            );
        }
        for bad in ["", "soon", "1w", "1h30", "h"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ranges_parse() {
        for (text, start, end) in [
            ("10..20", 10, Some(20)),
            ("10..", 10, None),
            ("..20", 0, Some(20)),
        ] {
            let range = ByteRange::parse(text).unwrap();
            assert_eq!((range.start, range.end), (start, end), "{text}");
            assert_eq!(
                range.length(),
                end.map(|e| e.saturating_sub(start)),
                "{text}"
            );
        }
        for bad in ["20..10", "nonsense", "a..b"] {
            assert!(ByteRange::parse(bad).is_err(), "{bad}");
        }
    }
}
