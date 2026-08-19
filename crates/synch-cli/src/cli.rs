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
    /// Create an identity and database.
    Init {
        /// The stable origin id, as `<name>@<domain>`. Without it the device
        /// key is the identity and cannot rotate.
        #[arg(long)]
        id: Option<String>,
    },
    /// Print the OriginId and current device key(s), or name a key-identified node.
    Id {
        /// The id subcommand. With none, print the current identity.
        #[command(subcommand)]
        command: Option<IdCommand>,
    },
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
    /// Per membership domain: record found, attached, last error.
    Status,
}

/// `synch id set ...`
#[derive(Debug, Subcommand)]
pub enum IdCommand {
    /// Adopt a named origin for a key-identified node, without rotating the
    /// device key. The daemon must be stopped first; `synch scan` after it
    /// restarts publishes under the new name.
    Set {
        /// The stable origin id, as `<name>@<domain>`.
        id: String,
    },
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
    /// Trust a device key.
    Add {
        /// The peer's z-base-32 device key.
        key: String,
        /// Bind it to a named origin, which makes rotation available.
        #[arg(long = "as")]
        name: Option<String>,
        /// The membership domain for the named origin.
        #[arg(long)]
        domain: Option<String>,
        /// A note for `synch trust ls`.
        #[arg(long)]
        note: Option<String>,
        /// A direct address to remember for dialing.
        #[arg(long)]
        addr: Option<String>,
    },
    /// Point a named origin at a new device key.
    Rebind {
        /// The origin to rebind.
        origin: String,
        /// Its new z-base-32 device key.
        key: String,
    },
    /// Remove trust.
    Rm {
        /// The origin to stop trusting.
        origin: String,
        /// Drop only this z-base-32 key's binding, keeping the origin's other
        /// keys — the cleanup step after a peer's rotation window closes.
        #[arg(long)]
        key: Option<String>,
    },
    /// List bindings.
    Ls,
}

/// `synch domain ...`
#[derive(Debug, Subcommand)]
pub enum DomainCommand {
    /// Add a DNSSEC membership domain.
    Add {
        /// The domain, e.g. `cluster.example.com`.
        domain: String,
    },
    /// Remove a membership domain and its bindings.
    Rm {
        /// The domain.
        domain: String,
    },
    /// List configured membership domains.
    Ls,
    /// Re-resolve one configured domain now, or every one.
    Refresh {
        /// The domain to refresh. Omitted, every configured domain is.
        domain: Option<String>,
    },
}

/// `synch space ...`
#[derive(Debug, Subcommand)]
pub enum SpaceCommand {
    /// Index a local directory.
    Add {
        /// The space id.
        id: String,
        /// The local directory.
        path: PathBuf,
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
        assert!(!cli.dht);
        assert!(cli.dht_bootstrap.is_empty());
        assert!(!cli.dht_publish_addrs);

        // The DHT joins the pkarr/DNS lookup rather than replacing it, so
        // --dht and --discovery are usable together.
        let cli = Cli::parse_from([
            "synch",
            "daemon",
            "run",
            "--dht",
            "--dht-bootstrap",
            "boot1.example:6881,boot2.example:6881",
            "--dht-publish-addrs",
            "--discovery",
            "https://dns.example.com/pkarr",
        ]);
        assert!(cli.dht);
        assert_eq!(
            cli.dht_bootstrap,
            ["boot1.example:6881", "boot2.example:6881"]
        );
        assert!(cli.dht_publish_addrs);

        // --offline means nothing leaves the machine, so it refuses every DHT
        // flag rather than quietly ignoring it, as it already does for
        // --relay and --discovery.
        for args in [
            vec!["synch", "daemon", "run", "--offline", "--dht"],
            vec![
                "synch",
                "daemon",
                "run",
                "--offline",
                "--dht-bootstrap",
                "boot.example:6881",
            ],
            vec!["synch", "daemon", "run", "--offline", "--dht-publish-addrs"],
        ] {
            assert!(Cli::try_parse_from(&args).is_err(), "{args:?}");
        }

        // The DHT sub-knobs are meaningless without the DHT itself.
        for args in [
            vec![
                "synch",
                "daemon",
                "run",
                "--dht-bootstrap",
                "boot.example:6881",
            ],
            vec!["synch", "daemon", "run", "--dht-publish-addrs"],
        ] {
            assert!(Cli::try_parse_from(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn parses_the_documented_commands() {
        // Every §9.2 command must parse.
        for args in [
            vec!["synch", "init", "--id", "nas@cluster.example.com"],
            vec!["synch", "id"],
            vec!["synch", "id", "set", "orb@cluster.example.com"],
            vec!["synch", "key", "rotate"],
            vec!["synch", "key", "activate", "abc"],
            vec![
                "synch",
                "key",
                "activate",
                "abc",
                "--bind",
                "127.0.0.1:4433",
            ],
            vec!["synch", "key", "retire", "abc"],
            vec!["synch", "key", "ls"],
            vec!["synch", "daemon", "run"],
            vec!["synch", "daemon", "status"],
            vec!["synch", "daemon", "stop"],
            vec!["synch", "trust", "add", "abc", "--as", "nas"],
            vec![
                "synch",
                "trust",
                "add",
                "abc",
                "--as",
                "nas@cluster.example.com",
            ],
            vec!["synch", "sync"],
            vec!["synch", "trust", "rebind", "nas@x.example", "abc"],
            vec!["synch", "trust", "rm", "nas@x.example"],
            vec!["synch", "trust", "ls"],
            vec!["synch", "domain", "add", "cluster.example.com"],
            vec!["synch", "domain", "ls"],
            vec!["synch", "space", "add", "media", "/srv/media"],
            vec!["synch", "space", "ls"],
            vec!["synch", "space", "rm", "media"],
            vec!["synch", "ls", "media/talks"],
            vec!["synch", "ls", "nas@x:media/talks", "--all"],
            vec!["synch", "status", "media/a.txt"],
            vec!["synch", "cat", "media/a.txt", "--range", "0..10"],
            vec!["synch", "cat", "media/a.txt", "--from", "nas@x"],
            vec!["synch", "cat", "media/a.txt", "--strict"],
            vec!["synch", "cat", "nas@x:media/a.txt", "--range", "0..10"],
            vec!["synch", "get", "media/a.txt", "-o", "/tmp/a"],
            vec!["synch", "get", "media/a.txt", "--strict"],
            vec!["synch", "get", "nas@x:media/a.txt", "-o", "/tmp/a"],
            vec!["synch", "take", "nas@x:media/a.txt"],
            vec!["synch", "log", "media/a.txt"],
            vec!["synch", "compare", "media", "--to", "nas@x"],
            vec![
                "synch",
                "compare",
                "media/photos",
                "--from",
                "laptop@x",
                "--to",
                "nas@x",
            ],
            vec!["synch", "compare", "media", "--to", "nas@x", "--json"],
            vec!["synch", "mirror", "add", "media", "/mnt/nas"],
            vec![
                "synch", "mirror", "add", "media", "/mnt/nas", "--policy", "strict",
            ],
            vec!["synch", "mirror", "rm", "/mnt/nas"],
            vec!["synch", "mirror", "ls"],
            vec!["synch", "pin", "add", "aabb"],
            vec!["synch", "peers"],
            vec!["synch", "recover"],
            vec!["synch", "recover", "--wait", "90m", "--gap", "5000"],
            vec!["synch", "doctor"],
            vec!["synch", "cloud", "enable"],
            vec!["synch", "cloud", "disable"],
            vec!["synch", "cloud", "status"],
        ] {
            Cli::try_parse_from(&args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
    }

    /// `--space` named a local allowlist; the tunnel now serves whatever the
    /// control plane requests, so the flag is not part of the surface.
    #[test]
    fn cloud_enable_takes_no_space_list() {
        assert!(Cli::try_parse_from(["synch", "cloud", "enable", "--space", "media"]).is_err());
    }

    /// `--from` and `--strict` are two answers to the same question, so the
    /// command surface refuses both at once rather than picking one.
    #[test]
    fn from_and_strict_are_mutually_exclusive() {
        assert!(Cli::try_parse_from([
            "synch",
            "cat",
            "media/a.txt",
            "--from",
            "nas@x",
            "--strict"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "synch",
            "get",
            "media/a.txt",
            "--from",
            "nas@x",
            "--strict"
        ])
        .is_err());
    }

    #[test]
    fn global_flags_work_before_and_after_the_subcommand() {
        let cli = Cli::try_parse_from(["synch", "--offline", "id"]).unwrap();
        assert!(cli.offline);
        let cli = Cli::try_parse_from(["synch", "id", "--offline"]).unwrap();
        assert!(cli.offline);
    }

    #[test]
    fn relay_and_discovery_parse_and_conflict_with_offline() {
        let cli = Cli::try_parse_from([
            "synch",
            "--relay",
            "https://relay-a.example.com",
            "--relay",
            "https://relay-b.example.com",
            "--discovery",
            "https://dns.example.com/pkarr",
            "daemon",
            "run",
        ])
        .unwrap();
        assert_eq!(
            cli.relay,
            [
                "https://relay-a.example.com".to_string(),
                "https://relay-b.example.com".to_string()
            ]
        );
        assert_eq!(
            cli.discovery.as_deref(),
            Some("https://dns.example.com/pkarr")
        );
        // Offline means no relays and no discovery; both at once is a
        // mistake to refuse, not a combination to interpret.
        assert!(Cli::try_parse_from([
            "synch",
            "--offline",
            "--relay",
            "https://r.example.com",
            "id"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "synch",
            "--offline",
            "--discovery",
            "https://d.example.com",
            "id"
        ])
        .is_err());
    }

    #[test]
    fn durations_parse() {
        use std::time::Duration;
        assert_eq!(parse_duration("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_duration("45").unwrap(), Duration::from_secs(45));
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("90m").unwrap(), Duration::from_secs(5_400));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3_600));
        assert_eq!(parse_duration("2h30m").unwrap(), Duration::from_secs(9_000));
        assert_eq!(parse_duration(" 1d ").unwrap(), Duration::from_secs(86_400));

        assert!(parse_duration("").is_err());
        assert!(parse_duration("soon").is_err());
        assert!(parse_duration("1w").is_err());
        assert!(
            parse_duration("1h30").is_err(),
            "a trailing number is not a unit"
        );
        assert!(parse_duration("h").is_err());
    }

    #[test]
    fn ranges_parse() {
        assert_eq!(
            ByteRange::parse("10..20").unwrap(),
            ByteRange {
                start: 10,
                end: Some(20)
            }
        );
        assert_eq!(
            ByteRange::parse("10..").unwrap(),
            ByteRange {
                start: 10,
                end: None
            }
        );
        assert_eq!(
            ByteRange::parse("..20").unwrap(),
            ByteRange {
                start: 0,
                end: Some(20)
            }
        );
        assert_eq!(ByteRange::parse("10..20").unwrap().length(), Some(10));
        assert_eq!(ByteRange::parse("10..").unwrap().length(), None);
        assert!(ByteRange::parse("20..10").is_err());
        assert!(ByteRange::parse("nonsense").is_err());
        assert!(ByteRange::parse("a..b").is_err());
    }
}
