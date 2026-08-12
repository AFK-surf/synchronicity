//! The `synch` command surface (§9.2).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// synchronicity — an omnipresent peer-to-peer file store.
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

    /// Increase log verbosity.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
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
    /// Print the OriginId and current device key(s).
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
    /// DNSSEC membership domains.
    Domain {
        /// The domain subcommand.
        #[command(subcommand)]
        command: DomainCommand,
    },
    /// Live peers, addresses, last sync, lag.
    Peers,
    /// Index a local directory as a space.
    Space {
        /// The space subcommand.
        #[command(subcommand)]
        command: SpaceCommand,
    },
    /// List entries.
    Ls {
        /// `[<origin>:]<space>[/<dir>]`. Defaults to the merged view.
        reference: String,
        /// Show every origin's entry, not just one per path.
        #[arg(long)]
        all: bool,
    },
    /// Show agreement and divergence across origins.
    Status {
        /// `<space>[/<path>]`.
        reference: Option<String>,
    },
    /// Verified streaming read to stdout.
    Cat {
        /// `<origin>:<space>/<path>`.
        reference: String,
        /// A byte range, as `START..END`, `START..`, or `..END`.
        #[arg(long)]
        range: Option<String>,
    },
    /// Fetch to a file.
    Get {
        /// `<origin>:<space>/<path>`.
        reference: String,
        /// Where to write. Defaults to the entry's file name.
        #[arg(short, long)]
        output: Option<PathBuf>,
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
    /// Connectivity, membership, equivocation, and GC report.
    Doctor {
        /// Rebuild the derived views from the authoritative trie.
        #[arg(long)]
        rebuild: bool,
    },
    /// Scan every configured space and publish the result.
    Scan,
}

/// `synch key ...`
///
/// Rotation is operator-driven end to end (§3.4): the node never polls its own
/// domain and never switches signing keys on its own.
#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// Generate the next device key and print the TXT record to publish.
    Rotate,
    /// Switch signing to a generated key, keeping the old one serving.
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
    /// Re-resolve every configured domain now.
    Refresh,
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
#[derive(Debug, Subcommand)]
pub enum MirrorCommand {
    /// Mirror a peer's space into a local directory.
    Add {
        /// `<origin>:<space>`.
        reference: String,
        /// The local directory.
        path: PathBuf,
    },
    /// Stop mirroring.
    Rm {
        /// `<origin>:<space>`.
        reference: String,
    },
    /// List mirrors.
    Ls,
    /// Bring every mirror up to date now.
    Sync,
}

/// `synch pin ...`
#[derive(Debug, Subcommand)]
pub enum PinCommand {
    /// Pin an object root.
    Add {
        /// The object root, hex.
        root: String,
    },
    /// Unpin an object root.
    Rm {
        /// The object root, hex.
        root: String,
    },
    /// List pinned objects.
    Ls,
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
    fn parses_the_documented_commands() {
        // Every §9.2 command must parse.
        for args in [
            vec!["synch", "init", "--id", "nas@cluster.example.com"],
            vec!["synch", "id"],
            vec!["synch", "key", "rotate"],
            vec!["synch", "key", "activate", "abc"],
            vec!["synch", "key", "retire", "abc"],
            vec!["synch", "key", "ls"],
            vec!["synch", "daemon", "run"],
            vec!["synch", "daemon", "status"],
            vec!["synch", "daemon", "stop"],
            vec!["synch", "trust", "add", "abc", "--as", "nas"],
            vec!["synch", "trust", "rebind", "nas@x.example", "abc"],
            vec!["synch", "trust", "rm", "nas@x.example"],
            vec!["synch", "trust", "ls"],
            vec!["synch", "domain", "add", "cluster.example.com"],
            vec!["synch", "domain", "ls"],
            vec!["synch", "space", "add", "media", "/srv/media"],
            vec!["synch", "space", "ls"],
            vec!["synch", "space", "rm", "media"],
            vec!["synch", "ls", "media/talks"],
            vec!["synch", "status", "media/a.txt"],
            vec!["synch", "cat", "nas@x:media/a.txt", "--range", "0..10"],
            vec!["synch", "get", "nas@x:media/a.txt", "-o", "/tmp/a"],
            vec!["synch", "take", "nas@x:media/a.txt"],
            vec!["synch", "log", "media/a.txt"],
            vec!["synch", "mirror", "add", "nas@x:media", "/mnt/nas"],
            vec!["synch", "mirror", "ls"],
            vec!["synch", "pin", "add", "aabb"],
            vec!["synch", "peers"],
            vec!["synch", "doctor"],
        ] {
            Cli::try_parse_from(&args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
    }

    #[test]
    fn global_flags_work_before_and_after_the_subcommand() {
        let cli = Cli::try_parse_from(["synch", "--offline", "id"]).unwrap();
        assert!(cli.offline);
        let cli = Cli::try_parse_from(["synch", "id", "--offline"]).unwrap();
        assert!(cli.offline);
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
