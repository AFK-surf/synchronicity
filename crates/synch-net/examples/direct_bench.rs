//! A benchmark of a direct-TCP run against the QUIC streamed run it replaces
//! (`docs/DIRECT-TCP.md`).
//!
//! The provider runs in a child process of its own, so the CPU each side
//! spends is measured separately, from `/proc` or `ps`. Both ends are real `Net`
//! endpoints on loopback with static trust, and the requester reads the whole
//! object as one run through `BlobClient::stream_run` or
//! `BlobClient::stream_run_direct`, verifying every group as it arrives, as a
//! transient read does. Rounds alternate between the two paths so neither
//! gets a warmer cache.
//!
//! ```sh
//! cargo run --release -p synch-net --example direct_bench
//! cargo run --release -p synch-net --example direct_bench -- --mib 4096 --rounds 5
//! ```
//!
//! Loopback has no propagation delay and no bandwidth ceiling, so what this
//! measures is each path's cost per byte — the work the design expects to
//! differ — not how either behaves over a real link.

use std::{
    io::{BufRead, Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use iroh::{EndpointAddr, TransportAddr};
use iroh_base::{PublicKey, SecretKey};
use synch_core::{now_ns, GroupRange, Hash, NodeId, OriginId};
use synch_net::{BlobClient, Net, NetOptions};
use synch_store::{Binding, BindingSource, Store};

/// How large the object is, in MiB.
const DEFAULT_MIB: u64 = 1024;
/// How many times each path reads it.
const DEFAULT_ROUNDS: usize = 3;
/// The piece a transient read hands out (`synch-engine`'s `TRANSIENT_PIECE`).
const PIECE: usize = 256 * 1024;
/// Linux's `USER_HZ`, the unit of `/proc/<pid>/stat`'s CPU times.
const CLOCK_TICKS: f64 = 100.0;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    match args.first().map(String::as_str) {
        Some("serve") => runtime.block_on(serve(&args[1..])),
        _ => runtime.block_on(bench(Options::parse(&args))),
    }
}

#[derive(Debug)]
struct Options {
    mib: u64,
    rounds: usize,
    /// Read over one path only, for profiling it.
    only: Option<Route>,
}

impl Options {
    fn parse(args: &[String]) -> Options {
        let mut options = Options {
            mib: DEFAULT_MIB,
            rounds: DEFAULT_ROUNDS,
            only: None,
        };
        let mut args = args.iter();
        while let Some(flag) = args.next() {
            let value = args
                .next()
                .unwrap_or_else(|| panic!("{flag} wants a value"));
            match flag.as_str() {
                "--mib" => options.mib = value.parse().expect("--mib wants a number"),
                "--rounds" => options.rounds = value.parse().expect("--rounds wants a number"),
                "--only" => {
                    options.only = Some(match value.as_str() {
                        "quic" => Route::Quic,
                        "direct" => Route::Direct,
                        other => panic!("--only wants quic or direct, not {other}"),
                    })
                }
                other => {
                    panic!("unknown flag {other}; try --mib N --rounds N [--only quic|direct]")
                }
            }
        }
        options
    }
}

/// The provider: serves `<dir>/provider` under the given key, trusting the
/// given requester, until its stdin closes.
async fn serve(args: &[String]) {
    let [dir, secret, requester] = args else {
        panic!("serve <dir> <secret hex> <requester key hex>");
    };
    let secret = SecretKey::from_bytes(&decode32(secret));
    let requester = PublicKey::from_bytes(&decode32(requester)).expect("a requester key");
    let store = open_store(&Path::new(dir).join("provider")).await;
    trust(&store, requester);
    let net = Net::bind(
        store,
        secret,
        NetOptions {
            direct_listen: Some("127.0.0.1:0".parse().unwrap()),
            ..NetOptions::loopback()
        },
    )
    .await
    .expect("the provider binds");
    let addr = net
        .direct_addr()
        .ip_addrs()
        .next()
        .copied()
        .expect("a loopback address");
    println!("{addr}");
    std::io::stdout().flush().unwrap();
    tokio::task::spawn_blocking(|| {
        let _ = std::io::stdin().read_to_end(&mut Vec::new());
    })
    .await
    .unwrap();
    net.shutdown().await.unwrap();
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Route {
    Quic,
    Direct,
}

#[derive(Debug)]
struct Sample {
    seconds: f64,
    requester_cpu: f64,
    provider_cpu: f64,
}

async fn bench(options: Options) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let size = options.mib * 1024 * 1024;
    println!(
        "direct-TCP vs QUIC streamed run — {} MiB object, {} rounds each, loopback",
        options.mib, options.rounds
    );
    let root = {
        let object = dir.path().join("object");
        write_object(&object, size);
        let store = open_store(&dir.path().join("provider")).await;
        let started = Instant::now();
        let root = tokio::task::spawn_blocking(move || {
            store.ingest_file(&object, now_ns()).expect("ingest").0
        })
        .await
        .unwrap();
        std::fs::remove_file(dir.path().join("object")).unwrap();
        println!("ingested in {:.1}s", started.elapsed().as_secs_f64());
        root
    };
    encode_ceiling(&dir.path().join("provider"), root, size, options.mib).await;

    let provider_secret = SecretKey::generate();
    let requester_secret = SecretKey::generate();
    let mut provider = Command::new(std::env::current_exe().unwrap())
        .args([
            "serve",
            dir.path().to_str().unwrap(),
            &hex::encode(provider_secret.to_bytes()),
            &hex::encode(requester_secret.public().as_bytes()),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the provider starts");
    let mut line = String::new();
    std::io::BufReader::new(provider.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let provider_addr: SocketAddr = line.trim().parse().expect("the provider's address");

    let client_dir = tempfile::tempdir().unwrap();
    let store = open_store(client_dir.path()).await;
    trust(&store, provider_secret.public());
    let net = Net::bind(
        store,
        requester_secret,
        NetOptions {
            direct_dial: true,
            ..NetOptions::loopback()
        },
    )
    .await
    .expect("the requester binds");
    let blob = net
        .connect_blob(EndpointAddr::from_parts(
            provider_secret.public(),
            [TransportAddr::Ip(provider_addr)],
        ))
        .await
        .expect("the requester connects");
    let run = GroupRange::new(0, synch_core::group_count(size));

    let routes: Vec<Route> = match options.only {
        Some(route) => vec![route],
        None => vec![Route::Quic, Route::Direct],
    };
    let mut samples: Vec<(Route, Sample)> = Vec::new();
    for _ in 0..options.rounds {
        for &path in &routes {
            let sample = read_once(&blob, path, root, size, run, provider.id()).await;
            println!(
                "  {:<6} {:>8.0} MiB/s   requester {:.2} CPU-s/GiB   provider {:.2} CPU-s/GiB",
                label(path),
                options.mib as f64 / sample.seconds,
                sample.requester_cpu / gib(size),
                sample.provider_cpu / gib(size),
            );
            samples.push((path, sample));
        }
    }

    println!("\nmedian of {} rounds:", options.rounds);
    println!(
        "  {:<6} {:>10} {:>16} {:>16}",
        "path", "MiB/s", "requester CPU", "provider CPU"
    );
    let mut rates = Vec::new();
    for &path in &routes {
        let of = |pick: fn(&Sample) -> f64| {
            median(
                samples
                    .iter()
                    .filter(|(p, _)| *p == path)
                    .map(|(_, s)| pick(s))
                    .collect(),
            )
        };
        let rate = options.mib as f64 / of(|s| s.seconds);
        rates.push(rate);
        println!(
            "  {:<6} {:>10.0} {:>11.2} s/GiB {:>11.2} s/GiB",
            label(path),
            rate,
            of(|s| s.requester_cpu) / gib(size),
            of(|s| s.provider_cpu) / gib(size),
        );
    }
    if let [quic, direct] = rates[..] {
        println!("  direct/QUIC throughput: {:.2}x", direct / quic);
    }

    net.shutdown().await.unwrap();
    drop(provider.stdin.take());
    provider.wait().unwrap();
}

/// Times the provider's half of a run with no transport at all: every
/// window encoded one after another, as `serve_run` encodes them. Neither
/// path can stream faster than this, so it says which side bounds a run.
async fn encode_ceiling(dir: &Path, root: Hash, size: u64, mib: u64) {
    let store = open_store(dir).await;
    let groups = synch_core::group_count(size);
    let started = Instant::now();
    tokio::task::spawn_blocking(move || {
        for start in (0..groups).step_by(synch_core::STREAM_WINDOW_GROUPS as usize) {
            let window = synch_core::ChunkRanges::single(
                start,
                groups.min(start + synch_core::STREAM_WINDOW_GROUPS),
            );
            store
                .encode_slice(&root, &window)
                .expect("an encoded window");
        }
    })
    .await
    .unwrap();
    println!(
        "provider encode alone, one window at a time: {:.0} MiB/s",
        mib as f64 / started.elapsed().as_secs_f64()
    );
}

/// Reads the whole run once over `path`, verifying it, and reports the wall
/// time and the CPU each process spent.
async fn read_once(
    blob: &BlobClient,
    path: Route,
    root: Hash,
    size: u64,
    run: GroupRange,
    provider: u32,
) -> Sample {
    let (requester_before, provider_before) =
        (cpu_seconds("self"), cpu_seconds(&provider.to_string()));
    let started = Instant::now();
    let mut stream = match path {
        Route::Quic => blob.stream_run(root, size, run, PIECE).await,
        Route::Direct => blob.stream_run_direct(root, size, run, PIECE).await,
    }
    .expect("the run starts");
    assert_eq!(stream.is_direct(), path == Route::Direct);
    let mut got = 0u64;
    while let Some(pieces) = stream.next_window().await.expect("a verified window") {
        got += pieces.iter().map(|piece| piece.len() as u64).sum::<u64>();
    }
    let seconds = started.elapsed().as_secs_f64();
    assert_eq!(got, size, "the whole object arrives");
    drop(stream);
    // Let the provider's side of the run wind down before its CPU is read.
    tokio::time::sleep(Duration::from_millis(200)).await;
    Sample {
        seconds,
        requester_cpu: cpu_seconds("self") - requester_before,
        provider_cpu: cpu_seconds(&provider.to_string()) - provider_before,
    }
}

fn label(path: Route) -> &'static str {
    match path {
        Route::Quic => "QUIC",
        Route::Direct => "direct",
    }
}

fn gib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0 * 1024.0)
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

/// User plus system CPU time of every thread of a process, in seconds:
/// from `/proc` on Linux, from `ps` elsewhere.
fn cpu_seconds(pid: &str) -> f64 {
    if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        // The command name may hold spaces; the fields after it do not.
        let fields: Vec<&str> = stat[stat.rfind(')').unwrap() + 2..].split(' ').collect();
        let ticks: u64 = fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap();
        return ticks as f64 / CLOCK_TICKS;
    }
    let pid = match pid {
        "self" => std::process::id().to_string(),
        pid => pid.to_string(),
    };
    let out = Command::new("ps")
        .args(["-o", "time=", "-p", &pid])
        .output()
        .expect("ps runs");
    // `[[hh:]mm:]ss.cc`
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .split(':')
        .fold(0.0, |total, part| {
            total * 60.0 + part.parse::<f64>().unwrap_or(0.0)
        })
}

/// Writes `size` bytes no two groups of which are alike, so nothing
/// deduplicates.
fn write_object(path: &PathBuf, size: u64) {
    let mut out = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    let mut block = vec![0u8; 1 << 20];
    let mut written = 0u64;
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    while written < size {
        for word in block.chunks_mut(8) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            word.copy_from_slice(&seed.to_le_bytes()[..word.len()]);
        }
        let n = (size - written).min(block.len() as u64) as usize;
        out.write_all(&block[..n]).unwrap();
        written += n as u64;
    }
    out.flush().unwrap();
}

async fn open_store(dir: &Path) -> Arc<Store> {
    std::fs::create_dir_all(dir).unwrap();
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || Arc::new(Store::open(&dir).expect("a store")))
        .await
        .unwrap()
}

fn trust(store: &Store, key: NodeId) {
    store
        .put_binding(&Binding {
            origin: OriginId::Key(key),
            node_id: key,
            source: BindingSource::Static,
            domain: None,
            issuer: None,
            spaces: Vec::new(),
            read_only: Vec::new(),
            note: None,
            added_at: 0,
            expires_at: None,
        })
        .expect("a static binding");
}

fn decode32(hex: &str) -> [u8; 32] {
    hex::decode(hex).expect("hex").try_into().expect("32 bytes")
}
