//! Linux-only, isolated whole-process memory measurements, including Lean's
//! allocator. Kept ignored because RSS and timing are environment-sensitive.
//! Remove the Rust-baseline modes when Store entrypoints switch to Lean;
//! never retain a production fallback just to preserve this comparison.
use std::{io::Write, process::Command, time::Instant};

use crate::{lean_resources::Input, Store};

fn status_kib(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix(field)
                .map(|value| value.split_whitespace().next().unwrap().parse().unwrap())
        })
        .expect("Linux process memory field")
}

#[test]
#[ignore = "worker for isolated_ingestion_memory; not a standalone benchmark"]
fn isolated_ingestion_memory_worker() {
    let Ok(mode) = std::env::var("SYNCH_INGEST_MEMORY_WORKER") else {
        return;
    };
    let size: usize = std::env::var("SYNCH_INGEST_MEMORY_BYTES")
        .unwrap()
        .parse()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).unwrap();
    let path = directory.path().join("source");
    let from_file = mode.ends_with("file");
    let native = mode.starts_with("lean-");
    assert!(matches!(
        mode.as_str(),
        "lean-file" | "lean-bytes" | "rust-file" | "rust-bytes"
    ));
    let mut expected = blake3::Hasher::new();
    // File fixtures are produced in bounded chunks; byte fixtures are fully
    // touched before the baseline, so caller-owned input is not miscounted as
    // an ingestion allocation. Each measurement has its own child process.
    let bytes = if from_file {
        let mut file = std::fs::File::create(&path).unwrap();
        let block = [0x69; 65536];
        let mut remaining = size;
        while remaining != 0 {
            let count = remaining.min(block.len());
            file.write_all(&block[..count]).unwrap();
            expected.update(&block[..count]);
            remaining -= count;
        }
        file.sync_all().unwrap();
        Vec::new()
    } else {
        let bytes = vec![0x69; size];
        expected.update(&bytes);
        bytes
    };
    // Warm runtime initialization independently of the measured input.
    super::lean_ingest::ingest(&store, Input::Bytes(b"warm"), 0).unwrap();
    let before = status_kib("VmHWM:");
    let started = Instant::now();
    let (root, length) = match (native, from_file) {
        (true, true) => super::lean_ingest::ingest(&store, Input::File(&path), 1).unwrap(),
        (true, false) => super::lean_ingest::ingest(&store, Input::Bytes(&bytes), 1).unwrap(),
        (false, true) => store.ingest_file(&path, 1).unwrap(),
        (false, false) => (store.ingest_bytes(&bytes, 1).unwrap(), size as u64),
    };
    let elapsed = started.elapsed().as_millis();
    let after = status_kib("VmHWM:");
    assert_eq!(root.as_bytes(), expected.finalize().as_bytes());
    assert_eq!(length, size as u64);
    assert!(store.blob(&root).unwrap().unwrap().complete);
    assert!(!store.is_being_written(&root));
    assert!(store.active_temporaries().is_empty());
    println!(
        "INGEST_MEMORY mode={mode} size={size} baseline_kib={before} peak_kib={after} delta_kib={} elapsed_ms={elapsed}",
        after.saturating_sub(before)
    );
}

#[test]
#[ignore = "isolated Linux RSS/throughput probe; run under a memory-capped scope"]
fn isolated_ingestion_memory() {
    let executable = std::env::current_exe().unwrap();
    for mode in ["lean-file", "lean-bytes", "rust-file", "rust-bytes"] {
        let mut deltas = Vec::new();
        for size in [4 * 1024 * 1024 + 3, 64 * 1024 * 1024 + 3] {
            let output = Command::new(&executable)
                .args([
                    "--exact",
                    "lean_ingest_memory::isolated_ingestion_memory_worker",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("SYNCH_INGEST_MEMORY_WORKER", mode)
                .env("SYNCH_INGEST_MEMORY_BYTES", size.to_string())
                .output()
                .unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(
                output.status.success(),
                "{mode}/{size}: {stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let line = stdout
                .lines()
                .find_map(|line| line.find("INGEST_MEMORY ").map(|start| &line[start..]))
                .expect("worker measurement");
            println!("{line}");
            let delta: u64 = line
                .split_whitespace()
                .find_map(|field| field.strip_prefix("delta_kib="))
                .unwrap()
                .parse()
                .unwrap();
            deltas.push(delta);
        }
        if mode.starts_with("lean-") {
            // Deliberately loose process-level gates, not allocator-level or
            // universal asymptotic proofs. Catch retained payload/outboard
            // regressions without asserting noisy sub-MiB allocator details.
            assert!(deltas[1] < 16 * 1024, "{mode}: {deltas:?}");
            assert!(
                deltas[1] <= deltas[0] + 8 * 1024,
                "{mode}: ingestion memory grew with input: {deltas:?}"
            );
        }
    }
}
