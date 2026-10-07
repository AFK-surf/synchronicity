//! `synch lock` — best-effort cluster locks from the command line
//! (`docs/LOCKS.md` §10).
//!
//! Every subcommand is a program call on the control service rather than a
//! rendered `Run`: a hold outlives an answer, and `run` owns a child process
//! whose life is the hold's. The daemon does the exchange; this process only
//! asks, holds the stream, and reports.

use std::{ffi::OsString, path::Path, process::ExitStatus, time::Duration};

use anyhow::{Context, Result};

use crate::{
    cli::{parse_duration, LockCommand, OnLost},
    control::{proto::pb, Client, ControlError, ErrorCode},
};

/// The exit status of a `synch lock run` that never acquired: `EX_TEMPFAIL`,
/// as `flock -n` callers expect of "try again later".
pub const EXIT_NOT_ACQUIRED: i32 = 75;

/// Runs one `synch lock` subcommand.
pub async fn run(data_dir: &Path, command: &LockCommand) -> Result<()> {
    let mut client = Client::connect(data_dir).await?;
    match command {
        LockCommand::Run {
            lock,
            ttl,
            wait,
            owner,
            on_lost,
            allow_behind,
            command,
        } => {
            let request = request(lock, ttl, wait.as_deref(), owner.as_deref(), *allow_behind)?;
            let status = run_locked(&mut client, request, *on_lost, command).await?;
            std::process::exit(exit_code(status));
        }
        LockCommand::Acquire {
            lock,
            ttl,
            wait,
            owner,
            sticky,
            hold,
            allow_behind,
            json,
        } => {
            let mut request = request(lock, ttl, wait.as_deref(), owner.as_deref(), *allow_behind)?;
            request.mode = if *hold {
                pb::LockMode::Session
            } else if *sticky {
                pb::LockMode::Sticky
            } else {
                pb::LockMode::Lease
            } as i32;
            let (held, mut events) = client.lock(request).await?;
            report_hold(lock, &held, *json);
            if *hold {
                // Attached: the hold lives until this process is interrupted
                // or the lock is lost.
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        release(&mut client, lock, &held.token).await?;
                    }
                    reason = events.lost() => {
                        anyhow::bail!("lost {lock}: {}", reason.unwrap_or_else(|| "the daemon went away".into()));
                    }
                }
            }
            Ok(())
        }
        LockCommand::Renew { lock, token, ttl } => {
            let (space, name) = split(lock)?;
            let held = client
                .lock_renew(pb::LockRenewRequest {
                    space,
                    name,
                    token: token.clone(),
                    ttl_ms: ttl
                        .as_deref()
                        .map(|t| parse_duration(t).map(|d| d.as_millis() as u64))
                        .transpose()
                        .context("--ttl")?,
                    payload: None,
                })
                .await?;
            println!(
                "renewed {lock}: valid for {}",
                render_millis(held.valid_for_ms)
            );
            Ok(())
        }
        LockCommand::Release { lock, token } => {
            let (space, name) = split(lock)?;
            let ended = client
                .lock_release(pb::LockReleaseRequest {
                    space,
                    name,
                    token: token.clone().unwrap_or_default(),
                    force: false,
                    holder: String::new(),
                })
                .await?;
            for token in ended {
                println!("released {lock} ({token})");
            }
            Ok(())
        }
        LockCommand::Break { lock, holder } => {
            let (space, name) = split(lock)?;
            let ended = client
                .lock_release(pb::LockReleaseRequest {
                    space,
                    name,
                    token: String::new(),
                    force: true,
                    holder: holder.clone().unwrap_or_default(),
                })
                .await?;
            if ended.is_empty() {
                println!("no claim on {lock} to break");
            }
            for token in ended {
                println!("broke {lock} ({token})");
            }
            Ok(())
        }
        LockCommand::Ls { space, json } => {
            let status = client
                .lock_status(pb::LockStatusRequest {
                    space: space.clone().unwrap_or_default(),
                    name: String::new(),
                    peers: false,
                })
                .await?;
            if *json {
                let claims: Vec<_> = status.claims.iter().map(claim_json).collect();
                println!("{}", serde_json::Value::Array(claims));
            } else if status.claims.is_empty() {
                println!("no locks known");
            } else {
                for claim in &status.claims {
                    println!("{}", claim_line(claim));
                }
            }
            Ok(())
        }
        LockCommand::Status { lock, json } => {
            let (space, name) = split(lock)?;
            let status = client
                .lock_status(pb::LockStatusRequest {
                    space,
                    name,
                    peers: true,
                })
                .await?;
            if *json {
                let peers: Vec<_> = status
                    .peers
                    .iter()
                    .map(|peer| {
                        serde_json::json!({
                            "peer": peer.peer,
                            "error": (!peer.error.is_empty()).then_some(&peer.error),
                            "claims": peer.claims.iter().map(claim_json).collect::<Vec<_>>(),
                        })
                    })
                    .collect();
                let value = serde_json::json!({
                    "lock": lock,
                    "claims": status.claims.iter().map(claim_json).collect::<Vec<_>>(),
                    "peers": peers,
                    "watermarks": status.watermarks,
                });
                println!("{value}");
                return Ok(());
            }
            println!("{lock}");
            println!("  this node:");
            if status.claims.is_empty() {
                println!("    no claims");
            }
            for claim in &status.claims {
                println!("    {}", claim_line(claim));
            }
            let mut held: Vec<&str> = Vec::new();
            for peer in &status.peers {
                println!("  peer {}:", &peer.peer[..peer.peer.len().min(10)]);
                if !peer.error.is_empty() {
                    println!("    did not answer: {}", peer.error);
                }
                for claim in &peer.claims {
                    println!("    {}", claim_line(claim));
                    if claim.state == "held" {
                        held.push(&claim.token);
                    }
                }
            }
            held.extend(
                status
                    .claims
                    .iter()
                    .filter(|c| c.state == "held")
                    .map(|c| c.token.as_str()),
            );
            held.sort();
            held.dedup();
            if held.len() > 1 {
                println!(
                    "  CONTESTED: {} claims are held at once — split brain; the next renewal heals it",
                    held.len()
                );
            }
            for mark in &status.watermarks {
                println!("  last released at {mark}");
            }
            Ok(())
        }
    }
}

/// Acquires, runs the command with the token in its environment, and
/// releases when it exits; signals it per `on_lost` if the lock is lost
/// first.
async fn run_locked(
    client: &mut Client,
    request: pb::LockRequest,
    on_lost: OnLost,
    command: &[OsString],
) -> Result<ExitStatus> {
    let lock = format!("{}/{}", request.space, request.name);
    let (held, mut events) = match client.lock(request).await {
        Ok(acquired) => acquired,
        Err(e) if retryable(&e) => {
            eprintln!("synch: {e}");
            std::process::exit(EXIT_NOT_ACQUIRED);
        }
        Err(e) => return Err(e.into()),
    };
    let (program, args) = command.split_first().context("no command to run")?;
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .env("SYNCH_LOCK_NAME", &lock)
        .env("SYNCH_LOCK_TOKEN", &held.token)
        .spawn()
        .with_context(|| format!("starting {}", program.to_string_lossy()))?;

    let status = tokio::select! {
        status = child.wait() => status?,
        reason = events.lost() => {
            let reason = reason.unwrap_or_else(|| "the daemon went away".into());
            eprintln!("synch: lost {lock}: {reason}");
            match on_lost {
                OnLost::Ignore => {}
                OnLost::Kill => {
                    let _ = child.start_kill();
                }
                OnLost::Term => terminate(&mut child),
            }
            return Ok(child.wait().await?);
        }
    };
    // Released before this process exits, so the next holder does not wait
    // for the stream's end to reach the daemon.
    if let Err(e) = release(client, &lock, &held.token).await {
        eprintln!("synch: releasing {lock}: {e:#}");
    }
    drop(events);
    Ok(status)
}

#[cfg(unix)]
fn terminate(child: &mut tokio::process::Child) {
    if let Some(pid) = child
        .id()
        .and_then(|id| rustix::process::Pid::from_raw(id as i32))
    {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
    }
}

#[cfg(not(unix))]
fn terminate(child: &mut tokio::process::Child) {
    let _ = child.start_kill();
}

async fn release(client: &mut Client, lock: &str, token: &str) -> Result<()> {
    let (space, name) = split(lock)?;
    client
        .lock_release(pb::LockReleaseRequest {
            space,
            name,
            token: token.to_string(),
            force: false,
            holder: String::new(),
        })
        .await?;
    Ok(())
}

fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

/// Whether an acquire failure means "somebody else has it; try later".
fn retryable(e: &ControlError) -> bool {
    matches!(
        e.code,
        ErrorCode::LockHeld | ErrorCode::LockContended | ErrorCode::HandoffPending
    )
}

fn request(
    lock: &str,
    ttl: &str,
    wait: Option<&str>,
    owner: Option<&str>,
    allow_behind: bool,
) -> Result<pb::LockRequest> {
    let (space, name) = split(lock)?;
    let ttl = parse_duration(ttl).context("--ttl")?;
    let wait = wait
        .map(parse_duration)
        .transpose()
        .context("--wait")?
        .unwrap_or(Duration::ZERO);
    Ok(pb::LockRequest {
        space,
        name,
        ttl_ms: ttl.as_millis() as u64,
        wait_ms: wait.as_millis() as u64,
        owner: owner.map(str::to_string).unwrap_or_else(default_owner),
        payload: Vec::new(),
        mode: pb::LockMode::Session as i32,
        allow_behind,
    })
}

/// `user@host (pid N)`: enough for an operator reading `synch lock status`
/// on another node to find the process.
fn default_owner() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "someone".into());
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "this host".into());
    let owner = format!("{user}@{host} (pid {})", std::process::id());
    owner
        .chars()
        .take(synch_core::MAX_LOCK_OWNER_BYTES / 4)
        .collect()
}

fn split(lock: &str) -> Result<(String, String)> {
    let parsed = synch_core::LockName::parse(lock).with_context(|| format!("{lock:?}"))?;
    Ok((parsed.space, parsed.name))
}

fn report_hold(lock: &str, held: &pb::LockHold, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "lock": lock,
                "token": held.token,
                "valid_for_ms": held.valid_for_ms,
                "waited_on": held.waited_on,
                "handoff": held.handoff,
            })
        );
        return;
    }
    println!("{}", held.token);
    eprintln!(
        "acquired {lock}: valid for {}",
        render_millis(held.valid_for_ms)
    );
    if !held.waited_on.is_empty() {
        eprintln!(
            "  waited on {} unreachable peer(s); a partition with them could grant this lock there too",
            held.waited_on.len()
        );
    }
}

fn claim_line(claim: &pb::LockClaim) -> String {
    let mode = if claim.mode.is_empty() {
        String::new()
    } else {
        format!(" {}", claim.mode)
    };
    format!(
        "{}/{}  {}{mode}  {}  {}  {} left  {}",
        claim.space,
        claim.name,
        claim.state,
        claim.origin,
        if claim.owner.is_empty() {
            "-"
        } else {
            &claim.owner
        },
        render_millis(claim.remaining_ms),
        claim.token,
    )
}

fn claim_json(claim: &pb::LockClaim) -> serde_json::Value {
    serde_json::json!({
        "lock": format!("{}/{}", claim.space, claim.name),
        "token": claim.token,
        "origin": claim.origin,
        "owner": claim.owner,
        "state": claim.state,
        "mode": (!claim.mode.is_empty()).then_some(&claim.mode),
        "remaining_ms": claim.remaining_ms,
        "ttl_ms": claim.ttl_ms,
        "supersedes": claim.supersedes,
    })
}

fn render_millis(ms: u64) -> String {
    let secs = ms / 1000;
    match secs {
        0..=119 => format!("{}.{}s", secs, (ms % 1000) / 100),
        120..=7199 => format!("{}m{}s", secs / 60, secs % 60),
        _ => format!("{}h{}m", secs / 3600, (secs % 3600) / 60),
    }
}
