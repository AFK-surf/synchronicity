//! Probe: a caller disconnect ends the invocation (finding 4, fixed
//! `2026-08-28`).
//!
//! The invocation lifecycle (`run_job`'s select, runtime/mod.rs) ends when
//! the caller's stream fails: the transport's death reaches `SY_SELF` as the
//! endpoint's `Failed` state (the reader pump fails it on a stream error,
//! endpoint.rs), and the runtime ends the invocation rather than holding a
//! slot, a worker placement and a set of rings for a caller that can never
//! be delivered to. A clean FIN is not this — a half-close is normal for a
//! proxy — and the guest's own `sy_shutdown`/`sy_close` of `SY_SELF` must
//! not end the invocation either. Only the transport's failure does.
//!
//! This probe models transport death faithfully: a real TCP pair, with the
//! caller's end closed under `SO_LINGER(0)`, which sends a RST rather than a
//! FIN. A dropped tokio duplex would not do — it surfaces as a clean EOF,
//! which is the half-close case and must *not* end the invocation.
//!
//! Break signature (before the fix): with `idle_deadline = 300 ms` and an
//! upstream that keeps streaming bytes, an invocation whose caller is gone
//! runs past 3 s (10x the deadline), because egress progress keeps resetting
//! the deadline and nothing observes the caller's death. Fixed behavior: the
//! invocation ends with `Deadline` well within that window.

#![cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod harness;

use std::time::Duration;

use harness::{compile, peer, Harness};
use synch_sock::{DuplexStream, EffectivePolicy, Limits};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// Connects to the dripper, then polls and reads it forever. Never touches
/// `SY_SELF` after connecting, so the only way it can notice the caller's
/// death is the runtime ending the invocation.
const DRIP_CONSUMER: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  sy_s64 up = sy_tcp_connect(SY_STR("127.0.0.1"), PORT_PLACEHOLDER);
  if (up < 0) return up;
  char buf[4096];
  for (;;) {
    struct sy_pollfd fds[1] = { { up, SY_POLL_IN, 0 } };
    sy_s64 r = sy_poll(fds, 1, -1);
    if (r < 0) return r;
    if (r > 0) {
      sy_s64 n = sy_read(up, buf, sizeof buf);
      if (n == 0) return 0;
      if (n < 0 && n != SY_EAGAIN) return n;
    }
  }
}
"#;

#[tokio::test]
async fn caller_transport_death_ends_an_invocation_making_egress_progress() {
    // A listener that drips one byte every 50 ms forever, standing in for an
    // upstream the armed program is allowed to reach.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a dripper");
    let port = listener.local_addr().unwrap().port();
    let dripper = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                loop {
                    if sock.write_all(b"x").await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            });
        }
    });

    // The caller's stream: a real TCP pair, so its death is a transport
    // event. The caller writes, then closes its end with SO_LINGER(0) —
    // a RST, the way a dead connection actually fails the reader pump —
    // not a FIN, which is the half-close case the runtime must work past.
    let caller_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let caller_addr = caller_listener.local_addr().unwrap();
    let caller_stream = TcpStream::connect(caller_addr).await.unwrap();
    let (worker_stream, _) = caller_listener.accept().await.unwrap();

    let source = DRIP_CONSUMER.replace("PORT_PLACEHOLDER", &port.to_string());
    let elf = compile(&source, "drip-consumer.c");
    let harness = Harness::with_limits(Limits {
        idle_deadline: Duration::from_millis(300),
        ..Limits::default()
    });
    let policy = EffectivePolicy {
        egress: vec![format!("127.0.0.1:{port}")],
        ..EffectivePolicy::default()
    };

    let invocation = harness.invocation(
        &elf,
        DuplexStream::from_split(worker_stream),
        policy,
        peer(None),
        vec![],
    );

    // The caller side: a couple of bytes, then gone for good. The RST needs
    // SO_LINGER(0), which std's set_linger cannot express yet and tokio's
    // marks deprecated because it can block the runtime thread on drop — the
    // block is exactly the transport-death behavior this probe wants, and a
    // socket with no unread data closes immediately.
    let mut caller_stream = caller_stream;
    #[allow(deprecated)]
    let caller = tokio::spawn(async move {
        let _ = caller_stream.write_all(b"hello").await;
        let _ = caller_stream.set_linger(Some(Duration::ZERO));
        drop(caller_stream);
    });
    caller.await.unwrap();

    // 10x the idle deadline. The invocation must end with `Deadline` within
    // about a second of the RST — the runtime ends it because the caller's
    // transport failed, not because it went idle (the dripper is still
    // streaming, so egress progress alone would keep it alive forever).
    let ran = tokio::time::timeout(Duration::from_secs(3), harness.pool.run(invocation));
    let outcome = ran
        .await
        .expect("BREAK: the invocation survived 3s (10x the 300ms idle deadline) after its \
                 caller's transport died — a dead caller's invocation still pins its slot")
        .expect("the invocation ran");
    assert_eq!(
        outcome.status,
        synch_core::SockStatus::Deadline,
        "a dead caller must end the invocation with Deadline, not {:?}",
        outcome.status
    );
    dripper.abort();
}

/// The half-close control: the caller sends its bytes and FINs cleanly, and
/// the invocation must *not* end on the FIN alone — the guest is still
/// working, and ending here would cut off a proxy's reply.
#[tokio::test]
async fn a_clean_fin_does_not_end_the_invocation() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a dripper");
    let port = listener.local_addr().unwrap().port();
    let dripper = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                loop {
                    if sock.write_all(b"x").await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            });
        }
    });

    let caller_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let caller_addr = caller_listener.local_addr().unwrap();
    let mut caller_stream = TcpStream::connect(caller_addr).await.unwrap();
    let (worker_stream, _) = caller_listener.accept().await.unwrap();

    let source = DRIP_CONSUMER.replace("PORT_PLACEHOLDER", &port.to_string());
    let elf = compile(&source, "drip-consumer.c");
    let harness = Harness::with_limits(Limits {
        idle_deadline: Duration::from_millis(500),
        ..Limits::default()
    });
    let policy = EffectivePolicy {
        egress: vec![format!("127.0.0.1:{port}")],
        ..EffectivePolicy::default()
    };
    let invocation = harness.invocation(
        &elf,
        DuplexStream::from_split(worker_stream),
        policy,
        peer(None),
        vec![],
    );

    let caller = tokio::spawn(async move {
        let _ = caller_stream.write_all(b"hello").await;
        let _ = caller_stream.shutdown().await; // clean FIN
    });
    caller.await.unwrap();

    let ran = tokio::time::timeout(Duration::from_secs(2), harness.pool.run(invocation));
    match ran.await {
        Ok(outcome) => {
            // The invocation ended while the caller's half-close was still in
            // flight. That is only acceptable if the guest itself decided to
            // end; here it never does, so ending on the FIN would be the bug
            // (a proxy's caller always FINs before the reply is done).
            let outcome = outcome.expect("the invocation ran");
            panic!(
                "a clean FIN ended the invocation with {:?} — the half-close case must \
                 work past the caller's FIN (the guest never returned)",
                outcome.status
            );
        }
        Err(_) => {
            // Still running at 2 s: the FIN did not end it. It will end when
            // the egress dripper is gone and the idle deadline arrives.
        }
    }
    harness.pool.shutdown().await;
    dripper.abort();
}
