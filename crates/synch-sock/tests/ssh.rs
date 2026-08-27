//! End-to-end SSH protocol coverage over an in-memory socket invocation.

#![cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod harness;

use std::sync::Arc;

use harness::{compile, peer, Harness};
use russh::keys::PublicKeyOrCertificate;
use synch_core::{FileTransferCapability, SockStatus};
use synch_sock::{DuplexStream, EffectivePolicy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SSH_ECHO: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  struct sy_pollfd fds[9] = {{ SY_SELF, SY_POLL_IN, 0 }};
  sy_u64 count = 1;
  if (sy_ssh_start(SY_SELF, SY_SSH_AUTH_NONE) < 0) return 10;

  for (;;) {
    sy_s64 ready = sy_poll(fds, count, 5000);
    if (ready < 0) return 11;
    if (ready == 0) continue;

    if (fds[0].revents & SY_POLL_IN) {
      struct sy_ssh_event event;
      while (sy_ssh_next(SY_SELF, &event, sizeof event) == 1) {
        if (event.kind == SY_SSH_EVENT_AUTH_NONE) {
          if (sy_ssh_auth_reply(event.id, SY_SSH_AUTH_ACCEPT,
                                SY_SSH_AUTH_NONE) < 0) return 12;
        } else if (event.kind == SY_SSH_EVENT_AUTHENTICATED) {
          if (sy_ssh_event_done(event.id) < 0) return 13;
        } else if (event.kind == SY_SSH_EVENT_CHANNEL_OPEN) {
          if (count == 9) {
            sy_ssh_channel_reject(event.id, SY_SSH_OPEN_RESOURCE_SHORTAGE);
            continue;
          }
          sy_s64 channel = sy_ssh_channel_accept(event.id);
          if (channel < 0) return 14;
          fds[count++] = (struct sy_pollfd){ channel, SY_POLL_IN, 0 };
        } else if (event.kind == SY_SSH_EVENT_CHANNEL_REQUEST) {
          if (sy_ssh_request_reply(event.id, SY_SSH_REQUEST_SUCCESS) < 0)
            return 15;
        } else {
          if (sy_ssh_event_done(event.id) < 0) return 16;
        }
      }
    }

    for (sy_u64 i = 1; i < count; i++) {
      if (!(fds[i].revents & SY_POLL_IN)) continue;
      char buffer[1024];
      sy_s64 n = sy_read(fds[i].handle, buffer, sizeof buffer);
      if (n == 0) {
        sy_shutdown(fds[i].handle);
        continue;
      }
      if (n < 0) { if (n == SY_EAGAIN) continue; return 17; }
      sy_s64 offset = 0;
      while (offset < n) {
        sy_s64 written = sy_write(fds[i].handle, buffer + offset,
                                  (sy_u64)(n - offset));
        if (written == SY_EAGAIN) continue;
        if (written < 0) return 18;
        offset += written;
      }
    }
    if (fds[0].revents & (SY_POLL_HUP | SY_POLL_ERR)) return 0;
  }
}
"#;

const AUTHORIZED_KEYS: &str = r#"
#include <synch.h>

static sy_s64 match_key(sy_u64 event_id, sy_s64 keys) {
  for (;;) {
    sy_s64 matched = sy_ssh_authorized_keys_match(event_id, keys);
    if (matched != SY_EAGAIN) return matched;
    struct sy_pollfd wait[1] = {{ keys, SY_POLL_IN, 0 }};
    if (sy_poll(wait, 1, 5000) <= 0) return SY_ETIMEDOUT;
  }
}

SY_ENTRY sy_s64 entry(void) {
  const char path[] = "keys/authorized_keys";
  sy_s64 keys = sy_open(path, sizeof(path) - 1);
  if (keys < 0) return 20;
  if (sy_ssh_start(SY_SELF, SY_SSH_AUTH_PUBLICKEY) < 0) return 21;
  struct sy_pollfd conn[1] = {{ SY_SELF, SY_POLL_IN, 0 }};
  for (;;) {
    if (sy_poll(conn, 1, 5000) < 0) return 22;
    if (conn[0].revents & SY_POLL_IN) {
      struct sy_ssh_event event;
      while (sy_ssh_next(SY_SELF, &event, sizeof event) == 1) {
        if (event.kind == SY_SSH_EVENT_AUTH_PUBLICKEY_OFFER ||
            event.kind == SY_SSH_EVENT_AUTH_PUBLICKEY_VERIFIED) {
          sy_s64 matched = match_key(event.id, keys);
          if (matched < 0) return 23;
          sy_u32 result = matched
              ? (event.kind == SY_SSH_EVENT_AUTH_PUBLICKEY_OFFER
                     ? SY_SSH_AUTH_OFFER_ACCEPT : SY_SSH_AUTH_ACCEPT)
              : SY_SSH_AUTH_REJECT;
          if (sy_ssh_auth_reply(event.id, result,
                                SY_SSH_AUTH_PUBLICKEY) < 0) return 24;
        } else {
          if (sy_ssh_event_done(event.id) < 0) return 25;
        }
      }
    }
    if (conn[0].revents & (SY_POLL_HUP | SY_POLL_ERR)) return 0;
  }
}
"#;

const SFTP_SERVER: &str = r#"
#include <synch.h>

static sy_s64 copy_ready(sy_s64 from, sy_s64 to) {
  char buffer[4096];
  sy_s64 n = sy_read(from, buffer, sizeof buffer);
  if (n <= 0) return n;
  sy_s64 offset = 0;
  while (offset < n) {
    sy_s64 written = sy_write(to, buffer + offset, (sy_u64)(n - offset));
    if (written == SY_EAGAIN) continue;
    if (written < 0) return written;
    offset += written;
  }
  return n;
}

SY_ENTRY sy_s64 entry(void) {
  if (sy_ssh_start(SY_SELF, SY_SSH_AUTH_NONE) < 0) return 30;
  sy_s64 channel = -1, backend = -1;
  struct sy_pollfd fds[3] = {{ SY_SELF, SY_POLL_IN, 0 }};
  sy_u64 count = 1;
  for (;;) {
    if (sy_poll(fds, count, 5000) < 0) return 31;
    if (fds[0].revents & SY_POLL_IN) {
      struct sy_ssh_event event;
      while (sy_ssh_next(SY_SELF, &event, sizeof event) == 1) {
        if (event.kind == SY_SSH_EVENT_AUTH_NONE) {
          if (sy_ssh_auth_reply(event.id, SY_SSH_AUTH_ACCEPT,
                                SY_SSH_AUTH_NONE) < 0) return 32;
        } else if (event.kind == SY_SSH_EVENT_CHANNEL_OPEN) {
          channel = sy_ssh_channel_accept(event.id);
          if (channel < 0) return 33;
          fds[1] = (struct sy_pollfd){ channel, SY_POLL_IN, 0 };
          count = 2;
        } else if (event.kind == SY_SSH_EVENT_CHANNEL_REQUEST) {
          if (backend >= 0) return 34;
          backend = sy_sftp_open(1);
          if (backend < 0) return 35;
          fds[2] = (struct sy_pollfd){ backend, SY_POLL_IN, 0 };
          count = 3;
          if (sy_ssh_request_reply(event.id, SY_SSH_REQUEST_SUCCESS) < 0)
            return 36;
        } else {
          if (sy_ssh_event_done(event.id) < 0) return 37;
        }
      }
    }
    if (count == 3 && (fds[1].revents & SY_POLL_IN) &&
        copy_ready(channel, backend) < 0) return 38;
    if (count == 3 && (fds[2].revents & SY_POLL_IN) &&
        copy_ready(backend, channel) < 0) return 39;
    if (fds[0].revents & (SY_POLL_HUP | SY_POLL_ERR)) return 0;
  }
}
"#;

const SERVER_OPEN_EXTENSION: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  const char type[] = "echo@example.com";
  const char opening[] = "opaque opening data";
  sy_s64 channel = -1;
  if (sy_ssh_start(SY_SELF, SY_SSH_AUTH_NONE) < 0) return 40;
  struct sy_pollfd fds[2] = {{ SY_SELF, SY_POLL_IN, 0 }};
  sy_u64 count = 1;
  for (;;) {
    if (sy_poll(fds, count, 5000) < 0) return 41;
    if (fds[0].revents & SY_POLL_IN) {
      struct sy_ssh_event event;
      while (sy_ssh_next(SY_SELF, &event, sizeof event) == 1) {
        if (event.kind == SY_SSH_EVENT_AUTH_NONE) {
          if (sy_ssh_auth_reply(event.id, SY_SSH_AUTH_ACCEPT,
                                SY_SSH_AUTH_NONE) < 0) return 42;
        } else if (event.kind == SY_SSH_EVENT_AUTHENTICATED) {
          channel = sy_ssh_channel_open(SY_SELF, type, sizeof(type) - 1,
                                        opening, sizeof(opening) - 1);
          if (channel < 0) return 43;
          fds[1] = (struct sy_pollfd){ channel, SY_POLL_IN, 0 };
          count = 2;
          if (sy_ssh_event_done(event.id) < 0) return 44;
        } else {
          if (sy_ssh_event_done(event.id) < 0) return 45;
        }
      }
    }
    if (count == 2 && (fds[1].revents & SY_POLL_IN)) {
      char buffer[256];
      sy_s64 n = sy_read(channel, buffer, sizeof buffer);
      if (n > 0 && sy_write(channel, buffer, (sy_u64)n) != n) return 46;
    }
    if (fds[0].revents & (SY_POLL_HUP | SY_POLL_ERR)) return 0;
  }
}
"#;

#[derive(Clone)]
struct Client;

impl russh::client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct UnknownClient {
    channel: tokio::sync::mpsc::UnboundedSender<russh::Channel<russh::client::Msg>>,
}

impl russh::client::Handler for UnknownClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn should_accept_unknown_server_channel(
        &mut self,
        _id: russh::ChannelId,
        channel_type: &str,
    ) -> bool {
        channel_type == "echo@example.com"
    }

    async fn server_channel_open_unknown(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        self.channel
            .send(channel)
            .map_err(|_| russh::Error::Disconnect)
    }
}

#[tokio::test]
async fn none_auth_and_multiple_session_channels_share_one_connection() {
    let elf = compile(SSH_ECHO, "ssh-echo.c");
    let harness = Harness::new();
    let (client_stream, server_stream) = tokio::io::duplex(256 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_stream);
    let invocation = harness.invocation(
        &elf,
        DuplexStream::new(server_reader, server_writer),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );
    let run = tokio::spawn(async move { harness.pool.run(invocation).await.unwrap() });

    let config = Arc::new(russh::client::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(5)),
        ..Default::default()
    });
    let mut client = russh::client::connect_stream(config, client_stream, Client)
        .await
        .expect("SSH handshake completed");
    assert!(client
        .authenticate_none("test")
        .await
        .expect("none authentication got a response")
        .success());

    let first = client.channel_open_session().await.expect("first channel");
    let second = client.channel_open_session().await.expect("second channel");
    first
        .request_shell(true)
        .await
        .expect("first shell request");
    second
        .exec(true, b"ignored-by-echo".to_vec())
        .await
        .expect("second exec request");

    let first = tokio::spawn(round_trip(first.into_stream(), b"first channel"));
    let second = tokio::spawn(round_trip(second.into_stream(), b"second channel"));
    assert_eq!(first.await.unwrap(), b"first channel");
    assert_eq!(second.await.unwrap(), b"second channel");

    client
        .disconnect(russh::Disconnect::ByApplication, "done", "en")
        .await
        .unwrap();
    drop(client);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), run)
        .await
        .expect("invocation stopped after disconnect")
        .unwrap();
    assert_eq!(outcome.status, SockStatus::Ok(0));
}

#[tokio::test]
async fn public_key_auth_can_consult_authorized_keys_in_the_virtual_tree() {
    use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg};

    let allowed = PrivateKey::random(&mut rand_10::rng(), Algorithm::Ed25519).unwrap();
    let denied = PrivateKey::random(&mut rand_10::rng(), Algorithm::Ed25519).unwrap();
    let authorized = format!("{} test key\n", allowed.public_key().to_openssh().unwrap());
    let elf = compile(AUTHORIZED_KEYS, "ssh-authorized-keys.c");
    let harness = Harness::with_tree(&[("keys/authorized_keys", &authorized)]);
    let (client_stream, server_stream) = tokio::io::duplex(256 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_stream);
    let mut policy = EffectivePolicy::default();
    policy.tree_reads.push("keys".into());
    let invocation = harness.invocation(
        &elf,
        DuplexStream::new(server_reader, server_writer),
        policy,
        peer(None),
        vec![],
    );
    let run = tokio::spawn(async move { harness.pool.run(invocation).await.unwrap() });
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_stream,
        Client,
    )
    .await
    .unwrap();

    let denied = client
        .authenticate_publickey("test", PrivateKeyWithHashAlg::new(Arc::new(denied), None))
        .await
        .unwrap();
    assert!(!denied.success());
    let allowed = client
        .authenticate_publickey("test", PrivateKeyWithHashAlg::new(Arc::new(allowed), None))
        .await
        .unwrap();
    assert!(allowed.success());

    client
        .disconnect(russh::Disconnect::ByApplication, "done", "en")
        .await
        .unwrap();
    drop(client);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), run)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome.status, SockStatus::Ok(0));
}

#[tokio::test]
async fn sftp_runs_as_a_declared_backend_over_an_ordinary_channel() {
    let elf = compile(SFTP_SERVER, "ssh-sftp.c");
    let harness = Harness::with_tree(&[("files/hello.txt", "hello over sftp")]);
    let (client_stream, server_stream) = tokio::io::duplex(256 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_stream);
    let mut policy = EffectivePolicy::default();
    policy.file_transfers.push(FileTransferCapability {
        id: 1,
        protocol: 1,
        access: 0x01 | 0x04,
        scope: "files".into(),
    });
    let invocation = harness.invocation(
        &elf,
        DuplexStream::new(server_reader, server_writer),
        policy,
        peer(None),
        vec![],
    );
    let run = tokio::spawn(async move { harness.pool.run(invocation).await.unwrap() });
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_stream,
        Client,
    )
    .await
    .unwrap();
    assert!(client.authenticate_none("test").await.unwrap().success());
    let channel = client.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "sftp").await.unwrap();
    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
        .await
        .unwrap();
    assert_eq!(sftp.read("hello.txt").await.unwrap(), b"hello over sftp");
    drop(sftp);

    client
        .disconnect(russh::Disconnect::ByApplication, "done", "en")
        .await
        .unwrap();
    drop(client);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), run)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome.status, SockStatus::Ok(0));
}

#[tokio::test]
async fn server_initiated_extension_channels_are_generic_fds() {
    let elf = compile(SERVER_OPEN_EXTENSION, "ssh-extension-channel.c");
    let harness = Harness::new();
    let (client_stream, server_stream) = tokio::io::duplex(256 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_stream);
    let invocation = harness.invocation(
        &elf,
        DuplexStream::new(server_reader, server_writer),
        EffectivePolicy::default(),
        peer(None),
        vec![],
    );
    let run = tokio::spawn(async move { harness.pool.run(invocation).await.unwrap() });
    let (channel_tx, mut channel_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_stream,
        UnknownClient {
            channel: channel_tx,
        },
    )
    .await
    .unwrap();
    assert!(client.authenticate_none("test").await.unwrap().success());
    let channel = tokio::time::timeout(std::time::Duration::from_secs(5), channel_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        round_trip(channel.into_stream(), b"extension").await,
        b"extension"
    );

    client
        .disconnect(russh::Disconnect::ByApplication, "done", "en")
        .await
        .unwrap();
    drop(client);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), run)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome.status, SockStatus::Ok(0));
}

async fn round_trip(
    mut stream: russh::ChannelStream<russh::client::Msg>,
    message: &'static [u8],
) -> Vec<u8> {
    stream.write_all(message).await.unwrap();
    let mut reply = vec![0; message.len()];
    stream.read_exact(&mut reply).await.unwrap();
    reply
}
