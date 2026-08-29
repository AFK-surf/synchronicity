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

const SSH_CERT_SERVER: &str = r#"
#include <synch.h>

static const unsigned char trusted_ca[32] = { __TRUSTED_CA_BYTES__ };

static sy_s64 trusted(sy_u64 event_id) {
  unsigned char seen[32];
  if (sy_ssh_event_data(event_id, SY_SSH_FIELD_AUTH_CERT_CA_SHA256,
                        seen, sizeof seen) != 32) return 0;
  for (sy_u64 i = 0; i < sizeof seen; i++)
    if (seen[i] != trusted_ca[i]) return 0;
  return 1;
}

SY_ENTRY sy_s64 entry(void) {
  if (sy_ssh_start(SY_SELF, SY_SSH_AUTH_PUBLICKEY) < 0) return 50;
  struct sy_pollfd conn[1] = {{ SY_SELF, SY_POLL_IN, 0 }};
  for (;;) {
    if (sy_poll(conn, 1, 5000) < 0) return 51;
    if (conn[0].revents & SY_POLL_IN) {
      struct sy_ssh_event event;
      while (sy_ssh_next(SY_SELF, &event, sizeof event) == 1) {
        if (event.kind == SY_SSH_EVENT_AUTH_PUBLICKEY_OFFER) {
          /* The certificate probe: accept the offer so the client signs
             its possession proof, but only for the declared trusted CA. */
          sy_u64 result = trusted(event.id) ? SY_SSH_AUTH_OFFER_ACCEPT
                                            : SY_SSH_AUTH_REJECT;
          if (sy_ssh_auth_reply(event.id, result,
                                SY_SSH_AUTH_PUBLICKEY) < 0) return 52;
        } else if (event.kind == SY_SSH_EVENT_AUTH_OPENSSH_CERT) {
          /* Structure, principal and possession are host-validated; the guest
             still authorizes the signing CA. */
          sy_u64 result = trusted(event.id) ? SY_SSH_AUTH_ACCEPT
                                            : SY_SSH_AUTH_REJECT;
          if (sy_ssh_auth_reply(event.id, result,
                                SY_SSH_AUTH_PUBLICKEY) < 0) return 53;
        } else {
          if (sy_ssh_event_done(event.id) < 0) return 54;
        }
      }
    }
    if (conn[0].revents & (SY_POLL_HUP | SY_POLL_ERR)) return 0;
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

const REQUEST_POLICY: &str = r#"
#include <synch.h>

static int equal(const char *left, sy_s64 len, const char *right, sy_u64 right_len) {
  if (len != (sy_s64)right_len) return 0;
  for (sy_s64 i = 0; i < len; i++) if (left[i] != right[i]) return 0;
  return 1;
}

SY_ENTRY sy_s64 entry(void) {
  if (sy_ssh_start(SY_SELF, SY_SSH_AUTH_NONE) < 0) return 50;
  struct sy_pollfd conn[1] = {{ SY_SELF, SY_POLL_IN, 0 }};
  for (;;) {
    if (sy_poll(conn, 1, 5000) < 0) return 51;
    if (conn[0].revents & SY_POLL_IN) {
      struct sy_ssh_event event;
      while (sy_ssh_next(SY_SELF, &event, sizeof event) == 1) {
        if (event.kind == SY_SSH_EVENT_AUTH_NONE) {
          if (sy_ssh_auth_reply(event.id, SY_SSH_AUTH_ACCEPT,
                                SY_SSH_AUTH_NONE) < 0) return 52;
        } else if (event.kind == SY_SSH_EVENT_CHANNEL_OPEN) {
          if (sy_ssh_channel_accept(event.id) < 0) return 53;
        } else if (event.kind == SY_SSH_EVENT_CHANNEL_REQUEST) {
          char type[64];
          sy_s64 n = sy_ssh_event_data(event.id, SY_SSH_FIELD_REQUEST_TYPE,
                                       type, sizeof type);
          if (n < 0) return 54;
          sy_u32 result = SY_SSH_REQUEST_FAILURE;
          if (equal(type, n, "env", 3)) {
            if (event.flags & SY_SSH_EVENT_WANT_REPLY) return 55;
            result = SY_SSH_REQUEST_SUCCESS;
          } else if (equal(type, n, "exec", 4)) {
            if (!(event.flags & SY_SSH_EVENT_WANT_REPLY)) return 56;
          } else if (equal(type, n, "x11-req", 7)) {
            if (event.a != 7 || event.b != 1) return 57;
            result = SY_SSH_REQUEST_SUCCESS;
          } else if (equal(type, n, "auth-agent-req@openssh.com", 26)) {
            result = SY_SSH_REQUEST_SUCCESS;
          }
          if (sy_ssh_request_reply(event.id, result) < 0) return 58;
        } else if (sy_ssh_event_done(event.id) < 0) {
          return 59;
        }
      }
    }
    if (conn[0].revents & (SY_POLL_HUP | SY_POLL_ERR)) return 0;
  }
}
"#;

const LANE_CLOSE: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  if (sy_ssh_start(SY_SELF, SY_SSH_AUTH_NONE) < 0) return 60;
  sy_s64 channel = -1;
  struct sy_pollfd fds[2] = {{ SY_SELF, SY_POLL_IN, 0 }};
  sy_u64 count = 1;
  for (;;) {
    if (sy_poll(fds, count, 5000) < 0) return 61;
    if (fds[0].revents & SY_POLL_IN) {
      struct sy_ssh_event event;
      while (sy_ssh_next(SY_SELF, &event, sizeof event) == 1) {
        if (event.kind == SY_SSH_EVENT_AUTH_NONE) {
          if (sy_ssh_auth_reply(event.id, SY_SSH_AUTH_ACCEPT,
                                SY_SSH_AUTH_NONE) < 0) return 62;
        } else if (event.kind == SY_SSH_EVENT_CHANNEL_OPEN) {
          channel = sy_ssh_channel_accept(event.id);
          if (channel < 0) return 63;
          fds[1] = (struct sy_pollfd){ channel, SY_POLL_IN, 0 };
          count = 2;
        } else if (event.kind == SY_SSH_EVENT_CHANNEL_REQUEST) {
          sy_s64 lane = sy_ssh_channel_lane(channel, SY_SSH_EXTENDED_STDERR);
          if (lane < 0 || sy_close(lane) < 0) return 64;
          if (sy_ssh_request_reply(event.id, SY_SSH_REQUEST_SUCCESS) < 0)
            return 65;
        } else if (event.kind == SY_SSH_EVENT_CHANNEL_EXTENDED_DATA) {
          if (event.fd != channel || event.a != SY_SSH_EXTENDED_STDERR) return 66;
          if (sy_ssh_event_done(event.id) < 0) return 67;
        } else if (sy_ssh_event_done(event.id) < 0) {
          return 68;
        }
      }
    }
    if (count == 2 && (fds[1].revents & SY_POLL_IN)) {
      char buffer[64];
      sy_s64 n = sy_read(channel, buffer, sizeof buffer);
      if (n > 0 && sy_write(channel, buffer, (sy_u64)n) != n) return 69;
    }
    if (fds[0].revents & (SY_POLL_HUP | SY_POLL_ERR)) return 0;
  }
}
"#;

const METHOD_POLICY: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  if (sy_ssh_start(SY_SELF,
                   SY_SSH_AUTH_NONE | SY_SSH_AUTH_PUBLICKEY) < 0) return 70;
  struct sy_pollfd conn[1] = {{ SY_SELF, SY_POLL_IN, 0 }};
  for (;;) {
    if (sy_poll(conn, 1, 5000) < 0) return 71;
    if (conn[0].revents & SY_POLL_IN) {
      struct sy_ssh_event event;
      while (sy_ssh_next(SY_SELF, &event, sizeof event) == 1) {
        if (event.kind == SY_SSH_EVENT_AUTH_PASSWORD) return 72;
        if (event.kind == SY_SSH_EVENT_AUTH_NONE ||
            event.kind == SY_SSH_EVENT_AUTH_PUBLICKEY_OFFER ||
            event.kind == SY_SSH_EVENT_AUTH_PUBLICKEY_VERIFIED) {
          /* A channel decision helper must not consume an auth token. */
          if (sy_ssh_channel_reject(
                  event.id,
                  SY_SSH_OPEN_ADMINISTRATIVELY_PROHIBITED) != SY_ESTATE)
            return 75;
          if (sy_ssh_auth_reply(event.id, SY_SSH_AUTH_REJECT,
                                SY_SSH_AUTH_NONE | SY_SSH_AUTH_PUBLICKEY) < 0)
            return 73;
        } else if (sy_ssh_event_done(event.id) < 0) {
          return 74;
        }
      }
    }
    if (conn[0].revents & (SY_POLL_HUP | SY_POLL_ERR)) return 0;
  }
}
"#;

const PARTIAL_AUTH: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  if (sy_ssh_start(SY_SELF,
                   SY_SSH_AUTH_NONE | SY_SSH_AUTH_PASSWORD) < 0) return 80;
  struct sy_pollfd conn[1] = {{ SY_SELF, SY_POLL_IN, 0 }};
  for (;;) {
    if (sy_poll(conn, 1, 5000) < 0) return 81;
    if (conn[0].revents & SY_POLL_IN) {
      struct sy_ssh_event event;
      while (sy_ssh_next(SY_SELF, &event, sizeof event) == 1) {
        if (event.kind == SY_SSH_EVENT_AUTH_NONE) {
          /* The outer identity is one accepted factor; a password is still
             required to finish. */
          if (sy_ssh_auth_reply(event.id, SY_SSH_AUTH_PARTIAL,
                                SY_SSH_AUTH_PASSWORD) < 0) return 82;
        } else if (event.kind == SY_SSH_EVENT_AUTH_PASSWORD) {
          if (sy_ssh_auth_reply(event.id, SY_SSH_AUTH_ACCEPT, 0) < 0)
            return 83;
        } else if (sy_ssh_event_done(event.id) < 0) {
          return 84;
        }
      }
    }
    if (conn[0].revents & (SY_POLL_HUP | SY_POLL_ERR)) return 0;
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
    // SSH invocations count channel cleartext, once per direction: each byte
    // the echo read and each byte it wrote back (`docs/SSH-SOCKETS.md` §8).
    let moved = (b"first channel".len() + b"second channel".len()) as u64;
    assert_eq!(outcome.bytes_in, moved);
    assert_eq!(outcome.bytes_out, moved);
}

#[tokio::test]
async fn none_is_accepted_by_policy_but_never_advertised() {
    use russh::MethodKind;

    let elf = compile(METHOD_POLICY, "ssh-method-policy.c");
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
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_stream,
        Client,
    )
    .await
    .unwrap();

    // The guest rejects the `none` attempt with next_methods naming both
    // `none` and `publickey`; RFC 4252 requires the failure's advertised
    // name-list to omit `none` all the same.
    let rejected = client.authenticate_none("test").await.unwrap();
    let russh::client::AuthResult::Failure {
        remaining_methods, ..
    } = rejected
    else {
        panic!("the guest rejects none authentication here");
    };
    assert!(
        remaining_methods.contains(&MethodKind::PublicKey),
        "publickey stays advertised"
    );
    assert!(
        !remaining_methods.contains(&MethodKind::None),
        "none must never appear in the advertised method name-list"
    );

    // Password is outside the guest's method set. The host rejects the
    // attempt on its own: the program exits nonzero if the event reaches it.
    assert!(!client
        .authenticate_password("test", "swordfish")
        .await
        .unwrap()
        .success());

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

/// A guest's `SY_SSH_AUTH_PARTIAL` reaches the client as RFC 4252 partial
/// success — the flag in `USERAUTH_FAILURE`, not merely a narrowed method
/// list — and the named next method then completes authentication.
#[tokio::test]
async fn partial_success_reaches_the_client_and_the_next_factor_completes() {
    use russh::MethodKind;

    let elf = compile(PARTIAL_AUTH, "ssh-partial-auth.c");
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
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_stream,
        Client,
    )
    .await
    .unwrap();

    let first = client.authenticate_none("test").await.unwrap();
    let russh::client::AuthResult::Failure {
        remaining_methods,
        partial_success,
    } = first
    else {
        panic!("the first factor alone must not complete authentication");
    };
    assert!(
        partial_success,
        "the guest's PARTIAL decision reaches the wire as partial success"
    );
    assert!(remaining_methods.contains(&MethodKind::Password));
    assert!(!remaining_methods.contains(&MethodKind::None));

    assert!(client
        .authenticate_password("test", "second-factor")
        .await
        .unwrap()
        .success());

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
async fn pipelined_request_replies_retain_their_own_want_reply_bit() {
    let elf = compile(REQUEST_POLICY, "ssh-request-policy.c");
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
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_stream,
        Client,
    )
    .await
    .unwrap();
    assert!(client.authenticate_none("test").await.unwrap().success());
    let mut channel = client.channel_open_session().await.unwrap();

    channel.set_env(false, "IGNORED", "yes").await.unwrap();
    channel.exec(true, b"must-fail".to_vec()).await.unwrap();
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(5), channel.wait())
            .await
            .unwrap(),
        Some(russh::ChannelMsg::Failure)
    ));
    channel
        .request_x11(true, true, "MIT-MAGIC-COOKIE-1", "00", 7)
        .await
        .expect("X11 request reached eBPF and was accepted");
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(5), channel.wait())
            .await
            .unwrap(),
        Some(russh::ChannelMsg::Success)
    ));
    channel
        .agent_forward(true)
        .await
        .expect("agent request reached eBPF and was accepted");
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(5), channel.wait())
            .await
            .unwrap(),
        Some(russh::ChannelMsg::Success)
    ));

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
async fn closing_an_extended_data_lane_does_not_close_the_connection() {
    let elf = compile(LANE_CLOSE, "ssh-lane-close.c");
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
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_stream,
        Client,
    )
    .await
    .unwrap();
    assert!(client.authenticate_none("test").await.unwrap().success());
    let channel = client.channel_open_session().await.unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        channel.request_shell(true),
    )
    .await
    .expect("the shell request got a reply")
    .unwrap();
    channel
        .extended_data_bytes(1, b"discard me".as_slice())
        .await
        .unwrap();
    assert_eq!(
        round_trip(channel.into_stream(), b"connection survived").await,
        b"connection survived"
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
async fn openssh_certificate_auth_arrives_as_its_own_event_kind() {
    use russh::keys::ssh_key::certificate::{Builder, CertType};
    use russh::keys::{Algorithm, PrivateKey};

    // A CA-signed user certificate, built in-process exactly as the russh
    // server-side tests do: no ssh-keygen on the path. Its digest is compiled
    // into the guest policy, which must make the CA trust decision.
    let ca = PrivateKey::random(&mut rand_10::rng(), Algorithm::Ed25519).unwrap();
    let user = PrivateKey::random(&mut rand_10::rng(), Algorithm::Ed25519).unwrap();
    let ca_blob = ca.public_key().to_bytes().unwrap();
    let ca_digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &ca_blob);
    let ca_bytes = ca_digest
        .as_ref()
        .iter()
        .map(|byte| format!("0x{byte:02x}"))
        .collect::<Vec<_>>()
        .join(", ");
    let source = SSH_CERT_SERVER.replace("__TRUSTED_CA_BYTES__", &ca_bytes);
    let elf = compile(&source, "ssh-cert.c");
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
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_stream,
        Client,
    )
    .await
    .unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut builder = Builder::new_with_random_nonce(
        &mut rand_10::rng(),
        user.public_key(),
        now - 60,
        now + 3600,
    )
    .unwrap();
    builder.serial(1).unwrap();
    builder.key_id("test-user").unwrap();
    builder.cert_type(CertType::User).unwrap();
    builder.valid_principal("test").unwrap();
    let cert = builder.sign(&ca).unwrap();

    // Host validation rejects a certificate whose principals do not include
    // the requested SSH username, even when the signing CA is trusted.
    let mut wrong_principal_builder = Builder::new_with_random_nonce(
        &mut rand_10::rng(),
        user.public_key(),
        now - 60,
        now + 3600,
    )
    .unwrap();
    wrong_principal_builder.serial(3).unwrap();
    wrong_principal_builder.key_id("wrong-principal").unwrap();
    wrong_principal_builder.cert_type(CertType::User).unwrap();
    wrong_principal_builder
        .valid_principal("somebody-else")
        .unwrap();
    let wrong_principal = wrong_principal_builder.sign(&ca).unwrap();
    let rejected = client
        .authenticate_openssh_cert("test", Arc::new(user.clone()), wrong_principal)
        .await
        .unwrap();
    assert!(
        !rejected.success(),
        "a certificate for another principal must be rejected"
    );

    // The adapter implements no OpenSSH critical options; unknown critical
    // semantics must fail closed rather than being ignored.
    let mut critical_builder = Builder::new_with_random_nonce(
        &mut rand_10::rng(),
        user.public_key(),
        now - 60,
        now + 3600,
    )
    .unwrap();
    critical_builder.serial(4).unwrap();
    critical_builder.key_id("critical-option").unwrap();
    critical_builder.cert_type(CertType::User).unwrap();
    critical_builder.valid_principal("test").unwrap();
    critical_builder
        .critical_option("force-command", "forbidden")
        .unwrap();
    let critical = critical_builder.sign(&ca).unwrap();
    let rejected = client
        .authenticate_openssh_cert("test", Arc::new(user.clone()), critical)
        .await
        .unwrap();
    assert!(
        !rejected.success(),
        "unsupported critical certificate options must be rejected"
    );

    // An internally valid certificate from an arbitrary CA is not trusted.
    let rogue_ca = PrivateKey::random(&mut rand_10::rng(), Algorithm::Ed25519).unwrap();
    let mut rogue_builder = Builder::new_with_random_nonce(
        &mut rand_10::rng(),
        user.public_key(),
        now - 60,
        now + 3600,
    )
    .unwrap();
    rogue_builder.serial(2).unwrap();
    rogue_builder.key_id("rogue-user").unwrap();
    rogue_builder.cert_type(CertType::User).unwrap();
    rogue_builder.valid_principal("test").unwrap();
    let rogue = rogue_builder.sign(&rogue_ca).unwrap();
    let rejected = client
        .authenticate_openssh_cert("test", Arc::new(user.clone()), rogue)
        .await
        .unwrap();
    assert!(
        !rejected.success(),
        "an untrusted signing CA must be rejected"
    );

    let auth = client
        .authenticate_openssh_cert("test", Arc::new(user), cert)
        .await
        .unwrap();
    assert!(auth.success(), "certificate authentication completes");

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
async fn sftp_directory_reads_are_paginated_and_complete() {
    let owned: Vec<(String, String)> = (0..300)
        .map(|index| (format!("files/item-{index:03}"), format!("body-{index}")))
        .collect();
    let borrowed: Vec<(&str, &str)> = owned
        .iter()
        .map(|(name, body)| (name.as_str(), body.as_str()))
        .collect();
    let elf = compile(SFTP_SERVER, "ssh-sftp-list.c");
    let harness = Harness::with_tree(&borrowed);
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
    let mut entries = sftp
        .read_dir(".")
        .await
        .unwrap()
        .map(|entry| entry.file_name())
        .collect::<Vec<_>>();
    entries.sort();
    assert_eq!(entries.len(), 300);
    assert_eq!(entries.first().map(String::as_str), Some("item-000"));
    assert_eq!(entries.last().map(String::as_str), Some("item-299"));
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
async fn sftp_listing_skips_refused_rows_and_shows_real_directory_attributes() {
    let elf = compile(SFTP_SERVER, "ssh-sftp-list.c");
    let harness = Harness::with_tree_and_refused(
        &[
            ("files/a.txt", "a"),
            ("files/sub/x", "x"),
            ("files/sock", ""),
            ("files/z.txt", "z"),
        ],
        &["files/sock"],
    );
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
    let mut entries = sftp
        .read_dir(".")
        .await
        .unwrap()
        .map(|entry| (entry.file_name(), entry.metadata()))
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    // The refused socket-like row is skipped -- never presented with
    // fabricated attributes -- and the real directory row is listed with
    // directory attributes derived from its kind.
    let names: Vec<&str> = entries.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, vec!["a.txt", "sub", "z.txt"]);
    let sub = entries.iter().find(|(name, _)| name == "sub").unwrap();
    assert!(
        sub.1.is_dir(),
        "a directory row is listed with dir attributes"
    );
    assert_eq!(sub.1.permissions, Some(0o040555));
    assert!(!entries.iter().any(|(name, _)| name == "sock"));
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

// ---- F1: the outbound lane must backpressure instead of buffering -------

const LANE_FLOOD: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  if (sy_ssh_start(SY_SELF, SY_SSH_AUTH_NONE) < 0) return 100;
  sy_s64 channel = -1;
  struct sy_pollfd fds[2] = {{ SY_SELF, SY_POLL_IN, 0 }};
  sy_u64 count = 1;
  for (;;) {
    if (sy_poll(fds, count, 5000) < 0) return 101;
    if (fds[0].revents & SY_POLL_IN) {
      struct sy_ssh_event event;
      while (sy_ssh_next(SY_SELF, &event, sizeof event) == 1) {
        if (event.kind == SY_SSH_EVENT_AUTH_NONE) {
          if (sy_ssh_auth_reply(event.id, SY_SSH_AUTH_ACCEPT,
                                SY_SSH_AUTH_NONE) < 0) return 102;
        } else if (event.kind == SY_SSH_EVENT_CHANNEL_OPEN) {
          channel = sy_ssh_channel_accept(event.id);
          if (channel < 0) return 103;
          fds[1] = (struct sy_pollfd){ channel, SY_POLL_IN, 0 };
          count = 2;
        } else if (event.kind == SY_SSH_EVENT_CHANNEL_REQUEST) {
          sy_s64 lane = sy_ssh_channel_lane(channel, SY_SSH_EXTENDED_STDERR);
          if (lane < 0) return 104;
          if (sy_ssh_request_reply(event.id, SY_SSH_REQUEST_SUCCESS) < 0)
            return 105;
          /* Flood the outbound lane without ever reading it back. The lane
             channel is bounded (CHANNEL_LANE_CAPACITY): once the ring and
             the lane are full, sy_write must report SY_EAGAIN rather than
             buffer forever in host memory. */
          char block[8192];
          sy_s64 backpressured = 0;
          for (sy_s64 i = 0; i < 600; i++) {
            sy_s64 n = sy_write(lane, block, sizeof block);
            if (n == SY_EAGAIN) { backpressured = 1; break; }
            if (n < 0) return 106;
          }
          return backpressured ? 0 : 107;
        } else {
          if (sy_ssh_event_done(event.id) < 0) return 108;
        }
      }
    }
    if (fds[0].revents & (SY_POLL_HUP | SY_POLL_ERR)) return 0;
  }
}
"#;

#[tokio::test]
async fn a_full_outbound_lane_backpressures_the_guest_with_eagain() {
    let elf = compile(LANE_FLOOD, "ssh-lane-flood.c");
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
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_stream,
        Client,
    )
    .await
    .unwrap();
    assert!(client.authenticate_none("test").await.unwrap().success());
    let channel = client.channel_open_session().await.unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        channel.request_shell(true),
    )
    .await
    .expect("the shell request got a reply")
    .unwrap();
    // Do not read yet: the flood must backpressure, which is what the guest
    // asserts (SY_EAGAIN instead of an always-successful write).
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    // Drain whatever the lane buffered, so the invocation's teardown drain
    // completes promptly.
    let draining = tokio::spawn(async move {
        let mut stream = channel.into_stream();
        let mut buf = vec![0u8; 65536];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });
    let _ = client
        .disconnect(russh::Disconnect::ByApplication, "done", "en")
        .await;
    drop(client);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(15), run)
        .await
        .expect("invocation stopped after the flood")
        .unwrap();
    assert_eq!(outcome.status, SockStatus::Ok(0));
    draining.await.ok();
}

// ---- F17: a refused outbound open must release its handle slot -----------

const REJECTED_OPENS: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  const char type[] = "no-such-type@example.com";
  const char opening[] = "";
  if (sy_ssh_start(SY_SELF, SY_SSH_AUTH_NONE) < 0) return 90;
  struct sy_pollfd fds[1] = {{ SY_SELF, SY_POLL_IN, 0 }};
  for (;;) {
    if (sy_poll(fds, 1, 5000) < 0) return 91;
    if (fds[0].revents & SY_POLL_IN) {
      struct sy_ssh_event event;
      while (sy_ssh_next(SY_SELF, &event, sizeof event) == 1) {
        if (event.kind == SY_SSH_EVENT_AUTH_NONE) {
          if (sy_ssh_auth_reply(event.id, SY_SSH_AUTH_ACCEPT,
                                SY_SSH_AUTH_NONE) < 0) return 92;
        } else if (event.kind == SY_SSH_EVENT_AUTHENTICATED) {
          /* Every open is refused by the peer (CHANNEL_OPEN_FAILURE). The
             failed fd stays reserved until the guest closes it, so it cannot
             alias a later endpoint; closing each one must allow more than a
             handle-table's worth of sequential refusals. */
          for (sy_s64 i = 0; i < 40; i++) {
            sy_s64 h = sy_ssh_channel_open(SY_SELF, type, sizeof(type) - 1,
                                           opening, 0);
            if (h < 0) return 93;
            struct sy_pollfd wait[1] = {{ h, SY_POLL_IN, 0 }};
            sy_s64 refused = 0;
            for (sy_s64 tries = 0; tries < 50; tries++) {
              if (sy_poll(wait, 1, 100) < 0) return 94;
              if (wait[0].revents & SY_POLL_ERR) { refused = 1; break; }
            }
            if (!refused) return 95;
            if (sy_close(h) < 0) return 98;
          }
          if (sy_ssh_event_done(event.id) < 0) return 96;
          return 0;
        } else {
          if (sy_ssh_event_done(event.id) < 0) return 97;
        }
      }
    }
    if (fds[0].revents & (SY_POLL_HUP | SY_POLL_ERR)) return 0;
  }
}
"#;

struct RejectingClient;

impl russh::client::Handler for RejectingClient {
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
        _channel_type: &str,
    ) -> bool {
        false
    }
}

#[tokio::test]
async fn rejected_server_initiated_channel_opens_release_their_handle_slots() {
    let elf = compile(REJECTED_OPENS, "ssh-rejected-opens.c");
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
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_stream,
        RejectingClient,
    )
    .await
    .unwrap();
    assert!(client.authenticate_none("test").await.unwrap().success());
    // The guest refuses nothing itself: it opens 40 outbound channels, all of
    // which this client refuses; give the refusal round trips time.
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    let _ = client
        .disconnect(russh::Disconnect::ByApplication, "done", "en")
        .await;
    drop(client);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), run)
        .await
        .expect("invocation stopped after the refused opens")
        .unwrap();
    assert_eq!(outcome.status, SockStatus::Ok(0));
}

// ---- F18: exit-status delivery loss must be countable, never silent -------

const EXIT_STATUS_LIVE: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  if (sy_ssh_start(SY_SELF, SY_SSH_AUTH_NONE) < 0) return 70;
  sy_s64 channel = -1;
  struct sy_pollfd fds[2] = {{ SY_SELF, SY_POLL_IN, 0 }};
  sy_u64 count = 1;
  for (;;) {
    if (sy_poll(fds, count, 5000) < 0) return 71;
    if (fds[0].revents & SY_POLL_IN) {
      struct sy_ssh_event event;
      while (sy_ssh_next(SY_SELF, &event, sizeof event) == 1) {
        if (event.kind == SY_SSH_EVENT_AUTH_NONE) {
          if (sy_ssh_auth_reply(event.id, SY_SSH_AUTH_ACCEPT,
                                SY_SSH_AUTH_NONE) < 0) return 72;
        } else if (event.kind == SY_SSH_EVENT_CHANNEL_OPEN) {
          channel = sy_ssh_channel_accept(event.id);
          if (channel < 0) return 73;
          fds[1] = (struct sy_pollfd){ channel, SY_POLL_IN, 0 };
          count = 2;
        } else if (event.kind == SY_SSH_EVENT_CHANNEL_REQUEST) {
          if (sy_ssh_request_reply(event.id, SY_SSH_REQUEST_SUCCESS) < 0)
            return 74;
          /* the channel is confirmed: deliver a status and a signal while
             the client is still there */
          if (sy_ssh_exit_status(channel, 42) < 0) return 75;
          if (sy_ssh_exit_signal(channel, "SIGX", 4, 0) < 0) return 76;
        } else {
          if (sy_ssh_event_done(event.id) < 0) return 77;
        }
      }
    }
    if (fds[0].revents & (SY_POLL_HUP | SY_POLL_ERR)) {
      /* the delivery tasks have long finished; nothing may have been lost */
      if (sy_ssh_exit_status_lost(SY_SELF) != 0) return 78;
      return 0;
    }
  }
}
"#;

#[tokio::test]
async fn exit_status_and_signal_reach_the_client_and_nothing_is_counted_lost() {
    let elf = compile(EXIT_STATUS_LIVE, "ssh-exit-status-live.c");
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
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_stream,
        Client,
    )
    .await
    .unwrap();
    assert!(client.authenticate_none("test").await.unwrap().success());
    let mut channel = client.channel_open_session().await.unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        channel.request_shell(true),
    )
    .await
    .expect("the shell request got a reply")
    .unwrap();
    let mut got_success = false;
    let mut got_status = false;
    let mut got_signal = false;
    while !(got_success && got_status && got_signal) {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(5), channel.wait())
            .await
            .expect("the channel delivered something")
            .expect("the channel stayed open");
        match msg {
            russh::ChannelMsg::Success => got_success = true,
            russh::ChannelMsg::ExitStatus { exit_status: 42 } => got_status = true,
            russh::ChannelMsg::ExitSignal {
                signal_name: russh::Sig::Custom(name),
                ..
            } if name == "SIGX" => got_signal = true,
            other => panic!("unexpected channel message: {other:?}"),
        }
    }

    client
        .disconnect(russh::Disconnect::ByApplication, "done", "en")
        .await
        .unwrap();
    drop(client);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), run)
        .await
        .expect("invocation stopped after the disconnect")
        .unwrap();
    assert_eq!(outcome.status, SockStatus::Ok(0));
}

const EXIT_STATUS_LOST: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  if (sy_ssh_start(SY_SELF, SY_SSH_AUTH_NONE) < 0) return 80;
  sy_s64 channel = -1;
  struct sy_pollfd fds[2] = {{ SY_SELF, SY_POLL_IN, 0 }};
  sy_u64 count = 1;
  for (;;) {
    if (sy_poll(fds, count, 5000) < 0) return 81;
    if (fds[0].revents & SY_POLL_IN) {
      struct sy_ssh_event event;
      while (sy_ssh_next(SY_SELF, &event, sizeof event) == 1) {
        if (event.kind == SY_SSH_EVENT_AUTH_NONE) {
          if (sy_ssh_auth_reply(event.id, SY_SSH_AUTH_ACCEPT,
                                SY_SSH_AUTH_NONE) < 0) return 82;
        } else if (event.kind == SY_SSH_EVENT_CHANNEL_OPEN) {
          channel = sy_ssh_channel_accept(event.id);
          if (channel < 0) return 83;
          fds[1] = (struct sy_pollfd){ channel, SY_POLL_IN, 0 };
          count = 2;
        } else if (event.kind == SY_SSH_EVENT_CHANNEL_REQUEST) {
          if (sy_ssh_request_reply(event.id, SY_SSH_REQUEST_SUCCESS) < 0)
            return 84;
        } else {
          if (sy_ssh_event_done(event.id) < 0) return 85;
        }
      }
    }
    if (fds[0].revents & (SY_POLL_HUP | SY_POLL_ERR)) {
      /* The connection is gone, so the status can never reach the client:
         the delivery must be counted, never silently claimed as made. */
      if (sy_ssh_exit_status(channel, 43) < 0) return 86;
      /* The counting happens in a task spawned by sy_ssh_exit_status, which
         runs only while the guest is blocked. SY_SELF stays HUP-ready, so a
         poll on it would return at once and never let the task run; a fresh
         lane endpoint, instead, is open with no data in flight and blocks
         its full timeout — the yield the delivery task needs. */
      sy_s64 lane = sy_ssh_channel_lane(channel, 0);
      if (lane < 0) return 89;
      for (sy_s64 tries = 0; tries < 200; tries++) {
        if (sy_ssh_exit_status_lost(SY_SELF) > 0) return 0;
        struct sy_pollfd wait[1] = {{ lane, SY_POLL_IN, 0 }};
        if (sy_poll(wait, 1, 20) < 0) return 87;
      }
      return 88;
    }
  }
}
"#;

#[tokio::test]
async fn lost_exit_delivery_is_counted_and_visible_to_the_guest() {
    let elf = compile(EXIT_STATUS_LOST, "ssh-exit-status-lost.c");
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
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_stream,
        Client,
    )
    .await
    .unwrap();
    assert!(client.authenticate_none("test").await.unwrap().success());
    let channel = client.channel_open_session().await.unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        channel.request_shell(true),
    )
    .await
    .expect("the shell request got a reply")
    .unwrap();
    // Ending the connection is what makes the guest's later exit-status
    // undeliverable: the run loop is gone, so the Handle send fails, and the
    // guest must observe the failure through sy_ssh_exit_status_lost.
    client
        .disconnect(russh::Disconnect::ByApplication, "done", "en")
        .await
        .unwrap();
    drop(client);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), run)
        .await
        .expect("invocation stopped after the disconnect")
        .unwrap();
    assert_eq!(outcome.status, SockStatus::Ok(0));
}
