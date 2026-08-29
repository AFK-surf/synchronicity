# Local russh patch

This directory contains `russh` 0.63.1 (Apache-2.0), patched narrowly for the
generic SSH channel ABI in `docs/SSH-SOCKETS.md`.

The patch:

- preserves and exposes opaque payloads for unknown inbound channel types;
- exposes inbound agent and forwarded-streamlocal channels to the server
  handler instead of rejecting them internally;
- adds a symmetric generic server-initiated channel-open operation;
- preserves and exposes unknown channel-request payloads;
- adds detachable per-request reply tokens so asynchronous handlers preserve
  each packet's `want-reply` bit;
- permits agent requests to use the same deferred policy path; and
- encodes the handler's RFC 4252 partial-success flag in `USERAUTH_FAILURE`
  (upstream stored the decision's flag and then unconditionally overwrote it
  with `false` before encoding), resetting it after each rejection so no
  other rejection path replays a stale value.

Security hardening patches from the SSH audit:

- server/encrypted.rs: preserve the handler's `Auth::Reject` `partial_success`
  bit at all four USERAUTH dispatch sites (password, none, publickey signed,
  publickey probe) instead of clearing it; the bit now reaches the wire as the
  final octet of `SSH_MSG_USERAUTH_FAILURE`. `reject_auth_request` resets
  `AuthRequest::partial_success` immediately after encoding it, so the flag
  describes exactly the one request it was decided for and the in-memory field
  is `false` again by the time the next packet is dispatched. The wire bytes,
  not that field, are therefore what the regression test asserts on.
- server/encrypted.rs: every message queued to the per-channel mpsc
  (data, extended data, eof, close, open-confirmation, open-failure, and
  all nine channel-request arms) is sent under a 1s timeout, so the run loop
  can never block past 1s per message or past the inactivity timer's polling
  interval (mirrors synch-sock's `LANE_SEND_TIMEOUT_MS`). The window-adjust
  path uses a non-blocking `try_send`. Reliable data and extended-data go
  through `Session::send_channel_data`, which distinguishes the two failure
  modes:
  - a **timeout** (the receiver is alive but stalled) terminates the
    connection with `Error::SendError`. The packet's receive window has
    already been consumed and adjusted, so dropping it would silently corrupt
    the reliable byte stream.
  - a **closed receiver** (the application dropped its `Channel` while the SSH
    channel entry is still live) is not a connection-level fault. The message
    is discarded and that channel's sender is retired from `Session::channels`;
    every other channel multiplexed on the connection keeps running. Upstream
    tolerated this case with `.unwrap_or(())`, and so does this patch.

  Control-message timeouts remain best-effort (`let _ = timeout(...)`).
- server/mod.rs + server/encrypted.rs: add `auth_publickey_offered_cert`
  (default delegates to `auth_publickey_offered` with the embedded key) and
  call it from the publickey probe path when the request carried an OpenSSH
  certificate, so servers can distinguish certificate-backed offers.
- server/encrypted.rs: user certificates must match the SSH username and may
  not carry unsupported critical options. Signed requests without a cached
  probe decision also use the certificate-specific handler path. Certificate
  authority trust remains an explicit server-handler policy decision.
- server/encrypted.rs + server/mod.rs: an unknown `SSH_MSG_CHANNEL_REQUEST`
  that set `want-reply` is answered exactly once. The patch routes such
  requests to `Handler::channel_request_unknown`, whose default body does
  nothing; the `CHANNEL_REQUEST` arm therefore calls `Session::channel_failure`
  after the handler returns, which is a no-op when the handler already
  answered — inline, or by detaching the reply right with
  `Session::take_channel_request_reply` and answering later, both of which
  clear the channel's `wants_reply` bit. This restores upstream's fallback
  (`self.channel_failure(channel_num)?`) without taking away the patch's
  ability to handle or defer such a request. Leaving a `want-reply` request
  unanswered let a client that matches channel replies in strict request order
  misattribute a later `CHANNEL_SUCCESS` to it.
- channels/io/rx.rs: `ChannelRx::poll_read` no longer reports a zero-byte
  `Poll::Ready(Ok(()))` for a message that carries no readable bytes. An empty
  `CHANNEL_DATA` (or `CHANNEL_EXTENDED_DATA`) payload from the peer used to
  fill zero bytes and return `Ready`, which every Rust `AsyncRead` consumer —
  `tokio::io::copy` included — takes for end of stream: one empty packet
  truncated an SFTP transfer or closed a shell's stdin, after which the reader
  was never polled again and the peer's subsequent packets filled the
  16-slot per-channel buffer until the 1s send bound above tore the whole
  connection down. `poll_read` now loops around the receive: an empty payload,
  or a message this reader is not attached to, is consumed and the poll
  continues to the next `ChannelMsg`. Going back around to `poll_recv` is what
  keeps the waker registered, so no `Poll::Pending` is ever returned without
  one (this also replaces upstream's `wake_by_ref()` busy-poll for unrelated
  messages). Only a closed receiver and `ChannelMsg::Eof` still yield a
  zero-byte `Ready`. Partial-message buffering for non-empty payloads,
  including a read into a buffer with no room, is unchanged.

Mechanical divergences (no behavior change, needed to build cleanly under this
workspace's feature selection — `default-features = false`, `aws-lc-rs` only,
so neither `flate2` nor `rsa` is on):

- src/cipher/mod.rs:376 — `#[allow(dead_code)]` on
  `MAXIMUM_DECOMPRESSED_PACKET_LEN`. The constant is read only from
  `src/compression.rs`, which is compiled only with `flate2`.
- src/msg.rs:96 — `#[allow(dead_code)]` on
  `server::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`, which has no reader in the
  crate.
- src/keys/format/pkcs5.rs:17 — `#[allow(unused_variables)]` on the decrypted
  `sec` binding, which is consumed only by the `rsa`-gated branch.
- src/client/encrypted.rs:899 — `ChannelType::Unknown { typ, .. }` instead of
  `ChannelType::Unknown { typ }`, following the extra field the patch added to
  that variant to carry the opaque payload.

All parsing remains under russh's transport packet bounds. Known channel types
continue to require their exact RFC/OpenSSH layouts with no trailing data.

## Running the vendored crate's tests

The workspace root `exclude`s `vendor/russh`, and cargo does not resolve
`[dev-dependencies]` for a package that is not a workspace member. Running
`cargo check -p russh --tests` **from the workspace root therefore fails** with
unresolved `anyhow`/`env_logger`/`tempfile` and a `tokio` without the `macros`
and `rt-multi-thread` features — not because the manifest is missing anything,
but because those dev-deps are dropped from the root resolve. The crate is its
own workspace root (that is what `exclude` makes it), so its tests must be run
from this directory:

```
cd vendor/russh
cargo check -p russh --tests
cargo test -p russh --lib
```

`src/server/encrypted.rs` and `src/channels/io/rx.rs` carry the regression
tests for the patches above. The `keys::test::test_*agent*`,
`keys::test::test_sign_request_*` and
`tests::future_certificate::test_future_certificate_auth_full_flow` tests are
upstream tests that spawn an external `ssh-agent`; they fail with
`NotFound` on any host that does not have OpenSSH installed and are unrelated
to this patch.
