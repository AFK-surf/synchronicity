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
  final octet of `SSH_MSG_USERAUTH_FAILURE`.
- server/encrypted.rs: every message queued to the per-channel mpsc
  (data, extended data, eof, close, open-confirmation, open-failure, and
  all nine channel-request arms) is sent under a 1s timeout and dropped
  under sustained backpressure, so the run loop can never block past 1s
  per message and never past the inactivity timer's polling interval
  (mirrors synch-sock's `LANE_SEND_TIMEOUT_MS`). The window-adjust path
  uses a non-blocking `try_send`.
- server/mod.rs + server/encrypted.rs: add `auth_publickey_offered_cert`
  (default delegates to `auth_publickey_offered` with the embedded key) and
  call it from the publickey probe path when the request carried an OpenSSH
  certificate, so servers can distinguish certificate-backed offers.

All parsing remains under russh's transport packet bounds. Known channel types
continue to require their exact RFC/OpenSSH layouts with no trailing data.
