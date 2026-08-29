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

All parsing remains under russh's transport packet bounds. Known channel types
continue to require their exact RFC/OpenSSH layouts with no trailing data.
