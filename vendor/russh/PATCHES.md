# Local russh patch

This directory contains `russh` 0.63.1 (Apache-2.0), patched narrowly for the
generic SSH channel ABI in `docs/SSH-SOCKETS.md`.

The patch:

- preserves and exposes opaque payloads for unknown inbound channel types;
- exposes inbound agent and forwarded-streamlocal channels to the server
  handler instead of rejecting them internally;
- adds a symmetric generic server-initiated channel-open operation; and
- preserves and exposes unknown channel-request payloads.

All parsing remains under russh's transport packet bounds. Known channel types
continue to require their exact RFC/OpenSSH layouts with no trailing data.
