/* A drop-box: members and delegates of `code` deposit files into
 * `code/inbox/<their-origin>/`, append-only, at most one per minute
 * (`docs/TREE-WRITES.md` §7).
 *
 * The pieces the tree-write design exists to provide are all visible here: a
 * target path built from the *handshake's* identity, caller input reduced to
 * one validated filename, a prefix and a mode the operator approved in
 * advance, a size bound enforced as bytes arrive, and a commit whose root
 * goes back to the caller as a receipt the caller can verify against the
 * tree.
 *
 * Call it with the filename in the connection metadata:
 *
 *   synch connect nas:code/drop.sock --meta name=report.pdf < report.pdf
 */

#include <synch.h>

SY_INIT_ENTRY sy_s64 declare(void) {
  sy_s64 cap = sy_json_parse(SY_STR(
      "{\"id\":1,\"prefix\":\"code/inbox\",\"allow\":[\"create\"],"
      "\"max_bytes\":16777216}"));
  if (cap < 0) return cap;
  sy_s64 rc = sy_declare_tree_write(cap);
  sy_close(cap);
  if (rc < 0) return rc;
  sy_declare_name(SY_STR("drop-box"));
  sy_declare_max_streams(8);
  return 0;
}

/* `name` comes from caller-chosen Open.meta: untrusted. One flat component,
 * no dotfiles, no controls — everything else about the path is ours. */
static int name_ok(const char *s, sy_s64 n) {
  if (n <= 0 || n > 128 || s[0] == '.') return 0;
  for (sy_s64 i = 0; i < n; i++)
    if (s[i] == '/' || s[i] < 0x20) return 0;
  return 1;
}

SY_ENTRY sy_s64 entry(void) {
  /* 1. Authorization is the handshake. Nothing here parses caller input
     to decide who may deposit. */
  if (!sy_peer_has_space(SY_STR("code"))) return -1;

  /* 2. Per-caller rate limit, keyed by device key — survives a rename. */
  sy_u8 key[32];
  sy_peer_device_key(key);
  if (sy_rate_limit(key, sizeof key, 1, 60000) < 0) return -1;

  /* 3. One validated filename out of the caller's metadata. */
  char name[129];
  sy_s64 nlen = sy_conn_meta(SY_STR("name"), name, sizeof name);
  if (nlen <= 0 || nlen >= (sy_s64)sizeof name || !name_ok(name, nlen))
    return -1;

  /* 4. The rest of the path is the handshake's, not the caller's. */
  char path[256];
  sy_u64 plen = 0;
  sy_memcpy(path, "code/inbox/", 11);
  plen = 11;
  plen += sy_peer_origin(path + plen, sizeof path - plen - 1);
  path[plen++] = '/';
  sy_memcpy(path + plen, name, (sy_u64)nlen);
  plen += (sy_u64)nlen;

  sy_s64 w = sy_put_open(1, path, plen);
  if (w < 0) return w;

  /* 5. Drain the caller into staging; the payload never enters the frame. */
  for (;;) {
    sy_s64 n = sy_put_splice(w, SY_SELF, 65536);
    if (n == 0) break; /* caller's clean EOF */
    if (n == SY_EAGAIN) {
      struct sy_pollfd fds[2] = { { SY_SELF, SY_POLL_IN, 0 },
                                  { w, SY_POLL_OUT, 0 } };
      if (sy_poll(fds, 2, -1) <= 0) return -1;
      if ((fds[0].revents | fds[1].revents) & SY_POLL_ERR) return -1;
    } else if (n < 0) {
      return n;
    }
  }

  /* 6. Commit: dispatch, poll, repeat the call for the receipt. */
  sy_u8 root[32];
  sy_s64 rc;
  while ((rc = sy_put_commit(w, root)) == SY_EAGAIN) {
    struct sy_pollfd fd = { w, SY_POLL_IN, 0 };
    if (sy_poll(&fd, 1, -1) <= 0) return -1;
  }
  if (rc < 0) return rc; /* SY_EPERM: already deposited (create-only) */

  char hex[65];
  sy_hex_encode(root, sizeof root, hex, sizeof hex, 0);
  sy_write_all(SY_SELF, hex, 64, 5000);
  return 0;
}
