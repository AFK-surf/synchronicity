/* whoami — what the node knows about the caller, and where it learned it.
 *
 *   synch socket build examples/whoami.c -o whoami.o
 *   synch socket declare ops/whoami.sock
 *   synch socket arm ops/whoami.sock
 *   synch socket connect nas:ops/whoami.sock --meta tag=laptop
 *
 * Useful as it stands — it is the fastest way to find out whether a delegation
 * is doing what you think — and it is here to make one distinction concrete.
 * Everything above the blank line came out of the iroh handshake and cannot be
 * forged by the caller. Everything below it is text the caller typed.
 */

#include <synch.h>

#define TIMEOUT 10000

SY_MANIFEST("{\"manifest\":1,\"name\":\"whoami\",\"max_streams\":8}");

/* Every out-parameter here has snprintf semantics: the return is what a
   complete write would have needed, so a value larger than the buffer is
   detectable without asking twice. These buffers are sized past every answer
   the host can give, so this example checks the length only where the answer
   is genuinely optional. */
static void field(const char *label, const char *value, sy_u64 len) {
  sy_write_all(SY_SELF, label, sy_strlen(label), TIMEOUT);
  sy_write_all(SY_SELF, value, len, TIMEOUT);
  sy_write_all(SY_SELF, SY_STR("\n"), TIMEOUT);
}

SY_ENTRY sy_s64 entry(void) {
  char buf[192];
  char hex[65];
  char number[24];
  sy_u8 key[32];

  sy_peer_origin(buf, sizeof buf);
  field("peer-origin:  ", buf, sy_strlen(buf));

  /* The device key survives an origin rename, which is what makes it the right
     key for a per-caller rate limit and the wrong one to print at a human. */
  sy_peer_device_key(key);
  sy_hex_encode(key, sizeof key, hex, sizeof hex, 0);
  field("peer-key:     ", hex, sy_strlen(hex));

  /* The identity JSON names the kind; no numbered enum to translate. */
  sy_s64 info = sy_peer_info();
  char kind[16] = "unknown";
  if (info >= 0) {
    sy_json_get_string(info, SY_STR("kind"), kind, sizeof kind);
    sy_close(info);
  }
  field("peer-kind:    ", kind, sy_strlen(kind));

  /* A rooted member reads every space by construction; a delegate reads the
     list its delegation names. Asking about one space is the whole of an
     access rule that a caller cannot talk its way past. */
  field("reads `code`: ", sy_peer_has_space(SY_STR("code")) ? "yes" : "no",
        sy_peer_has_space(SY_STR("code")) ? 3 : 2);

  /* Informational: it can be a relay's address rather than the caller's. */
  sy_peer_addr(buf, sizeof buf);
  field("peer-addr:    ", buf, sy_strlen(buf));

  sy_s64 written = sy_utoa((sy_u64)sy_stream_index(), number, sizeof number);
  field("stream-index: ", number, (sy_u64)written);

  sy_self_origin(buf, sizeof buf);
  field("this-node:    ", buf, sy_strlen(buf));
  sy_socket_path(buf, sizeof buf);
  field("this-socket:  ", buf, sy_strlen(buf));
  sy_version(buf, sizeof buf);
  field("software:     ", buf, sy_strlen(buf));

  /* Below the line: not authenticated, not checked, not a fact. `sy_conn_meta`
     returns SY_ENOENT for a key the caller did not send, and a positive length
     otherwise — including a length longer than this buffer, which is why the
     result is compared against the buffer rather than only against zero. */
  sy_s64 n = sy_conn_meta(SY_STR("tag"), buf, sizeof buf);
  if (n > 0 && n < (sy_s64)sizeof buf) {
    sy_write_all(SY_SELF, SY_STR("\n"), TIMEOUT);
    field("claimed tag:  ", buf, (sy_u64)n);
  }

  sy_shutdown(SY_SELF);
  return 0;
}
