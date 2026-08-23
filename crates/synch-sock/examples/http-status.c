/* http-status — a status page, over HTTP, from inside the cluster.
 *
 *   synch socket build examples/http-status.c -o http-status.o
 *   synch socket add ops/status.sock
 *   synch socket arm ops/status.sock
 *   synch connect nas:ops/status.sock --tcp 127.0.0.1:8080   # then open it
 *
 * `synch connect --tcp` puts a local listener in front of the stream, so a
 * socket that speaks HTTP is a page in a browser without anything on the node
 * listening on a port. The counter is in the socket map, so it survives the
 * invocation that incremented it and is shared by every stream of this socket
 * — which is the difference between socket state and program state.
 */

#include <synch.h>

#define TIMEOUT 15000

SY_INIT_ENTRY sy_s64 declare(void) {
  sy_declare_name(SY_STR("http-status"));
  sy_declare_max_streams(32);
  return 0;
}

/* Appends to a fixed buffer, refusing to overrun it. Returns the new length,
   or `cap + 1` once anything has been dropped — a marker the caller checks
   once at the end rather than after every field. */
static sy_u64 append(char *out, sy_u64 off, sy_u64 cap, const char *text,
                     sy_u64 len) {
  if (off > cap || len > cap - off) return cap + 1;
  sy_memcpy(out + off, text, len);
  return off + len;
}

static sy_u64 append_u64(char *out, sy_u64 off, sy_u64 cap, sy_u64 value) {
  char digits[24];
  sy_s64 n = sy_utoa(value, digits, sizeof digits);
  if (n < 0) return cap + 1;
  return append(out, off, cap, digits, (sy_u64)n);
}

/* Reads the request head and throws it away. A status page has one answer, so
   nothing here parses a method or a path — but the head still has to be read,
   because a client that has not finished sending will not start receiving. */
static void drain_request(void) {
  char scratch[512];
  sy_u64 seen = 0;
  for (;;) {
    struct sy_pollfd fds[1] = {{SY_SELF, SY_POLL_IN, 0}};
    if (sy_poll(fds, 1, 5000) <= 0) return;
    sy_s64 n = sy_read(SY_SELF, scratch, sizeof scratch);
    if (n == SY_EAGAIN) continue;
    if (n <= 0) return;
    seen += (sy_u64)n;
    /* Bounded: whatever this is, it is not a request for a status page. */
    if (seen > 16384) return;
    /* The blank line, in whichever chunk it landed. Approximate on purpose —
       a `\n\n` split across two reads just means one more poll. */
    for (sy_s64 i = 1; i < n; i++)
      if (scratch[i] == '\n' && (scratch[i - 1] == '\n' || scratch[i - 1] == '\r'))
        return;
  }
}

SY_ENTRY sy_s64 entry(void) {
  drain_request();

  /* Shared by every stream of this socket, and outliving all of them. A TTL of
     0 means no expiry; the map is bounded by key count and bytes instead. */
  sy_s64 hits = sy_map_incr(SY_STR("requests"), 1, 0);
  if (hits < 0) hits = 0;
  sy_metric_add(SY_STR("requests"), 1);

  char body[640];
  char scratch[192];
  sy_u64 len = 0;

  len = append(body, len, sizeof body, SY_STR("synchronicity "));
  sy_version(scratch, sizeof scratch);
  len = append(body, len, sizeof body, scratch, sy_strlen(scratch));

  len = append(body, len, sizeof body, SY_STR("\nnode      "));
  sy_self_origin(scratch, sizeof scratch);
  len = append(body, len, sizeof body, scratch, sy_strlen(scratch));

  len = append(body, len, sizeof body, SY_STR("\nsocket    "));
  sy_socket_path(scratch, sizeof scratch);
  len = append(body, len, sizeof body, scratch, sy_strlen(scratch));

  len = append(body, len, sizeof body, SY_STR("\npeer      "));
  sy_peer_origin(scratch, sizeof scratch);
  len = append(body, len, sizeof body, scratch, sy_strlen(scratch));
  len = append(body, len, sizeof body,
               sy_peer_kind() == SY_PEER_MEMBER ? " (member)" : " (delegate)",
               sy_peer_kind() == SY_PEER_MEMBER ? 9 : 11);

  len = append(body, len, sizeof body, SY_STR("\nuptime-ms "));
  len = append_u64(body, len, sizeof body, sy_monotonic_ns() / 1000000);

  len = append(body, len, sizeof body, SY_STR("\nrequests  "));
  len = append_u64(body, len, sizeof body, (sy_u64)hits);
  len = append(body, len, sizeof body, SY_STR("\n"));

  if (len > sizeof body) {
    /* Nothing was truncated silently: the body is a whole answer or it is a
       500, because half a status page reads like a working one. */
    sy_log(SY_STR("status body did not fit\n"));
    sy_write_all(SY_SELF,
                 SY_STR("HTTP/1.1 500 Internal Server Error\r\n"
                        "Content-Length: 0\r\n"
                        "Connection: close\r\n\r\n"),
                 TIMEOUT);
    sy_shutdown(SY_SELF);
    return 1;
  }

  char head[128];
  sy_u64 head_len = 0;
  head_len = append(head, head_len, sizeof head,
                    SY_STR("HTTP/1.1 200 OK\r\n"
                           "Content-Type: text/plain; charset=utf-8\r\n"
                           "Connection: close\r\n"
                           "Content-Length: "));
  head_len = append_u64(head, head_len, sizeof head, len);
  head_len = append(head, head_len, sizeof head, SY_STR("\r\n\r\n"));
  if (head_len > sizeof head) return 2;

  if (sy_write_all(SY_SELF, head, head_len, TIMEOUT) < 0) return 3;
  if (sy_write_all(SY_SELF, body, len, TIMEOUT) < 0) return 4;

  sy_shutdown(SY_SELF);
  return 0;
}
