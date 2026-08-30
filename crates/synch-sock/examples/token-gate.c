/* token-gate — a shared secret, checked the way a shared secret has to be.
 *
 *   synch socket build examples/token-gate.c -o token-gate.o
 *   synch socket declare ops/gate.sock --config token=hunter2
 *   synch socket arm ops/gate.sock
 *   printf 'hunter2\n' | synch socket connect nas:ops/gate.sock
 *
 * Membership already decides who may open this socket, so a token here is a
 * second factor rather than the only one — a way to scope a socket more
 * tightly than the delegation that reaches it. The secret comes from the
 * socket's config and not from the daemon's environment, which on a serverless
 * node holds cloud credentials that every socket would otherwise be able to
 * read.
 */

#include <synch.h>

#define TIMEOUT 5000
/* Guesses one caller may make in a minute. An offered token is a guess. */
#define ATTEMPTS_PER_MINUTE 10

SY_MANIFEST("{\"manifest\":1,\"name\":\"token-gate\",\"max_streams\":8}");

static sy_s64 read_line(char *out, sy_u64 cap) {
  sy_u64 len = 0;
  for (;;) {
    struct sy_pollfd fds[1] = {{SY_SELF, SY_POLL_IN, 0}};
    sy_s64 ready = sy_poll(fds, 1, TIMEOUT);
    if (ready < 0) return ready;
    if (ready == 0) return SY_ETIMEDOUT;

    char c;
    sy_s64 n = sy_read(SY_SELF, &c, 1);
    if (n == SY_EAGAIN) continue;
    if (n < 0) return n;
    if (n == 0) break;
    if (c == '\n') break;
    if (c == '\r') continue;
    if (len + 1 >= cap) return SY_ELIMIT;
    out[len++] = c;
  }
  out[len] = 0;
  return (sy_s64)len;
}

static sy_s64 refuse(const char *why, sy_s64 code) {
  sy_write_all(SY_SELF, why, sy_strlen(why), TIMEOUT);
  sy_shutdown(SY_SELF);
  return code;
}

SY_ENTRY sy_s64 entry(void) {
  char expected[128];
  sy_s64 want = sy_config_get(SY_STR("token"), expected, sizeof expected);
  if (want <= 0 || want >= (sy_s64)sizeof expected) {
    /* Refusing to run without a secret beats running without one. A socket
       that treats a missing config key as "no gate" is a gate that opens when
       somebody mistypes `synch socket declare`. */
    sy_log(SY_STR("no usable `token` in this socket's config\n"));
    return refuse("misconfigured\n", 1);
  }

  sy_u8 device[32];
  sy_peer_device_key(device);
  if (sy_rate_limit(device, sizeof device, ATTEMPTS_PER_MINUTE, 60000) < 0) {
    sy_metric_add(SY_STR("throttled"), 1);
    return refuse("too many attempts\n", 2);
  }

  char offered[128];
  sy_s64 got = read_line(offered, sizeof offered);
  if (got < 0) return refuse("no token offered\n", 3);

  /* Length first, then a constant-time compare of that many bytes. `sy_ct_eq`
     compares a fixed count and cannot tell the caller *where* two secrets
     differ; a comparison that stopped at the first mismatch would, one byte of
     timing at a time. The length is compared in the open because a length is
     not a secret, and `sy_ct_eq` has to be given one number of bytes anyway. */
  if (got != want || sy_ct_eq(offered, expected, (sy_u64)want) != 1) {
    sy_metric_add(SY_STR("denied"), 1);
    sy_log(SY_STR("denied\n"));
    return refuse("denied\n", 4);
  }

  sy_metric_add(SY_STR("allowed"), 1);
  sy_label_set(SY_STR("phase"), SY_STR("authorized"));

  /* Past the gate. A real one would go on to do the work the token bought;
     this one says so and stops, so that what it demonstrates is the check. */
  sy_write_all(SY_SELF, SY_STR("ok\n"), TIMEOUT);
  sy_shutdown(SY_SELF);
  return 0;
}
