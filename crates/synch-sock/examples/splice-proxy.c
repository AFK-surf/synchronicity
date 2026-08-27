/* splice-proxy — tcp-proxy.c's job, with the bytes never entering the program.
 *
 *   synch socket build examples/splice-proxy.c -o splice-proxy.o
 *   synch socket add code/git.sock
 *   synch socket arm code/git.sock        # inspect and copy the printed root
 *   synch socket arm code/git.sock --review <token>
 *   synch connect nas:code/git.sock --listen 127.0.0.1:9418
 *
 * `sy_splice` moves bytes from one endpoint's receive side straight into
 * another's send side. A program that only forwards has no reason to copy them
 * into itself twice on the way, and — because a short move leaves what did not
 * fit exactly where it was — no remainder to carry either. Compare
 * `tcp-proxy.c`: two 1536-byte buffers and two `struct sy_pump`s, all of which
 * exist so that a short write cannot lose the bytes it did not place.
 *
 * Read `tcp-proxy.c` first if you want the annotated version of the rest: the
 * declared upstream, the per-caller rate limit, and why each direction has to
 * be allowed to end on its own.
 */

#include <synch.h>

#ifndef UPSTREAM_HOST
#define UPSTREAM_HOST "git.internal"
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 9418
#endif

/* The most one call moves. A bound rather than "whatever both sides allow", so
   a saturated direction cannot keep the loop away from the other one. */
#define CHUNK 32768

SY_INIT_ENTRY sy_s64 declare(void) {
  sy_declare_name(SY_STR("splice-proxy"));
  sy_declare_egress(SY_STR(UPSTREAM_HOST), UPSTREAM_PORT);
  sy_declare_max_streams(32);
  return 0;
}

SY_ENTRY sy_s64 entry(void) {
  /* Authorization is the handshake, here as everywhere. */
  if (!sy_peer_has_space(SY_STR("code"))) {
    sy_log(SY_STR("refused: caller is not delegated `code`\n"));
    return 1;
  }

  sy_s64 up = sy_tcp_connect(SY_STR(UPSTREAM_HOST), UPSTREAM_PORT);
  if (up < 0) {
    sy_metric_add(SY_STR("connect-failed"), 1);
    return 3;
  }

  /* The whole of this proxy's state. There is no buffer and no remainder; what
     is left to know is which side each direction is waiting on. */
  int caller_done = 0, upstream_done = 0;
  int upward_blocked = 0, downward_blocked = 0;

  while (!(caller_done && upstream_done)) {
    struct sy_pollfd fds[2] = {{SY_SELF, 0, 0}, {up, 0, 0}};
    /* With bytes waiting and no room for them, wait for the room: asking for
       more input would wake immediately on input already delivered. */
    if (!caller_done) {
      if (upward_blocked) fds[1].events |= SY_POLL_OUT;
      else fds[0].events |= SY_POLL_IN;
    }
    if (!upstream_done) {
      if (downward_blocked) fds[0].events |= SY_POLL_OUT;
      else fds[1].events |= SY_POLL_IN;
    }

    /* HUP and ERR are unconditional, so an endpoint no longer part of either
       direction must not stay in the set with events == 0, where a terminal
       event would wake a wait that was about something else. */
    sy_u64 nfds;
    if (fds[0].events == 0) {
      fds[0] = fds[1];
      nfds = 1;
    } else {
      nfds = fds[1].events == 0 ? 1 : 2;
    }

    if (sy_poll(fds, nfds, -1) <= 0) break;

    if (!caller_done) {
      sy_s64 n = sy_splice(SY_SELF, up, CHUNK);
      if (n == 0) {
        sy_shutdown(up);
        caller_done = 1;
      } else if (n < 0 && n != SY_EAGAIN) {
        break;
      } else {
        /* Bytes still in the source with a full destination is the one state
           where waiting on the source would spin. It is also the only thing a
           short move leaves behind, which is why the flag is the state. */
        upward_blocked = sy_readable(SY_SELF) > 0 && sy_writable(up) == 0;
      }
    }
    if (!upstream_done) {
      sy_s64 n = sy_splice(up, SY_SELF, CHUNK);
      if (n == 0) {
        sy_shutdown(SY_SELF);
        upstream_done = 1;
      } else if (n < 0 && n != SY_EAGAIN) {
        break;
      } else {
        downward_blocked = sy_readable(up) > 0 && sy_writable(SY_SELF) == 0;
      }
    }

    sy_u32 revents = 0;
    for (sy_u64 i = 0; i < nfds; i++) revents |= fds[i].revents;
    if (revents & SY_POLL_ERR) break;
  }

  sy_close(up);
  sy_shutdown(SY_SELF);
  return 0;
}
