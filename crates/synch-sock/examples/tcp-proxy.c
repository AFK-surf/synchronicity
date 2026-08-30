/* tcp-proxy — one upstream, reachable through the cluster and nowhere else.
 *
 *   synch socket build examples/tcp-proxy.c -o tcp-proxy.o
 *   synch socket declare code/git.sock
 *   synch socket arm code/git.sock        # inspect and copy the printed root
 *   synch socket arm code/git.sock --review <token>
 *   synch socket connect nas:code/git.sock --listen 127.0.0.1:9418
 *
 * The upstream is a compile-time constant because it is a *declaration*: the
 * init hook runs at arm time, with no config and nothing to reach, and what it
 * names is what the operator is shown and asked to approve. Overriding it is a
 * rebuild — `synch socket build --define UPSTREAM_PORT=9419 …` — and a rearm,
 * which is the point. A destination that could change without another approval
 * would not be a destination anybody approved.
 */

#include <synch.h>

#ifndef UPSTREAM_HOST
#define UPSTREAM_HOST "git.internal"
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 9418
#endif

/* Connections one caller may open in a minute. Keyed by device key, so it
   follows the caller through an origin rename. */
#define PER_PEER_PER_MINUTE 60

/* The whole of what this program may reach, as data in the object itself.
   Changing it changes the content root, so what an activated path serves is
   always exactly what its current bytes declare. */
SY_MANIFEST("{\"manifest\":1,\"name\":\"tcp-proxy\",\"max_streams\":32,"
            "\"egress\":[\"" UPSTREAM_HOST ":" SY_STRINGIZE(UPSTREAM_PORT)
            "\"]}");

SY_ENTRY sy_s64 entry(void) {
  /* Authorization is the handshake. Nothing below parses caller input to
     decide who they are, because there is nothing they could send that would
     be better evidence than what iroh already proved. */
  if (!sy_peer_has_space(SY_STR("code"))) {
    sy_log(SY_STR("refused: caller is not delegated `code`\n"));
    return 1;
  }

  sy_u8 device[32];
  sy_peer_device_key(device);
  if (sy_rate_limit(device, sizeof device, PER_PEER_PER_MINUTE, 60000) < 0) {
    sy_metric_add(SY_STR("throttled"), 1);
    return 2;
  }

  char peer[128];
  sy_peer_origin(peer, sizeof peer);
  sy_label_set(SY_STR("peer"), peer, sy_strlen(peer));

  /* Returns immediately, still connecting. Both the name and the address it
     resolves to are checked, so a name that resolves back at this node is
     refused where the address would have been. */
  sy_s64 up = sy_tcp_connect(SY_STR(UPSTREAM_HOST), UPSTREAM_PORT);
  if (up < 0) {
    sy_metric_add(SY_STR("connect-failed"), 1);
    return 3;
  }

  /* One buffer and one pump per direction: they fill and drain independently,
     and sharing either would make one direction's backpressure the other's. */
  char upward[1536], downward[1536];
  struct sy_pump to_upstream = SY_PUMP_INIT, to_caller = SY_PUMP_INIT;
  int caller_done = 0, upstream_done = 0;

  while (!(caller_done && upstream_done)) {
    struct sy_pollfd fds[2] = {{SY_SELF, 0, 0}, {up, 0, 0}};
    if (!caller_done) {
      if (sy_pump_blocked(&to_upstream)) fds[1].events |= SY_POLL_OUT;
      else fds[0].events |= SY_POLL_IN;
    }
    if (!upstream_done) {
      if (sy_pump_blocked(&to_caller)) fds[0].events |= SY_POLL_OUT;
      else fds[1].events |= SY_POLL_IN;
    }

    /* HUP and ERR are unconditional, so an endpoint that is no longer part of
       either active pump must not remain in the poll set with events == 0.
       Compact the two fixed per-handle entries after their interests are
       assembled. At least one direction is active while the loop continues. */
    sy_u64 nfds;
    if (fds[0].events == 0) {
      fds[0] = fds[1];
      nfds = 1;
    } else {
      nfds = fds[1].events == 0 ? 1 : 2;
    }

    /* A proxy is expected to be long-lived. Defer idle policy to the host's
       progress-based deadline instead of imposing a shorter timeout here. */
    if (sy_poll(fds, nfds, -1) <= 0) break;

    /* Each direction ends on its own. A loop that stopped the moment either
       side hung up would cut off the reply to the last request it forwarded,
       which is the single most common way to get this wrong. */
    if (!caller_done) {
      sy_s64 n = sy_pump(SY_SELF, up, upward, sizeof upward, &to_upstream);
      if (n == 0) {
        sy_shutdown(up);
        caller_done = 1;
      } else if (n < 0 && n != SY_EAGAIN) {
        break;
      }
    }
    if (!upstream_done) {
      sy_s64 n = sy_pump(up, SY_SELF, downward, sizeof downward, &to_caller);
      if (n == 0) {
        sy_shutdown(SY_SELF);
        upstream_done = 1;
      } else if (n < 0 && n != SY_EAGAIN) {
        break;
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
