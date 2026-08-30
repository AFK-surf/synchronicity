/* echo — the smallest socket that is still a real one.
 *
 *   synch socket build examples/echo.c -o echo.o
 *   cp echo.o ~/synchronicity/code/echo.sock
 *   synch socket declare code/echo.sock
 *   synch socket arm code/echo.sock
 *   synch socket connect nas:code/echo.sock
 *
 * Everything a socket must have and nothing it need not: a declaration hook
 * the operator reads at arm time, one event loop, and an end that lets the
 * last bytes out before it closes.
 */

#include <synch.h>

SY_MANIFEST("{\"manifest\":1,\"name\":\"echo\",\"max_streams\":16}");

SY_ENTRY sy_s64 entry(void) {
  char buf[2048];
  struct sy_pump pump = SY_PUMP_INIT;
  sy_s64 total = 0;

  for (;;) {
    struct sy_pollfd fds[1] = {{SY_SELF, 0, 0}};

    /* Backpressure decides what to wait for. While the pump still holds a
       short write's remainder there is nowhere to put more input, so wait for
       room to write rather than for something to read. Getting this the wrong
       way round is how a proxy ends up spinning on a full window. */
    fds[0].events = sy_pump_blocked(&pump) ? SY_POLL_OUT : SY_POLL_IN;

    if (sy_poll(fds, 1, 30000) <= 0) break; /* 0 = 30s idle, or all quiet */
    if (fds[0].revents & SY_POLL_ERR) return sy_errno(SY_SELF);

    sy_s64 n = sy_pump(SY_SELF, SY_SELF, buf, sizeof buf, &pump);
    if (n == 0) break; /* a clean EOF, with nothing left unwritten */
    if (n < 0 && n != SY_EAGAIN) return n;
    if (n > 0) total += n;
  }

  /* Half-closes once what is buffered has drained, so the caller sees the
     whole reply and then an EOF rather than a truncated one. */
  sy_shutdown(SY_SELF);
  return total; /* → Closed{ Ok(bytes echoed) } */
}
