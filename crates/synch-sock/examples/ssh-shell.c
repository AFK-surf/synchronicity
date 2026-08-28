/* ssh-shell — a real `ssh nas` login, terminated by a socket.
 *
 *   synch socket build examples/ssh-shell.c -o ssh-shell.o
 *   cp ssh-shell.o ~/synchronicity/code/ssh.sock
 *   synch socket add code/ssh.sock
 *   synch socket arm code/ssh.sock       # shows the exact /bin/bash declaration
 *   ssh -o 'ProxyCommand=synch connect %h:code/ssh.sock' nas
 *
 * The SSH adapter turns the inbound stream into a control fd and channel fds;
 * the process declaration is what lets this program put a PTY-backed bash
 * behind one of them (`docs/SSH-SOCKETS.md`). The three parts stay separate on
 * purpose: accepting the `session` channel starts nothing, a successful
 * `pty-req` allocates a terminal but starts nothing, and only the `shell`
 * request spawns the one executable the operator approved at arm time. The
 * client's username and command bytes never choose what runs.
 *
 * Authorization is the outer handshake: whoever the cluster let reach this
 * socket gets the shell, so SSH `none` completes the inner exchange. Arm it
 * only where that is the intended policy — §15.2 of the design shows the
 * two-line `sy_peer_device_key` gate that narrows it to one machine, and §15.3
 * shows tree-backed `authorized_keys` when the inner identity should be an SSH
 * key instead.
 *
 * Session bytes move with `sy_splice`: a terminal server forwards keystrokes
 * and output without looking at them, so there is no buffer to size and no
 * short-write remainder to carry — what does not fit stays in the ring it was
 * in, exactly as in `splice-proxy.c`.
 */

#include <synch.h>

#ifndef SHELL_EXECUTABLE
#define SHELL_EXECUTABLE "/bin/bash"
#endif
#ifndef SHELL_ARGV0
#define SHELL_ARGV0 "bash"
#endif

#define SHELL_CAPABILITY 1

/* The most one splice call moves, so one busy direction cannot keep the loop
   away from the control fd or the other direction. */
#define CHUNK 32768

SY_INIT_ENTRY sy_s64 declare(void) {
  sy_declare_name(SY_STR("ssh-shell"));
  sy_declare_max_streams(4);

  /* The complete capability, embedded in the object: the exact executable,
     argv, PTY permission, and the signals the guest may relay. Built on the
     stack because helper arguments live there. */
  struct sy_process_capability shell = {0};
  shell.id = SHELL_CAPABILITY;
  shell.flags = SY_PROCESS_ALLOW_PTY;
  sy_memcpy(shell.executable, SHELL_EXECUTABLE, sizeof SHELL_EXECUTABLE - 1);
  shell.executable_len = sizeof SHELL_EXECUTABLE - 1;
  shell.argc = 1;
  sy_memcpy(shell.argv[0], SHELL_ARGV0, sizeof SHELL_ARGV0 - 1);
  shell.argv_len[0] = sizeof SHELL_ARGV0 - 1;
  shell.allowed_signals = SY_PROCESS_SIGNAL_HUP | SY_PROCESS_SIGNAL_INT |
                          SY_PROCESS_SIGNAL_TERM;
  return sy_declare_process(&shell, sizeof shell);
}

static int field_is(sy_u64 event_id, sy_u32 field, const char *want,
                    sy_u64 want_len) {
  char value[32];
  sy_s64 len = sy_ssh_event_data(event_id, field, value, sizeof value);
  if (len < 0 || (sy_u64)len != want_len || want_len > sizeof value) return 0;
  for (sy_u64 i = 0; i < want_len; i++)
    if (value[i] != want[i]) return 0;
  return 1;
}

/* A request that asked for a reply gets one; one that did not is finished. */
static sy_s64 finish(const struct sy_ssh_event *event, sy_u32 result) {
  if (event->flags & SY_SSH_EVENT_WANT_REPLY)
    return sy_ssh_request_reply(event->id, result);
  return sy_ssh_event_done(event->id);
}

/* Everything one shell session is. -1 handles mean "not yet". */
struct session {
  sy_s64 channel;
  sy_s64 pty;
  sy_s64 process;
  int input_done;       /* client EOF reached the shell as a hangup       */
  int output_done;      /* the PTY reached EOF: the shell is gone         */
  int upward_blocked;   /* keystrokes waiting on PTY room                 */
  int downward_blocked; /* output waiting on SSH channel window           */
  int have_status;
  int status_sent;
  struct sy_process_status status;
};

static sy_s64 handle_open(const struct sy_ssh_event *event,
                          struct session *s) {
  /* One session per connection keeps the example one struct; §15.1's slot
     array is the multi-channel shape a control master would want. */
  if (s->channel >= 0 ||
      !field_is(event->id, SY_SSH_FIELD_CHANNEL_TYPE, SY_STR("session")))
    return sy_ssh_channel_reject(event->id,
                                 SY_SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);
  sy_s64 channel = sy_ssh_channel_accept(event->id);
  if (channel < 0) return channel;
  s->channel = channel;
  return 0;
}

static sy_s64 handle_request(const struct sy_ssh_event *event,
                             struct session *s) {
  if (event->fd != s->channel) return finish(event, SY_SSH_REQUEST_FAILURE);

  if (field_is(event->id, SY_SSH_FIELD_REQUEST_TYPE, SY_STR("pty-req"))) {
    if (s->pty >= 0) return finish(event, SY_SSH_REQUEST_FAILURE);
    struct sy_pty_spec spec;
    if (sy_ssh_pty_spec(event->id, &spec, sizeof spec) < 0)
      return finish(event, SY_SSH_REQUEST_FAILURE);
    sy_s64 pty = sy_pty_open(SHELL_CAPABILITY, &spec, sizeof spec);
    if (pty < 0) return finish(event, SY_SSH_REQUEST_FAILURE);
    s->pty = pty; /* a terminal exists; nothing is running on it yet */
    return finish(event, SY_SSH_REQUEST_SUCCESS);
  }

  if (field_is(event->id, SY_SSH_FIELD_REQUEST_TYPE, SY_STR("shell"))) {
    if (s->pty < 0 || s->process >= 0)
      return finish(event, SY_SSH_REQUEST_FAILURE);
    sy_s64 process = sy_process_spawn_pty(SHELL_CAPABILITY, s->pty);
    if (process < 0) return finish(event, SY_SSH_REQUEST_FAILURE);
    s->process = process;
    return finish(event, SY_SSH_REQUEST_SUCCESS);
  }

  if (field_is(event->id, SY_SSH_FIELD_REQUEST_TYPE,
               SY_STR("window-change"))) {
    if (s->pty < 0) return finish(event, SY_SSH_REQUEST_FAILURE);
    sy_s64 resized =
        sy_pty_resize(s->pty, event->a, event->b, event->c, event->d);
    return finish(event, resized < 0 ? SY_SSH_REQUEST_FAILURE
                                     : SY_SSH_REQUEST_SUCCESS);
  }

  if (field_is(event->id, SY_SSH_FIELD_REQUEST_TYPE, SY_STR("signal"))) {
    char name[32];
    sy_s64 len =
        sy_ssh_event_data(event->id, SY_SSH_FIELD_SIGNAL, name, sizeof name);
    sy_s64 sent = s->process < 0 || len < 0 || len > (sy_s64)sizeof name
                      ? SY_EPERM
                      : sy_process_signal(s->process, name, (sy_u64)len);
    return finish(event, sent < 0 ? SY_SSH_REQUEST_FAILURE
                                  : SY_SSH_REQUEST_SUCCESS);
  }

  /* exec, subsystem, env, forwarding: not this socket's policy. The refusal
     costs nothing — none of those names could have started anything. */
  return finish(event, SY_SSH_REQUEST_FAILURE);
}

/* Both directions of the terminal, each allowed to end on its own. */
static sy_s64 move_terminal(struct session *s) {
  if (!s->input_done) {
    sy_s64 n = sy_splice(s->channel, s->pty, CHUNK);
    if (n == 0) {
      /* Client EOF. A PTY has no write half to shut, so ask the shell to
         hang up and keep the master open to drain its last output. */
      if (s->process >= 0) sy_process_signal(s->process, SY_STR("HUP"));
      s->input_done = 1;
    } else if (n < 0 && n != SY_EAGAIN) {
      return n;
    } else {
      s->upward_blocked =
          sy_readable(s->channel) > 0 && sy_writable(s->pty) == 0;
    }
  }
  if (!s->output_done) {
    sy_s64 n = sy_splice(s->pty, s->channel, CHUNK);
    if (n == 0) {
      s->output_done = 1;
    } else if (n < 0 && n != SY_EAGAIN) {
      return n;
    } else {
      s->downward_blocked =
          sy_readable(s->pty) > 0 && sy_writable(s->channel) == 0;
    }
  }
  return 0;
}

static void close_session(struct session *s) {
  if (s->process >= 0) sy_close(s->process); /* kills and reaps a live shell */
  if (s->pty >= 0) sy_close(s->pty);
  if (s->channel >= 0) sy_close(s->channel);
  s->process = s->pty = s->channel = -1;
}

SY_ENTRY sy_s64 entry(void) {
  if (sy_ssh_start(SY_SELF, SY_SSH_AUTH_NONE) < 0) return 1;

  struct session s = {0};
  s.channel = s.pty = s.process = -1;

  for (;;) {
    /* fd zero, then whichever session fds still have something coming. */
    struct sy_pollfd fds[4] = {{SY_SELF, SY_POLL_IN, 0}};
    sy_u64 nfds = 1;
    sy_u64 channel_at = 0, pty_at = 0;

    if (s.channel >= 0 && s.pty >= 0) {
      sy_u32 channel_events = 0, pty_events = 0;
      /* As in splice-proxy.c: bytes waiting on a full destination wait for
         the room, not for more input that has nowhere to go. */
      if (!s.input_done) {
        if (s.upward_blocked) pty_events |= SY_POLL_OUT;
        else channel_events |= SY_POLL_IN;
      }
      if (!s.output_done) {
        if (s.downward_blocked) channel_events |= SY_POLL_OUT;
        else pty_events |= SY_POLL_IN;
      }
      if (channel_events) {
        channel_at = nfds;
        fds[nfds++] = (struct sy_pollfd){s.channel, channel_events, 0};
      }
      if (pty_events) {
        pty_at = nfds;
        fds[nfds++] = (struct sy_pollfd){s.pty, pty_events, 0};
      }
    }
    if (s.process >= 0 && !s.have_status)
      fds[nfds++] = (struct sy_pollfd){s.process, SY_POLL_IN, 0};

    if (sy_poll(fds, nfds, -1) <= 0) break; /* idle deadline, or all quiet */

    if (fds[0].revents & SY_POLL_IN) {
      struct sy_ssh_event event;
      while (sy_ssh_next(SY_SELF, &event, sizeof event) == 1) {
        sy_s64 handled = 0;
        if (event.kind == SY_SSH_EVENT_AUTH_NONE)
          handled = sy_ssh_auth_reply(event.id, SY_SSH_AUTH_ACCEPT, 0);
        else if (event.kind == SY_SSH_EVENT_CHANNEL_OPEN)
          handled = handle_open(&event, &s);
        else if (event.kind == SY_SSH_EVENT_CHANNEL_REQUEST)
          handled = handle_request(&event, &s);
        else
          handled = sy_ssh_event_done(event.id); /* AUTHENTICATED, lanes */
        if (handled < 0) {
          close_session(&s);
          return 2;
        }
      }
    }

    if (s.channel >= 0 && s.pty >= 0 && move_terminal(&s) < 0) {
      close_session(&s);
      return 3;
    }

    /* The channel failing, or reaching HUP before the shell ended, is the
       client going away: no one is left to see an exit status. */
    if ((channel_at && (fds[channel_at].revents & (SY_POLL_ERR | SY_POLL_HUP))) ||
        (pty_at && (fds[pty_at].revents & SY_POLL_ERR))) {
      close_session(&s);
      return 0;
    }

    if (s.process >= 0 && !s.have_status &&
        sy_process_status(s.process, &s.status, sizeof s.status) == 1)
      s.have_status = 1;

    /* Exit status goes out only after the terminal's last output: reporting
       first would race the goodbye off the screen. */
    if (s.have_status && s.output_done && !s.status_sent) {
      if (s.status.signaled)
        sy_ssh_exit_signal(s.channel, s.status.signal, s.status.signal_len,
                           s.status.core_dumped);
      else
        sy_ssh_exit_status(s.channel, s.status.exit_code);
      sy_shutdown(s.channel); /* EOF after the queued output drains */
      s.status_sent = 1;
      close_session(&s);
      /* The connection stays up for the client to close: fd zero reaches
         HUP below, and that is this invocation's clean end. */
    }

    if (fds[0].revents & (SY_POLL_ERR | SY_POLL_HUP)) break;
  }

  close_session(&s);
  return 0;
}
