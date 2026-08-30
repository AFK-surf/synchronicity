/* ssh-shell — a real `ssh nas` login, terminated by a socket.
 *
 *   synch socket build examples/ssh-shell.c -o ssh-shell.o
 *   cp ssh-shell.o ~/synchronicity/code/ssh.sock
 *   synch socket declare code/ssh.sock
 *   synch socket arm code/ssh.sock       # shows the exact /bin/bash declaration
 *   ssh -o 'ProxyCommand=synch socket connect %h:code/ssh.sock' nas
 *
 * The SSH adapter turns the inbound stream into a control fd and channel fds;
 * the process declaration is what lets this program put a PTY-backed bash
 * behind one of them (`docs/SSH-SOCKETS.md`). The three parts stay separate on
 * purpose: accepting the `session` channel starts nothing, a successful
 * `pty-req` allocates a terminal but starts nothing, and only the `shell`
 * request spawns the one executable the operator approved at arm time. The
 * client's username and command bytes never choose what runs.
 *
 * Every event arrives as a JSON handle: its `kind` is a name, its fields are
 * members, and the whole dispatch below is string comparison rather than
 * numbered constants. An event handle is closed as soon as it is handled; the
 * event itself stays outstanding until it is answered.
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

  /* The complete capability, embedded in the object as JSON: the exact
     executable, argv, PTY permission, and the signals the guest may relay.
     Literal concatenation splices the macros in at compile time. */
  sy_s64 shell = sy_json_parse(
      SY_STR("{\"id\":1,\"allow\":[\"pty\"],"
             "\"executable\":\"" SHELL_EXECUTABLE "\","
             "\"argv\":[\"" SHELL_ARGV0 "\"],"
             "\"allowed_signals\":[\"HUP\",\"INT\",\"TERM\"]}"));
  if (shell < 0) return shell;
  sy_s64 declared = sy_declare_process(shell);
  sy_close(shell);
  return declared;
}

static int str_is(const char *value, const char *want) {
  sy_u64 len = sy_strlen(want);
  return sy_strlen(value) == len && sy_memcmp(value, want, len) == 0;
}

/* A request that asked for a reply gets one; one that did not is finished. */
static sy_s64 finish(sy_s64 event, sy_u64 id, sy_u32 granted) {
  if (sy_json_get_bool(event, SY_STR("want_reply")) == 1)
    return sy_ssh_request_reply(id, granted);
  return sy_ssh_event_done(id);
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
  int signaled;
  int core_dumped;
  sy_s64 exit_code;
  char signal[32];
};

static sy_s64 handle_open(sy_s64 event, sy_u64 id, struct session *s) {
  /* One live session at a time keeps the example one struct; a session that
     has ended frees the slot for the next open, so sequential logins on one
     connection work (§7.3). §15.1's slot array is the shape for concurrent
     channels. */
  char type[32] = {0};
  sy_json_get_string(event, SY_STR("channel_type"), type, sizeof type);
  if (s->channel >= 0 || !str_is(type, "session"))
    return sy_ssh_channel_reject(id, SY_STR("administratively_prohibited"));
  sy_s64 channel = sy_ssh_channel_accept(id);
  if (channel < 0) return channel;
  s->channel = channel;
  return 0;
}

static sy_s64 handle_request(sy_s64 event, sy_u64 id, struct session *s) {
  sy_s64 fd = -1;
  sy_json_get_i64(event, SY_STR("fd"), &fd);
  if (fd != s->channel) return finish(event, id, 0);

  char type[32] = {0};
  sy_json_get_string(event, SY_STR("request_type"), type, sizeof type);

  if (str_is(type, "pty-req")) {
    if (s->pty >= 0) return finish(event, id, 0);
    sy_s64 spec = sy_ssh_pty_spec(id);
    if (spec < 0) return finish(event, id, 0);
    sy_s64 pty = sy_pty_open(SHELL_CAPABILITY, spec);
    sy_close(spec);
    if (pty < 0) return finish(event, id, 0);
    s->pty = pty; /* a terminal exists; nothing is running on it yet */
    return finish(event, id, 1);
  }

  if (str_is(type, "shell")) {
    if (s->pty < 0 || s->process >= 0) return finish(event, id, 0);
    sy_s64 process = sy_process_spawn_pty(SHELL_CAPABILITY, s->pty);
    if (process < 0) return finish(event, id, 0);
    s->process = process;
    return finish(event, id, 1);
  }

  if (str_is(type, "window-change")) {
    if (s->pty < 0) return finish(event, id, 0);
    sy_s64 columns = 0, rows = 0, width = 0, height = 0;
    sy_json_get_i64(event, SY_STR("columns"), &columns);
    sy_json_get_i64(event, SY_STR("rows"), &rows);
    sy_json_get_i64(event, SY_STR("pixel_width"), &width);
    sy_json_get_i64(event, SY_STR("pixel_height"), &height);
    sy_s64 resized = sy_pty_resize(s->pty, (sy_u32)columns, (sy_u32)rows,
                                   (sy_u32)width, (sy_u32)height);
    return finish(event, id, resized < 0 ? 0 : 1);
  }

  if (str_is(type, "signal")) {
    char name[32] = {0};
    sy_s64 len = sy_json_get_string(event, SY_STR("signal"), name, sizeof name);
    sy_s64 sent = s->process < 0 || len < 0 || len >= (sy_s64)sizeof name
                      ? SY_EPERM
                      : sy_process_signal(s->process, name, (sy_u64)len);
    return finish(event, id, sent < 0 ? 0 : 1);
  }

  /* exec, subsystem, env, forwarding: not this socket's policy. The refusal
     costs nothing — none of those names could have started anything. */
  return finish(event, id, 0);
}

/* Both directions of the terminal, each allowed to end on its own. An error
   ends its direction rather than the session: a PTY write half failing after
   the shell exited must not race the exit status away, and a broken channel
   surfaces through its own ERR in the poll loop. */
static void move_terminal(struct session *s) {
  if (!s->input_done) {
    sy_s64 n = sy_splice(s->channel, s->pty, CHUNK);
    if (n == 0 || (n < 0 && n != SY_EAGAIN)) {
      /* Client EOF: no more keystrokes, and nothing else. A PTY has no write
         half to shut, and hanging the shell up here would kill commands the
         client already typed — `printf 'exit\n' | ssh` sends EOF right behind
         the keystrokes, and sshd lets the shell drain them and end itself.
         A client that vanishes entirely still can't leak the process: the
         connection closing reaches close_session, which kills a live shell. */
      s->input_done = 1;
    } else {
      s->upward_blocked =
          sy_readable(s->channel) > 0 && sy_writable(s->pty) == 0;
    }
  }
  if (!s->output_done) {
    sy_s64 n = sy_splice(s->pty, s->channel, CHUNK);
    if (n == 0 || (n < 0 && n != SY_EAGAIN)) {
      s->output_done = 1;
    } else {
      s->downward_blocked =
          sy_readable(s->pty) > 0 && sy_writable(s->channel) == 0;
    }
  }
}

static void close_session(struct session *s) {
  if (s->process >= 0) sy_close(s->process); /* kills and reaps a live shell */
  if (s->pty >= 0) sy_close(s->pty);
  if (s->channel >= 0) sy_close(s->channel);
  s->process = s->pty = s->channel = -1;
  /* A clean slate, so the next `session` open on this connection starts a
     fresh shell instead of inheriting this one's finished lifecycle. */
  s->input_done = s->output_done = 0;
  s->upward_blocked = s->downward_blocked = 0;
  s->have_status = s->status_sent = 0;
}

/* Reads a finished process's status JSON into the session, once. */
static void collect_status(struct session *s) {
  sy_s64 status = sy_process_status(s->process);
  if (status < 0) return; /* SY_EAGAIN: still running */
  s->have_status = 1;
  s->signaled = sy_json_get_bool(status, SY_STR("signaled")) == 1;
  s->core_dumped = sy_json_get_bool(status, SY_STR("core_dumped")) == 1;
  s->exit_code = 0;
  sy_json_get_i64(status, SY_STR("exit_code"), &s->exit_code);
  s->signal[0] = 0;
  sy_json_get_string(status, SY_STR("signal"), s->signal, sizeof s->signal);
  sy_close(status);
}

SY_ENTRY sy_s64 entry(void) {
  sy_s64 methods = sy_json_parse(SY_STR("[\"none\"]"));
  if (methods < 0) return 1;
  sy_s64 started = sy_ssh_start(SY_SELF, methods);
  sy_close(methods);
  if (started < 0) return 1;

  struct session s = {0};
  s.channel = s.pty = s.process = -1;

  for (;;) {
    /* fd zero, then whichever session fds still have something coming. */
    struct sy_pollfd fds[4] = {{SY_SELF, SY_POLL_IN, 0}};
    sy_u64 nfds = 1;
    sy_u64 channel_at = 0;

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
      if (pty_events) fds[nfds++] = (struct sy_pollfd){s.pty, pty_events, 0};
    }
    if (s.process >= 0 && !s.have_status)
      fds[nfds++] = (struct sy_pollfd){s.process, SY_POLL_IN, 0};

    if (sy_poll(fds, nfds, -1) <= 0) break; /* idle deadline, or all quiet */

    if (fds[0].revents & SY_POLL_IN) {
      sy_s64 event;
      while ((event = sy_ssh_next(SY_SELF)) > 0) {
        char kind[32] = {0};
        sy_s64 id = 0;
        sy_json_get_string(event, SY_STR("kind"), kind, sizeof kind);
        sy_json_get_i64(event, SY_STR("id"), &id);

        sy_s64 handled = 0;
        if (str_is(kind, "auth_none")) {
          sy_s64 accept = sy_json_parse(SY_STR("{\"result\":\"accept\"}"));
          handled = accept < 0 ? accept : sy_ssh_auth_reply((sy_u64)id, accept);
          if (accept >= 0) sy_close(accept);
        } else if (str_is(kind, "channel_open")) {
          handled = handle_open(event, (sy_u64)id, &s);
        } else if (str_is(kind, "channel_request")) {
          handled = handle_request(event, (sy_u64)id, &s);
        } else {
          handled = sy_ssh_event_done((sy_u64)id); /* authenticated, lanes */
        }
        sy_close(event);
        if (handled < 0) {
          close_session(&s);
          return 2;
        }
      }
    }

    if (s.channel >= 0 && s.pty >= 0) move_terminal(&s);

    /* The channel failing is the client abandoning this session: no one is
       left to see an exit status, so reap it and keep serving — the
       connection itself may have more sessions to open. */
    if (channel_at &&
        (fds[channel_at].revents & (SY_POLL_ERR | SY_POLL_HUP)))
      close_session(&s);

    if (s.process >= 0 && !s.have_status) collect_status(&s);

    /* Exit status goes out only after the terminal's last output: reporting
       first would race the goodbye off the screen. */
    if (s.have_status && s.output_done && !s.status_sent) {
      if (s.signaled)
        sy_ssh_exit_signal(s.channel, s.signal, sy_strlen(s.signal),
                           (sy_u32)s.core_dumped);
      else
        sy_ssh_exit_status(s.channel, (sy_u32)s.exit_code);
      sy_shutdown(s.channel); /* EOF after the queued output drains */
      s.status_sent = 1;
      close_session(&s);
      /* The connection stays up for the client to close or to log in again —
         a new `session` open reuses the freed slot — and fd zero reaching
         HUP below is this invocation's clean end. */
    }

    if (fds[0].revents & (SY_POLL_ERR | SY_POLL_HUP)) break;
  }

  close_session(&s);
  return 0;
}
