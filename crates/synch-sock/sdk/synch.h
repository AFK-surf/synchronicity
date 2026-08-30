/* synchronicity socket SDK — `synch socket sdk > synch.h`
 *
 * A socket is a file in a node's published tree whose content is an eBPF ELF
 * object. The node that published it runs it, once per incoming stream, for a
 * peer that connects with `synch connect <origin>:<space>/<path>`. See
 * `docs/SOCKETS.md`.
 *
 * `synch socket build prog.c -o prog.o` compiles against this header with the
 * compiler built into the binary, so nothing has to be installed first;
 * `--clang` selects optimized system clang/llc output. Worked examples are in
 * `crates/synch-sock/examples/`.
 *
 * Three things about the machine you are writing for, because they are not the
 * machine you are used to:
 *
 *   1. You have no heap and no mutable globals. The stack holds at least eight
 *      local-call frames; frames are 16 KiB and guarded where the host page is
 *      no larger than that. Larger-page hosts warn and use contiguous frames
 *      unless `synchronicity.init` declares otherwise. A large buffer is a
 *      stack buffer; state that must outlive the invocation goes in the socket
 *      map (`sy_map_*`). A `static` you write to will not link.
 *
 *   2. Nothing blocks except `sy_poll`. Every read and write returns
 *      immediately, with a short count or `SY_EAGAIN`, and a short write is
 *      backpressure rather than failure. Write an event loop.
 *
 *   3. Every out-parameter has `snprintf` semantics: the return value is what a
 *      complete write would have needed, so a value larger than your buffer is
 *      detectable without a second call.
 *
 *   4. Structured data crosses the boundary as JSON handles (`sy_json_*`),
 *      never as C structs or numbered enums: a stat result, an SSH event, a
 *      process status, a backing-service declaration are all JSON values the
 *      host owns, navigated and read through small integer handles and
 *      released with `sy_close`. The one struct left is `sy_pollfd`, because
 *      poll is the hot path.
 *
 * Authorization is the handshake, not the payload. `sy_peer_origin`,
 * `sy_peer_info` and `sy_peer_has_space` read an identity iroh authenticated
 * before your program started. `sy_conn_meta` is the caller's own text and is
 * not any of those things.
 */

#ifndef SYNCHRONICITY_SDK_SYNCH_H
#define SYNCHRONICITY_SDK_SYNCH_H

typedef unsigned long long sy_u64;
typedef long long sy_s64;
typedef unsigned int sy_u32;
typedef int sy_s32;
typedef unsigned short sy_u16;
typedef unsigned char sy_u8;

/* Pairs a string literal with its length, for every `(ptr, len)` argument. */
#define SY_STR(s) (s), sy_strlen((s))

#define SY_SECTION(name) __attribute__((section(name)))
#define SY_INLINE __attribute__((always_inline))
#define SY_MAYBE_UNUSED __attribute__((unused))

/* The per-stream entrypoint. Runs once per incoming connection; its return
 * value reaches the caller as the invocation's exit status.
 *
 *   SY_ENTRY sy_s64 entry(void) { ... }
 */
#define SY_ENTRY SY_SECTION("synchronicity.stream")

/* The declaration hook. Runs once, at `synch socket arm`, with no endpoint
 * table at all — an I/O helper called from here returns SY_EPERM. What it
 * declares is what the operator is shown and approves. Undeclared capabilities
 * remain unavailable.
 *
 *   SY_INIT_ENTRY sy_s64 declare(void) {
 *     sy_declare_name(SY_STR("git-http"));
 *     sy_declare_egress(SY_STR("git.internal"), 9418);
 *     return 0;
 *   }
 */
#define SY_INIT_ENTRY SY_SECTION("synchronicity.init")

/* ---- error codes ------------------------------------------------------- */

#define SY_EAGAIN     -1  /* would block — poll and come back                */
#define SY_EBADF      -2  /* no such handle in this invocation               */
#define SY_EINVAL     -3  /* a malformed argument                            */
#define SY_EPERM      -4  /* refused by policy                               */
#define SY_ECONNRESET -5  /* the peer reset the connection                   */
#define SY_ETIMEDOUT  -6  /* a connect or a read timed out                   */
#define SY_ELIMIT     -7  /* a documented bound was hit                      */
#define SY_ENOENT     -8  /* no such path, key or object                     */
#define SY_EPIPE      -9  /* wrote after the peer's read side went away      */
#define SY_ESTATE    -10  /* valid operation, wrong selected protocol state  */
#define SY_ESTALE    -11  /* conditional commit lost: the tree moved         */
#define SY_EIO       -12  /* staging or commit failed host-side (disk, CAS)  */

/* ---- poll -------------------------------------------------------------- */

#define SY_POLL_IN   0x1  /* readable, or an EOF is pending                  */
#define SY_POLL_OUT  0x2  /* tx has room; a connecting endpoint is up        */
#define SY_POLL_HUP  0x4  /* both halves shut; reported without asking        */
#define SY_POLL_ERR  0x8  /* failed; sy_errno(h) says why                    */
#define SY_POLL_RDHUP 0x10 /* peer write-half EOF; reported only when asked    */

/* The inbound stream. Always handle 0, always open when your program starts. */
#define SY_SELF 0

struct sy_pollfd {
  sy_s64 handle;
  sy_u32 events;
  sy_u32 revents;
};

/* ---- JSON values --------------------------------------------------------
 *
 * Structured data lives host-side as JSON; the guest holds handles into the
 * same table endpoints and objects come from, released with `sy_close` and
 * charged against the same per-invocation footprint. Every handle owns its
 * own value: `sy_json_get`/`sy_json_array_get` return a *copy* as a fresh
 * handle, and `sy_json_set`/`sy_json_array_push` copy the inserted value in,
 * so no two handles ever alias and nested documents are built bottom-up.
 * Valid in `synchronicity.init` too — the declaration helpers take JSON. */

#define SY_JSON_NULL   0
#define SY_JSON_BOOL   1
#define SY_JSON_NUMBER 2
#define SY_JSON_STRING 3
#define SY_JSON_ARRAY  4
#define SY_JSON_OBJECT 5

/* Parses UTF-8 JSON text into a fresh handle. */
extern sy_s64 sy_json_parse(const void *data, sy_u64 data_len);
/* Serializes a handle's value; snprintf semantics. */
extern sy_s64 sy_json_stringify(sy_s64 json, char *out, sy_u64 out_len);
extern sy_s64 sy_json_new_object(void);
extern sy_s64 sy_json_new_array(void);
/* SY_JSON_*. */
extern sy_s64 sy_json_type(sy_s64 json);
/* Elements of an array, keys of an object, bytes of a string. */
extern sy_s64 sy_json_len(sy_s64 json);
/* A copy of one object member as a fresh handle; SY_ENOENT if absent. */
extern sy_s64 sy_json_get(sy_s64 json, const char *key, sy_u64 key_len);
/* A copy of one array element as a fresh handle; SY_ENOENT past the end. */
extern sy_s64 sy_json_array_get(sy_s64 json, sy_u64 index);
/* The value at the handle, which must be a string; snprintf semantics. */
extern sy_s64 sy_json_read_string(sy_s64 json, char *out, sy_u64 out_len);
/* Writes the number as a little-endian sy_s64 into `out` (>= 8 bytes). A
 * number that does not fit an sy_s64 exactly is SY_EINVAL. */
extern sy_s64 sy_json_read_i64(sy_s64 json, void *out, sy_u64 out_len);
/* 1 or 0 for a boolean value; SY_EINVAL for anything else. */
extern sy_s64 sy_json_read_bool(sy_s64 json);
/* Inserts a copy of `value_json` under `key`; the target must be an object. */
extern sy_s64 sy_json_set(sy_s64 json, const char *key, sy_u64 key_len,
                          sy_s64 value_json);
extern sy_s64 sy_json_remove(sy_s64 json, const char *key, sy_u64 key_len);
/* Appends a copy of `value_json`; the target must be an array. */
extern sy_s64 sy_json_array_push(sy_s64 json, sy_s64 value_json);
/* The set_* helpers replace the handle's own value in place. */
extern sy_s64 sy_json_set_string(sy_s64 json, const char *value,
                                 sy_u64 value_len);
extern sy_s64 sy_json_set_i64(sy_s64 json, sy_s64 value);
extern sy_s64 sy_json_set_bool(sy_s64 json, sy_u64 value);
extern sy_s64 sy_json_set_null(sy_s64 json);

/* Declared ahead of its section: the conveniences below release their
 * intermediate handle with it. A repeated declaration is ordinary C. */
extern sy_s64 sy_close(sy_s64 handle);

/* One object member's scalar, without keeping the intermediate handle: get,
 * read, close. Guest-side because they are the same three calls in every
 * program. Negative on error, including SY_ENOENT for an absent key. */
SY_MAYBE_UNUSED static sy_s64 sy_json_get_string(sy_s64 json, const char *key,
                                                 sy_u64 key_len, char *out,
                                                 sy_u64 out_len) {
  sy_s64 member = sy_json_get(json, key, key_len);
  if (member < 0) return member;
  sy_s64 n = sy_json_read_string(member, out, out_len);
  sy_close(member);
  return n;
}

SY_MAYBE_UNUSED static sy_s64 sy_json_get_i64(sy_s64 json, const char *key,
                                              sy_u64 key_len, sy_s64 *out) {
  sy_s64 member = sy_json_get(json, key, key_len);
  if (member < 0) return member;
  sy_s64 n = sy_json_read_i64(member, out, sizeof *out);
  sy_close(member);
  return n;
}

/* 1, 0, or negative — SY_ENOENT when absent, so a missing flag can default
 * either way at the call site: `sy_json_get_bool(...) == 1`. */
SY_MAYBE_UNUSED static sy_s64 sy_json_get_bool(sy_s64 json, const char *key,
                                               sy_u64 key_len) {
  sy_s64 member = sy_json_get(json, key, key_len);
  if (member < 0) return member;
  sy_s64 value = sy_json_read_bool(member);
  sy_close(member);
  return value;
}

/* Flags for sy_base64_encode / sy_base64_decode_in_place: two orthogonal
 * booleans, combinable with `|`, rather than a numbered alphabet enum. */
#define SY_BASE64_URL    0x1 /* URL-safe alphabet   */
#define SY_BASE64_NO_PAD 0x2 /* no `=` padding      */

/* ---- diagnostics and configuration ------------------------------------- */

extern sy_s64 sy_log(const char *msg, sy_u64 len);
extern sy_u64 sy_now_ms(void);
extern sy_u64 sy_monotonic_ns(void);
extern sy_s64 sy_getrandom(void *out, sy_u64 out_len);
extern sy_s64 sy_version(char *out, sy_u64 out_len);
/* Reads a key set by `synch socket add --config k=v`. Deliberately not an
 * environment read: this program is reachable by every member of the cluster,
 * and on a serverless node the daemon's environment holds cloud credentials. */
extern sy_s64 sy_config_get(const char *key, sy_u64 key_len, char *out,
                            sy_u64 out_len);
extern sy_s64 sy_metric_add(const char *name, sy_u64 name_len, sy_s64 delta);
extern sy_s64 sy_label_set(const char *key, sy_u64 key_len, const char *value,
                           sy_u64 value_len);

/* ---- identity: from the handshake, never from the payload --------------- */

extern sy_s64 sy_self_origin(char *out, sy_u64 out_len);
extern sy_s64 sy_socket_path(char *out, sy_u64 out_len);
extern sy_s64 sy_peer_origin(char *out, sy_u64 out_len);
/* Writes the caller's raw 32-byte device key: the identity that survives an
 * origin rename, and the right key for a per-caller rate limit. */
extern sy_s64 sy_peer_device_key(void *out32);
/* The whole authenticated identity as one JSON handle: {"origin",
 * "device_key" (hex), "kind" ("member" | "delegate"), "addr",
 * "stream_index"}. `sy_json_get_string(info, SY_STR("kind"), ...)` is the
 * one-line way to ask "is this a rooted member?". */
extern sy_s64 sy_peer_info(void);
/* 1 if the caller may read that space: always so for a rooted member, and
 * list membership for a delegate. The one-line way to write "only the people I
 * gave `code` to". */
extern sy_s64 sy_peer_has_space(const char *space, sy_u64 space_len);
extern sy_s64 sy_peer_addr(char *out, sy_u64 out_len);
/* A key from the caller's `--meta`. Untrusted: it is whatever they typed. */
extern sy_s64 sy_conn_meta(const char *key, sy_u64 key_len, char *out,
                           sy_u64 out_len);
extern sy_s64 sy_stream_index(void);

/* ---- endpoint I/O: never blocks ---------------------------------------- */

/* > 0 bytes, 0 at a clean EOF, SY_EAGAIN when empty and still open. */
extern sy_s64 sy_read(sy_s64 handle, void *buf, sy_u64 len);
/* Bytes accepted. A short count is normal and is the backpressure signal. */
extern sy_s64 sy_write(sy_s64 handle, const void *buf, sy_u64 len);
/* Moves up to `max` bytes from `from`'s receive side straight into `to`'s send
 * side, without them passing through this program's memory. Returns the bytes
 * moved, 0 at a clean EOF on `from`, SY_EAGAIN when neither side could make
 * progress, or a negative error: `to`'s if the destination is the broken one,
 * which is checked before any bytes are taken from anywhere, and otherwise
 * `from`'s, exactly as `sy_read` would have reported it. A destination that has
 * been shut or closed is SY_EPIPE, which a read alone never returns.
 *
 * What `sy_pump` does with a buffer and a remainder, in one call and with
 * neither. Bytes that do not fit are never picked up: they stay where they
 * were, so there is nothing to hold between calls and nothing to drop. A short
 * move is backpressure, exactly as a short write is, and the answer to it is
 * the same poll.
 *
 * Reach for it in either direction of a proxy that does not need to look at
 * what it forwards, and for `sy_pump` where it does. `max` bounds one call, so
 * one busy direction cannot monopolise a loop; pass something large to move
 * whatever the two sides allow. Zero is SY_EINVAL, because zero already means
 * EOF. Both handles must be endpoints — an object from `sy_open` is read with
 * `sy_pread`. */
extern sy_s64 sy_splice(sy_s64 from, sy_s64 to, sy_u64 max);
extern sy_s64 sy_readable(sy_s64 handle);
extern sy_s64 sy_writable(sy_s64 handle);
/* Half-closes the write side once what is buffered has drained. */
extern sy_s64 sy_shutdown(sy_s64 handle);
/* Releases the handle. What you had already written to it still goes out: the
 * write side drains and half-closes in the background, here and again when the
 * program returns, within one bounded window for the whole teardown. Closing an
 * endpoint that never finished connecting abandons it instead — there is
 * nowhere to flush it to.
 *
 * Draining endpoints are bounded like open ones: hold more than the outbound
 * limit of them at once — closing one whose peer has stopped reading, over and
 * over — and the oldest is dropped where it stands, unsent bytes and all. */
extern sy_s64 sy_close(sy_s64 handle);
extern sy_s64 sy_errno(sy_s64 handle);

/* ---- outbound connections ---------------------------------------------- */

/* Returns a handle immediately, still connecting; poll for SY_POLL_OUT. Both
 * the name and the address it resolves to are checked against the armed egress
 * list, so a name that resolves inward is refused where the address would be. */
extern sy_s64 sy_tcp_connect(const char *host, sy_u64 host_len, sy_u64 port);
extern sy_s64 sy_tcp_connect_ip(const void *addr, sy_u64 addr_len, sy_u64 port);
extern sy_s64 sy_endpoint_info(sy_s64 handle, char *out, sy_u64 out_len);

/* ---- SSH protocol termination ------------------------------------------
 *
 * Events, replies and specs are JSON (`docs/SSH-SOCKETS.md`). An event's
 * JSON names its kind — "auth_none", "auth_password", "auth_publickey_offer",
 * "auth_publickey_verified", "auth_openssh_cert", "authenticated",
 * "channel_open", "channel_request", "channel_extended_data" — and carries
 * the decoded fields for that kind: "username", "service", "password",
 * "channel_type", "request_type", "want_reply", "terminal", "env_name" /
 * "env_value", "command", "subsystem", "signal", "destination_host" /
 * "originator_host" / "port" / "originator_port", "columns" / "rows" /
 * "pixel_width" / "pixel_height", "data_type", "auth_attempts",
 * "public_key_algorithm", "public_key_sha256" (hex), and for certificates a
 * "cert" object: {"ca_public_key_sha256" (hex), "key_id", "serial", "type"
 * ("user" | "host"), "principals": [...]}. */

/* Starts SSH on the inbound stream. `auth_methods_json` is a JSON array of
 * method names — "none", "publickey", "password" — naming what the client
 * may attempt first. */
extern sy_s64 sy_ssh_start(sy_s64 stream, sy_s64 auth_methods_json);
/* One event as a fresh JSON handle (> 0) — close it with sy_close whenever;
 * the event itself stays outstanding until answered. SY_EAGAIN while the
 * queue is empty on a live connection, 0 once it is empty after HUP: no
 * further event will arrive. */
extern sy_s64 sy_ssh_next(sy_s64 conn);
/* One raw field of an outstanding event, byte-for-byte as the wire carried
 * it, named by string: everything the JSON view decodes, plus what it leaves
 * out on purpose — "public_key_blob", "cert_blob", "ca_public_key_blob",
 * "open_data", "request_data", and a "command" that is not UTF-8. Returns
 * the field's full length, snprintf-style. */
extern sy_s64 sy_ssh_event_data(sy_u64 event_id, const char *field,
                                sy_u64 field_len, void *out, sy_u64 out_len);
extern sy_s64 sy_ssh_event_done(sy_u64 event_id);
/* Answers an auth event with JSON: {"result": "accept" | "reject" |
 * "partial" | "offer_accept", "next_methods": ["publickey", ...]?}.
 * "offer_accept" is valid only on an "auth_publickey_offer" — it tells the
 * client to proceed to the signed attempt, and is not an authentication.
 * Absent "next_methods" leaves nothing further attemptable, fail-closed. */
extern sy_s64 sy_ssh_auth_reply(sy_u64 event_id, sy_s64 reply_json);
/* Matches only option-free authorized_keys records. A cold immutable object
 * returns SY_EAGAIN and becomes pollable; retry with the same event token. */
extern sy_s64 sy_ssh_authorized_keys_match(sy_u64 event_id, sy_s64 object);

extern sy_s64 sy_ssh_channel_accept(sy_u64 event_id);
/* `reason` is "administratively_prohibited", "connect_failed",
 * "unknown_channel_type" or "resource_shortage". */
extern sy_s64 sy_ssh_channel_reject(sy_u64 event_id, const char *reason,
                                    sy_u64 reason_len);
extern sy_s64 sy_ssh_channel_open(sy_s64 conn, const char *type,
                                  sy_u64 type_len, const void *open_data,
                                  sy_u64 open_data_len);
extern sy_s64 sy_ssh_channel_type(sy_s64 channel, char *out, sy_u64 out_len);
#define SY_SSH_EXTENDED_STDERR 1
extern sy_s64 sy_ssh_channel_lane(sy_s64 channel, sy_u32 data_type);

/* `granted` is 1 to grant the request or 0 to refuse it. */
extern sy_s64 sy_ssh_request_reply(sy_u64 event_id, sy_u32 granted);
extern sy_s64 sy_ssh_exit_status(sy_s64 channel, sy_u32 status);
extern sy_s64 sy_ssh_exit_signal(sy_s64 channel, const char *name,
                                 sy_u64 name_len, sy_u32 core_dumped);

/* A `pty-req`'s terminal parameters, as a JSON handle: {"term", "columns",
 * "rows", "pixel_width", "pixel_height", "modes": [{"opcode", "value"}, ...]}.
 * The mode opcodes are SSH wire values (RFC 4254 §8), so they stay numeric.
 * The same shape — the same handle, even — is what sy_pty_open takes. */
extern sy_s64 sy_ssh_pty_spec(sy_u64 event_id);
/* Number of exit-status/exit-signal deliveries that could not be sent to the
   SSH client since the connection started (channel closed, connection gone,
   or invocation torn down). Nonzero means the last process status may be
   missing; poll after reading process status to tell "delivered" from
   "lost". */
extern sy_s64 sy_ssh_exit_status_lost(sy_s64 conn);

/* ---- declared process and PTY backing ---------------------------------- */

/* `spec_json` is the shape sy_ssh_pty_spec returns; that handle can be
 * passed straight through. */
extern sy_s64 sy_pty_open(sy_u32 process_capability, sy_s64 spec_json);
extern sy_s64 sy_process_spawn_pty(sy_u32 process_capability, sy_s64 pty);
extern sy_s64 sy_process_spawn(sy_u32 process_capability);

/* `stream` names a stdio endpoint: "main" (stdin/stdout) or "stderr". */
extern sy_s64 sy_process_stdio(sy_s64 process, const char *stream,
                               sy_u64 stream_len);
extern sy_s64 sy_pty_resize(sy_s64 pty, sy_u32 columns, sy_u32 rows,
                            sy_u32 pixel_width, sy_u32 pixel_height);

/* SY_EAGAIN while running; after exit, a fresh JSON handle — {"exited":
 * true, "exit_code", "signaled", "core_dumped", "signal"?} — repeatable
 * until the process handle is closed. */
extern sy_s64 sy_process_status(sy_s64 process);
extern sy_s64 sy_process_signal(sy_s64 process, const char *name,
                                sy_u64 name_len);

/* Starts the scope-confined SFTP engine as an ordinary byte-stream endpoint.
 * The guest chooses which protocol channel carries those bytes. */
extern sy_s64 sy_sftp_open(sy_u32 file_transfer_capability);

/* ---- poll: the only helper that suspends -------------------------------- */

/* Waits for readiness on up to 256 handles. Returns how many are ready, 0 on
 * timeout, negative on error. A negative timeout means "until something
 * happens", clamped by the host to this invocation's idle deadline. */
extern sy_s64 sy_poll(struct sy_pollfd *fds, sy_u64 n, sy_s64 timeout_ms);

/* ---- reading the tree --------------------------------------------------- */

/* Opens `space/path` in this node's own view — the same scope this program
 * came from. Every path this node holds is readable, socket entries included:
 * a socket declares no read permissions and none are enforced. */
extern sy_s64 sy_open(const char *path, sy_u64 path_len);
/* Another origin's version of a path. Needs no declaration. */
extern sy_s64 sy_open_from(const char *origin, sy_u64 origin_len,
                           const char *path, sy_u64 path_len);
extern sy_s64 sy_open_root(const void *root32);
/* The object's metadata as a JSON handle: {"size", "mtime_ns", "mode",
 * "kind" ("file" | "dir" | "symlink" | "tombstone" | "socket"),
 * "root" (the BLAKE3 content root, hex)}. */
extern sy_s64 sy_stat(sy_s64 obj);
/* Verified range read. Bytes already held return at once; bytes that must be
 * fetched from a peer return SY_EAGAIN and the handle becomes pollable, so a
 * cold read is an ordinary poll wait rather than a hidden stall. */
extern sy_s64 sy_pread(sy_s64 obj, void *buf, sy_u64 len, sy_u64 offset);
extern sy_s64 sy_list_open(const char *prefix, sy_u64 prefix_len);
extern sy_s64 sy_list_next(sy_s64 cursor, char *out, sy_u64 out_len);

/* ---- writing the tree ---------------------------------------------------
 *
 * Requires an armed tree-write declaration (`sy_declare_tree_write`): the
 * grant's prefix, modes and size bound are the operator's approval, and the
 * helpers below are the only door to mutation. A committed write publishes
 * this node's own new version of the path — an ordinary local publish, which
 * wins `newest` selection like any local save — and a delete publishes this
 * node's tombstone. A writer is opened, filled, committed (or deleted), and
 * closed; `sy_close` on an uncommitted writer aborts it and nothing is
 * published. See `docs/TREE-WRITES.md`. */

/* Opens a writer on `space/path` under declared capability `id`. The path
 * must sit inside the declared prefix by whole components, and a declared
 * socket path is never writable. */
extern sy_s64 sy_put_open(sy_u32 tree_write_capability, const char *path,
                          sy_u64 path_len);
/* Appends bytes to the writer's staging. A short count is backpressure,
 * SY_EAGAIN a full buffer — poll the writer for SY_POLL_OUT. */
extern sy_s64 sy_put_write(sy_s64 writer, const void *buf, sy_u64 len);
/* Moves up to `max` bytes from an endpoint's rx ring into the writer,
 * host-side — sy_splice with a writer destination. Same returns: a count,
 * 0 at the source's clean EOF, SY_EAGAIN when nothing could move. */
extern sy_s64 sy_put_splice(sy_s64 writer, sy_s64 from, sy_u64 max);
/* Commits the staged bytes as this node's own new version of the path.
 * First call dispatches and returns SY_EAGAIN; poll the writer for
 * SY_POLL_IN, then repeat the call — it returns 0 and fills `root32` with
 * the published content root. After success the writer is spent. A parked
 * answer is collected only by the family that dispatched it: collecting a
 * dispatched delete here (or a commit with sy_put_delete) is SY_ESTATE.
 * A refusal (SY_EPERM, SY_ESTALE) leaves the writer retryable; a host-side
 * failure (SY_EIO) is sticky — open a new writer. */
extern sy_s64 sy_put_commit(sy_s64 writer, void *root32);
/* The same, but only if this node's own live version of the path currently
 * has content root `expected32`; all-zero expected means "no live version of
 * ours" (create). SY_ESTALE if the tree moved: re-read and decide again. */
extern sy_s64 sy_put_commit_if(sy_s64 writer, const void *expected32,
                               void *root32);
/* Publishes this node's tombstone for the path instead of bytes. Requires
 * the `delete` mode and a writer with nothing staged. Idempotent: a path we
 * already publish no live version of returns 0. */
extern sy_s64 sy_put_delete(sy_s64 writer);

/* ---- state that outlives an invocation ---------------------------------- */
/* ttl_ms and the rate-limit window_ms are clamped to u32::MAX (about 49.7
 * days): a longer value is held at the clamp, which is indistinguishable
 * from the program's intent and keeps every host-side duration computation
 * in range. */

extern sy_s64 sy_map_get(const void *key, sy_u64 key_len, void *out,
                         sy_u64 out_len);
extern sy_s64 sy_map_set(const void *key, sy_u64 key_len, const void *value,
                         sy_u64 value_len, sy_u64 ttl_ms);
extern sy_s64 sy_map_delete(const void *key, sy_u64 key_len);
extern sy_s64 sy_map_incr(const void *key, sy_u64 key_len, sy_s64 delta,
                          sy_u64 ttl_ms);
/* Sliding-window limiter over the same store: 0 allowed, SY_ELIMIT denied. */
extern sy_s64 sy_rate_limit(const void *key, sy_u64 key_len, sy_u64 limit,
                            sy_u64 window_ms);

/* ---- bytes, hashes, encodings ------------------------------------------- */

extern void *sy_memcpy(void *dst, const void *src, sy_u64 n);
extern sy_s64 sy_memcmp(const void *a, const void *b, sy_u64 n);
extern void *sy_memset(void *dst, sy_s32 c, sy_u64 n);
/* Guest-side rather than a host helper: direct byte reads avoid probing for
 * the end of the containing stack or data region on every call. As in C's
 * strlen, `s` must point to a NUL-terminated string. */
SY_MAYBE_UNUSED static sy_u64 sy_strlen(const char *s) {
  sy_u64 len = 0;
  while (s[len]) len++;
  return len;
}
/* Constant-time equality, for anything a token is checked against.
 * Returns 1 when the n bytes are equal and 0 otherwise — including when the
 * comparison could not be made at all (an unreadable pointer). Never
 * negative, so `if (sy_ct_eq(a, b, n))` fails closed; the explicit `== 1`
 * is still the clearer spelling. */
extern sy_s64 sy_ct_eq(const void *a, const void *b, sy_u64 n);
/* First-class because content roots are BLAKE3: a program can check what it
 * read against what the tree said it would be. */
extern sy_s64 sy_blake3(const void *data, sy_u64 len, void *out32);
extern sy_s64 sy_sha256(const void *data, sy_u64 len, void *out32);
extern sy_s64 sy_hmac_sha256(const void *key, sy_u64 key_len, const void *msg,
                             sy_u64 msg_len, void *out32);
/* `flags` is any combination of SY_BASE64_URL and SY_BASE64_NO_PAD; 0 is
 * the standard alphabet, padded. */
extern sy_s64 sy_base64_encode(const void *data, sy_u64 len, void *out,
                               sy_u64 out_len, sy_u64 flags);
extern sy_s64 sy_base64_decode_in_place(void *buf, sy_u64 len, sy_u64 flags);
extern sy_s64 sy_hex_encode(const void *data, sy_u64 len, void *out,
                            sy_u64 out_len, sy_u64 uppercase);
extern sy_s64 sy_hex_decode_in_place(void *buf, sy_u64 len);

/* ---- declarations: `synchronicity.init` only ---------------------------- */

extern sy_s64 sy_declare_name(const char *name, sy_u64 name_len);
/* Port 0 means any port on that host, and is printed in red at the arm prompt. */
extern sy_s64 sy_declare_egress(const char *host, sy_u64 host_len, sy_u64 port);
extern sy_s64 sy_declare_max_streams(sy_u64 n);
/* Must match the compiler's eBPF stack-frame setting: a multiple of 16 bytes,
 * from 16 through 32768. The default is 16384. */
extern sy_s64 sy_declare_stack_frame_size(sy_u64 bytes);
/* `enabled` is 0 or 1. Guarded frames are enabled by default when the host
 * page is at most 16 KiB; larger-page hosts warn and default to contiguous
 * frames. Disabling guards permits sizes not aligned to the host page. */
extern sy_s64 sy_declare_guarded_stack_frames(sy_u64 enabled);

/* Backing-service declarations are complete JSON values embedded in the
 * object. Their ids are nonzero and local to this exact program root; no
 * operator-side registry or mutable named configuration is consulted at
 * runtime.
 *
 * A process capability is an object: {"id", "allow": ["pty" | "pipe", ...],
 * "executable" (exact absolute path), "argv" (exact argv, argv[0] included,
 * one through eight arguments of at most 128 bytes),
 * "allowed_signals": ["HUP" | "INT" | "TERM", ...]?}.
 *
 *   sy_s64 shell = sy_json_parse(SY_STR(
 *       "{\"id\":1,\"allow\":[\"pty\"],\"executable\":\"/bin/bash\","
 *       "\"argv\":[\"bash\"],\"allowed_signals\":[\"HUP\",\"INT\",\"TERM\"]}"));
 *   sy_declare_process(shell);
 *   sy_close(shell);
 */
extern sy_s64 sy_declare_process(sy_s64 capability_json);

/* A file-transfer capability is an object: {"id", "protocol": "sftp",
 * "access": ["read", "recursive"?], "scope" (exact normalized tree path of
 * at most 256 bytes)}. */
extern sy_s64 sy_declare_file_transfer(sy_s64 capability_json);

/* A tree-write capability is an object: {"id", "prefix" (a normalized tree
 * path: a space, or space/dir), "allow": ["create" | "replace" | "delete"],
 * "max_bytes"?}. `max_bytes` bounds one commit's staged bytes; absent means
 * 16 MiB, and 0 means unbounded — printed loudly at the arm prompt, like
 * egress port 0. */
extern sy_s64 sy_declare_tree_write(sy_s64 capability_json);

/* ---- what the compiler calls whether you write it or not ---------------- */

/* A struct initializer, an array assignment or a large local is enough to make
 * a C compiler emit a call to `memset` or `memcpy`. There is no libc here to
 * resolve one, and an unresolved symbol is a program that fails to *link* — at
 * arm time, on somebody else's node, a long way from the line that caused it.
 * So the SDK supplies them, forwarding to the host helpers.
 *
 * Clang emits an *intrinsic* rather than a call, which never meets these
 * definitions; `synch socket build --clang` rewrites the intrinsics its
 * backend cannot expand into the same helper calls, so both compilers end
 * up in the same place.
 *
 * `memmove` is `sy_memcpy`: the host copies through a buffer of its own, so a
 * copy is never torn. Overlap itself is refused, not papered over — the
 * pointer cage registers the source and the destination of one call, and a
 * destination that overlaps a source this call already read is `SY_EINVAL`.
 * The one exception is the identity `dst == src`, which a compiler can emit
 * for a self-assignment and which is a no-op. A `memmove` that genuinely
 * needs to shift a buffer must stage it through two buffers or copy in the
 * direction that does not overlap. */
SY_MAYBE_UNUSED static void *memset(void *dst, int c, unsigned long n) {
  return sy_memset(dst, c, (sy_u64)n);
}
SY_MAYBE_UNUSED static void *memcpy(void *dst, const void *src,
                                    unsigned long n) {
  return sy_memcpy(dst, src, (sy_u64)n);
}
SY_MAYBE_UNUSED static void *memmove(void *dst, const void *src,
                                     unsigned long n) {
  return sy_memcpy(dst, src, (sy_u64)n);
}

/* ---- convenience -------------------------------------------------------- */

/* Writes all of `buf`, waiting for room as often as it takes. Returns `len`,
 * SY_ETIMEDOUT if `timeout_ms` passes with no room, or a negative error.
 *
 * The counterpart to `sy_pump`, for a program whose reply is a message rather
 * than a stream. A short write is backpressure to be threaded through the
 * event loop only when the program has something else to do meanwhile; when
 * the whole job is "say this", waiting here is the honest way to wait. Do not
 * reach for it in a proxy: blocking one direction on the other's window is a
 * deadlock waiting for a large enough payload. */
SY_MAYBE_UNUSED static sy_s64 sy_write_all(sy_s64 handle, const void *buf,
                                           sy_u64 len, sy_s64 timeout_ms) {
  const char *p = (const char *)buf;
  sy_u64 off = 0;
  while (off < len) {
    sy_s64 w = sy_write(handle, p + off, len - off);
    if (w == SY_EAGAIN) {
      struct sy_pollfd fds[1] = {{handle, SY_POLL_OUT, 0}};
      sy_s64 r = sy_poll(fds, 1, timeout_ms);
      if (r < 0) return r;
      if (r == 0) return SY_ETIMEDOUT;
      continue;
    }
    if (w < 0) return w;
    off += (sy_u64)w;
  }
  return (sy_s64)len;
}

/* Writes `value` in decimal into `out`, returning how many bytes it wrote or
 * SY_EINVAL if `cap` was too small. Nothing here is `snprintf`, and a
 * Content-Length, a counter or an id has to be spelled somehow. */
SY_MAYBE_UNUSED static sy_s64 sy_utoa(sy_u64 value, char *out, sy_u64 cap) {
  char digits[20];
  sy_u64 n = 0;
  do {
    digits[n++] = (char)('0' + (int)(value % 10));
    value /= 10;
  } while (value);
  if (n > cap) return SY_EINVAL;
  for (sy_u64 i = 0; i < n; i++) out[i] = digits[n - 1 - i];
  return (sy_s64)n;
}

/* Carries a short write across polls. Zero-initialise it — `struct sy_pump st
 * = SY_PUMP_INIT;` — and give each direction its own, alongside its buffer. */
struct sy_pump {
  sy_u64 len; /* bytes of the buffer that hold data */
  sy_u64 off; /* how many of those have been written */
};

#define SY_PUMP_INIT { 0, 0 }

/* 1 while a short write's remainder is still waiting to go out. Poll `to` for
 * SY_POLL_OUT while this is true, rather than `from` for SY_POLL_IN: reading
 * more would have nowhere to put it. */
SY_MAYBE_UNUSED static int sy_pump_blocked(const struct sy_pump *st) {
  return st->off < st->len;
}

/* Moves one buffer's worth from `from` to `to`. Returns the bytes read, 0 at a
 * clean EOF on `from`, SY_EAGAIN when it could make no progress, or a negative
 * error.
 *
 * The shape almost every proxying socket wants that also wants to *see* what
 * it is proxying, written once so it is written right. Where the bytes are
 * only passing through, `sy_splice` moves them with no buffer and no remainder
 * at all. A short write is backpressure, not failure, and the remainder stays
 * in `buf` under `st` until the next call can place it — which is why `st` and
 * `buf` must be the same pair every time, and why nothing is read while
 * anything is pending. Dropping that remainder is the quiet way to corrupt
 * whatever is being proxied, and it is invisible until the payload is large
 * enough to fill the far side's window. */
SY_MAYBE_UNUSED static sy_s64 sy_pump(sy_s64 from, sy_s64 to, char *buf,
                                      sy_u64 cap, struct sy_pump *st) {
  while (st->off < st->len) {
    sy_s64 w = sy_write(to, buf + st->off, st->len - st->off);
    if (w == SY_EAGAIN) return SY_EAGAIN;
    if (w < 0) return w;
    st->off += (sy_u64)w;
  }
  st->len = st->off = 0;

  sy_s64 n = sy_read(from, buf, cap);
  if (n <= 0) return n;
  st->len = (sy_u64)n;
  while (st->off < st->len) {
    sy_s64 w = sy_write(to, buf + st->off, st->len - st->off);
    if (w == SY_EAGAIN) break;
    if (w < 0) return w;
    st->off += (sy_u64)w;
  }
  return n;
}

#endif /* SYNCHRONICITY_SDK_SYNCH_H */
