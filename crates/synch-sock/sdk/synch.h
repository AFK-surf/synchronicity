/* synchronicity socket SDK — `synch socket sdk > synch.h`
 *
 * A socket is a file in a node's published tree whose content is an eBPF ELF
 * object. The node that published it runs it, once per incoming stream, for a
 * peer that connects with `synch connect <origin>:<space>/<path>`. See
 * `docs/SOCKETS.md`.
 *
 * `synch socket build prog.c -o prog.o` compiles against this header with the
 * compiler built into the binary, so nothing has to be installed first. Worked
 * examples are in `crates/synch-sock/examples/`.
 *
 * Three things about the machine you are writing for, because they are not the
 * machine you are used to:
 *
 *   1. You have 32 KiB of stack, no heap, and no mutable globals. A large
 *      buffer is a stack buffer; state that must outlive the invocation goes
 *      in the socket map (`sy_map_*`). A `static` you write to will not link.
 *
 *   2. Nothing blocks except `sy_poll`. Every read and write returns
 *      immediately, with a short count or `SY_EAGAIN`, and a short write is
 *      backpressure rather than failure. Write an event loop.
 *
 *   3. Every out-parameter has `snprintf` semantics: the return value is what a
 *      complete write would have needed, so a value larger than your buffer is
 *      detectable without a second call.
 *
 * Authorization is the handshake, not the payload. `sy_peer_origin`,
 * `sy_peer_kind` and `sy_peer_has_space` read an identity iroh authenticated
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

/* ---- poll -------------------------------------------------------------- */

#define SY_POLL_IN   0x1  /* readable, or an EOF is pending                  */
#define SY_POLL_OUT  0x2  /* tx has room; a connecting endpoint is up        */
#define SY_POLL_HUP  0x4  /* the peer half-closed                            */
#define SY_POLL_ERR  0x8  /* failed; sy_errno(h) says why                    */

/* The inbound stream. Always handle 0, always open when your program starts. */
#define SY_SELF 0

struct sy_pollfd {
  sy_s64 handle;
  sy_u32 events;
  sy_u32 revents;
};

/* `kind` takes the values below; `root` is the BLAKE3 content root. */
struct sy_stat {
  sy_u64 size;
  sy_s64 mtime_ns;
  sy_u32 mode;
  sy_u32 kind;
  sy_u8 root[32];
};

#define SY_KIND_FILE      0
#define SY_KIND_DIR       1
#define SY_KIND_SYMLINK   2
#define SY_KIND_TOMBSTONE 3
#define SY_KIND_SOCKET    4

#define SY_PEER_MEMBER   1
#define SY_PEER_DELEGATE 2

#define SY_BASE64_STANDARD        0
#define SY_BASE64_STANDARD_NO_PAD 1
#define SY_BASE64_URL             2
#define SY_BASE64_URL_NO_PAD      3

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
extern sy_s64 sy_peer_kind(void);
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
extern sy_s64 sy_readable(sy_s64 handle);
extern sy_s64 sy_writable(sy_s64 handle);
/* Half-closes the write side once what is buffered has drained. */
extern sy_s64 sy_shutdown(sy_s64 handle);
extern sy_s64 sy_close(sy_s64 handle);
extern sy_s64 sy_errno(sy_s64 handle);

/* ---- outbound connections ---------------------------------------------- */

/* Returns a handle immediately, still connecting; poll for SY_POLL_OUT. Both
 * the name and the address it resolves to are checked against the armed egress
 * list, so a name that resolves inward is refused where the address would be. */
extern sy_s64 sy_tcp_connect(const char *host, sy_u64 host_len, sy_u64 port);
extern sy_s64 sy_tcp_connect_ip(const void *addr, sy_u64 addr_len, sy_u64 port);
extern sy_s64 sy_endpoint_info(sy_s64 handle, char *out, sy_u64 out_len);

/* ---- poll: the only helper that suspends -------------------------------- */

/* Waits for readiness on up to 16 handles. Returns how many are ready, 0 on
 * timeout, negative on error. A negative timeout means "until something
 * happens", clamped by the host to this invocation's idle deadline. */
extern sy_s64 sy_poll(struct sy_pollfd *fds, sy_u64 n, sy_s64 timeout_ms);

/* ---- reading the tree --------------------------------------------------- */

/* Opens `space/path` in this node's own view — the same scope this program
 * came from. Refuses a socket entry, so a socket cannot read out its
 * neighbours' code. */
extern sy_s64 sy_open(const char *path, sy_u64 path_len);
/* Another origin's version of a path. Must be declared at arm time. */
extern sy_s64 sy_open_from(const char *origin, sy_u64 origin_len,
                           const char *path, sy_u64 path_len);
extern sy_s64 sy_open_root(const void *root32);
extern sy_s64 sy_stat(sy_s64 obj, void *out, sy_u64 out_len);
/* Verified range read. Bytes already held return at once; bytes that must be
 * fetched from a peer return SY_EAGAIN and the handle becomes pollable, so a
 * cold read is an ordinary poll wait rather than a hidden stall. */
extern sy_s64 sy_pread(sy_s64 obj, void *buf, sy_u64 len, sy_u64 offset);
extern sy_s64 sy_list_open(const char *prefix, sy_u64 prefix_len);
extern sy_s64 sy_list_next(sy_s64 cursor, char *out, sy_u64 out_len);

/* ---- state that outlives an invocation ---------------------------------- */

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
extern sy_u64 sy_strlen(const char *s);
/* Constant-time equality, for anything a token is checked against. */
extern sy_s64 sy_ct_eq(const void *a, const void *b, sy_u64 n);
/* First-class because content roots are BLAKE3: a program can check what it
 * read against what the tree said it would be. */
extern sy_s64 sy_blake3(const void *data, sy_u64 len, void *out32);
extern sy_s64 sy_sha256(const void *data, sy_u64 len, void *out32);
extern sy_s64 sy_hmac_sha256(const void *key, sy_u64 key_len, const void *msg,
                             sy_u64 msg_len, void *out32);
extern sy_s64 sy_base64_encode(const void *data, sy_u64 len, void *out,
                               sy_u64 out_len, sy_u64 alphabet);
extern sy_s64 sy_base64_decode_in_place(void *buf, sy_u64 len, sy_u64 alphabet);
extern sy_s64 sy_hex_encode(const void *data, sy_u64 len, void *out,
                            sy_u64 out_len, sy_u64 uppercase);
extern sy_s64 sy_hex_decode_in_place(void *buf, sy_u64 len);

/* ---- declarations: `synchronicity.init` only ---------------------------- */

extern sy_s64 sy_declare_name(const char *name, sy_u64 name_len);
/* Port 0 means any port on that host, and is printed in red at the arm prompt. */
extern sy_s64 sy_declare_egress(const char *host, sy_u64 host_len, sy_u64 port);
extern sy_s64 sy_declare_tree_read(const char *prefix, sy_u64 prefix_len);
extern sy_s64 sy_declare_max_streams(sy_u64 n);

/* ---- what the compiler calls whether you write it or not ---------------- */

/* A struct initializer, an array assignment or a large local is enough to make
 * a C compiler emit a call to `memset` or `memcpy`. There is no libc here to
 * resolve one, and an unresolved symbol is a program that fails to *link* — at
 * arm time, on somebody else's node, a long way from the line that caused it.
 * So the SDK supplies them, forwarding to the host helpers.
 *
 * `memmove` is `sy_memcpy` because the host copies through a buffer of its own
 * before writing, which makes every one of these overlap-safe already. */
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
 * The shape almost every proxying socket wants, written once so it is written
 * right. A short write is backpressure, not failure, and the remainder stays in
 * `buf` under `st` until the next call can place it — which is why `st` and
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
