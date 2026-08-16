/*
 * csqlite — SQLite behind a stdio port, one process per connection.
 *
 * The BEAM must never load SQLite into its own address space: a database
 * fault here kills this process and nothing else; the pool sees the port
 * exit and replaces the worker. The protocol is deliberately synchronous — one
 * request, one response — because the caller serializes access per
 * connection anyway.
 *
 * Usage: csqlite [datadir]
 *
 * `datadir` is the directory holding the database. It is not trusted
 * input — the spawner passes it — and it exists so the sandbox can be
 * sealed before the first frame of untrusted input is read: on Linux a
 * Landlock ruleset confines filesystem access to that directory (plus
 * /dev/urandom, which SQLite reads for randomness), then a seccomp
 * allowlist reduces the kernel surface to stdio + file I/O + memory;
 * on OpenBSD the same shape via unveil(2) + pledge(2). Without the
 * argument the filesystem stays unconfined (a warning says so) but the
 * syscall filter still applies. OPEN/RESET are not re-checked in
 * userland: the kernel is the authority, and an out-of-directory path
 * simply fails to open.
 *
 * Framing: every message, both directions, is a 4-byte big-endian length
 * followed by that many payload bytes ({packet,4} on the BEAM side).
 *
 * Requests (first payload byte is the opcode):
 *   0x01 OPEN   u8 mode (0 ro | 1 rw | 2 rwc), path = rest of frame
 *   0x02 EXEC   u32 sql_len, sql, u16 nparams, nparams TLV values
 *   0x03 CLOSE  (empty)
 *   0x04 SCRIPT sql = rest of frame     -- sqlite3_exec, no params, no rows
 *   0x05 RESET  (empty)  -- close + reopen the OPENed path: discards all
 *                           connection state and picks up a replaced file
 *
 * Responses:
 *   0x81 OK
 *   0x82 DONE   i64 changes, i64 last_insert_rowid
 *   0x83 ROWS   u16 ncols, ncols x (u32 len, name), u32 nrows,
 *               nrows x ncols TLV values
 *   0x84 ERR    i32 extended errcode, u32 len, message
 *
 * Value TLV: 0x00 NULL | 0x01 INT i64 | 0x02 FLOAT f64 (IEEE bits)
 *          | 0x03 TEXT u32 len, bytes | 0x04 BLOB u32 len, bytes
 * All integers big-endian.
 */

/* -std=c11 alone hides O_PATH and syscall(), both needed by the Linux
 * sandbox; this must precede every include. */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#if defined(__has_include)
#if __has_include(<linux/landlock.h>)
#include <linux/landlock.h>
#define CSQLITE_HAVE_LANDLOCK 1
#endif
#endif
#endif

#if SQLITE_VERSION_NUMBER < 3037000
#error "csqlite needs SQLite >= 3.37.0 (sqlite3_changes64, SQLITE_OPEN_EXRESCODE)"
#endif

/* This program is pointer-arithmetic-audited for LP64 only: MAX_FRAME
 * (< INT_MAX) is what makes the (int) casts into sqlite3_bind_* safe. */
_Static_assert(sizeof(size_t) >= 8, "csqlite assumes a 64-bit size_t");

/* A frame larger than this is a protocol violation, not a workload. */
#define MAX_FRAME (64u * 1024u * 1024u)

/* Responses are capped too: an oversized result set becomes a clean
 * SQLITE_TOOBIG error instead of a giant binary pushed into the VM (or,
 * at 2^32, a truncated length prefix that desyncs the framing). */
#define MAX_RESP (64u * 1024u * 1024u)

/* ---- sandbox ----------------------------------------------------------- */
/*
 * Sealed before the first read of untrusted input; every failure is
 * best-effort-with-a-loud-warning rather than fatal, because a worker
 * that cannot start at all is an outage while a worker missing one
 * defense layer still has the others (and the message lands in the
 * journal, where it is not ignorable). Platforms other than Linux and
 * OpenBSD get no confinement; the port still runs.
 */

#if defined(__linux__)

/* Filesystem: Landlock (5.13+), unprivileged. The ruleset handles every
 * access kind this kernel's ABI knows so anything unlisted is denied,
 * then grants the database directory just what SQLite needs for the db,
 * its -wal/-shm/journal companions, and temp spill files (main() points
 * the VFS temp path here). The grant is the *database's* directory, which
 * is why the operator keeps the signing key elsewhere: Landlock cannot
 * express a filename, only a directory. */
#ifdef CSQLITE_HAVE_LANDLOCK
/* Returns 1 if the rule was added, 0 on any failure (already warned). */
static int grant_path(int rfd, const char *path, uint64_t access) {
  struct landlock_path_beneath_attr pb = {0};
  pb.parent_fd = open(path, O_PATH | O_CLOEXEC);
  if (pb.parent_fd < 0) {
    fprintf(stderr, "csqlite: landlock: cannot open %s: %s\n", path,
            strerror(errno));
    return 0;
  }
  pb.allowed_access = access;
  int ok = syscall(__NR_landlock_add_rule, rfd, LANDLOCK_RULE_PATH_BENEATH,
                   &pb, 0) == 0;
  if (!ok)
    fprintf(stderr, "csqlite: landlock: add rule for %s: %s\n", path,
            strerror(errno));
  close(pb.parent_fd);
  return ok;
}

static void confine_fs(const char *datadir) {
  long abi = syscall(__NR_landlock_create_ruleset, NULL, 0,
                     LANDLOCK_CREATE_RULESET_VERSION);
  if (abi < 0) {
    fputs("csqlite: landlock unsupported here; filesystem unconfined\n",
          stderr);
    return;
  }
  struct landlock_ruleset_attr attr = {0};
  attr.handled_access_fs =
      LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
      LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
      LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
      LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
      LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
      LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
      LANDLOCK_ACCESS_FS_MAKE_SYM;
  uint64_t dir_access =
      LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE |
      LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
      LANDLOCK_ACCESS_FS_MAKE_REG;
#ifdef LANDLOCK_ACCESS_FS_REFER
  if (abi >= 2) attr.handled_access_fs |= LANDLOCK_ACCESS_FS_REFER;
#endif
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
  /* SQLite truncates journals and the WAL; only an ABI that handles
   * truncate needs (or accepts) the explicit grant. */
  if (abi >= 3) {
    attr.handled_access_fs |= LANDLOCK_ACCESS_FS_TRUNCATE;
    dir_access |= LANDLOCK_ACCESS_FS_TRUNCATE;
  }
#endif
  int rfd = (int)syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
  if (rfd < 0) {
    fprintf(stderr, "csqlite: landlock: create ruleset: %s\n",
            strerror(errno));
    return;
  }
  /* If the database directory itself could not be granted, sealing the
   * ruleset would deny every OPEN — a worker that is confined but cannot
   * serve. Warn-and-continue policy: leave the filesystem unconfined and
   * loud rather than sealed and dead. (/dev/urandom is best-effort: a
   * failed grant only costs SQLite its preferred randomness source.) */
  if (!grant_path(rfd, datadir, dir_access)) {
    fputs("csqlite: landlock: database directory not granted; leaving "
          "filesystem unconfined\n",
          stderr);
    close(rfd);
    return;
  }
  grant_path(rfd, "/dev/urandom", LANDLOCK_ACCESS_FS_READ_FILE);
  if (syscall(__NR_landlock_restrict_self, rfd, 0) != 0)
    fprintf(stderr, "csqlite: landlock: restrict self: %s\n",
            strerror(errno));
  close(rfd);
}
#else
static void confine_fs(const char *datadir) {
  (void)datadir;
  fputs("csqlite: built without landlock headers; filesystem unconfined\n",
        stderr);
}
#endif

/* Syscalls: a hand-rolled BPF allowlist (no libseccomp dependency) of
 * what glibc + SQLite actually reach for — stdio, one database's file
 * I/O, memory, locking, time/sleep (busy_timeout). No exec, no
 * sockets, no clone. Anything else kills the worker; the pool replaces
 * it and the SIGSYS is visible in the journal. */
#if defined(__x86_64__)
#define CSQLITE_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define CSQLITE_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__riscv) && __riscv_xlen == 64
#define CSQLITE_AUDIT_ARCH AUDIT_ARCH_RISCV64
#endif

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif

static void confine_syscalls(void) {
#ifndef CSQLITE_AUDIT_ARCH
  fputs("csqlite: no seccomp arch mapping for this target; syscalls "
        "unconfined\n",
        stderr);
#else
  static const long allowed[] = {
  /* frames + database + journal/WAL I/O */
#ifdef __NR_read
      __NR_read,
#endif
#ifdef __NR_write
      __NR_write,
#endif
#ifdef __NR_readv
      __NR_readv,
#endif
#ifdef __NR_writev
      __NR_writev,
#endif
#ifdef __NR_pread64
      __NR_pread64,
#endif
#ifdef __NR_pwrite64
      __NR_pwrite64,
#endif
#ifdef __NR_open
      __NR_open,
#endif
#ifdef __NR_openat
      __NR_openat,
#endif
#ifdef __NR_close
      __NR_close,
#endif
#ifdef __NR_lseek
      __NR_lseek,
#endif
#ifdef __NR_ftruncate
      __NR_ftruncate,
#endif
#ifdef __NR_fallocate
      __NR_fallocate,
#endif
#ifdef __NR_fsync
      __NR_fsync,
#endif
#ifdef __NR_fdatasync
      __NR_fdatasync,
#endif
#ifdef __NR_unlink
      __NR_unlink,
#endif
#ifdef __NR_unlinkat
      __NR_unlinkat,
#endif
  /* fcntl covers SQLite's POSIX advisory locks */
#ifdef __NR_fcntl
      __NR_fcntl,
#endif
#ifdef __NR_flock
      __NR_flock,
#endif
  /* unixDeviceCharacteristics() probes the fs on the commit path; a
   * libsqlite3 built with SQLITE_ENABLE_BATCH_ATOMIC_WRITE issues an
   * ioctl there. The distro build linked here does not, but the Makefile
   * does not pin the build, so allow it rather than SIGSYS on first write
   * against a differently-configured SQLite. */
#ifdef __NR_ioctl
      __NR_ioctl,
#endif
  /* journal/WAL files are fchmod'd to match the database */
#ifdef __NR_fchmod
      __NR_fchmod,
#endif
#ifdef __NR_fchown
      __NR_fchown,
#endif
  /* path metadata: stat family, access, readlink, getcwd */
#ifdef __NR_stat
      __NR_stat,
#endif
#ifdef __NR_lstat
      __NR_lstat,
#endif
#ifdef __NR_fstat
      __NR_fstat,
#endif
#ifdef __NR_newfstatat
      __NR_newfstatat,
#endif
#ifdef __NR_statx
      __NR_statx,
#endif
#ifdef __NR_access
      __NR_access,
#endif
#ifdef __NR_faccessat
      __NR_faccessat,
#endif
#ifdef __NR_faccessat2
      __NR_faccessat2,
#endif
#ifdef __NR_readlink
      __NR_readlink,
#endif
#ifdef __NR_readlinkat
      __NR_readlinkat,
#endif
#ifdef __NR_getcwd
      __NR_getcwd,
#endif
  /* memory: malloc, SQLite page cache, WAL -shm mapping. mmap and
   * mprotect are handled separately below, with a PROT_EXEC check — this
   * is a C process with no JIT, so nothing legitimately maps writable-
   * then-executable, and denying it removes the last step of the usual
   * "corrupt a page, run it" chain against a hostile database file. */
#ifdef __NR_munmap
      __NR_munmap,
#endif
#ifdef __NR_mremap
      __NR_mremap,
#endif
#ifdef __NR_madvise
      __NR_madvise,
#endif
#ifdef __NR_brk
      __NR_brk,
#endif
#ifdef __NR_futex
      __NR_futex,
#endif
  /* identity + randomness (temp names, xRandomness fallback) */
#ifdef __NR_getpid
      __NR_getpid,
#endif
#ifdef __NR_gettid
      __NR_gettid,
#endif
#ifdef __NR_getuid
      __NR_getuid,
#endif
#ifdef __NR_geteuid
      __NR_geteuid,
#endif
#ifdef __NR_getgid
      __NR_getgid,
#endif
#ifdef __NR_getegid
      __NR_getegid,
#endif
#ifdef __NR_getrandom
      __NR_getrandom,
#endif
  /* time + sleep: sqlite3_busy_timeout parks in nanosleep */
#ifdef __NR_clock_gettime
      __NR_clock_gettime,
#endif
#ifdef __NR_clock_getres
      __NR_clock_getres,
#endif
#ifdef __NR_gettimeofday
      __NR_gettimeofday,
#endif
#ifdef __NR_nanosleep
      __NR_nanosleep,
#endif
#ifdef __NR_clock_nanosleep
      __NR_clock_nanosleep,
#endif
#ifdef __NR_sched_yield
      __NR_sched_yield,
#endif
  /* shutdown + signal return */
#ifdef __NR_rt_sigreturn
      __NR_rt_sigreturn,
#endif
#ifdef __NR_restart_syscall
      __NR_restart_syscall,
#endif
#ifdef __NR_exit
      __NR_exit,
#endif
#ifdef __NR_exit_group
      __NR_exit_group,
#endif
  };
  enum { NALLOWED = sizeof(allowed) / sizeof(allowed[0]) };

  /* Upper bound (x86_64, every guard live): 4 prologue + 2 x32 check
   * + 5 mmap + 5 mprotect + 2 per allowlisted syscall + 1 final. Other
   * arches emit fewer; over-sizing is a few unused stack slots. */
  struct sock_filter prog[17 + 2 * NALLOWED];
  size_t n = 0;
  prog[n++] = (struct sock_filter)BPF_STMT(
      BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
  prog[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                           CSQLITE_AUDIT_ARCH, 1, 0);
  prog[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                           SECCOMP_RET_KILL_PROCESS);
  prog[n++] = (struct sock_filter)BPF_STMT(
      BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
#if defined(__x86_64__)
  /* The x32 ABI shares the arch token; its numbers carry bit 30. */
  prog[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K,
                                           0x40000000u, 0, 1);
  prog[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                           SECCOMP_RET_KILL_PROCESS);
#endif
  /* W^X: mmap/mprotect are allowed only without PROT_EXEC. Each block is
   * "if nr==call, load args[2] (prot, low word — every mapped arch here
   * is little-endian), kill on PROT_EXEC else allow; if nr!=call skip the
   * four-instruction body with the accumulator still holding nr". Both
   * interior arms return, so a taken block never falls through and the
   * allowlist below always sees nr, never a stale prot value. */
#if defined(__NR_mmap) || defined(__NR_mprotect)
  static const int prot_calls[] = {
#ifdef __NR_mmap
      __NR_mmap,
#endif
#ifdef __NR_mprotect
      __NR_mprotect,
#endif
  };
  for (size_t i = 0; i < sizeof(prot_calls) / sizeof(prot_calls[0]); i++) {
    prog[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                             (uint32_t)prot_calls[i], 0, 4);
    prog[n++] = (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2]));
    prog[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K,
                                             (uint32_t)PROT_EXEC, 0, 1);
    prog[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                             SECCOMP_RET_KILL_PROCESS);
    prog[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                             SECCOMP_RET_ALLOW);
  }
#endif
  for (size_t i = 0; i < NALLOWED; i++) {
    prog[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                             (uint32_t)allowed[i], 0, 1);
    prog[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                             SECCOMP_RET_ALLOW);
  }
  prog[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                           SECCOMP_RET_KILL_PROCESS);

  struct sock_fprog fprog = {(unsigned short)n, prog};
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog, 0, 0) != 0)
    fprintf(stderr, "csqlite: seccomp install failed: %s\n", strerror(errno));
#endif
}

static void sandbox(const char *datadir) {
  /* The database holds user and key-binding state: no core dumps, and
   * not ptrace-able by an unprivileged peer. */
  struct rlimit no_core = {0, 0};
  if (setrlimit(RLIMIT_CORE, &no_core) != 0)
    fprintf(stderr, "csqlite: RLIMIT_CORE: %s\n", strerror(errno));
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
    fprintf(stderr, "csqlite: PR_SET_DUMPABLE: %s\n", strerror(errno));
  /* db + wal + shm + journal + dir fsync handles + urandom: 64 is
   * generous for one connection and starves nothing legitimate. */
  struct rlimit few_files = {64, 64};
  if (setrlimit(RLIMIT_NOFILE, &few_files) != 0)
    fprintf(stderr, "csqlite: RLIMIT_NOFILE: %s\n", strerror(errno));
  /* Required (unprivileged) by both landlock_restrict_self and
   * SECCOMP_MODE_FILTER. */
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    fprintf(stderr, "csqlite: no_new_privs: %s\n", strerror(errno));
  if (datadir)
    confine_fs(datadir);
  else
    fputs("csqlite: no data directory argument; filesystem unconfined\n",
          stderr);
  /* Last: the landlock setup above needs syscalls the filter denies. */
  confine_syscalls();
}

#elif defined(__OpenBSD__)

static void sandbox(const char *datadir) {
  if (datadir) {
    if (unveil(datadir, "rwc") != 0)
      fprintf(stderr, "csqlite: unveil %s: %s\n", datadir, strerror(errno));
    /* Best-effort, as on Linux: absent /dev/urandom degrades SQLite's
     * randomness source, it does not stop the worker. */
    if (unveil("/dev/urandom", "r") != 0)
      fprintf(stderr, "csqlite: unveil /dev/urandom: %s\n", strerror(errno));
    if (unveil(NULL, NULL) != 0)
      fprintf(stderr, "csqlite: unveil lock: %s\n", strerror(errno));
  } else {
    fputs("csqlite: no data directory argument; filesystem unconfined\n",
          stderr);
  }
  /* stdio: frames, mmap, ftruncate, nanosleep. rpath/wpath/cpath: the
   * database and its journal/WAL siblings. flock: SQLite's POSIX
   * locks. fattr: journal/WAL fchmod-to-match-the-database. No chown
   * promise: SQLite only fchowns journals when running as root, which
   * this service never is. */
  if (pledge("stdio rpath wpath cpath flock fattr", NULL) != 0)
    fprintf(stderr, "csqlite: pledge: %s\n", strerror(errno));
}

#else

/* No confinement on this platform (dev hosts, e.g. macOS); documented
 * in the header comment rather than warned per-spawn, because the pool
 * starts a worker per connection and the noise would drown real
 * warnings. */
static void sandbox(const char *datadir) { (void)datadir; }

#endif

enum {
  OP_OPEN = 0x01,
  OP_EXEC = 0x02,
  OP_CLOSE = 0x03,
  OP_SCRIPT = 0x04,
  OP_RESET = 0x05,
  RESP_OK = 0x81,
  RESP_DONE = 0x82,
  RESP_ROWS = 0x83,
  RESP_ERR = 0x84,
  VAL_NULL = 0x00,
  VAL_INT = 0x01,
  VAL_FLOAT = 0x02,
  VAL_TEXT = 0x03,
  VAL_BLOB = 0x04,
};

/* ---- exact stdio ------------------------------------------------------- */

static int read_exact(uint8_t *buf, size_t len) {
  size_t got = 0;
  while (got < len) {
    ssize_t n = read(STDIN_FILENO, buf + got, len - got);
    if (n == 0) return 0;  /* clean EOF: port closed */
    if (n < 0) {
      if (errno == EINTR) continue;
      perror("csqlite: read");
      exit(1);
    }
    got += (size_t)n;
  }
  return 1;
}

static void write_exact(const uint8_t *buf, size_t len) {
  size_t sent = 0;
  while (sent < len) {
    ssize_t n = write(STDOUT_FILENO, buf + sent, len - sent);
    if (n < 0) {
      if (errno == EINTR) continue;
      /* SIGPIPE is ignored; the owner closing the port is a shutdown,
       * not a crash. */
      if (errno == EPIPE) exit(0);
      perror("csqlite: write");
      exit(1);
    }
    if (n == 0) {
      fputs("csqlite: zero-byte write\n", stderr);
      exit(1);
    }
    sent += (size_t)n;
  }
}

/* ---- growable response buffer ------------------------------------------ */

typedef struct {
  uint8_t *data;
  size_t len;
  size_t cap;
} Buf;

static void buf_reserve(Buf *b, size_t extra) {
  if (b->len + extra <= b->cap) return;
  size_t cap = b->cap ? b->cap : 256;
  while (cap < b->len + extra) {
    if (cap > SIZE_MAX / 2) {
      cap = b->len + extra;
      break;
    }
    cap *= 2;
  }
  b->data = realloc(b->data, cap);
  if (!b->data) {
    fputs("csqlite: out of memory\n", stderr);
    exit(1);
  }
  b->cap = cap;
}

static void put_u8(Buf *b, uint8_t v) {
  buf_reserve(b, 1);
  b->data[b->len++] = v;
}

static void put_u16(Buf *b, uint16_t v) {
  buf_reserve(b, 2);
  b->data[b->len++] = (uint8_t)(v >> 8);
  b->data[b->len++] = (uint8_t)v;
}

static void put_u32(Buf *b, uint32_t v) {
  buf_reserve(b, 4);
  b->data[b->len++] = (uint8_t)(v >> 24);
  b->data[b->len++] = (uint8_t)(v >> 16);
  b->data[b->len++] = (uint8_t)(v >> 8);
  b->data[b->len++] = (uint8_t)v;
}

static void put_u64(Buf *b, uint64_t v) {
  put_u32(b, (uint32_t)(v >> 32));
  put_u32(b, (uint32_t)v);
}

static void put_bytes(Buf *b, const void *data, size_t len) {
  /* Zero-length appends carry NULL sources (empty blobs, OOM'd
   * column_text) — memcpy(dst, NULL, 0) is UB, so never reach it. */
  if (len == 0) return;
  buf_reserve(b, len);
  memcpy(b->data + b->len, data, len);
  b->len += len;
}

static void send_frame(const Buf *b) {
  if (b->len > 0xFFFFFFFFu) {
    /* Unreachable behind MAX_RESP, but a truncated length prefix would
     * silently desync the framing forever — die loudly instead. */
    fputs("csqlite: response exceeds framable size\n", stderr);
    exit(1);
  }
  uint8_t hdr[4] = {
      (uint8_t)(b->len >> 24),
      (uint8_t)(b->len >> 16),
      (uint8_t)(b->len >> 8),
      (uint8_t)b->len,
  };
  write_exact(hdr, 4);
  write_exact(b->data, b->len);
}

/* ---- request cursor ---------------------------------------------------- */

typedef struct {
  const uint8_t *data;
  size_t len;
  size_t pos;
  int truncated; /* set when a read ran past the frame: protocol error */
} Cur;

static uint8_t get_u8(Cur *c) {
  if (c->pos + 1 > c->len) {
    c->truncated = 1;
    return 0;
  }
  return c->data[c->pos++];
}

static uint16_t get_u16(Cur *c) {
  if (c->pos + 2 > c->len) {
    c->truncated = 1;
    return 0;
  }
  uint16_t v = ((uint16_t)c->data[c->pos] << 8) | c->data[c->pos + 1];
  c->pos += 2;
  return v;
}

static uint32_t get_u32(Cur *c) {
  if (c->pos + 4 > c->len) {
    c->truncated = 1;
    return 0;
  }
  uint32_t v = ((uint32_t)c->data[c->pos] << 24) |
               ((uint32_t)c->data[c->pos + 1] << 16) |
               ((uint32_t)c->data[c->pos + 2] << 8) | c->data[c->pos + 3];
  c->pos += 4;
  return v;
}

static uint64_t get_u64(Cur *c) {
  uint64_t hi = get_u32(c);
  return (hi << 32) | get_u32(c);
}

static const uint8_t *get_bytes(Cur *c, size_t len) {
  /* pos <= len always holds, so the subtraction cannot underflow and
   * the comparison cannot be defeated by wraparound on any target. */
  if (len > c->len - c->pos) {
    c->truncated = 1;
    return NULL;
  }
  const uint8_t *p = c->data + c->pos;
  c->pos += len;
  return p;
}

/* ---- responses --------------------------------------------------------- */

static void reply_err_msg(int code, const char *msg) {
  Buf b = {0};
  size_t len = strlen(msg);
  put_u8(&b, RESP_ERR);
  put_u32(&b, (uint32_t)code);
  put_u32(&b, (uint32_t)len);
  put_bytes(&b, msg, len);
  send_frame(&b);
  free(b.data);
}

static void reply_err_db(sqlite3 *db) {
  reply_err_msg(sqlite3_extended_errcode(db), sqlite3_errmsg(db));
}

static void reply_ok(void) {
  Buf b = {0};
  put_u8(&b, RESP_OK);
  send_frame(&b);
  free(b.data);
}

/* ---- EXEC -------------------------------------------------------------- */

static int bind_param(sqlite3_stmt *stmt, int idx, Cur *c) {
  uint8_t tag = get_u8(c);
  switch (tag) {
    case VAL_NULL:
      return sqlite3_bind_null(stmt, idx);
    case VAL_INT:
      return sqlite3_bind_int64(stmt, idx, (sqlite3_int64)get_u64(c));
    case VAL_FLOAT: {
      uint64_t bits = get_u64(c);
      double d;
      memcpy(&d, &bits, 8);
      return sqlite3_bind_double(stmt, idx, d);
    }
    case VAL_TEXT: {
      uint32_t len = get_u32(c);
      if (len > MAX_FRAME) {
        c->truncated = 1;
        return SQLITE_MISUSE;
      }
      const uint8_t *p = get_bytes(c, len);
      if (!p) return SQLITE_MISUSE;
      return sqlite3_bind_text(stmt, idx, (const char *)p, (int)len,
                               SQLITE_TRANSIENT);
    }
    case VAL_BLOB: {
      uint32_t len = get_u32(c);
      if (len > MAX_FRAME) {
        c->truncated = 1;
        return SQLITE_MISUSE;
      }
      const uint8_t *p = get_bytes(c, len);
      if (!p) return SQLITE_MISUSE;
      return sqlite3_bind_blob(stmt, idx, p, (int)len, SQLITE_TRANSIENT);
    }
    default:
      c->truncated = 1;
      return SQLITE_MISUSE;
  }
}

static void put_column(Buf *b, sqlite3_stmt *stmt, int col) {
  switch (sqlite3_column_type(stmt, col)) {
    case SQLITE_NULL:
      put_u8(b, VAL_NULL);
      break;
    case SQLITE_INTEGER:
      put_u8(b, VAL_INT);
      put_u64(b, (uint64_t)sqlite3_column_int64(stmt, col));
      break;
    case SQLITE_FLOAT: {
      double d = sqlite3_column_double(stmt, col);
      uint64_t bits;
      memcpy(&bits, &d, 8);
      put_u8(b, VAL_FLOAT);
      put_u64(b, bits);
      break;
    }
    case SQLITE_TEXT: {
      const uint8_t *p = sqlite3_column_text(stmt, col);
      uint32_t len = (uint32_t)sqlite3_column_bytes(stmt, col);
      put_u8(b, VAL_TEXT);
      put_u32(b, len);
      put_bytes(b, p, len);
      break;
    }
    case SQLITE_BLOB:
    default: {
      const void *p = sqlite3_column_blob(stmt, col);
      uint32_t len = (uint32_t)sqlite3_column_bytes(stmt, col);
      put_u8(b, VAL_BLOB);
      put_u32(b, len);
      if (len) put_bytes(b, p, len);
      break;
    }
  }
}

static void handle_exec(sqlite3 *db, Cur *c) {
  uint32_t sql_len = get_u32(c);
  const uint8_t *sql = get_bytes(c, sql_len);
  uint16_t nparams = c->truncated ? 0 : get_u16(c);
  if (c->truncated) {
    reply_err_msg(SQLITE_MISUSE, "truncated EXEC frame");
    return;
  }
  /* An embedded NUL would end the tokenizer early and hide trailing
   * text from the single-statement gate below. */
  if (memchr(sql, '\0', sql_len) != NULL) {
    reply_err_msg(SQLITE_MISUSE, "embedded NUL in SQL");
    return;
  }

  sqlite3_stmt *stmt = NULL;
  const char *tail = NULL;
  int rc = sqlite3_prepare_v2(db, (const char *)sql, (int)sql_len, &stmt, &tail);
  if (rc != SQLITE_OK) {
    reply_err_db(db);
    return;
  }
  if (!stmt) {
    /* Whitespace/comment-only SQL: nothing to run. */
    reply_err_msg(SQLITE_MISUSE, "empty statement");
    return;
  }
  /* One statement per EXEC; scripts go through SCRIPT. Anything but
   * whitespace/semicolons after the first statement is refused. */
  const char *rest = tail;
  const char *sql_end = (const char *)sql + sql_len;
  while (rest && rest < sql_end &&
         (*rest == ' ' || *rest == '\n' || *rest == '\t' || *rest == '\r' ||
          *rest == ';'))
    rest++;
  if (rest && rest < sql_end) {
    sqlite3_finalize(stmt);
    reply_err_msg(SQLITE_MISUSE, "EXEC takes a single statement (use SCRIPT)");
    return;
  }

  int expected = sqlite3_bind_parameter_count(stmt);
  if (expected != (int)nparams) {
    sqlite3_finalize(stmt);
    reply_err_msg(SQLITE_MISUSE, "parameter count mismatch");
    return;
  }
  for (int i = 1; i <= expected; i++) {
    rc = bind_param(stmt, i, c);
    if (c->truncated) {
      sqlite3_finalize(stmt);
      reply_err_msg(SQLITE_MISUSE, "truncated parameter");
      return;
    }
    if (rc != SQLITE_OK) {
      sqlite3_finalize(stmt);
      reply_err_db(db);
      return;
    }
  }
  /* Strict framing: trailing bytes mean the encoder and this parser
   * disagree — refuse loudly rather than diverge silently. */
  if (c->pos != c->len) {
    sqlite3_finalize(stmt);
    reply_err_msg(SQLITE_MISUSE, "trailing bytes after parameters");
    return;
  }

  int ncols = sqlite3_column_count(stmt);
  if (ncols == 0) {
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
      sqlite3_finalize(stmt);
      reply_err_db(db);
      return;
    }
    sqlite3_finalize(stmt);
    Buf b = {0};
    put_u8(&b, RESP_DONE);
    put_u64(&b, (uint64_t)sqlite3_changes64(db));
    put_u64(&b, (uint64_t)sqlite3_last_insert_rowid(db));
    send_frame(&b);
    free(b.data);
    return;
  }

  Buf b = {0};
  put_u8(&b, RESP_ROWS);
  put_u16(&b, (uint16_t)ncols);
  for (int i = 0; i < ncols; i++) {
    const char *name = sqlite3_column_name(stmt, i);
    if (!name) name = "";
    uint32_t len = (uint32_t)strlen(name);
    put_u32(&b, len);
    put_bytes(&b, name, len);
  }
  /* Row count is patched in after stepping. */
  size_t nrows_at = b.len;
  put_u32(&b, 0);
  uint32_t nrows = 0;
  for (;;) {
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
      for (int i = 0; i < ncols; i++) put_column(&b, stmt, i);
      nrows++;
      if (b.len > MAX_RESP) {
        sqlite3_finalize(stmt);
        free(b.data);
        reply_err_msg(SQLITE_TOOBIG, "result set too large");
        return;
      }
      continue;
    }
    if (rc == SQLITE_DONE) break;
    sqlite3_finalize(stmt);
    free(b.data);
    reply_err_db(db);
    return;
  }
  sqlite3_finalize(stmt);
  b.data[nrows_at] = (uint8_t)(nrows >> 24);
  b.data[nrows_at + 1] = (uint8_t)(nrows >> 16);
  b.data[nrows_at + 2] = (uint8_t)(nrows >> 8);
  b.data[nrows_at + 3] = (uint8_t)nrows;
  send_frame(&b);
  free(b.data);
}

/* ---- main loop --------------------------------------------------------- */

/* No SQL statement may name a second file. ATTACH is the obvious way SQL
 * opens a path other than the OPENed one; VACUUM INTO reaches the VFS
 * through the same SQLITE_ATTACH authorization. Nothing the control plane
 * runs needs either, and denying them keeps a compromised query from
 * touching the signing key (or anything else) that shares the granted
 * directory — a distinction the kernel confinement cannot draw, and the
 * one layer that still holds on a host without Landlock. */
static int deny_second_file(void *unused, int action, const char *a,
                            const char *b, const char *c, const char *d) {
  (void)unused;
  (void)a;
  (void)b;
  (void)c;
  (void)d;
  if (action == SQLITE_ATTACH || action == SQLITE_DETACH) return SQLITE_DENY;
  return SQLITE_OK;
}

/* Opens `zpath` with the mode's flags and the full hostile-file hardening
 * applied. On failure the handle is closed and *out is NULL. */
static int open_hardened(const char *zpath, uint8_t mode, sqlite3 **out) {
  /* NOFOLLOW in every mode: the database is opened by absolute path and
   * the replica refresh contract is an atomic rename, never a symlink, so
   * a symlinked target is always someone redirecting the open — and for a
   * writable mode it would land the db (and its -wal/-shm) outside the
   * granted directory. */
  int flags = mode == 0   ? SQLITE_OPEN_READONLY
              : mode == 1 ? SQLITE_OPEN_READWRITE
                          : SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
  flags |= SQLITE_OPEN_EXRESCODE | SQLITE_OPEN_NOFOLLOW;
  sqlite3 *db = NULL;
  int rc = sqlite3_open_v2(zpath, &db, flags, NULL);
  if (rc != SQLITE_OK) {
    if (db) sqlite3_close_v2(db);
    *out = NULL;
    return rc;
  }
  sqlite3_extended_result_codes(db, 1);
  /* Replicas open database files written by external replication
   * tooling — treat every file as potentially hostile. */
  sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, NULL);
  sqlite3_db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, NULL);
  sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, NULL);
  sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 16 * 1024 * 1024);
  sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 1024 * 1024);
  sqlite3_limit(db, SQLITE_LIMIT_EXPR_DEPTH, 200);
  sqlite3_limit(db, SQLITE_LIMIT_VDBE_OP, 250000);
  sqlite3_busy_timeout(db, 5000);
  sqlite3_exec(db, "PRAGMA cell_size_check=ON", NULL, NULL, NULL);
  /* ATTACH / VACUUM INTO / DETACH are refused (see deny_second_file):
   * the sandbox grants one directory, so SQL must not be able to name a
   * file in it beyond the database. */
  sqlite3_set_authorizer(db, deny_second_file, NULL);
  *out = db;
  return SQLITE_OK;
}

int main(int argc, char **argv) {
  /* The database (and its -wal/-shm/journal companions) holds user and
   * key-binding state; never create it world-readable. */
  umask(077);
  /* The owner closing the port must be a clean shutdown (EPIPE path in
   * write_exact), not death by signal 13. */
  signal(SIGPIPE, SIG_IGN);
  /* Seal before the first frame: everything after this point handles
   * untrusted input with the kernel surface already reduced. */
  const char *datadir = argc > 1 ? argv[1] : NULL;
  sandbox(datadir);

  /* Sorts and statement journals spill into the granted directory rather
   * than an ungranted /tmp: temp_store stays at its FILE default and the
   * VFS temp path points at the database's own directory. (temp_store=
   * MEMORY, the obvious alternative, turns a disk-bounded sort into an
   * unbounded heap allocation — a fleet-wide ORDER BY would then size the
   * worker's RSS instead of spilling.) The hard heap limit is a backstop
   * for the paths that still allocate: a runaway query gets SQLITE_NOMEM,
   * not the cgroup's OOM killer. */
  if (datadir) sqlite3_temp_directory = sqlite3_mprintf("%s", datadir);
  sqlite3_hard_heap_limit64(256 * 1024 * 1024);

  sqlite3 *db = NULL;
  char *saved_path = NULL;
  uint8_t saved_mode = 0;
  uint8_t hdr[4];

  while (read_exact(hdr, 4)) {
    uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                   ((uint32_t)hdr[2] << 8) | hdr[3];
    if (len == 0 || len > MAX_FRAME) {
      fputs("csqlite: bad frame length\n", stderr);
      return 1;
    }
    uint8_t *payload = malloc(len);
    if (!payload) {
      fputs("csqlite: out of memory\n", stderr);
      return 1;
    }
    if (!read_exact(payload, len)) {
      free(payload);
      break; /* EOF mid-frame: owner went away */
    }

    Cur c = {payload, len, 0, 0};
    uint8_t op = get_u8(&c);
    switch (op) {
      case OP_OPEN: {
        if (db) {
          reply_err_msg(SQLITE_MISUSE, "already open");
          break;
        }
        uint8_t mode = get_u8(&c);
        if (c.truncated || mode > 2) {
          reply_err_msg(SQLITE_MISUSE, "bad OPEN frame");
          break;
        }
        size_t path_len = c.len - c.pos;
        /* An empty path would open an anonymous temp database — the
         * service would come up "healthy" and discard every write. An
         * embedded NUL would silently truncate the path. Fail closed. */
        if (path_len == 0 ||
            memchr(c.data + c.pos, '\0', path_len) != NULL) {
          reply_err_msg(SQLITE_MISUSE, "empty or NUL-bearing database path");
          break;
        }
        const uint8_t *path = get_bytes(&c, path_len);
        char *zpath = malloc(path_len + 1);
        if (!zpath) {
          fputs("csqlite: out of memory\n", stderr);
          free(payload);
          return 1;
        }
        memcpy(zpath, path, path_len);
        zpath[path_len] = '\0';
        int rc = open_hardened(zpath, mode, &db);
        if (rc != SQLITE_OK) {
          free(zpath);
          reply_err_msg(rc, "open failed");
          break;
        }
        /* Remember the identity for RESET: pooled connections reopen the
         * same path so an atomically renamed replacement file is picked
         * up on the next checkout. */
        free(saved_path);
        saved_path = zpath;
        saved_mode = mode;
        reply_ok();
        break;
      }
      case OP_RESET: {
        /* Discard all connection state — open transaction, temp tables,
         * statement caches — and reopen the saved path fresh. */
        if (!saved_path) {
          reply_err_msg(SQLITE_MISUSE, "RESET before OPEN");
          break;
        }
        if (db) {
          sqlite3_close_v2(db);
          db = NULL;
        }
        int rc = open_hardened(saved_path, saved_mode, &db);
        if (rc != SQLITE_OK) {
          reply_err_msg(rc, "reopen failed");
          break;
        }
        reply_ok();
        break;
      }
      case OP_EXEC:
        if (!db) {
          reply_err_msg(SQLITE_MISUSE, "no open database");
        } else {
          handle_exec(db, &c);
        }
        break;
      case OP_SCRIPT: {
        if (!db) {
          reply_err_msg(SQLITE_MISUSE, "no open database");
          break;
        }
        size_t sql_len = c.len - c.pos;
        const uint8_t *sql = get_bytes(&c, sql_len);
        char *zsql = malloc(sql_len + 1);
        if (!zsql) {
          fputs("csqlite: out of memory\n", stderr);
          free(payload);
          return 1;
        }
        memcpy(zsql, sql, sql_len);
        zsql[sql_len] = '\0';
        char *errmsg = NULL;
        int rc = sqlite3_exec(db, zsql, NULL, NULL, &errmsg);
        free(zsql);
        if (rc != SQLITE_OK) {
          reply_err_msg(sqlite3_extended_errcode(db),
                        errmsg ? errmsg : "script failed");
          sqlite3_free(errmsg);
        } else {
          reply_ok();
        }
        break;
      }
      case OP_CLOSE:
        if (db) {
          sqlite3_close_v2(db);
          db = NULL;
        }
        reply_ok();
        free(payload);
        return 0;
      default:
        reply_err_msg(SQLITE_MISUSE, "unknown opcode");
        break;
    }
    free(payload);
  }

  if (db) sqlite3_close_v2(db);
  return 0;
}
