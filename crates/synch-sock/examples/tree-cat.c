/* tree-cat — hands one directory of this node's tree to a caller who cannot
 * read it any other way.
 *
 *   synch socket build examples/tree-cat.c -o tree-cat.o
 *   synch socket add code/cat.sock
 *   synch socket arm code/cat.sock
 *   printf 'readme\n' | synch connect nas:code/cat.sock
 *
 * A delegate holding only `code` still cannot sync `code/pub` unless somebody
 * delegated it; a socket is how a node lends out a *view* rather than a space.
 * Which makes the input validation below the point of the example: the caller
 * names a leaf under a prefix this program chose, and nothing else, because a
 * socket that pastes caller input into a tree path has handed over the tree.
 */

#include <synch.h>

/* The one directory this socket serves. Everything the caller says is a leaf
   under it. */
#define ROOT "code/pub/"

SY_INIT_ENTRY sy_s64 declare(void) {
  sy_declare_name(SY_STR("tree-cat"));
  sy_declare_max_streams(16);
  return 0;
}

/* Reads one `\n`-terminated line. A byte at a time, which is the wrong way to
   read a stream and the right way to read one short line: it cannot read past
   the line into bytes a later stage would have wanted. */
static sy_s64 read_line(char *out, sy_u64 cap) {
  sy_u64 len = 0;
  for (;;) {
    struct sy_pollfd fds[1] = {{SY_SELF, SY_POLL_IN, 0}};
    sy_s64 ready = sy_poll(fds, 1, 10000);
    if (ready < 0) return ready;
    if (ready == 0) return SY_ETIMEDOUT;

    char c;
    sy_s64 n = sy_read(SY_SELF, &c, 1);
    if (n == SY_EAGAIN) continue;
    if (n < 0) return n;
    if (n == 0) break; /* an EOF ends the last line too */
    if (c == '\n') break;
    if (c == '\r') continue;
    if (len + 1 >= cap) return SY_ELIMIT;
    out[len++] = c;
  }
  out[len] = 0;
  return (sy_s64)len;
}

static sy_s64 refuse(const char *why, sy_s64 code) {
  sy_write_all(SY_SELF, why, sy_strlen(why), 5000);
  sy_shutdown(SY_SELF);
  return code;
}

/* A leaf name: letters, digits, and three punctuation marks that cannot
   compose a traversal. An allow-list rather than a deny-list, because the
   list of things that mean "go up one directory" is longer than it looks. */
static int is_leaf(const char *name, sy_u64 len) {
  if (len == 0) return 0;
  for (sy_u64 i = 0; i < len; i++) {
    char c = name[i];
    int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
             (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
    if (!ok) return 0;
    if (c == '.' && i > 0 && name[i - 1] == '.') return 0;
  }
  return name[0] != '.';
}

SY_ENTRY sy_s64 entry(void) {
  char name[128];
  sy_s64 len = read_line(name, sizeof name);
  if (len < 0) return len;
  if (!is_leaf(name, (sy_u64)len))
    return refuse("usage: one file name under " ROOT "\n", 2);

  char path[192];
  sy_u64 root_len = sizeof ROOT - 1;
  sy_memcpy(path, ROOT, root_len);
  sy_memcpy(path + root_len, name, (sy_u64)len);
  sy_u64 path_len = root_len + (sy_u64)len;

  /* `sy_open` resolves in this node's own view — the same scope this program
     was published in — and refuses a socket entry, so this cannot be turned
     into a way to read the neighbouring sockets' code. */
  sy_s64 obj = sy_open(path, path_len);
  if (obj == SY_ENOENT) return refuse("no such file\n", 3);
  if (obj < 0) return refuse("cannot open\n", 4);

  struct sy_stat st;
  if (sy_stat(obj, &st, sizeof st) < 0) return refuse("cannot stat\n", 5);

  char buf[2048];
  sy_u64 off = 0;
  while (off < st.size) {
    sy_s64 got = sy_pread(obj, buf, sizeof buf, off);
    if (got == SY_EAGAIN) {
      /* The bytes are not held locally yet. A cold read is an ordinary poll
         wait rather than a hidden stall: the object handle becomes readable
         when the fetch from whoever does hold them lands. */
      struct sy_pollfd fds[1] = {{obj, SY_POLL_IN, 0}};
      if (sy_poll(fds, 1, 30000) <= 0) break;
      continue;
    }
    if (got <= 0) break;
    if (sy_write_all(SY_SELF, buf, (sy_u64)got, 30000) < 0) break;
    off += (sy_u64)got;
  }

  sy_close(obj);
  sy_shutdown(SY_SELF);
  return off == st.size ? 0 : 6;
}
