/*
 * csqlite — SQLite behind a stdio port, one process per connection.
 *
 * The BEAM must never load SQLite into its own address space: a database
 * fault here kills this process and nothing else; the owning actor sees the
 * port exit and reopens. The protocol is deliberately synchronous — one
 * request, one response — because the caller serializes access per
 * connection anyway.
 *
 * Framing: every message, both directions, is a 4-byte big-endian length
 * followed by that many payload bytes ({packet,4} on the BEAM side).
 *
 * Requests (first payload byte is the opcode):
 *   0x01 OPEN   u8 mode (0 ro | 1 rw | 2 rwc), path = rest of frame
 *   0x02 EXEC   u32 sql_len, sql, u16 nparams, nparams TLV values
 *   0x03 CLOSE  (empty)
 *   0x04 SCRIPT sql = rest of frame     -- sqlite3_exec, no params, no rows
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

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if SQLITE_VERSION_NUMBER < 3008000
#error "csqlite needs SQLite >= 3.8.0 (WAL + partial indexes)"
#endif

/* A frame larger than this is a protocol violation, not a workload. */
#define MAX_FRAME (64u * 1024u * 1024u)

enum {
  OP_OPEN = 0x01,
  OP_EXEC = 0x02,
  OP_CLOSE = 0x03,
  OP_SCRIPT = 0x04,
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
      perror("csqlite: write");
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
  while (cap < b->len + extra) cap *= 2;
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
  buf_reserve(b, len);
  memcpy(b->data + b->len, data, len);
  b->len += len;
}

static void send_frame(const Buf *b) {
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
  if (c->pos + len > c->len) {
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
      const uint8_t *p = get_bytes(c, len);
      if (!p) return SQLITE_MISUSE;
      return sqlite3_bind_text(stmt, idx, (const char *)p, (int)len,
                               SQLITE_TRANSIENT);
    }
    case VAL_BLOB: {
      uint32_t len = get_u32(c);
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
  /* One statement per EXEC; scripts go through SCRIPT. */
  const char *rest = tail;
  const char *sql_end = (const char *)sql + sql_len;
  while (rest && rest < sql_end &&
         (*rest == ' ' || *rest == '\n' || *rest == '\t' || *rest == '\r' ||
          *rest == ';'))
    rest++;
  if (rest && rest < sql_end && *rest != '\0') {
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

int main(void) {
  sqlite3 *db = NULL;
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
        size_t path_len = c.len - c.pos;
        const uint8_t *path = get_bytes(&c, path_len);
        char *zpath = malloc(path_len + 1);
        if (!zpath) {
          fputs("csqlite: out of memory\n", stderr);
          free(payload);
          return 1;
        }
        memcpy(zpath, path, path_len);
        zpath[path_len] = '\0';
        int flags = mode == 0   ? SQLITE_OPEN_READONLY
                    : mode == 1 ? SQLITE_OPEN_READWRITE
                                : SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
        int rc = sqlite3_open_v2(zpath, &db, flags, NULL);
        free(zpath);
        if (rc != SQLITE_OK) {
          const char *msg = db ? sqlite3_errmsg(db) : "open failed";
          reply_err_msg(rc, msg);
          if (db) {
            sqlite3_close(db);
            db = NULL;
          }
          break;
        }
        sqlite3_extended_result_codes(db, 1);
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
          sqlite3_close(db);
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

  if (db) sqlite3_close(db);
  return 0;
}
