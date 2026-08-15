//// The pragma sets each role runs before touching a connection, plus
//// direct openers for boot, CLI tools and tests. Request and serving
//// paths never open connections here — they borrow from `store/pool`,
//// which re-applies these pragma sets after every checkout reset.

import gleam/otp/actor
import gleam/result
import store/pool
import store/sqlite.{type Connection, type Error}

/// The primary's writer: WAL (required by external replication tooling
/// such as litestream), foreign keys on, and a busy timeout so a
/// concurrent reader never turns into an immediate SQLITE_BUSY.
pub fn open_primary(path: String) -> Result(Connection, Error) {
  use conn <- result.try(sqlite.open(path, sqlite.ReadWriteCreate))
  use _ <- result.try(pragmas(
    conn,
    "PRAGMA journal_mode=WAL;
     PRAGMA busy_timeout=5000;
     PRAGMA foreign_keys=ON;
     PRAGMA synchronous=NORMAL;",
  ))
  Ok(conn)
}

/// A read-only connection: replicas, and the primary's read pool.
pub fn open_read(path: String) -> Result(Connection, Error) {
  use conn <- result.try(sqlite.open(path, sqlite.ReadOnly))
  use _ <- result.try(pragmas(
    conn,
    "PRAGMA busy_timeout=5000;
     PRAGMA query_only=ON;",
  ))
  Ok(conn)
}

fn pragmas(conn: Connection, sql: String) -> Result(Nil, Error) {
  case sqlite.script(conn, sql) {
    Ok(Nil) -> Ok(Nil)
    Error(e) -> {
      sqlite.close(conn)
      Error(e)
    }
  }
}

/// The primary's per-checkout pragmas (WAL is set at boot and sticky in
/// the file; foreign keys and busy timeout are per-connection and must be
/// re-applied after every pool reset).
pub const primary_pragmas = "PRAGMA busy_timeout=5000;
   PRAGMA foreign_keys=ON;
   PRAGMA synchronous=NORMAL;"

/// Read-only serving pragmas.
pub const read_pragmas = "PRAGMA busy_timeout=5000;
   PRAGMA query_only=ON;"

/// An unsupervised read-write pool — tests and one-shot tools only.
/// Production pools are supervision-tree children (`pool.supervised` in
/// controlplane's serve functions).
pub fn start_primary_pool(
  path: String,
  size: Int,
) -> Result(pool.Pool, actor.StartError) {
  pool.start(path, sqlite.ReadWrite, primary_pragmas, size)
}

/// An unsupervised read-only pool — tests and one-shot tools only.
pub fn start_read_pool(
  path: String,
  size: Int,
) -> Result(pool.Pool, actor.StartError) {
  pool.start(path, sqlite.ReadOnly, read_pragmas, size)
}
