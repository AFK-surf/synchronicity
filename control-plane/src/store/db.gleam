//// Connection lifecycle: which pragmas a connection runs before anyone
//// else touches it, and which modes the two roles are allowed.

import gleam/result
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
