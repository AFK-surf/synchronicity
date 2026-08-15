import gleam/erlang/process
import store/db
import store/migrate
import store/pool
import store/sqlite.{Int as VInt}

@external(erlang, "test_ffi", "tmp_db")
fn tmp_db() -> String

fn ready_db(path: String) -> Nil {
  let assert Ok(conn) = db.open_primary(path)
  let assert Ok(_) = migrate.migrate(conn)
  sqlite.close(conn)
}

pub fn checkout_reset_isolates_borrowers_test() {
  let path = tmp_db()
  ready_db(path)
  let assert Ok(p) = db.start_primary_pool(path, 1)
  // First borrower leaves connection-local state behind on purpose.
  let assert Ok(_) =
    pool.with_connection(p, fn(conn) {
      let assert Ok(_) = sqlite.script(conn, "CREATE TEMP TABLE leak (a);")
      Nil
    })
  // Second borrower gets the same (size-1) worker — reset must have
  // erased every trace.
  let assert Ok(rows) =
    pool.with_connection(p, fn(conn) {
      sqlite.query(
        conn,
        "SELECT count(*) FROM sqlite_temp_schema WHERE name = 'leak'",
        [],
      )
    })
  assert rows == Ok([[VInt(0)]])
}

pub fn swapped_file_visible_on_next_checkout_test() {
  // The whole replica refresh contract: replace the file via atomic
  // rename, and the next checkout serves the replacement.
  let path_a = tmp_db()
  ready_db(path_a)
  let assert Ok(conn) = db.open_primary(path_a)
  let assert Ok(_) =
    sqlite.script(
      conn,
      "CREATE TABLE marker (v); INSERT INTO marker VALUES (1);",
    )
  sqlite.close(conn)
  let assert Ok(p) = db.start_read_pool(path_a, 1)
  let assert Ok(before) =
    pool.with_connection(p, fn(conn) {
      sqlite.query(conn, "SELECT v FROM marker", [])
    })
  assert before == Ok([[VInt(1)]])
  // Build the replacement under a different name, then rename over.
  let path_b = tmp_db()
  ready_db(path_b)
  let assert Ok(conn_b) = db.open_primary(path_b)
  let assert Ok(_) =
    sqlite.script(
      conn_b,
      "CREATE TABLE marker (v); INSERT INTO marker VALUES (2);",
    )
  sqlite.close(conn_b)
  rename(path_b, path_a)
  let assert Ok(after) =
    pool.with_connection(p, fn(conn) {
      sqlite.query(conn, "SELECT v FROM marker", [])
    })
  assert after == Ok([[VInt(2)]])
}

pub fn dead_borrower_releases_write_lock_test() {
  let path = tmp_db()
  ready_db(path)
  let assert Ok(p) = db.start_primary_pool(path, 1)
  // A borrower takes the write lock and is brutally killed — no defer
  // runs. The pool's monitor must reclaim (kill) the worker so the lock
  // is released.
  let victim =
    process.spawn_unlinked(fn() {
      let assert Ok(_) =
        pool.with_connection(p, fn(conn) {
          let assert Ok(_) = sqlite.exec(conn, "BEGIN IMMEDIATE", [])
          process.sleep(60_000)
        })
      Nil
    })
  process.sleep(150)
  process.kill(victim)
  process.sleep(150)
  let assert Ok(outcome) =
    pool.with_connection(p, fn(conn) {
      let assert Ok(_) = sqlite.exec(conn, "BEGIN IMMEDIATE", [])
      sqlite.exec(conn, "ROLLBACK", [])
    })
  let assert Ok(_) = outcome
}

@external(erlang, "test_ffi", "rename")
fn rename(from: String, to: String) -> Nil
