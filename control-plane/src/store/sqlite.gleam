//// Client for the csqlite port program: SQLite in a separate OS process,
//// one process per connection, spoken to over a length-framed stdio
//// protocol. A database fault kills the port process, never the VM.
////
//// A `Connection` must be used from the process that owns it — the port
//// delivers replies to its owning process only. Sharing happens by
//// ownership transfer (`give`/`take`): `store/pool` hands whole
//// connections to borrowers this way, so call sites keep this direct
//// interface with no per-statement message copying.

import gleam/bit_array
import gleam/erlang/process
import gleam/list
import gleam/option
import gleam/result

/// An Erlang port handle (opaque, from cp_port_ffi).
pub type Port

/// Transport-level failures, distinct from SQLite's own errors.
pub type PortError {
  Closed
  Timeout
}

@external(erlang, "cp_port_ffi", "priv_path")
fn priv_path(file: String) -> Result(String, Nil)

@external(erlang, "cp_port_ffi", "open")
fn port_open(exe: String, args: List(String)) -> Result(Port, Nil)

/// The directory part of the database path, handed to csqlite as its
/// one argument so the worker can confine its filesystem access
/// (Landlock on Linux, unveil on OpenBSD) before reading any frames.
@external(erlang, "filename", "dirname")
fn dirname(path: String) -> String

@external(erlang, "cp_port_ffi", "rpc")
fn port_rpc(
  port: Port,
  payload: BitArray,
  timeout_ms: Int,
) -> Result(BitArray, PortError)

@external(erlang, "cp_port_ffi", "close")
fn ffi_close(port: Port) -> Nil

@external(erlang, "cp_port_ffi", "os_pid")
fn ffi_os_pid(port: Port) -> Int

pub opaque type Connection {
  Connection(port: Port)
}

pub type Mode {
  ReadOnly
  ReadWrite
  ReadWriteCreate
}

/// One SQLite value, in either direction.
pub type Value {
  Null
  Int(Int)
  Float(Float)
  Text(String)
  Blob(BitArray)
}

/// What a statement produced.
pub type Outcome {
  /// A statement with no result columns ran to completion.
  Done(changes: Int, last_insert_rowid: Int)
  /// A statement with result columns, fully materialized.
  Rows(columns: List(String), rows: List(List(Value)))
}

pub type Error {
  /// SQLite refused: extended result code + message.
  Sqlite(code: Int, message: String)
  /// The port process is gone (crash or close); reopen to continue.
  ConnectionClosed
  /// No reply within the deadline. The transport closes the port on
  /// timeout, so the connection is genuinely dead — the late reply can
  /// never be misread as the answer to a later query. Reopen to continue.
  RpcTimeout
  /// The reply did not parse — a bug, not an operational state.
  Protocol
  /// priv/csqlite is missing: build it (make -C csqlite).
  MissingBinary
  /// The binary is there but the OS would not start it — a process or
  /// descriptor limit is the usual reason, since every open connection owns
  /// one csqlite process for as long as it is held.
  SpawnFailed
}

const rpc_timeout_ms = 60_000

/// Opens a database, spawning one csqlite OS process to own it.
/// An empty path is refused here and by the worker: SQLite would treat
/// it as an anonymous temp database and the service would come up
/// "healthy" while discarding every write.
pub fn open(path: String, mode: Mode) -> Result(Connection, Error) {
  use Nil <- result.try(case path {
    "" -> Error(Sqlite(21, "empty database path"))
    _ -> Ok(Nil)
  })
  use exe <- result.try(result.replace_error(
    priv_path("csqlite"),
    MissingBinary,
  ))
  use port <- result.try(result.replace_error(
    port_open(exe, [dirname(path)]),
    SpawnFailed,
  ))
  let conn = Connection(port)
  let mode_byte = case mode {
    ReadOnly -> 0
    ReadWrite -> 1
    ReadWriteCreate -> 2
  }
  case rpc(conn, <<0x01, mode_byte:int-size(8), path:utf8>>) {
    Ok(<<0x81>>) -> Ok(conn)
    Ok(other) -> {
      close(conn)
      Error(expect_error(other))
    }
    Error(e) -> {
      close(conn)
      Error(e)
    }
  }
}

/// Runs exactly one statement with positional `?` parameters.
pub fn exec(
  conn: Connection,
  sql: String,
  params: List(Value),
) -> Result(Outcome, Error) {
  let sql_bits = <<sql:utf8>>
  let param_bits = bit_array.concat(list.map(params, encode_value))
  let payload = <<
    0x02,
    bit_array.byte_size(sql_bits):int-size(32),
    sql_bits:bits,
    list.length(params):int-size(16),
    param_bits:bits,
  >>
  use resp <- result.try(rpc(conn, payload))
  decode_outcome(resp)
}

/// Runs a multi-statement script (no parameters, no result rows).
///
/// SECURITY: `sql` must be a compile-time literal or assembled only from
/// literals and integers — never from user input, ever. This is the one
/// API with no parameter support; a concatenated string here is a full
/// multi-statement injection. Anything user-influenced goes through
/// `exec` with `?` placeholders.
pub fn script(conn: Connection, sql: String) -> Result(Nil, Error) {
  use resp <- result.try(rpc(conn, <<0x04, sql:utf8>>))
  case resp {
    <<0x81>> -> Ok(Nil)
    other -> Error(expect_error(other))
  }
}

/// Runs `work` inside BEGIN IMMEDIATE / COMMIT with rollback on every
/// failure path. IMMEDIATE takes the write lock up front, so a
/// read-then-write inside can never deadlock upgrading. This is the one
/// implementation of the begin/commit/rollback mechanism; `fail` lifts a
/// begin or commit failure into the caller's error type.
pub fn transaction(
  conn: Connection,
  fail: fn(Error) -> e,
  work: fn() -> Result(a, e),
) -> Result(a, e) {
  run_transaction(conn, "BEGIN IMMEDIATE", fail, work)
}

/// Read-only variant: a deferred BEGIN takes no write lock, and under WAL
/// pins one database version for every read inside.
pub fn read_transaction(
  conn: Connection,
  fail: fn(Error) -> e,
  work: fn() -> Result(a, e),
) -> Result(a, e) {
  run_transaction(conn, "BEGIN", fail, work)
}

fn run_transaction(
  conn: Connection,
  begin: String,
  fail: fn(Error) -> e,
  work: fn() -> Result(a, e),
) -> Result(a, e) {
  case exec(conn, begin, []) {
    Error(e) -> Error(fail(e))
    Ok(_) ->
      case work() {
        Ok(value) ->
          case exec(conn, "COMMIT", []) {
            Ok(_) -> Ok(value)
            Error(e) -> {
              let _ = exec(conn, "ROLLBACK", [])
              Error(fail(e))
            }
          }
        Error(err) -> {
          let _ = exec(conn, "ROLLBACK", [])
          Error(err)
        }
      }
  }
}

/// Convenience: run a statement and demand rows (Done becomes []).
pub fn query(
  conn: Connection,
  sql: String,
  params: List(Value),
) -> Result(List(List(Value)), Error) {
  case exec(conn, sql, params) {
    Ok(Rows(_, rows)) -> Ok(rows)
    Ok(Done(_, _)) -> Ok([])
    Error(e) -> Error(e)
  }
}

/// Text value with "" mapped to NULL — the optional-column convention the
/// product schema uses throughout.
pub fn text_or_null(text: String) -> Value {
  case text {
    "" -> Null
    _ -> Text(text)
  }
}

/// Text value from an Option, None as NULL.
pub fn optional_text(text: option.Option(String)) -> Value {
  case text {
    option.Some(value) -> Text(value)
    option.None -> Null
  }
}

pub fn close(conn: Connection) -> Nil {
  // Best-effort polite close; the port going away is equivalent.
  let _ = rpc(conn, <<0x03>>)
  ffi_close(conn.port)
}

/// The OS pid of the port process — test support (crash-isolation tests
/// kill it out from under the connection).
pub fn os_pid(conn: Connection) -> Int {
  ffi_os_pid(conn.port)
}

/// Discards all connection state — open transaction, temp tables — and
/// reopens the database file at the path given to `open`. Pooled
/// connections run this at checkout: a borrower can never observe a
/// previous borrower's state, and an atomically replaced database file
/// (the replica refresh contract) is picked up on next use. Per-connection
/// pragmas do not survive; the pool re-applies them after.
pub fn reset(conn: Connection) -> Result(Nil, Error) {
  use resp <- result.try(rpc(conn, <<0x05>>))
  case resp {
    <<0x81>> -> Ok(Nil)
    other -> Error(expect_error(other))
  }
}

@external(erlang, "cp_port_ffi", "give")
fn ffi_give(port: Port, to: process.Pid) -> Result(Nil, Nil)

@external(erlang, "cp_port_ffi", "take")
fn ffi_take(port: Port) -> Nil

@external(erlang, "cp_port_ffi", "kill")
fn ffi_kill(port: Port) -> Nil

/// Transfers ownership of the connection to another process (pooling).
/// Only the current owner may give; the receiver must `take` before use.
pub fn give(conn: Connection, to: process.Pid) -> Result(Nil, Nil) {
  ffi_give(conn.port, to)
}

/// Completes an ownership transfer on the receiving side.
pub fn take(conn: Connection) -> Nil {
  ffi_take(conn.port)
}

/// Force-closes a connection from any process — for reclaiming workers
/// whose borrower died. The worker exits; SQLite discards any open
/// transaction.
pub fn kill(conn: Connection) -> Nil {
  ffi_kill(conn.port)
}

fn rpc(conn: Connection, payload: BitArray) -> Result(BitArray, Error) {
  case port_rpc(conn.port, payload, rpc_timeout_ms) {
    Ok(bin) -> Ok(bin)
    Error(Closed) -> Error(ConnectionClosed)
    Error(Timeout) -> Error(RpcTimeout)
  }
}

fn encode_value(value: Value) -> BitArray {
  case value {
    Null -> <<0x00>>
    Int(i) -> <<0x01, i:int-size(64)>>
    Float(f) -> <<0x02, f:float-size(64)>>
    Text(s) -> {
      let bits = <<s:utf8>>
      <<0x03, bit_array.byte_size(bits):int-size(32), bits:bits>>
    }
    Blob(b) -> <<0x04, bit_array.byte_size(b):int-size(32), b:bits>>
  }
}

fn decode_outcome(resp: BitArray) -> Result(Outcome, Error) {
  case resp {
    <<0x82, changes:int-signed-size(64), rowid:int-signed-size(64)>> ->
      Ok(Done(changes, rowid))
    <<0x83, ncols:int-size(16), rest:bits>> -> {
      use #(columns, rest) <- result.try(decode_columns(rest, ncols, []))
      case rest {
        <<nrows:int-size(32), rest:bits>> -> {
          use rows <- result.try(decode_rows(rest, nrows, ncols, []))
          Ok(Rows(columns, rows))
        }
        _ -> Error(Protocol)
      }
    }
    other -> Error(expect_error(other))
  }
}

fn expect_error(resp: BitArray) -> Error {
  case resp {
    <<0x84, code:int-signed-size(32), len:int-size(32), msg:bytes-size(len)>> ->
      case bit_array.to_string(msg) {
        Ok(text) -> Sqlite(code, text)
        Error(_) -> Protocol
      }
    _ -> Protocol
  }
}

fn decode_columns(
  bits: BitArray,
  remaining: Int,
  acc: List(String),
) -> Result(#(List(String), BitArray), Error) {
  case remaining {
    0 -> Ok(#(list.reverse(acc), bits))
    _ ->
      case bits {
        <<len:int-size(32), name:bytes-size(len), rest:bits>> ->
          case bit_array.to_string(name) {
            Ok(text) -> decode_columns(rest, remaining - 1, [text, ..acc])
            Error(_) -> Error(Protocol)
          }
        _ -> Error(Protocol)
      }
  }
}

fn decode_rows(
  bits: BitArray,
  remaining: Int,
  ncols: Int,
  acc: List(List(Value)),
) -> Result(List(List(Value)), Error) {
  case remaining {
    0 ->
      case bits {
        <<>> -> Ok(list.reverse(acc))
        _ -> Error(Protocol)
      }
    _ -> {
      use #(row, rest) <- result.try(decode_values(bits, ncols, []))
      decode_rows(rest, remaining - 1, ncols, [row, ..acc])
    }
  }
}

fn decode_values(
  bits: BitArray,
  remaining: Int,
  acc: List(Value),
) -> Result(#(List(Value), BitArray), Error) {
  case remaining {
    0 -> Ok(#(list.reverse(acc), bits))
    _ -> {
      use #(value, rest) <- result.try(decode_value(bits))
      decode_values(rest, remaining - 1, [value, ..acc])
    }
  }
}

fn decode_value(bits: BitArray) -> Result(#(Value, BitArray), Error) {
  case bits {
    <<0x00, rest:bits>> -> Ok(#(Null, rest))
    <<0x01, i:int-signed-size(64), rest:bits>> -> Ok(#(Int(i), rest))
    <<0x02, f:float-size(64), rest:bits>> -> Ok(#(Float(f), rest))
    <<0x03, len:int-size(32), data:bytes-size(len), rest:bits>> ->
      case bit_array.to_string(data) {
        Ok(text) -> Ok(#(Text(text), rest))
        Error(_) -> Error(Protocol)
      }
    <<0x04, len:int-size(32), data:bytes-size(len), rest:bits>> ->
      Ok(#(Blob(data), rest))
    _ -> Error(Protocol)
  }
}
