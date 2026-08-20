//// The read half of the product API's context.
////
//// A separate type rather than a bare `Pool` because it is the line the
//// replica surface is drawn on: a handler that takes this is one a node
//// holding a read-only copy of the database can mount, and a handler that
//// takes `AuthContext` is one that needs a zone key, a mailer or an OAuth
//// client — and therefore is not.

import api/middleware.{error_json}
import store/pool.{type Pool}
import store/sqlite.{type Connection}
import wisp.{type Response}

/// What a read handler needs, and the whole of it.
pub type Reads {
  Reads(pool: Pool)
}

/// Runs `next` with a pooled, freshly reset connection — the read-only twin
/// of `auth_api.with_db`, and the same contract: the pool returns the worker
/// on every exit path, panics included.
pub fn with_db(reads: Reads, next: fn(Connection) -> Response) -> Response {
  case pool.with_connection(reads.pool, next) {
    Ok(response) -> response
    Error(_) -> error_json(500, "internal", "database unavailable")
  }
}
