//// Shared serving path for all three DNS transports: decode, check a
//// pooled connection out (reset — pristine state, current file), answer
//// from SQLite, and shape transport errors. UDP additionally truncates
//// to the query's EDNS limit.

import dns/name.{type Name}
import dns/query
import dns/wire
import store/pool.{type Pool}

pub type Serving {
  Serving(pool: Pool, apex: Name)
}

/// One message's worth of work, transport-agnostic. `Error(Nil)` means
/// drop the datagram (unparseable beyond salvage).
pub fn handle_packet(
  serving: Serving,
  packet: BitArray,
  udp: Bool,
) -> Result(BitArray, Nil) {
  case wire.decode_query(packet) {
    Ok(q) -> {
      let answered =
        pool.with_connection(serving.pool, fn(conn) {
          query.answer(conn, serving.apex, q)
        })
      case answered {
        Ok(response) ->
          case udp {
            True -> Ok(query.fit_udp(q, response))
            False -> Ok(response)
          }
        // Pool exhausted or database unavailable: SERVFAIL beats silence.
        Error(_) -> Ok(query.error_stub(q.id, query.rcode_servfail))
      }
    }
    Error(wire.Unsupported(id)) -> Ok(query.error_stub(id, query.rcode_notimp))
    Error(wire.Malformed) -> Error(Nil)
  }
}
