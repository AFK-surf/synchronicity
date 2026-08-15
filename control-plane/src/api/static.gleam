//// Serves the built SPA (web/dist, copied to priv/web at deploy time).
//// Anything that is not an API, auth, or DNS route falls back to
//// index.html — client-side routing owns those paths.

import gleam/http
import gleam/option.{None}
import wisp.{type Request, type Response}

@external(erlang, "cp_sys_ffi", "priv_dir")
fn priv_dir(sub: String) -> Result(String, Nil)

pub fn serve(req: Request, next: fn() -> Response) -> Response {
  case priv_dir("web") {
    Error(Nil) -> next()
    Ok(dir) -> {
      use <- wisp.serve_static(req, under: "/", from: dir)
      case req.method {
        http.Get -> spa_fallback(dir)
        _ -> next()
      }
    }
  }
}

fn spa_fallback(dir: String) -> Response {
  wisp.response(200)
  |> wisp.set_header("content-type", "text/html; charset=utf-8")
  |> wisp.set_body(wisp.File(dir <> "/index.html", 0, None))
}
