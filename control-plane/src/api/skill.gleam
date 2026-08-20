//// `GET /SKILL.md` — the `synch` CLI guide, served as plain Markdown.
////
//// It rides in the shipment (`priv/skill/`) rather than in the SPA bundle,
//// and it is mounted role-agnostically beside `/healthz` rather than behind
//// the product API. Both choices follow from what the document is: public
//// text about a client binary, needing no session, no database and no zone.
//// An operator or an agent pointed at *any* node of a deployment — primary,
//// replica, external — gets the same answer from the same URL, which is the
//// only property that makes the URL worth publishing.
////
//// The path is capitalized exactly as the file is, because that is the name
//// the convention gives it; nothing here matches it case-insensitively.

import gleam/http
import simplifile
import wisp.{type Request, type Response}

@external(erlang, "cp_sys_ffi", "priv_dir")
fn priv_dir(sub: String) -> Result(String, Nil)

/// The directory inside `priv` the document ships in, and its file name.
pub const dir = "skill"

pub const file = "SKILL.md"

/// The document's bytes, or `Error` when this build did not ship them.
///
/// Read per request rather than at boot: it is a few kilobytes off the local
/// filesystem, and reading it here means a shipment that dropped the file
/// answers 404 instead of failing a service that has nothing else wrong.
pub fn read() -> Result(String, Nil) {
  case priv_dir(dir) {
    Error(Nil) -> Error(Nil)
    Ok(path) ->
      case simplifile.read(path <> "/" <> file) {
        Ok(body) -> Ok(body)
        Error(_) -> Error(Nil)
      }
  }
}

/// `GET /SKILL.md`. Any other method is a 405 carrying `allow: GET`.
///
/// GET only, `HEAD` included: nothing in this service installs wisp's
/// head-to-get middleware, and one route quietly answering a method the rest
/// refuses is a worse surprise than a consistent 405.
pub fn serve(req: Request) -> Response {
  use <- wisp.require_method(req, http.Get)
  case read() {
    Error(Nil) -> wisp.not_found()
    Ok(body) ->
      wisp.response(200)
      |> wisp.set_header("content-type", "text/markdown; charset=utf-8")
      |> wisp.set_body(wisp.Text(body))
  }
}
