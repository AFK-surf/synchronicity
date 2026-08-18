//// The two routes that live below wisp, and the wrapper that puts them
//// there.
////
//// Wisp's response body is a string, a byte tree or a file — there is no
//// streaming variant and no socket upgrade — so the attach tunnel and the
//// file download cannot be wisp handlers. Everything else still is: this
//// wrapper takes the two paths it owns and hands every other request to the
//// wisp handler unchanged, so there is one router and not two.

import api/agent
import api/browse_api.{type Browse}
import api/browse_file
import gleam/http.{Get}
import gleam/http/request.{type Request as HttpRequest}
import gleam/http/response.{type Response as HttpResponse}
import gleam/option.{type Option, None, Some}
import mist
import store/pool.{type Pool}

/// What the two below-wisp routes need. Absent with `CP_BROWSE` off, which is
/// how the whole surface disappears: not a flag consulted per request, but
/// routes that are not mounted.
pub type Surface {
  Surface(browse: Browse, db: Pool, session_secret: String)
}

/// Wraps a wisp-derived handler with the routes wisp cannot serve.
pub fn handler(
  next: fn(HttpRequest(mist.Connection)) -> HttpResponse(mist.ResponseData),
  surface: Option(Surface),
) -> fn(HttpRequest(mist.Connection)) -> HttpResponse(mist.ResponseData) {
  fn(req: HttpRequest(mist.Connection)) {
    case surface, request.path_segments(req), req.method {
      Some(surface), ["agent", "v1", "attach"], Get ->
        agent.handle(
          req,
          agent.Attach(
            browse_api.registry(surface.browse),
            surface.db,
            surface.browse.attach_url,
          ),
        )
      Some(surface),
        ["api", "orgs", slug, "networks", network, "browse", "file"],
        Get
      ->
        browse_file.handle(
          req,
          surface.browse,
          surface.db,
          surface.session_secret,
          slug,
          network,
        )
      _, _, _ -> next(req)
    }
  }
}

/// The surface a deployment with browsing on exposes, or `None`.
pub fn surface(
  browse: Option(Browse),
  db: Pool,
  secret: String,
) -> Option(Surface) {
  case browse {
    Some(browse) -> Some(Surface(browse, db, secret))
    None -> None
  }
}
