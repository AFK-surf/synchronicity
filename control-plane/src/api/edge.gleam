//// The routes that live below wisp, and the wrapper that puts them there.
////
//// Wisp's response body is a string, a byte tree or a file — there is no
//// streaming variant and no socket upgrade — so the two attach tunnels, the
//// file download and the file upload cannot be wisp handlers. Everything
//// else still is: this wrapper takes the paths it owns and hands every other
//// request to the wisp handler unchanged, so there is one router and not two.
////
//// **`PUT` and `DELETE` on `…/browse/file` are mounted on every role**, the
//// replica included, and they are the one non-`GET` a read-only node
//// mounts. `router.elsewhere`'s reasoning — every route a read-only node
//// mounts is a `GET` — is about the wisp table and stays true of it; this
//// pair sits below it and mutates no row (docs/CLOUD-WRITES.md §4.6): a file
//// write is relayed to the hosted replica's write tunnel and recorded here
//// nowhere, so any node with that tunnel attached serves it.

import api/agent
import api/browse_api.{type Browse}
import api/browse_file
import api/cloud_writer
import gleam/http.{Delete, Get, Put}
import gleam/http/request.{type Request as HttpRequest}
import gleam/http/response.{type Response as HttpResponse}
import mist
import store/pool.{type Pool}

/// What the two below-wisp routes need.
pub type Surface {
  Surface(browse: Browse, db: Pool, session_secret: String)
}

/// Wraps a wisp-derived handler with the routes wisp cannot serve.
pub fn handler(
  next: fn(HttpRequest(mist.Connection)) -> HttpResponse(mist.ResponseData),
  surface: Surface,
) -> fn(HttpRequest(mist.Connection)) -> HttpResponse(mist.ResponseData) {
  fn(req: HttpRequest(mist.Connection)) {
    case request.path_segments(req), req.method {
      ["agent", "v1", "attach"], Get ->
        agent.handle(
          req,
          agent.Attach(
            browse_api.registry(surface.browse),
            surface.db,
            surface.browse.attach_url,
          ),
        )
      ["api", "orgs", slug, "networks", network, "browse", "file"], Get ->
        browse_file.handle(
          req,
          surface.browse,
          surface.db,
          surface.session_secret,
          slug,
          network,
        )
      ["api", "orgs", slug, "networks", network, "browse", "file"], Put
      | ["api", "orgs", slug, "networks", network, "browse", "file"], Delete
      ->
        browse_file.write(
          req,
          surface.browse,
          surface.db,
          surface.session_secret,
          slug,
          network,
        )
      // The hosted replicas' write tunnel (docs/CLOUD-WRITES.md §5). A read
      // of the directory and a change to this node's own memory, so every
      // role mounts it, as every role mounts the browse attach.
      ["dp", "v1", "attach"], Get ->
        cloud_writer.handle(
          req,
          cloud_writer.Attach(
            browse_api.writers(surface.browse),
            browse_api.registry(surface.browse),
            surface.db,
            surface.browse.write_attach_url,
          ),
        )
      _, _ -> next(req)
    }
  }
}
