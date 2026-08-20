// A load balancer for the synchronicity control plane, as one Cloudflare
// Worker.
//
// The control plane is a primary that owns the only writable database and N
// replicas that hold a read-only copy of it (see ops/RUNBOOK.md). That split
// is in the service's own router — a replica answers every GET and refuses
// every write with 409 `read-only-replica` — so this Worker's whole job is to
// send each request to a node that can actually serve it, and to spread the
// reads, which are the load.
//
//   wrangler deploy, with vars:
//     PRIMARY   https://cp0.sync.example        (required)
//     REPLICAS  https://cp1.sync.example,https://cp2.sync.example
//
// Deployed at the *entry* name — the one a browser uses, and the one every
// node names as CP_ENTRY_URL so a magic link or an OAuth callback comes back
// here rather than to whichever node happened to mint it. Each node keeps its
// own CP_PUBLIC_URL for daemons to dial directly; those never come through
// here (see ATTACH_PATH below).

/// The rule, and the only one: a read-only node mounts GETs and nothing else.
///
/// Not a table of routes. The service guarantees the *shape* — every route a
/// replica mounts is a GET, so a non-GET under /api is by construction a route
/// only the primary has — and a table here would be a second copy of the
/// service's router to forget to update. Two paths need naming because they
/// are the exceptions to the shape, and both are named below.
function isRead(method) {
  return method === "GET" || method === "HEAD";
}

/// Where daemons attach. Never proxied.
///
/// A daemon signs its attach proof over the URL it dialed, and each node
/// verifies against its own CP_PUBLIC_URL — so a tunnel relayed from the entry
/// name would present a proof for the wrong URL and be refused, and the daemon
/// would retry forever against a balancer that cannot help it. Daemons find
/// each node's own name in the apex record (`_synchronicity-cp`) and dial it
/// directly; arriving here means something is misconfigured, and saying so is
/// more use than a refusal from a node.
const ATTACH_PATH = "/agent/v1/attach";

/// The one GET that must not go to a replica.
///
/// The login screen asks it before a session exists, to draw the methods this
/// deployment has configured. A replica answers "none, and the primary is
/// over there" — true of that node and wrong for this name, which *is* where
/// signing in happens.
const AUTH_METHODS_PATH = "/api/auth/methods";

/// How long a client stays pinned to the replica it was last served by.
///
/// Replication is asynchronous — `litestream restore` on the operator's own
/// interval — so two replicas are two different moments of the same database.
/// A reader bounced between them sees the zone go *backwards*: a network they
/// just created is there, gone, and there again. Pinning does not make the
/// data fresher, but it makes one reader's view move in one direction, which
/// is the difference between "a little behind" and "broken".
///
/// Minutes, not hours: long enough to cover someone working in the dashboard,
/// short enough that a node taken out of rotation drains on its own.
const STICKY_TTL_SECONDS = 300;

/// The namespaced cache the pins live in, and the synthetic origin they are
/// keyed under.
///
/// `caches.open(...)`, not `caches.default`: the default cache is the edge
/// cache for this zone, where an entry shares a namespace with real responses
/// and is keyed by a URL a client could ask for. A namespace of our own has
/// neither property — nothing but this Worker reads it, and no request can
/// name an entry in it — so the key does not have to be a URL the zone
/// serves, and it is better that it is not one.
///
/// The Cache API is per colo, so this is sticky *within a region* and nothing
/// more. A reader whose requests land in two colos gets two pins and two
/// replicas, and the guarantee degrades to what it was without this. That is
/// the honest shape of it: no coordination, no state to run, no request
/// waiting on a round trip to somewhere else. Cloudflare routes a client to a
/// colo by proximity, so in practice one reader stays in one.
const STICKY_CACHE = "control-plane-lb-sticky";
const STICKY_ORIGIN = "https://control-plane-lb.invalid";

/// How many nodes one request may be tried against.
///
/// A read that fails is retried on the next node and finally on the primary,
/// which always has the data. Bounded because a request that every node
/// refuses is a request the client should hear about, not one this Worker
/// should keep paying for.
const MAX_ATTEMPTS = 3;

/// Whether a response from a replica is worth trying elsewhere.
///
/// 5xx only, and not 4xx: a 404, a 401 or a 409 is an answer the next node
/// would repeat. 503 covers both a node that is unwell and the one failure
/// specific to this design — a browse call reaching a node whose tunnel to
/// the daemon is down, where a sibling with a live tunnel answers fine.
function worthRetrying(response) {
  return response.status >= 500;
}

function origins(env) {
  const primary = (env.PRIMARY || "").trim().replace(/\/+$/, "");
  if (!primary) throw new Error("PRIMARY is required");
  const replicas = (env.REPLICAS || "")
    .split(",")
    .map((origin) => origin.trim().replace(/\/+$/, ""))
    .filter(Boolean);
  return { primary, replicas };
}

/// The nodes to try, in order.
///
/// Writes and the sign-in flows go to the primary alone — there is one
/// writable database and the rest would refuse them. Reads start at a replica
/// chosen per request and fall back through the others to the primary, so a
/// deployment whose replicas are all down still serves, more slowly.
function route(url, method, { primary, replicas }, pinned = "") {
  if (!isRead(method)) return [primary];
  if (url.pathname === AUTH_METHODS_PATH) return [primary];
  if (url.pathname === "/auth" || url.pathname.startsWith("/auth/")) {
    // GETs here are the OAuth and magic-link flows. They are browser
    // navigations that end in a session row, which only the primary can
    // write, so they are reads in method only.
    return [primary];
  }
  if (replicas.length === 0) return [primary];
  // The pinned replica first, if this reader has one and it is still in the
  // configured set — a node removed from REPLICAS must not be reached by a
  // stale pin. Otherwise a per-request starting point: a Worker isolate is
  // not a single process and a counter in one of them balances nothing, so
  // randomness is what spreads across isolates for free.
  const start = replicas.indexOf(pinned);
  const from = start >= 0 ? start : Math.floor(Math.random() * replicas.length);
  const ordered = replicas.map((_, i) => replicas[(from + i) % replicas.length]);
  return [...ordered, primary].slice(0, MAX_ATTEMPTS);
}

/// The address this request came from, or "" when there is nothing to key on.
///
/// `cf-connecting-ip` is Cloudflare's own and cannot be spoofed by a client;
/// `x-forwarded-for` is a fallback for running this behind something else,
/// and is only ever used to *choose a replica*, never to decide anything
/// about trust. No address, no pin — the reader is balanced as before rather
/// than sharing one pin with every other anonymous request in the colo.
function clientAddress(request) {
  const direct = request.headers.get("cf-connecting-ip");
  if (direct) return direct.trim();
  const forwarded = request.headers.get("x-forwarded-for") || "";
  return forwarded.split(",")[0].trim();
}

/// The cache entry one reader's pin lives at.
///
/// Hashed rather than the address itself: the key is internal to Cloudflare,
/// but a cache full of client IPs is a thing to avoid making, and a digest
/// also flattens whatever an `x-forwarded-for` might contain into something
/// that is certainly a safe path segment.
async function stickyKey(address) {
  const bytes = new TextEncoder().encode(address);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const hex = [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return new Request(`${STICKY_ORIGIN}/${hex}`, { method: "GET" });
}

/// The pin namespace, or null where there is no Cache API at all.
///
/// Never fatal, like every other step of this: a balancer that cannot open a
/// cache balances, which is what it did before any of this existed.
async function stickyCache() {
  try {
    return (await globalThis.caches?.open(STICKY_CACHE)) ?? null;
  } catch {
    return null;
  }
}

/// The replica this reader was last served by in this colo, or "".
///
/// Never fatal: a cache that is unavailable, or an entry that is missing or
/// unreadable, means this request is balanced instead of pinned. Stickiness
/// is an improvement on the answer, not a precondition for having one.
async function readPin(cache, key) {
  if (!cache) return "";
  try {
    const hit = await cache.match(key);
    return hit ? (await hit.text()).trim() : "";
  } catch {
    return "";
  }
}

/// Remembers which replica served this reader, for the next request.
///
/// Written after the response is on its way — through `waitUntil` where the
/// runtime offers it — because a reader should never wait on a cache write
/// whose only purpose is to make a *later* request more consistent.
function writePin(cache, key, origin, ctx) {
  if (!cache) return;
  const write = cache
    .put(
      key,
      new Response(origin, {
        headers: {
          "cache-control": `max-age=${STICKY_TTL_SECONDS}`,
          "content-type": "text/plain",
        },
      }),
    )
    .catch(() => {});
  if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(write);
}

/// The request as the chosen node should see it.
///
/// The path, query, method, headers and body travel unchanged; only the origin
/// moves. `x-forwarded-proto` is set because the node uses it to decide
/// whether to mark the session cookie `Secure`, and behind a balancer it can
/// no longer see the scheme the browser used.
///
/// `duplex: "half"` is required by the fetch specification whenever the body
/// is a stream, and a request body always is here. Workers accept a Request
/// built without it; Node throws, which is how the tests found this — and the
/// throw would have surfaced in production as "could not reach any node" for
/// every write, on a balancer whose routing was perfectly correct.
function forwarded(request, url, origin) {
  const target = new URL(url.pathname + url.search, origin);
  const headers = new Headers(request.headers);
  headers.set("x-forwarded-proto", url.protocol.replace(":", ""));
  const body = request.body ?? null;
  return new Request(target, {
    method: request.method,
    headers,
    body,
    redirect: "manual",
    ...(body === null ? {} : { duplex: "half" }),
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === ATTACH_PATH) {
      return new Response(
        "This is the control plane's entry name, which balances across its " +
          "nodes. A daemon attaches to one node directly: read " +
          "_synchronicity-cp.<your base domain> and dial the URL it names.\n",
        { status: 421, headers: { "content-type": "text/plain; charset=utf-8" } },
      );
    }

    // Pinning is for reads: a write has one node whatever this says, and
    // looking one up would be a cache round trip bought for nothing. The
    // address is read first, so a request with nothing to key on does not
    // open a cache either.
    const address = isRead(request.method) ? clientAddress(request) : "";
    const cache = address ? await stickyCache() : null;
    const key = cache ? await stickyKey(address) : null;
    const pinned = key ? await readPin(cache, key) : "";

    let configured;
    try {
      configured = origins(env);
    } catch (e) {
      return new Response(`control-plane balancer is misconfigured: ${e.message}\n`, {
        status: 500,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }
    const nodes = route(url, request.method, configured, pinned);

    // A body can only be read once, so a request that carries one is sent to
    // one node and its answer stands. That costs nothing: every such request
    // is a write, and writes have exactly one node to go to anyway.
    const retryable = request.body === null || request.body === undefined;

    let last = null;
    for (const [index, origin] of nodes.entries()) {
      const isLast = index === nodes.length - 1;
      try {
        const response = await fetch(forwarded(request, url, origin));
        if (isLast || !retryable || !worthRetrying(response)) {
          // Pin what actually served, which re-pins a reader whose replica
          // was down onto the one that answered instead — a pin nobody
          // updates on failure sends every request through a dead node first
          // for as long as it stands.
          //
          // Replica membership, not "the node that is not last": with enough
          // replicas MAX_ATTEMPTS cuts the primary off the end of the list,
          // and a positional test would then quietly stop pinning whichever
          // replica happened to be last.
          if (key && origin !== pinned && configured.replicas.includes(origin)) {
            writePin(cache, key, origin, ctx);
          }
          return response;
        }
        last = response;
      } catch (e) {
        if (isLast) {
          return new Response(
            `control-plane balancer could not reach any node: ${e.message}\n`,
            { status: 502, headers: { "content-type": "text/plain; charset=utf-8" } },
          );
        }
        last = null;
      }
    }
    return last ?? new Response("control-plane balancer found no node to try\n", {
      status: 502,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  },
};

// Exported for ops/worker/lb.test.mjs, which is the only other reader.
export {
  route,
  isRead,
  worthRetrying,
  origins,
  clientAddress,
  stickyKey,
  STICKY_CACHE,
  STICKY_ORIGIN,
  ATTACH_PATH,
  AUTH_METHODS_PATH,
  STICKY_TTL_SECONDS,
};
