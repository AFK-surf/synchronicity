// Tests for the control-plane balancer (lb.js).
//
// Two levels. The first asserts *which* node each request is sent to, over
// every route the service mounts — that is the whole of what this Worker
// decides, and getting it wrong is silent: a write sent to a replica comes
// back 409 and a login sent to one comes back with no session. The second
// runs the Worker's own `fetch` against two stub origins, so the forwarding,
// the retry and the refusals are exercised as written rather than reasoned
// about.
//
//   node --test ops/worker/lb.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import worker from "./lb.js";
import {
  route,
  clientAddress,
  ATTACH_PATH,
  AUTH_METHODS_PATH,
  STICKY_TTL_SECONDS,
} from "./lb.js";

const PRIMARY = "https://cp0.sync.test";
const REPLICAS = ["https://cp1.sync.test", "https://cp2.sync.test"];
const ENV = { PRIMARY, REPLICAS: REPLICAS.join(",") };
const NODES = { primary: PRIMARY, replicas: REPLICAS };

const first = (path, method = "GET") =>
  route(new URL(`https://sync.test${path}`), method, NODES)[0];

/// Every route a replica mounts, taken from the service's read table
/// (src/api/router.gleam). These must reach a replica or the reads are not
/// spread at all, which is the only reason this Worker exists.
const READS = [
  "/api/me",
  "/api/invites/preview?token=x",
  "/api/orgs/acme",
  "/api/orgs/acme/members",
  "/api/orgs/acme/audit",
  "/api/orgs/acme/oidc",
  "/api/orgs/acme/networks",
  "/api/orgs/acme/networks/prod",
  "/api/orgs/acme/devices",
  "/api/orgs/acme/networks/prod/browse",
  "/api/orgs/acme/networks/prod/delegations",
  "/api/orgs/acme/networks/prod/browse/ls?space=media&path=",
  "/api/orgs/acme/networks/prod/browse/stat?space=media&path=a",
  "/api/orgs/acme/networks/prod/browse/file?space=media&path=a",
];

/// Every mutation, and the sign-in flows that mint the session the rest are
/// gated on. There is one writable database; these have one node.
const WRITES = [
  ["POST", "/api/orgs"],
  ["DELETE", "/api/orgs/acme"],
  ["PATCH", "/api/orgs/acme/members/u1"],
  ["POST", "/api/orgs/acme/transfer"],
  ["POST", "/api/orgs/acme/invites"],
  ["POST", "/api/invites/accept"],
  ["PUT", "/api/orgs/acme/oidc"],
  ["POST", "/api/orgs/acme/networks"],
  ["DELETE", "/api/orgs/acme/networks/prod"],
  ["PUT", "/api/orgs/acme/networks/prod/devices/d1"],
  ["PUT", "/api/orgs/acme/networks/prod/browse/enabled"],
  ["POST", "/api/orgs/acme/devices"],
  ["PATCH", "/api/orgs/acme/devices/d1"],
  ["POST", "/api/orgs/acme/devices/d1/keys"],
  ["POST", "/api/orgs/acme/devices/d1/keys/k1/revoke"],
  ["POST", "/api/logout"],
  ["POST", "/auth/magic"],
  // Browser navigations that end in a session row, so reads in method only.
  ["GET", "/auth/start/google"],
  ["GET", "/auth/callback/google?code=x"],
  ["GET", "/auth/magic/redeem?token=x"],
  ["GET", "/auth/oidc/acme"],
];

test("every read starts at a replica", () => {
  for (const path of READS) {
    assert.ok(
      REPLICAS.includes(first(path)),
      `${path} should start at a replica, got ${first(path)}`,
    );
  }
});

test("every write goes to the primary, and only there", () => {
  for (const [method, path] of WRITES) {
    const nodes = route(new URL(`https://sync.test${path}`), method, NODES);
    assert.deepEqual(nodes, [PRIMARY], `${method} ${path}`);
  }
});

test("the login screen's own question goes to the primary", () => {
  // A replica answers it truthfully about itself — no method, and the primary
  // is elsewhere — which is the wrong answer for the name that *is* where
  // signing in happens.
  assert.deepEqual(
    route(new URL(`https://sync.test${AUTH_METHODS_PATH}`), "GET", NODES),
    [PRIMARY],
  );
});

test("a read falls back through the replicas to the primary", () => {
  const nodes = route(new URL("https://sync.test/api/me"), "GET", NODES);
  assert.equal(nodes.length, 3);
  assert.equal(nodes.at(-1), PRIMARY, "the primary always has the data");
  assert.equal(new Set(nodes).size, 3, "no node is tried twice");
});

test("with no replicas configured everything goes to the primary", () => {
  const solo = { primary: PRIMARY, replicas: [] };
  assert.deepEqual(route(new URL("https://sync.test/api/me"), "GET", solo), [
    PRIMARY,
  ]);
});

test("reads are spread across the replicas", () => {
  const seen = new Set();
  for (let i = 0; i < 200; i++) seen.add(first("/api/me"));
  assert.deepEqual([...seen].sort(), [...REPLICAS].sort());
});

test("the SPA and the role-agnostic routes are served by any node", () => {
  for (const path of ["/", "/o/acme", "/login", "/SKILL.md", "/healthz"]) {
    assert.ok(REPLICAS.includes(first(path)), path);
  }
});

// -- the handler itself ------------------------------------------------------

/// Records where each attempt went, and answers as told.
function stubFetch(answers) {
  const seen = [];
  const original = globalThis.fetch;
  globalThis.fetch = async (request) => {
    seen.push(request);
    const answer = answers[seen.length - 1] ?? answers.at(-1);
    if (answer instanceof Error) throw answer;
    return answer();
  };
  return { seen, restore: () => (globalThis.fetch = original) };
}

const ok = (body = "ok") => () => new Response(body, { status: 200 });
const unwell = () => new Response("nope", { status: 503 });

test("the attach path is refused rather than proxied", async () => {
  const stub = stubFetch([ok()]);
  try {
    const response = await worker.fetch(
      new Request(`https://sync.test${ATTACH_PATH}`),
      ENV,
    );
    // A proof is signed over the URL the daemon dialed and each node verifies
    // against its own, so relaying one from here could only ever be refused.
    assert.equal(response.status, 421);
    assert.match(await response.text(), /_synchronicity-cp/);
    assert.equal(stub.seen.length, 0, "nothing was proxied");
  } finally {
    stub.restore();
  }
});

test("a forwarded request keeps its path, query, method and headers", async () => {
  const stub = stubFetch([ok()]);
  try {
    await worker.fetch(
      new Request("https://sync.test/api/orgs/acme/networks?x=1", {
        headers: { cookie: "cp_session=abc", "x-csrf": "t" },
      }),
      ENV,
    );
    const [sent] = stub.seen;
    const url = new URL(sent.url);
    assert.ok(REPLICAS.includes(url.origin));
    assert.equal(url.pathname, "/api/orgs/acme/networks");
    assert.equal(url.search, "?x=1");
    assert.equal(sent.headers.get("cookie"), "cp_session=abc");
    assert.equal(sent.headers.get("x-csrf"), "t");
    // The node cannot see the browser's scheme from behind a balancer, and it
    // decides whether the session cookie is `Secure` on exactly this.
    assert.equal(sent.headers.get("x-forwarded-proto"), "https");
  } finally {
    stub.restore();
  }
});

test("a read is retried past a node that is unwell", async () => {
  const stub = stubFetch([unwell, ok("second")]);
  try {
    const response = await worker.fetch(
      new Request("https://sync.test/api/me"),
      ENV,
    );
    assert.equal(response.status, 200);
    assert.equal(await response.text(), "second");
    assert.equal(stub.seen.length, 2);
    assert.notEqual(
      new URL(stub.seen[0].url).origin,
      new URL(stub.seen[1].url).origin,
    );
  } finally {
    stub.restore();
  }
});

test("a read is retried past a node that cannot be reached at all", async () => {
  const stub = stubFetch([new Error("connection refused"), ok("second")]);
  try {
    const response = await worker.fetch(
      new Request("https://sync.test/api/me"),
      ENV,
    );
    assert.equal(response.status, 200);
    assert.equal(stub.seen.length, 2);
  } finally {
    stub.restore();
  }
});

test("a 4xx stands: the next node would only repeat it", async () => {
  const stub = stubFetch([() => new Response("no", { status: 404 })]);
  try {
    const response = await worker.fetch(
      new Request("https://sync.test/api/orgs/nope"),
      ENV,
    );
    assert.equal(response.status, 404);
    assert.equal(stub.seen.length, 1);
  } finally {
    stub.restore();
  }
});

test("a write is sent once, to the primary, and its answer stands", async () => {
  const stub = stubFetch([unwell]);
  try {
    const response = await worker.fetch(
      new Request("https://sync.test/api/orgs", {
        method: "POST",
        body: JSON.stringify({ slug: "acme" }),
        headers: { "content-type": "application/json" },
      }),
      ENV,
    );
    // Not retried: a body reads once, and a write has one node regardless.
    assert.equal(response.status, 503);
    assert.equal(stub.seen.length, 1);
    assert.equal(new URL(stub.seen[0].url).origin, PRIMARY);
  } finally {
    stub.restore();
  }
});

test("every node failing is a 502 that says so", async () => {
  const stub = stubFetch([new Error("down"), new Error("down"), new Error("down")]);
  try {
    const response = await worker.fetch(
      new Request("https://sync.test/api/me"),
      ENV,
    );
    assert.equal(response.status, 502);
    assert.match(await response.text(), /could not reach any node/);
  } finally {
    stub.restore();
  }
});

test("a missing PRIMARY is a configuration error, not a crash", async () => {
  const response = await worker.fetch(
    new Request("https://sync.test/api/me"),
    { REPLICAS: REPLICAS.join(",") },
  );
  assert.equal(response.status, 500);
  assert.match(await response.text(), /misconfigured/);
});

test("trailing slashes in configuration do not become double slashes", async () => {
  const stub = stubFetch([ok()]);
  try {
    await worker.fetch(new Request("https://sync.test/api/me"), {
      PRIMARY: `${PRIMARY}/`,
      REPLICAS: `${REPLICAS[0]}/ , ${REPLICAS[1]}//`,
    });
    assert.equal(new URL(stub.seen[0].url).pathname, "/api/me");
  } finally {
    stub.restore();
  }
});


// -- per-region stickiness ---------------------------------------------------
//
// Replication is asynchronous, so two replicas are two moments of the same
// database. A reader bounced between them watches the zone move backwards.
// These pin that down — and the degradation too, because the Cache API is per
// colo and a reader who moves between them is balanced again.

/// The Cache API, as one colo has it: a map, and the option of not being
/// there at all.
function stubCache(entries = new Map()) {
  const original = globalThis.caches;
  globalThis.caches = {
    default: {
      async match(key) {
        const hit = entries.get(key.url);
        return hit === undefined ? undefined : new Response(hit);
      },
      async put(key, response) {
        entries.set(key.url, await response.text());
      },
    },
  };
  return { entries, restore: () => (globalThis.caches = original) };
}

const FROM = (ip) => ({ headers: { "cf-connecting-ip": ip } });

/// Lets the deferred cache write land. Without a `waitUntil` to hand it to,
/// `writePin` leaves the put running as a microtask and the response goes out
/// ahead of it — which is the point of it, so a test that wants to see the
/// entry has to wait where a reader does not.
const settled = () => new Promise((resolve) => setTimeout(resolve, 0));

test("a reader is served by one replica for the whole of a session", async () => {
  const cache = stubCache();
  const stub = stubFetch([ok()]);
  try {
    const served = new Set();
    for (let i = 0; i < 30; i++) {
      await worker.fetch(
        new Request("https://sync.test/api/me", FROM("203.0.113.7")),
        ENV,
      );
      await settled();
      served.add(new URL(stub.seen.at(-1).url).origin);
    }
    assert.equal(
      served.size,
      1,
      `one replica for one reader, got ${[...served]}`,
    );
    assert.ok(REPLICAS.includes([...served][0]));
  } finally {
    stub.restore();
    cache.restore();
  }
});

test("two readers are not pinned to the same replica by construction", async () => {
  // Not an assertion that they differ — one of two is a coin toss — but that
  // each is pinned independently, so the set over many addresses is both.
  const cache = stubCache();
  const stub = stubFetch([ok()]);
  try {
    const served = new Set();
    for (let i = 0; i < 40; i++) {
      await worker.fetch(
        new Request("https://sync.test/api/me", FROM(`198.51.100.${i}`)),
        ENV,
      );
      await settled();
      served.add(new URL(stub.seen.at(-1).url).origin);
    }
    assert.deepEqual([...served].sort(), [...REPLICAS].sort());
  } finally {
    stub.restore();
    cache.restore();
  }
});

test("the pin is what gets cached, with a TTL", async () => {
  const cache = stubCache();
  const stub = stubFetch([ok()]);
  try {
    await worker.fetch(
      new Request("https://sync.test/api/me", FROM("203.0.113.9")),
      ENV,
    );
    await settled();
    const [[key, value]] = [...cache.entries];
    // Keyed on a digest of the address, not the address: this cache should
    // not be a list of who has been here.
    // Under the request's own origin: caches.default refuses a key outside
    // the Worker's zone, and a refused put here is swallowed — so a synthetic
    // hostname would be stickiness that silently never happens.
    assert.match(key, /^https:\/\/sync\.test\/__cp-lb-sticky\/[0-9a-f]{64}$/);
    assert.ok(!key.includes("203.0.113.9"));
    assert.ok(REPLICAS.includes(value));
    assert.equal(STICKY_TTL_SECONDS, 300);
  } finally {
    stub.restore();
    cache.restore();
  }
});

test("a reader whose replica goes down is re-pinned to the one that answered", async () => {
  const cache = stubCache();
  let stub = stubFetch([ok()]);
  let firstChoice;
  try {
    await worker.fetch(new Request("https://sync.test/api/me", FROM("203.0.113.11")), ENV);
    await settled();
    firstChoice = new URL(stub.seen[0].url).origin;
  } finally {
    stub.restore();
  }

  stub = stubFetch([unwell, ok("from the sibling")]);
  try {
    const response = await worker.fetch(
      new Request("https://sync.test/api/me", FROM("203.0.113.11")),
      ENV,
    );
    assert.equal(await response.text(), "from the sibling");
    assert.equal(new URL(stub.seen[0].url).origin, firstChoice, "the pin was tried");
    const sibling = new URL(stub.seen[1].url).origin;
    assert.notEqual(sibling, firstChoice);
    await settled();
    // A pin nobody updates on failure sends every later request through the
    // dead node first, for as long as it stands.
    assert.equal([...cache.entries.values()][0], sibling);
  } finally {
    stub.restore();
    cache.restore();
  }
});

test("a stale pin naming a node no longer configured is ignored", async () => {
  const cache = stubCache();
  const stub = stubFetch([ok()]);
  try {
    await worker.fetch(new Request("https://sync.test/api/me", FROM("203.0.113.13")), ENV);
    await settled();
    const [key] = [...cache.entries.keys()];
    cache.entries.set(key, "https://cp9.sync.test"); // removed from REPLICAS
    await worker.fetch(new Request("https://sync.test/api/me", FROM("203.0.113.13")), ENV);
    assert.ok(REPLICAS.includes(new URL(stub.seen.at(-1).url).origin));
  } finally {
    stub.restore();
    cache.restore();
  }
});

test("the primary is never pinned: it is the fallback, not a replica", async () => {
  const cache = stubCache();
  const stub = stubFetch([unwell, unwell, ok("primary")]);
  try {
    await worker.fetch(new Request("https://sync.test/api/me", FROM("203.0.113.15")), ENV);
    await settled();
    assert.equal(new URL(stub.seen.at(-1).url).origin, PRIMARY);
    assert.equal(cache.entries.size, 0);
  } finally {
    stub.restore();
    cache.restore();
  }
});

test("writes are not pinned and cost no cache lookup", async () => {
  const cache = stubCache();
  const stub = stubFetch([ok()]);
  try {
    await worker.fetch(
      new Request("https://sync.test/api/orgs", {
        method: "POST",
        body: "{}",
        headers: { "cf-connecting-ip": "203.0.113.17" },
      }),
      ENV,
    );
    await settled();
    assert.equal(new URL(stub.seen[0].url).origin, PRIMARY);
    assert.equal(cache.entries.size, 0, "a write has one node whatever a pin says");
  } finally {
    stub.restore();
    cache.restore();
  }
});

test("a request with no address to key on is balanced, not pinned", async () => {
  const cache = stubCache();
  const stub = stubFetch([ok()]);
  try {
    const served = new Set();
    for (let i = 0; i < 60; i++) {
      await worker.fetch(new Request("https://sync.test/api/me"), ENV);
      served.add(new URL(stub.seen.at(-1).url).origin);
    }
    await settled();
    // Everyone sharing one pin would be worse than none: it would put the
    // whole colo's anonymous traffic on one replica.
    assert.deepEqual([...served].sort(), [...REPLICAS].sort());
    assert.equal(cache.entries.size, 0);
  } finally {
    stub.restore();
    cache.restore();
  }
});

test("no Cache API at all is a balancer that still works", async () => {
  // Which is also how every test above this section runs.
  const original = globalThis.caches;
  globalThis.caches = undefined;
  const stub = stubFetch([ok("served")]);
  try {
    const response = await worker.fetch(
      new Request("https://sync.test/api/me", FROM("203.0.113.19")),
      ENV,
    );
    assert.equal(response.status, 200);
    assert.equal(await response.text(), "served");
  } finally {
    stub.restore();
    globalThis.caches = original;
  }
});

test("the cache write does not hold the response up", async () => {
  const cache = stubCache();
  const stub = stubFetch([ok()]);
  const deferred = [];
  try {
    await worker.fetch(
      new Request("https://sync.test/api/me", FROM("203.0.113.21")),
      ENV,
      { waitUntil: (promise) => deferred.push(promise) },
    );
    // Handed to the runtime rather than awaited: a reader should not wait on
    // a write whose only purpose is to make a *later* request consistent.
    assert.equal(deferred.length, 1);
    await Promise.all(deferred);
    assert.equal(cache.entries.size, 1);
  } finally {
    stub.restore();
    cache.restore();
  }
});

test("cf-connecting-ip wins over a forwarded header a client can set", () => {
  assert.equal(
    clientAddress(
      new Request("https://sync.test/", {
        headers: {
          "cf-connecting-ip": "203.0.113.1",
          "x-forwarded-for": "198.51.100.1, 203.0.113.9",
        },
      }),
    ),
    "203.0.113.1",
  );
  // The fallback takes the first hop, for running this behind something else.
  assert.equal(
    clientAddress(
      new Request("https://sync.test/", {
        headers: { "x-forwarded-for": "198.51.100.1, 203.0.113.9" },
      }),
    ),
    "198.51.100.1",
  );
  assert.equal(clientAddress(new Request("https://sync.test/")), "");
});
