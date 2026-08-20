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
import { route, ATTACH_PATH, AUTH_METHODS_PATH } from "./lb.js";

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
