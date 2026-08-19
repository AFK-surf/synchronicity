# Chain-of-trust audit — DNSSEC and Sigstore Rekor, second pass

Date: 2026-08-19. Scope: the same two coupled chains of trust as
`AUDIT-CHAIN-OF-TRUST-2026-08.md` — DNSSEC membership and Sigstore Rekor v2
zone-key transparency — across the client data plane (`crates/synch-net`,
`crates/synch-engine`), the monitor (`crates/synch-monitor`) and the Gleam
control plane (`control-plane/`).

Baseline: `cargo test --workspace --all-targets`, `cargo clippy --workspace
--all-targets -D warnings`, `cargo fmt --all --check` and `gleam test` (204
tests) all pass on `ce7d75b`. Nothing here was a build failure.

Method: seven independent adversarial reviews from different angles — client
enforcement, offline verifier and trust roots, monitor and the tier coupling,
publisher-side byte formats, external-mode lifecycle, architecture and
complexity, and the verification apparatus itself — followed by two independent
false-positive challenge passes whose only goal was to kill findings. 62
findings were raised; **10 were killed outright and 21 downgraded**. Several
kills were correct and are recorded below, because a finding killed on evidence
is worth more than one nobody argued with.

## What this pass is actually about

The instruction that produced it was: *there have been multiple audit passes on
this; the fact that it still does not converge hints at deeper issues.* That is
right, and the deepest one is nameable.

**The delegation half of the chain walk had no test in the workspace at all.**
Hand mutation testing across `chain.rs` deleted `covers` from
`verify_dnskey_set_under` — the check that a link's DNSKEY RRset is proved by a
DS its parent signed, which is the step that makes a ladder a ladder — and
`cargo test --workspace` stayed green. So did replacing the SHA-256 digest
comparison with `true`. So did deleting the SHA-384 arm. So did the flag rule
inside `verify_rrset`, which is the only thing standing between RFC 5011's
"MUST NOT be used" and a revoked key signing a child's DS.

The reason is structural, not an oversight in one test file: **every chain
fixture that reached `authorize` was either self-anchored, so the descent loop
ran zero times, or built by the simulator, where the DS and the key set it
covers are derived from the same key and cannot disagree.** The harness could
not express the forgery the check exists to refuse. A reviewer reading the code
sees a correct check; a reviewer running the suite learns nothing; and the next
pass finds the next thing in the same neighbourhood.

Three more instances of the same shape turned up: the monitor's watch-coverage
guard (added by the *previous* audit) could be deleted whole with the suite
green, `Authorized`'s `#[non_exhaustive]` had been verified once by hand and by
nothing since, and `rekor/chain.gleam`'s 800 lines — an entire second
implementation of the chain the client verifies — had never had a single byte
read by the Rust validator.

So the theme is: **the checks were mostly right and the apparatus holding them
still was mostly absent.** The fixes below are weighted accordingly. Every
behavioural change carries a test that was verified to fail without it.

---

## High

### H1. The control-plane attach record is trusted on DNSSEC alone

`crates/synch-net/src/dns.rs:1053-1101`. `control_plane()` gates the membership
answer, derives the apex from it, then does a second validated lookup of
`_synchronicity-cp.<apex>` and returns its `url=`. Nothing compared that
answer's signer, or the key that verified its RRSIG, to the gated key. The
comment beside it stated the opposite as the reason the `url=` may be opaque —
*"That is acceptable because the zone key that published it is gated above"* —
and the comment fifteen lines up named the exact attack it believed was closed.

The attacker is the one the whole Rekor design exists for: a compromised or
coerced parent substituting a DS, which lets them add `K_evil` to the apex
DNSKEY RRset so everything it signs validates. They then serve the operator's
*genuine* membership RRset and RRSIG — public data — so the gate passes on the
logged key, and sign only the attach record with `K_evil`. The daemon attaches
to their control plane and serves `Ls`/`Stat`/`Resolve`/`Read` over every
exposed space (`crates/synch-engine/src/cloud/attach.rs:187-315`). `K_evil`
never enters the log, so no monitor sees anything.

**Fixed**: under `Require`, the attach answer is gated on its own signer. Both
answers are inside one signing zone by construction — `apex_of` forces
`signing_zone ⊇ apex ⊇ domain`, and the membership name is *below* the apex, so
there is no zone cut at the apex — and the proof covers the whole chain-proven
RRset rather than one key, so an ordinary RFC 6781 rollover reads the same
proof twice and passes twice. Covered by
`discovery_refuses_an_attach_record_signed_by_an_unlogged_key`, with a positive
control, and it needed a new sim knob: the harness could sign every RRset with
one key and so could not express the split.

### H2. Every `poke` forked a permanent second sweep timer

`control-plane/src/jobs/provider_sync.gleam`. `Msg` had one constructor, so the
reconciler could not tell a product mutation's poke from its own sweep timer
firing, and `handle` re-armed unconditionally. Each poke therefore started an
additional 300 s timer chain that was never cancelled — the steady-state sweep
rate became one pass per interval *per poke ever received*. Any authenticated
org member can drive that with a loop of device edits; each pass opens a fresh
SQLite writer and a csqlite port worker, and once arrival exceeds service the
mailbox grows monotonically while every queued tick arms another timer. A
revocation's own poke queues behind that backlog. The initialiser's comment
identifies exactly this hazard for itself and misses it for `poke`.

**Fixed**: a poke is its own message and re-arms nothing. Covered by
`a_poke_does_not_fork_a_second_sweep_timer_test`, which drives a real
supervisor.

### H3. `poke` raised instead of falling on the floor, and the revoking request 500'd

Same file. `process.send` on a `NamedSubject` is `let assert Ok(pid) =
named(name) as "Sending to unregistered name"` — it raises. The doc said
"falling on the floor is fine". Two windows reach it: boot, where
`serve_external` added the HTTP listener *before* the reconciler, and any
restart of the reconciler.

It fires inside `zone_mutation`, **after** the transaction has committed and
**before** the response is built. So an admin revoking a compromised device key
got a 500; `devices_api.revoke_key` never saw a 200 and therefore never called
`agent.drop_key`, leaving the revoked key's browse tunnel answering; and the
retry returned `404 "no such live key"` because the row was already revoked.

**Fixed**: the send is checked, and the listener starts after the jobs. Covered
by `a_poke_at_no_reconciler_is_a_no_op_test`.

### H4. One provider write permanently disabled the reconciler's delete authority

`control-plane/src/provider/diff.gleam`. Deletes require the ownership marker to
be present and byte-equal, and **both refusal arms return before `create` is
computed** — so a reconciler that lost its marker could never re-assert one.
Whoever holds the provider API token overwrites `_synchronicity-owner.<apex>`
with one write, or deletes it and adds any TXT below the apex with two, and
every pass afterwards refuses: no create, no replace, and above all no delete.
Every future revocation is dead. The module's own doc calls this authority "the
only thing standing between an API token and a forged record".

Downgraded from the reviewer's HIGH on two counts the challenge pass got right:
it is *visible* (`provider_in_sync` goes false and `provider_last_error` carries
the conflict text), and a token holder can already rewrite a forged record after
every pass. What it adds is turning "the attacker must keep writing" into "the
attacker writes once and the documented compensating control is dead", and
killing the operator's own revocations with it.

**Fixed**: a deployment that has already applied a set to *this* provider and
zone treats a mismatched marker as the drift it is. A first sync — the case the
rule was written for — still refuses. The bit comes from this deployment's own
row, which only `record_ok` writes and only after an apply that was itself gated
on ownership.

---

## Medium

### M1. The checkpoint's origin↔key binding read both its fields from the *unsigned* tail

`crates/synch-net/src/rekor.rs`. `verify_signature` decided *which log* had
signed from the signature line's name and its four-byte hint — both parsed from
`text[split + 2..]`, the region no signature covers — while the hint's
derivation, `SHA-256(origin ‖ 0x0A ‖ 0x01 ‖ raw32)`, is public arithmetic over
public inputs. An attacker holding one genuine note signed by a pinned key under
another name rewrites both, so the predicate collapsed to "some pinned key
signed these bytes", which the function's own doc says is insufficient and
claims to have closed.

The challenge pass correctly downgraded the severity: the doc names C2SP
cosigning as the mechanism, and the tree's own real fixture shows a witness
cosignature is 4-byte hint + 8-byte timestamp + 64-byte signature over the
`cosignature/v1` message, so it cannot satisfy `verify(&self.signed, …)`. The
one structural route to the precondition is closed. It remains a defence that
does not defend and a doc that oversells it.

**Fixed**: Go's `sumdb/note` takes its origin↔key binding from the caller's
`(name, hash) → key` verifier table. The trusted root carries the same pairing —
each shard's `baseUrl`, whose host is the origin its checkpoints carry, verified
against both shipped shards — and `tlog_keys` now keeps it instead of rendering
each key to base64 text and discarding the rest. A `--rekor-key` file has
nowhere to put a name and stays unbound, which the doc now says.

### M2. Two membership domains shared one binding row for an `id=`-less record

`crates/synch-store/src/schema.rs`, `bindings.rs`. The key was `(origin_id,
node_id, source)`, and `origin_id` carries the domain only for a *named* record:
an `id=`-less one binds `OriginId::Key(nk)`, which renders `key:<z32>`.

`hint_source_is_sole` — added by the previous audit precisely so a second
membership domain could not repoint a key the first one vouches for — asks
whether every live binding for a key is a DNS binding from this domain. With one
row it is trivially satisfied by whichever domain refreshed last, so the defence
was absent exactly where its own comment says the attack lives. `remove_domain`
was wrong in both directions for the same reason, and a short TTL from one
domain overwrote a long expiry from the other.

**Fixed**: migration v13 puts the domain in the key. Covered by
`a_second_domain_cannot_repoint_an_id_less_key_either`.

### M3. The Gleam checkpoint parser split the signed note at the *first* blank line

`control-plane/src/rekor/proof.gleam`. The previous audit fixed the Rust side to
`rfind`, matching Go's `bytes.LastIndex`, and left the mirror. Appending
`"\n— attacker <b64>\n"` to a genuine checkpoint creates a second blank line: a
first-blank reader takes `signed` to be exactly the real note, verifies the real
signature over it, and accepts the appended line as one the log put there.

The direction matters. This side reads a checkpoint to decide whether to *store
and serve* one, so the publisher would accept, store and serve a checkpoint every
`Require` client refuses — membership collapsing for every org on the control
plane, reproducibly, since `reusable` replays the same bytes. It is exactly the
class the verify-before-store step exists to prevent.

**Fixed**, with the Rust test ported. It also accepted a signature blob that was
nothing but its own key hint, where the client refuses one.

### M4. The gate's shield turned a replace into a delete

`control-plane/src/provider/diff.gleam`. The shield matched withheld records by
value, and `withheld` is rendered from the tables *as they are now* — so with
`omit_members` armed, a member whose rendered value changed since the last pass
matched nothing, was not shielded, and was deleted while its replacement was
withheld. The device left the zone entirely. The trigger is a dashboard edit by
any member, with the gate armed by somebody else's routine key rotation.

The challenge pass flagged the obvious fix as dangerous, and was right about the
fix it described: a *name-shaped* shield freezes forged and revoked records too,
which the previous audit had already rejected for that reason. The fix applied
is not that. It falls back to the identity a revocation actually removes — the
owner name plus the member label and device key — and **declines to do so when
two published records share one identity**, so a forgery copying a live device's
label and key sits beside the genuine record, doubles the identity, and is still
deleted. Covered by a test asserting all three cases.

### M5. `CP_REKOR_REQUIRE` failed open on every spelling but exactly `true`

`control-plane/src/rekor/gate.gleam` read `Ok("true") -> True, _ -> False`, so
`TRUE`, `True`, `1`, `yes`, `on` and a trailing space all left the gate silently
open — while the cosmetic `CP_BROWSE` two files away refuses anything it does
not recognise. An operator following the phase-1 recipe and typing `1` got the
opposite of what they asked for, with nothing anywhere saying so.

**Fixed**: an unrecognised spelling is refused. Off-by-default is unchanged and
remains argued (§7's phased rollout); that is a decision about the *absent*
value, not an unreadable one.

### M6. The monitor could not complete a run, permanently, with no attacker

The shipped trusted root pins `rekor.sigstore.dev`, which is Rekor **v1**: a
Trillian API with no `api/v2/checkpoint`, no hash tiles and no entry bundles
(measured live: 404 there, 200 on the v2 shard). `discover` walks every pinned
shard on purpose — a retired shard's proofs are still client-valid — so every
stock run filed that one as unreadable and returned `EXIT_INCOMPLETE`. The exit
code is the documented alerting interface; pinned at 30 forever it carries
nothing. `--log` was the only escape and collapses coverage to a single shard.

**Fixed**: `--skip-log` lets the operator name a pinned shard this monitor
cannot read, printing the coverage it costs — the same posture `--allow-gap`
takes toward a permanent loss. Stated by the operator and **never inferred from
a response**: a 404 is the audited party's own answer, and reading one as "not a
tiles log" would let a hostile or merely broken front end drop the live shard
from coverage and exit 0. That was the challenge pass's catch and it is right.

### M7. The widening guard missed an added ancestor

`crates/synch-monitor/src/classify.rs`. `widening_over` compared through
`watches`, which is bidirectional — so adding `example.com.` beside
`a.example.com.` reported no widening while the new list newly matched every
sibling subtree beneath it, none of which was matched before. Everything already
in the log for those names stays unclassified. Reachable by hand (§5.5 tells
operators the upward half matters most) and by the auto-insert, after which
`watched` is re-stamped so no later run can notice. The previous audit's test
asserted the unsound case as intended behaviour.

**Fixed**: a proper ancestor of a previously watched name is a widening.

### M8. The publisher's chain had no cross-language coverage of any kind

`control-plane/src/rekor/chain.gleam` builds the thing every client verifies —
the declaration and its three rules, the DNSKEY and DS RRsets, the RRSIG
signed-data construction, the wire RRs a link carries, the ladder's shape, the
DS digest tying one link to the next — and no byte of its output had ever been
read by the Rust validator. `crossval/chain.der` pins the DER *container*, and
pins it well; it cannot pin what goes inside a link. `publish.gleam` claimed
"the e2e crossval is what keeps this side honest about it" through two audit
passes; the e2e runs with `RekorPolicy::Off` and builds no chain.

The asymmetry is why it matters: the publisher writes to a public append-only
log, so a divergence found afterwards is a permanent entry no client accepts.

**Fixed** (the previous audit's M6, proposed and not applied). `gen_crossval`
seeds a two-zone universe with real keys and real signatures, runs
`chain.collect` over it, and writes the chain plus the anchor a reader installs.
The ladder is a real descent — the root signs a DS for `sync.test.` with `test.`
an empty non-terminal between — so
`a_chain_the_control_plane_collected_walks_under_this_validator` exercises
`verify_ds_set`, `verify_dnskey_set_under` and `covers` over foreign bytes.
Flipping one byte fails it. A Gleam test asserts the live collector still
produces that shape; the bytes themselves cannot be regenerated and diffed,
because ECDSA draws a fresh nonce.

### M9. The cross-language timing relation was six numbers, four of them transcriptions

`watch cadence + publish + ttl_proof < ttl_data + client trust grace` is what
keeps a routine provider key rotation from costing every DNS-sourced binding.
Two of its six terms were real constants at their point of use; the rest were
numbers typed into comments and tests on the far side of the language boundary,
and the previous audit found one of them stale — in the direction that
*understated* the margin. A comment in `dns.rs` said there was "no way to pin
them across the language boundary from this side", which stopped being true when
`meta.txt` was created for `MAX_PROOF_PARTS`.

**Fixed**: the three client terms are written into `meta.txt` by the regenerator
and asserted by both suites; the watch cadence is a public constant instead of a
private one restated by hand. Moving any of them fails a suite, verified in both
directions.

### M10. Serve mode's `/healthz` never compared the signature expiry to the clock

`control-plane/src/api/router.gleam`. A primary whose `resign` job had been
failing for weeks answered 200 `"status":"ok"` with `sig_expires_at` in the
past, while every validating resolver read its zone as `Bogus`. The status code
is the only thing the image's HEALTHCHECK, a load balancer or an orchestrator
reads, so a field nobody reads is not a signal. **Fixed**, with the rule split
out so it is testable without standing up the router.

### M11. `build.validate` re-checked half of what its doc promises

`control-plane/src/zone/build.gleam`'s doc says it re-checks every product
invariant the API layer enforces — the entire reason external mode calls it —
and it did not re-check the owner name's own shape. `model.read_txt_names`
assembles `_synchronicity.<network>.<slug>.<apex>` from two product columns and
`name.parse` splits on any dot inside either, so a network named `prod.acme`
under org `other` renders membership at a name reading as `acme`'s namespace.
**Fixed**: the owner must be three labels below the apex, the service label plus
two valid DNS labels.

---

## Low, fixed

- **Quadratic proof reassembly** (the previous audit's, unfixed until now).
  `assemble_group` rescanned every part for every claimed total. The records are
  the zone's and the threat model's attacker *is* the zone: sixteen validated
  TXT names hold tens of thousands of minimal `sync1p` records, and spreading
  their claimed totals across 1..=255 cost around 9×10⁸ tuple comparisons —
  roughly a second of CPU inside one `poll`, with no await for the per-domain
  deadline to fire at and no `spawn_blocking` under it. Indexed once by
  `(total, index)`; the cost is now asserted as a ceiling.
- **`is_wildcard` caught only a leading `*.`**, so `a.*.example.com` passed the
  watch-list guard while watching almost nothing. Now any label that is `*`.
- **`CP_PUBLIC_URL` was published unvalidated** into a signed apex TXT record
  while the client refuses anything that is not an `https://` origin and reads
  the record as whitespace-separated pairs. Validated at boot.
- **`record_observed` was a DELETE plus N INSERTs with no transaction**, where
  its sibling `rekor/store.put` transacts and says why. Two readers act on that
  table and an empty one means "arm the gate" to one and "serve every proof
  record" to the other.
- **Reconciler state writes were discarded**, so a failed error row left the
  previous success row standing and the next pass short-circuited past a
  provider it had just failed to reach. (Bounded by `recently_listed`, so this
  is smaller than it first looks.) The test-hygiene half is the sharper finding:
  `external_test` passed `"p"` as a provider name, violating a `CHECK`, so that
  `record_ok` silently failed and the test passed anyway.
- **The gate shield was handed the whole ungated render** rather than the
  difference the gate dropped. Behaviourally identical — the extra records are
  never `foreign` — but the parameter's name is its contract.
- **CI never linted the shipped binaries and never ran the shipped
  configuration.** `clippy --lib` selects library targets only, so
  `synch-monitor`'s 1500-line `main.rs` was linted only with `sim` on; and
  `--all-targets` unifies features across the graph, so no job had ever
  *executed* the suite against a client built the way a released one is. Both
  added.

## Low, corrected rather than fixed

Six claims a reader would have acted on:

- `tuf.rs` and §10.6 said "a key Sigstore removes is a key clients drop". True
  of `update`, and not a revocation story: Sigstore retires by *window*, keeping
  the entry listed, and `validFor.end` is unenforceable in principle because
  nothing near a proof carries a log-attested time. A leaked shard key is
  unrecoverable, and now says so.
- `verify`'s doc had the retire order backwards — a retire carrying a chain is
  chain-checked first, and the chainless retire the publisher may emit never
  reaches the action arm at all.
- `ValidChain::anchored_directly` named the apex where it means the signing
  zone, in a module that spends eighteen lines on the difference.
- `ttl`'s "each replay buys strictly less than the last" is false inside the
  final minute of an RRSIG, where `clamp_ttl`'s floor bites.
- The `apex=` field claimed a comparison against the certificate that does not
  happen; both names are bounded between the same two names instead.
- `ds_fields` claimed the log entry "names the key this way too" — an entry
  carries no DS field at all.
- The runbook said the client's grace was 10 minutes where it is 15, described
  revocation timing that only holds in serve mode, and documented external mode
  nowhere. `EXTERNAL-DNS-PROVIDER.md` named `oldest_unlogged_age` as "the number
  to alert on" when it is `null` for both "everything is logged" and "the
  watcher has never worked".

## Test-quality fixes

Four checks were deletable with the whole workspace green, each already having a
test whose shape made it unable to fail:

- `KnownKeys::contains_digest`'s parse-don't-trim rule — the test seeded the bad
  entry with an empty digest list, so `any()` was false whichever way the
  comparison went. Its neighbour indexed a literal map key, so a `parse_name`
  that stopped lowercasing would file two entries and still find a list of
  length one.
- `Authorized`'s `#[non_exhaustive]`, verified once by hand when it was added
  and by nothing since. Now a `compile_fail` doctest.
- The DS the monitor prints, computed over the signing zone. Every shape in the
  tiers suite had apex == signing zone.
- The tiers harness mapped `classify` returning `None` onto `Tier::B` with a
  comment about treating it "as C so the assertion below has teeth". There is no
  tier C, and the collapse erased the distinction it meant to keep: tier B is
  noted on stderr, `None` is never judged at all.

And the monitor's watch-coverage guard — the previous audit's own H1 fix — could
be deleted whole with the suite green, because the test cited for it covers
`widening_over` and not the guard. It is a function with a test now.

---

## Killed by the challenge passes

Recorded because a finding killed on evidence is worth more than one nobody
argued with.

- **`sumdb/note` divergences in the signed region** (`\r` stripping, `+`-prefixed
  tree sizes, lenient base64, control characters). The module draws the line
  itself: splitting at the first blank line "is a real divergence rather than a
  stylistic one". All four fall on the stylistic side — two are inside bytes
  only the log can produce, two are in the tail where the attacker already
  controls every byte.
- **Positions keyed on the log-chosen origin with no base-URL binding.** Argued
  at length in `state.rs`, and unreachable besides: to write `position["A"]`
  from shard B, B must serve a checkpoint claiming A's origin *and* tiles that
  reproduce its root, which `prepare` checks.
- **`--rekor-key`'s unread-shard warning.** `--rekor-key` replaces the keys and
  nothing else; the endpoints still come from the trusted root, so naming
  Sigstore's shards is the correct statement, and the file format has nowhere to
  carry a URL.
- **The two `trusted_root.json` readers' opposite failure policies.** CI asserts
  both byte-equality with the client's embedded root *and* that the Gleam reader
  parses it, so a file the strict reader rejects cannot reach production; the
  file is a build artifact that moves only on deploy.
- **`check_dnskey_rdata` over every observed rdata.** Reachable only from a
  hostile or broken resolver, which can already fail collection outright, and
  the watcher retries every cadence — so neither the capability nor the
  permanence is real.
- **Cloudflare's 5000-record listing cap**, a documented runaway guard whose
  precondition (a token that can create 5001 records) already permits strictly
  worse.
- **`--from-index` past a shard's tree size**, which is opt-in behind
  `--allow-gap` with a message naming the exact skipped range, and records the
  *conservative* position.
- **The monitor's bundle memory**, whose cap is argued at length and whose
  arithmetic the finding had 2× too high.
- **A corrupt pin file rolling back to the embedded set**, self-healed by the
  next networked run.

## Left open, and why

- **A leaked Rekor shard key is unrecoverable.** `validFor.end` cannot be
  enforced without a log-attested time, which nothing near a proof carries and
  which the design deliberately refuses to take from a reader's clock. Now
  documented as the limitation it is rather than claimed as revocation.
- **No checkpoint freshness test.** A frozen head is a perfect prefix of itself,
  so the consistency check passes and the run exits 0. The design documents
  cross-witnessing as the answer and does not implement it; a local staleness
  bound would catch the no-malice CDN variant and is worth doing, but it is a
  new signal with its own false-positive story, not a fix to an existing one.
- **One unverifiable leaf still walls the walk permanently.** Refusing to read a
  body the signed root does not commit to is correct; the residue is that the
  wall is not persisted, so it is visible only in that run's stderr.
- **External mode has no packaging or end-to-end coverage.** `image-smoke.sh`
  runs `CP_ROLE=primary` and `e2e/run.sh` never sets `CP_DNS_MODE`, so
  `connect_provider` and both real provider legs' HTTP paths are exercised by
  nothing.
- **External mode refuses to boot when the provider API is unreachable**,
  because zone discovery runs before the supervision tree. Setting
  `CP_CLOUDFLARE_ZONE_ID` avoids the call entirely; the runbook now says to.
- **The proof part-name derivation is still pinned by nothing** — the two sides
  agree today and nothing holds them there.
- **`synch-net` is still two disjoint crates in one**, so `synch-monitor` pulls
  a QUIC relay, UPnP and SQLite to run a chain walk. Build hygiene, and the
  thing that would make most of the above cheaper.

## What the next pass should not do

Not another sweep of the same two chains before the apparatus is finished. The
generator this pass found — checks that are right, held still by nothing, in a
harness that cannot express the failure — was still producing after five passes
because every pass fixed instances. The three that changed the *rate* here were
the delegation-half harness knob, the Gleam-collected chain carried through the
Rust validator, and the timing constants moved into the shared fixture. What is
left of that class is listed above, and is worth more than a sixth read of
`chain.rs`.
