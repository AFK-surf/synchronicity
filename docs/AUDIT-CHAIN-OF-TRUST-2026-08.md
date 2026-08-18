# Chain-of-trust audit — DNSSEC and Sigstore Rekor, across both planes

Date: 2026-08-18. Scope: the two coupled chains of trust — DNSSEC membership and
Sigstore Rekor v2 zone-key transparency — across the client data plane
(`crates/synch-net`, `crates/synch-engine`), the monitor (`crates/synch-monitor`),
and the Gleam control plane (`control-plane/`).

Method: seven independent adversarial reviews from different angles, then a
three-way false-positive challenge pass in which every finding had to survive a
reviewer whose explicit goal was to kill it. 41 findings were raised; 1 was
killed outright, 12 were downgraded or had their reasoning corrected, and 1 was
withdrawn after the fact when the design document turned out to have described
it already (see **Withdrawn** below). 39 stand.

Baseline: `cargo test --workspace`, `cargo clippy --workspace --all-targets
-D warnings`, `cargo fmt --all --check` and `gleam test` (181 tests) all pass on
`d89264f`. Nothing in this audit is a build failure; everything below is a
defect the suite does not catch.

Findings are listed by severity. Each names the smallest change that closes it.
Where the challenge pass corrected a finding, the correction is recorded inline —
in three cases it changes what the fix should be.

---

## Withdrawn

### ~~H1. Two of the nine pin-state fields are never re-derived~~ — withdrawn, and the surrounding design has since been simplified

Filed as the audit's top finding: `PinState::load_anchored` re-derived `root`,
`root_version`, `targets`, `targets_version` and `trusted_root` from the
binary's anchor but read `timestamp_version` and `snapshot_version` verbatim,
so a writer in the data directory could park both rollback floors at `u64::MAX`
and freeze pin refresh permanently. The mechanism was real and was verified end
to end in a scratch harness.

**It should not have been filed.** §10.2 of `docs/REKOR-ZONE-KEY.md` already
described it, in terms, before this audit ran — naming the two fields, naming
the ceiling, naming the permanent freeze, and giving the reason it was accepted:
the precondition is a same-uid write inside the `0700` data directory, and that
same access already writes a never-expiring `source='static'` binding straight
into `synch.db`. That is a deliberate, argued, documented decision, which is
exactly the challenge pass's fourth kill criterion. Neither the original review
nor the challenge found the passage; both read the code and the test file and
stopped there. The lesson is narrow and worth stating: a repo that carries its
security argument in prose has to be searched as prose, and "the tests do not
cover it" is not evidence that the designers did not consider it.

The finding is withdrawn on its merits, not softened.

Separately, and at the maintainer's direction, the premise it was arguing about
has now been settled the other way: local disk is trusted, so the load-time
re-derivation has been removed rather than extended. `load_anchored` reads the
state as written; what remains is a provenance check — the state records the
SHA-256 of the TUF root it was accumulated under and is not read under a
different anchor, because `update` chains from the stored root rather than
re-walking, so a state carried across a `--tuf-root` switch would extend the
wrong repository's chain forever. `verify_root_chain` is gone,
`tests/pin_state_authentication.rs` is now `tests/pin_state.rs` covering
round-trip, provenance and the clock floors, and §10.2 has been rewritten to
describe what the code now does.

## High

### H1. An apex added to the monitor's watch list is never rescanned

`crates/synch-monitor/src/main.rs:902`, `:964`. Read coverage is one `next_index`
per log, but the watch filter is applied per entry inside the walk: an entry
naming an unwatched apex is stepped over and the position advances past it.
Adding that apex to the watch list later resets nothing and warns about nothing,
so every entry for it already in the log is permanently unclassified and the run
exits 0.

This breaks the coupling invariant through *coverage* rather than
classification, with no divergence in `chain::authorize` at all. Sibling zones
are the reachable case, measured directly: with `a.example.com` watched,
`cp.example.com` matches `watches` in neither direction. An attacker who mints a
tier-A entry for `cp.example.com` at index *i* before the operator starts
watching it gets an entry every client accepts and no monitor ever reports.

Every other coverage input is guarded — the `--from-index` gap is announced
(`:789-803`) and a trust-surface change is refused (`:456-470`) — and the watch
list is not part of `TrustSurface` (`state.rs:78-86`). The auto-insert at
`:626-629` worsens it: reporting an entry adds its apex as a watch entry, so
coverage widens forward while the same hole stays open behind. The documented
onboarding recipe (`docs/REKOR-ZONE-KEY.md:1546-1559`) is `--from-index <n>
--allow-gap`, so real deployments start deep in the log.

**Fix (applied)**: the state now records `watched`, the apex set the stored
positions actually cover, and a run whose list has widened since is refused,
naming the new apexes and the index each log stands at. `--allow-gap` accepts
it, `--from-index 0` re-reads — the same escape and the same wording the
`--from-index` guard already uses, because it is the same event ("these entries
are permanently unread") arriving through the state file instead of the command
line.

`watched` is deliberately not part of `TrustSurface`: a surface change
invalidates recorded *verdicts*, this invalidates recorded *coverage*, and the
remedies differ. The comparison runs through `watches` rather than set
difference over the literal names, so the auto-insert at `:626-629` does not
trip it — a name the old list already watched in either direction was matched
by the set in force when those entries were read, so nothing was skipped.
String equality there would refuse a run that lost nothing, which the test
asserts by mutation. A state file predating the field is treated as covering
what it currently watches; refusing every upgrade would name a gap no run can
close anyway.

Covered by `a_watch_list_that_widened_since_the_last_walk_is_a_gap`.

### H2. The provider reconciler never re-reads the provider once converged

`control-plane/src/jobs/provider_sync.gleam:219-231`. `pass` computes its hash
from local state only and returns `Ok(Fresh)` before `prov.list()`, so a sweep
only ever touches the provider when *our* side changed. The module doc claims the
opposite twice (`:14`, `:55-58`): "self-heals drift introduced behind our back in
the provider's console".

Reproduced in a scratch copy: after convergence, a pass against a provider
listing an injected `_synchronicity.prod.acme.sync.test` record made no `list`
call at all, at t=3000 and again at t=999000. `/healthz` reports `synced: true`
throughout (`api/router.gleam:255-263` reads local state only), and external mode
schedules no re-sign job, so nothing bumps the serial on a cadence.

An attacker holding only the provider API token — strictly weaker than the
provider itself, and the party this repair sweep is the documented defence
against — re-creates a revoked device's TXT record, or removes
`_synchronicity-rekor.<apex>`, and it stands.

Correction: "forever" should read "until the next local mutation or process
restart" — boot and every product mutation bump the serial. In a quiescent
deployment that is unbounded.

**Fix (applied)**: the short-circuit is now time-bounded. `recently_listed`
ANDs `now - last_ok_at < reconcile_interval` into `fresh`, so a converged
reconciler still lists and diffs with nothing on our side changed. The interval
is 900 s, set by what a forged record has to outlive to be worth planting:
`ttl_data` (300) plus the client's `DEFAULT_TRUST_GRACE` (900) is 1200, so the
sweep has to fall inside that to be the thing bounding the exposure. Covered by
`a_converged_reconciler_still_reads_the_provider_eventually_test` and
`drift_introduced_at_the_provider_is_repaired_without_a_local_change_test` —
both driving a *converged* pass, since a first pass short-circuits on
`state.get` returning `Error(Nil)` and never consults the interval.

### H3. The external transparency gate deletes the published membership set instead of withholding a new one

`control-plane/src/zone/render_external.gleam:72-87` with
`control-plane/src/provider/diff.gleam:145-150`. When `omit_members` fires,
membership records leave the *desired* set; because the reconciler holds delete
authority below the apex and `deletable` filters `foreign` on `is_proof_name`
only, "omitted" means "deleted at the provider". The design's own stated posture
— "refuse to emit and leave the published zone standing" (`diff.gleam:139-141`) —
is applied to the proofs and not to the product.

Reproduced: `provider-sync: applied serial 1 (+0 ~0 -1)` with
`delete = ["_synchronicity.prod.acme.sync.test"]`. No attacker required — a
provider that pre-publishes its next key (the standard rotation dance) plus a
Rekor or chain-collection outage is enough. Permanent variants need no outage at
all: a provider DNSKEY with protocol byte ≠ 3 passes `chain.claimable`
(`chain.gleam:415-422`) but fails `check_dnskey_rdata` (`:438-450`), so it is
observed forever, never logged, and membership stays deleted.

Correction: the finding's two-tick arithmetic is wrong and should be struck.
`refresh_dns_bindings` has no delete path; only `expire_bindings` removes rows,
at last-good-refresh + ttl + `DEFAULT_TRUST_GRACE` = 900 s (`dns.rs:97`, not the
600 the comment at `render_external.gleam:44` claims). The real budget is 1200 s,
so a 600 s outage is invisible. The teeth are an outage beyond ~20 minutes —
which dissolves membership for every org on the control plane, including clients
running `RekorPolicy::Off` — and the permanent variants.

**Fix (applied)**: membership is shielded in `diff.deletable` the way proof
records already are, when the gate is the reason it is absent. "Do not add" is
the gate; "remove what is working" is not.

The shield is the **withheld records**, matched by name and value —
`diff_gated(desired, existing, withheld)`, with `diff/2` delegating as `[]` and
the reconciler rendering the ungated set to supply them. A first attempt passed
a `Bool` and shielded by name shape; adversarial review killed it, correctly. A
shape predicate cannot separate "membership we are holding back" from
"membership the renderer stopped producing", so it also froze **revoked
devices' records and outright forgeries** in the zone for as long as the gate
stayed armed — unbounded, and made permanent by the SHA-384 DS bug below. That
was a worse hole than the one being fixed. Matching the actual withheld records
shields exactly the set that was withheld and nothing else.

Covered by `published_members_survive_a_pass_the_gate_withheld_test` (which
also asserts the revocation case still deletes),
`the_gate_shields_withheld_records_not_membership_shaped_names_test` (a revoked
record and a forgery are both still deleted while the gate is armed), and
`the_gate_does_not_shield_anything_but_membership_test`.

---

## Medium

### M1. The key watcher trusts an unauthenticated resolver for a destructive write

`control-plane/src/rekor/chain.gleam:701-708`, `:746-755` — `doh_query` sets RD
only and `response_answers` checks the rcode and nothing else, not the AD bit and
no signature. `jobs/zonekey_watch.gleam:311-312` reads twice through the *same*
resolver and `provider/state.gleam:261,266` then issues
`DELETE FROM observed_zone_keys WHERE key_sha256 NOT IN (...)`.

`docs/EXTERNAL-DNS-PROVIDER.md:450` says step 1 is to "resolve and
DNSSEC-validate" this RRset; `chain.gleam:58` says "No signature is verified
here" and `:104` says the resolver "is not a trust decision". The code asserts the
resolver is untrusted and then trusts it for a destructive local write — plus a
permanent, public, irreversible Rekor entry.

Corrections: the DO bit *is* set and CD is 0, so the finding's own "set CD=0" fix
is already satisfied — but that defends only against parties other than the
resolver, and the resolver is the named attacker. The minted entry is tier B
("not reported"), so monitor noise is nil, and the delete-membership and
mint-entry consequences are mutually exclusive. Impact is availability plus a
permanent junk public leaf, not a client-trust bypass. Severity medium-high.

**Fix (applied, first half)**: the key watcher now takes
`chain.doh_validating`, which refuses any answer the resolver did not mark
authenticated (AD, RFC 4035 §3.2.3). Chain assembly keeps the plain resolver —
its output is copied into the certificate and re-verified by every reader, so
a hostile resolver there produces an entry that verifies nowhere. The
watcher's answer is spent on `record_observed` and re-checked by nothing,
which is the whole asymmetry. `CP_DNSSEC_CHAIN_RESOLVER` must therefore be
validating in external mode; the default is. Documented in
EXTERNAL-DNS-PROVIDER.md §5.1, REKOR-ZONE-KEY.md's env table and the RUNBOOK.

The second half — making `record_observed` additive-with-aging rather than
deleting on a single observation — is **not** done. It is a larger change to
how the watcher decides a key is gone, and worth doing: AD makes the resolver
say it validated, which is a much better answer than nothing, but a compromised
validating resolver still gets one destructive write per observation.

### M2. Dial hints from one membership domain repoint any key the node trusts

`crates/synch-engine/src/membership.rs:449` gates hint application on
`is_trusted_key`, which is `!live_origins_for_key(...).is_empty()` — any live
binding, any source, any domain. The write at `:468` reaches
`record_peer_seen`, whose `ON CONFLICT(node_id) DO UPDATE SET last_addr =
COALESCE(...)` (`crates/synch-store/src/views.rs:773-780`) is keyed on `node_id`
alone: global, unscoped, overwriting.

A second configured membership domain publishes a record naming a key the node
trusts statically, with `relay=`/`addr=` pointing at the attacker. The answer is
genuinely DNSSEC-valid for that domain, so it passes every gate, and every later
dial of that key goes through the attacker's relay. There is no repair path: the
only other `Some(..)` writers are `apply_member_set` itself and `synch peer add`;
successful connections pass `None`, which `COALESCE` preserves; nothing prunes
`peers_seen`.

**Correction that changed the fix**: the originally proposed gate on
this-answer bindings does *not* work — `refresh_dns_bindings` runs first, so
the hostile answer's own bindings contain the key and a this-answer gate is
satisfied.

**Fix (applied)**: the hint is applied only when the answering domain is the
key's **sole live source** — every live binding for that key is a DNS binding
from this same domain. The hostile answer binding the key itself is what makes
the this-answer gate useless and is exactly what makes this one fire: two
domains now vouch for the key, so neither one's dialing data is used and
discovery answers instead. That is the same posture §3.2 already takes toward
an ambiguous key, and a statically-bound key is likewise not a DNS answer's to
repoint.

Chosen over scoping `peers_seen.last_addr` by source domain, which the review
suggested: that needs a schema migration and leaves the "which of two hints do
I dial" question unanswered, where sole-source answers it — neither. Covered by
`a_second_domain_cannot_repoint_a_key_the_first_one_vouches_for`, verified to
fail without the gate.

Still true and not addressed: nothing prunes `peers_seen`, and no successful
connection writes a real address back, so any hint that does land is permanent.
That is now only reachable from a key's sole vouching domain, which is a party
already trusted to say who the members are.

### M3. One membership domain's refresh stalls every other domain into lapsing

`crates/synch-engine/src/membership.rs:628-660` walks due domains serially with
`.await` and no per-domain timeout; there is no `tokio::time::timeout` on the
production path anywhere in `membership.rs` or `dns.rs`. One `member_set` under
`Require` issues up to 18 validated lookups, each through `DnssecDnsHandle` with
hickory's default `max_request_depth: 26`, bounded only by `DOH_TIMEOUT = 10 s`
per exchange. `Binding::is_live` stops honouring a binding at its expiry
regardless of the deletion task, and the floor is ~16 minutes
(`MIN_TTL` + `DEFAULT_TRUST_GRACE`).

`crates/synch-net/src/rekor.rs:495-508` states this failure in the codebase's own
words and closes only the part-count multiplier.

**Fix**: a per-domain deadline well under `MIN_TTL + DEFAULT_TRUST_GRACE`, or
refresh domains concurrently.

### M4. `check_ds_covers` can never match a SHA-384 DS

`control-plane/src/rekor/chain.gleam:543-548` collects DS rdatas of digest type 2
*and* 4, then compares every one against `keys.ds_digest`, which is SHA-256 and
only SHA-256 (`dnssec/keys.gleam:66-71`). A 48-byte digest never equals a 32-byte
one, so the type-4 arm is dead code. The Rust reader dispatches correctly
(`crates/synch-net/src/chain.rs:792-795`).

This runs for every ancestor zone cut (`:501`), not just the signing zone, so any
zone on the ladder publishing only a digest-type-4 DS makes `chain.collect` fail
unconditionally — and the error text names SHA-384 as accepted. In external mode
that is a **permanent** `omit_members`: the gate arms and never disarms without a
code change. Since H3 that no longer deletes the published membership, but the
zone then runs indefinitely on a withheld set, publishing no new device. This is
therefore the finding that bounds how long H3's shield can be load-bearing, and
the one worth fixing first in this section.

**Fix (applied)**: `keys.ds_digest_384` added and `check_ds_covers` now keeps
the digest type with the digest, dispatching per type the way `covers` does.
Both digests are also pinned in the shared crossval fixture
(`ds-digest-sha256.bin`, `ds-digest-sha384.bin`) and asserted from each side,
so the construction is held still across the boundary rather than recomputed
independently — this was one of the two formats M6 identifies as unpinned, and
it is the one that drifted. Covered by
`a_delegation_published_with_a_sha384_ds_still_collects_test` (which also
asserts a type-4 DS over an unserved key is still refused),
`the_ds_digests_match_the_crossval_bytes_test`, and Rust's
`the_ds_digests_match_the_control_planes`.

Note on what the fixture pins: the mixed-case owner name pins the control
plane's lowercasing, since `name.encode` folds case itself. It does not pin
the client's — hickory folds case when it parses a `Name`, so `ds_input`'s
`to_lowercase` is belt-and-braces there and removing it leaves the suite
green. What is pinned is that both sides land on the same bytes for the same
delegation.

### M5. The client/monitor coupling invariant is enforced by comment, not by type

`crates/synch-net/src/chain.rs:283` — `validate` is `pub` and takes a
caller-supplied `&Name`; `Authorized` (`:184`) has all-public fields and no
`#[non_exhaustive]`, so it can be constructed by struct literal with no chain
walk. Both doc comments assert the opposite ("neither may supply its own apex",
"Produced only by `authorize`"). `walk_ladder` at `:372` is private "and
deliberately so", which shows the idiom was available.

The tiers suite exists because the two sides once composed the SAN differently
and put a client-accepted entry in the silent bin; this re-opens that door with
no compile error and no test failure.

**Fix (applied)**: `validate` is behind `cfg(any(test, feature = "sim"))` — the
pattern already used for `DnssecChain::encode` — with `authorize` and the
module's own callers going through an ungated `validate_inner`. `Authorized`
is `#[non_exhaustive]`, so every field stays readable and another crate cannot
build one by struct literal. Verified from outside the crate: a `synch-monitor`
test fabricating an `Authorized` fails to compile with `E0639`.

Note for anyone repeating this: gating a public item breaks any intra-doc link
to it, because `cargo doc` resolves the *sim-off* configuration and CI runs
rustdoc with `-D warnings`. `chain.rs`'s reference to `[`validate`]` had to
become plain text.

### M6. The cross-language conformance fixture pins the one chain shape no deployment produces

Verified directly: `control-plane/test/fixtures/rekor/dnssec-chain.der` is 483
bytes, exactly two links — the declaration and `sync.test.` (DNSKEY+RRSIG, no DS)
— and `anchor.key` anchors the apex itself. So `ladder.len() == 1` and the descent
loop at `crates/synch-net/src/chain.rs:421` runs zero times: `verify_ds_set`,
`verify_dnskey_set_under`, `covers` and both `ds_digest_*` are never reached.
`docs/REKOR-ZONE-KEY.md:1461` says outright that no deployment produces that
shape.

Sharpened by the challenge pass: the shared fixture is written by the *Rust*
simulator (`regenerate_the_shared_fixture`), and no Gleam test reads the chain
files at all — so it supplies zero cross-language coverage of the chain format in
any shape. The comment at `rekor_zone_key.rs:802-804` ("The certificate the Gleam
side built, read by the Rust parser") is false for it. `crossval/chain.der` is
Gleam-written but carries synthetic payloads and is only round-tripped through
`encode`/`decode`; `chain::validate` is never called on it.

`control-plane/src/rekor/publish.gleam:32-34` claims "the e2e crossval is what
keeps this side honest about it" — the e2e runs with `RekorPolicy::Off` and never
builds a chain. So `chain.rrset_of`'s output (770 lines of collection and RR
packing) has no cross-language artifact.

Correction: six of the eight duplicated formats *are* two-way pinned. Only the DS
digest and the trusted-root reader were unpinned — and those are precisely the two
that drifted (M4, and the reader-policy divergence below). The DS digest is now
pinned as part of M4's fix, which leaves the trusted-root reader.

**Fix**: have `gen_crossval` emit a chain collected by `rekor/chain.gleam` from a
seeded zone, and have a Rust test run `chain::authorize` over it.

### M7. The CI guard for the control-plane TUF shipment cannot fire

`control-plane/ops/image-smoke.sh:163` greps container logs for a string produced
only by `trusted_root.shipped()` → `client.discover()`, whose only boot-time
caller is `zonekey_watch` — mounted only in `serve_external`. The script starts
the container with `CP_ROLE=primary`. The grep never matches and the check always
passes. Reintroducing the `.dockerignore` regression it was written for leaves CI
green. Its comment describes a `tuf-refresh` job that migration v8 removed.

**Fix (applied)**: the check now searches the image filesystem for
`sigstore_trusted_root.json` instead of grepping container logs for a string
only external mode can produce. Searched by name rather than at a fixed path,
since `priv_dir/1` resolves through `code:priv_dir(controlplane)` and the
location inside an erlang-shipment is the release layout's business — pinning
one is how the original check came to match nothing.

Two neighbours fixed with it: the Dockerfile comment named `tuf/anchor.gleam`
(no such module — it is `tuf/trusted_root.gleam`) and the wrong file, and the
control plane's copy of `sigstore_tuf_root.json` is deleted. Nothing read it;
§10.2 described it as anchoring "the walk" while the next paragraph says the
control plane walks no repository.

### M8. Two load-bearing bindings have no test at all

Mutation testing: deleting `body.digest != sha256(&pae)`
(`crates/synch-net/src/rekor.rs:750`) and `authorized.signing_zone !=
observed_signer` (`:726`) each leaves the whole suite green, as does the
declaration RRSIG signer-name check (`chain.rs:470`). 7 of 10 deleted checks were
caught; these three were not.

For `:726` I worked out reachability myself: the upstream guards only force both
names to be ancestors-or-equal of the domain, and two ancestors of one name need
not be equal — a parent zone that nullifies its child's delegation produces
`signing_zone ⊋ observed_signer`. It is live code, not dead. Every `ZoneKey` in
the tree sets `signing_zone` equal to the apex, so the harness cannot reach it.

Correction on `:750`: it is cryptographically redundant given the attribution
check at `:745` (the body is parsed from the same bytes the leaf commits to), and
the monitor never reads the statement, so the claimed monitor-silence scenario
does not occur. It remains cheap defence in depth against a shard with broken
ingest validation. Low.

**Fix**: parameterise the tiers `Shape` with a separate chain zone — one shape
covers `:726` and `chain.rs:470` together.

### M9. `MAX_PROOF_PARTS` is one number written twice, pinned by nothing

`crates/synch-net/src/rekor.rs:479` and `control-plane/src/rekor/proof.gleam:172`
must be equal; each suite asserts its own constant against itself. Raising the
Gleam one silently truncates proofs client-side (`parts_claimed` ends
`.min(MAX_PROOF_PARTS)`) and every `Require` client refuses that zone
permanently; lowering it fails loudly at publish. The invisible direction is the
one that matters. The part-name derivation (`dns.rs:127` vs `build.gleam:175`) is
the same shape.

Correction: `PROOF_CHUNK_CHARS`/`txt_chunk_chars` is *not* a coupling —
`assemble_group` concatenates without inspecting chunk length — so that pair
should be dropped from the finding.

**Fix**: put the numbers in the shared fixture's `meta.txt` and assert both sides
against it.

### M10. The design document described a multi-apex walk the code refuses — **fixed (doc)**

`docs/REKOR-ZONE-KEY.md:566-573` said each usable apex "is tried in turn,
most-attested first and bounded, rather than the whole answer failing".
`crates/synch-net/src/dns.rs:206-215` is a hard refusal. The function's own
rustdoc at `:169-189` rebutted the design doc using the design doc's exact
examples, and `:1024` says "One apex, one verification." The code is right; the
authoritative document was wrong, in a repo whose stated method is to carry the
security argument in prose.

**Fixed** in the document, not the code: the passage now says a second usable
apex at one name is a refusal and why — the cases that look like they need a
candidate list all relocate the owner name along with the apex, and trying
several in turn would let whichever one an attacker can publish decide the
answer. It also separates `MAX_PROOF_CANDIDATES`, which bounds a genuinely
tried-in-turn list of *proofs* at a single apex and is a different question.
That last point is the residue the finding noted: `candidates_to_verify` is a
function whose entire body is `truncate(4)` carrying 15 lines of
justification, and it now has a doc that agrees with it.

### M11. Shard retirement can never be revocation

`crates/synch-net/src/tuf.rs:748-757` pins the key of every listed tlog entry
regardless of `validFor`; `valid_at` is used only for endpoint selection. No proof
carries a log-attested time, so `validFor.end` is unenforceable in principle. The
module doc justifies the daily walk with "a key Sigstore removes is a key clients
drop" — but the shipped trusted root shows Sigstore *retires by window*, keeping
entries listed (`rekor.sigstore.dev`'s 2021 P-256 key is listed with a start and
no end). The P-256 arm also has no origin binding. A shard key that has ever been
listed is unrevocable here, and one leak permanently breaks "client-accepted
implies tier A".

**Fix**: carry a log-attested time and gate on `valid_at`, or delete the
revocation claim and state plainly that a leaked shard key is unrecoverable.

---

## Low

- **`synch-net` is two disjoint crates in one.** The five trust modules have zero
  references to iroh/store/mpt/core and vice versa; only `dns.rs:21` straddles.
  `synch-monitor` consequently pulls 307 packages including a QUIC relay, UPnP
  and SQLite. Extracting `crates/synch-trust` halves the graph and strengthens
  rather than weakens the shared-validator property. Build hygiene, not behaviour.
- ~~**`Certificate::parse` never exhausts `tbsCertificate`**~~ **fixed.** A
  second `[3]` extensions block was silently dropped, so the exactly-one-SAN and
  exactly-one-chain-extension rules never fired on it — while the comment beside
  them claimed the rule was applied at every level. `tbs.finish(...)` closes it;
  `a_second_extensions_block_inside_the_tbs_is_refused` builds a certificate with
  a smuggled second block naming a different zone and is verified to fail without
  the fix.
- **Quadratic proof reassembly.** `assemble_group` (`rekor.rs:410-448`) rescans
  every part for every claimed total; the candidate cap runs *after*. Measured at
  938,074,384 iterations / ~0.9 s of CPU on the async task with no
  `spawn_blocking`, from one hostile zone per TTL, in a serial refresh loop where
  every neighbouring cost is bounded. Index the parts once.
- **`Checkpoint::parse` splits the signed note at the first blank line**
  (`rekor.rs:1183`); Go's `sumdb/note` uses the last. Demonstrated: appending
  `"\n— attacker <b64>\n"` to a genuine checkpoint is accepted here and refused by
  Go. The checkpoint is not covered by the leaf hash, so it is malleable in the
  zone's TXT. No authorization break, but it is checkpoint malleability on a
  genuine note — slightly stronger than filed.
- **`strip_off_path_rrsigs` documents a defence that does not exist**
  (`dns.rs:1811-1813`), referencing a `ValidatedTxt::rrsigs` field that is not
  there (the field is singular). The file contradicts itself at `:1889-1893`.
  During a double-signature rollover a transport that controls answer ordering
  deterministically picks which key must carry a proof.
- ~~**A wildcard watch entry parses and watches almost nothing**~~ **fixed.**
  Measured: `*.example.com` watched `example.com` and up and *nothing* below,
  including `cp.example.com` — the ordinary shape of both a control plane and a
  takeover. `unwatchable` now refuses it, with an error saying to watch the apex
  itself, which already covers the whole delegation path in both directions.
- ~~**`ds_fields` hardcodes digest type 2**~~ **fixed.** The report line exists
  to be compared against a registrar, and a registrar shows whichever digest type
  the delegation uses — `covers` accepts both. `ds_fields_sha384` is now reported
  beside it, in the JSON as an additive `ds_sha384` field and in the human line,
  on the same reasoning the line's own doc gives: one an operator has to re-run a
  tool to complete is one they will not act on.
- **`ParsedLink::parse` accepts DNS name compression pointers**, contradicting the
  documented uncompressed-only format. Verified: a backward pointer resolves and
  passes the owner check. Harmless here, but a third-party monitor written to the
  documented format would reject a link this reader accepts.
- **The control plane ships a TUF anchor no code reads.** `priv/tuf/
  sigstore_tuf_root.json` is byte-identical to the client's and referenced only by
  a Dockerfile comment naming `tuf/anchor.gleam`, which does not exist. A test
  comment claims a byte-equality guard for it; there is none.
- **The two `trusted_root.json` readers have opposite failure policies** — Rust
  skips an unreadable tlog entry with a 12-line rationale, Gleam fails the whole
  file. Downgraded: CI asserts `tlogs` parses the shipped file, so it cannot reach
  production. The residual is that the byte-equality test freezes both copies, so
  Gleam's strictness would block the *client's* embedded root from updating.
- **The control plane's trusted root never refreshes, and a comment says it does**
  — `controlplane.gleam:493-495` advertises "the TUF refresh job both primary
  modes share"; no such job exists in either mode, and `jobs/resign.gleam:6-7`
  says the opposite in the same tree. The no-refresh design itself is sound and
  defended; the false comment is the defect.
- **A frozen pin set is invisible until fatal.** The only signal is a `warn!` after
  seven consecutive days, inside `member_set`, only under `Require`. `doctor`
  never prints the last successful walk.
- **A failed Rekor submission costs a full 300 s tick**, leaving exactly one
  retry of headroom in the documented timing relation — which is itself
  maintained against a stale `600` where the real `DEFAULT_TRUST_GRACE` is 900.
- **Publisher and client ship opposite defaults**: `gate.required()` is off unless
  `CP_REKOR_REQUIRE=true`, while the client defaults to `Require`. A stock control
  plane publishes a zone every stock client refuses, and `promote` without a prior
  `rekor-publish` takes the cluster down at the moment of promotion. (Narrowed:
  serve mode having no watcher is a consequence of who holds the key, not an
  omission — drop that half.)
- **The entry-signature "attribution" check is cryptographically vacuous.**
  `body.certificate.spki` is read at exactly one production site. Inclusion and
  the checkpoint signature are verified *before* the body is parsed, so by then
  the entry has already passed Rekor's admission control, which requires that same
  signature; `ProofError::Attribution` cannot fire against a real log. Keep it as
  a stated consistency check, not a link in the trust chain. (Two reviewer errors:
  P-256 is forced by the `keyDetails` refusal, not by this check, and the docs do
  not oversell it.)
- **The P-256 SPKI prefix is duplicated at five sites**, not two. Drift risk is
  closed by the real-entry test; cosmetic.
- **`sim` is enabled for every workspace *test* build.** Disproved in part: `cargo
  doc --workspace --no-deps` in CI does compile the sim-off configuration, so a
  compile error cannot ship. Residual: that pass exits 0 on `dead_code`/
  `unused_imports`, and clippy `-D warnings` never runs against sim-off. Add
  `cargo clippy --workspace --lib`.
- **The multi-total reassembly reading** is justified by a rollover case that
  cannot occur — but a chunk-size change *does* produce two totals in one group
  from an honest publisher, which the machinery survives. Reduce to fixing the
  comment, not deleting the code.

---

## Dropped after challenge

**`NetError::Rekor*` variants have no consumer.** Killed. `docs/REKOR-ZONE-KEY.md:684-686`
says `synch doctor` "explains each" and never claims a per-variant `match`; the
mechanism is the per-variant `#[error(...)]` Display string, which is distinct for
every class and is exactly what doctor prints. Three supporting claims were also
wrong: `RekorAbsent` carries `key_tag: u16` not `reason: String`, the translation
has seven arms not ten, and `RekorAbsent` is not produced by it. No fix needed.

## Rejected fixes

Two proposed fixes should **not** be applied as written:

- Exiting 30 when a run sees tier-B findings and zero tier-A hands any attacker a
  remote button to wedge the operator's alerting into permanent critical, for the
  price of one self-signed certificate. The trust surface is also already printed
  on the startup line.
- Gating dial hints on this-answer bindings does not stop the attack it targets
  (M2), because the hostile answer binds the key itself. Scope the stored address
  instead.

## What was checked and found sound

Recorded so the next reader does not re-walk it: the RFC 6962 inclusion walk and
its length bounds; leaf-bytes/parsed-bytes identity; `check_binds` as exact set
equality; DSSE PAE construction; full 32-byte log-id comparison; checkpoint origin
binding against cosigned-foreign-log replay; the DER reader's length and recursion
handling; canonical SAN spelling; hickory's validating path actually running and
`Bogus`/`Insecure`/`Indeterminate` being refused; wildcard synthesis being covered
by hickory's NSEC handling; the `signing_zone ⊇ apex ⊇ domain` lattice at both
ends; TUF's dual-threshold root chain, threshold dedup, canonical JSON, clock
handling and mutex discipline; `MAX_RRSIG_VERIFICATIONS` accounting; DS matching by
digest rather than tag; and the bidirectional watch being exhaustive for
correctly-seeded lists. The published Rekor conformance fixture is genuine and is
verified end to end by both the client and the monitor.
