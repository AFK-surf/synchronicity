# Duplicated logic: what was consolidated, and what is proposed

Status: the **consolidated** section is implemented; the **proposed** section is
an audited backlog, each entry verified against the tree at the time of writing
(file references are anchors, not line-stable citations). The bar throughout:
a copy is worth consolidating when the copies must agree to be correct — a
policy rule, a wire bound, a durability step — or when they have already
drifted. A resemblance that is free to diverge is left alone.

## Consolidated

### `synch_core::fs` — the directory fsync

`fsync_parent` existed five times: the canonical `pub(crate)` copy in
`synch-store::cas`, two blocks inlined in `synch-store::backend` (in the same
crate as the helper they restate), a private re-declaration in
`synch-engine::scanner`, and `fsync_dir` in `synch-engine::uploads`, whose doc
comment — "the same posture the CAS takes" — recorded that the author knew it
was a copy. It is durability-critical (§6.2): the one implementation now lives
in `synch_core::fs`, and every crate calls it.

### `synch_core::civil` — proleptic-Gregorian date math

Howard Hinnant's `days_from_civil` / `civil_from_days` pair was written out
five times — `synch-s3::auth` (SigV4 scope dates), `synch-s3::xml`
(`Last-Modified`), `synch-net::tuf` (expiry parsing), `synch-net::sim`, and
`synch-net::x509` (validity windows) — with two different spellings of the
negative-day floor. They agreed, but arithmetic where a divergent edit is
silent is the last place to keep copies. One module, with the round-trip and
pre-epoch edges tested once.

### `synch_net::tuf::HttpRepo` — one TUF transport

The HTTPS `Repo` implementation was duplicated between `synch-net::dns` and
`synch-monitor::discover`, each with its own `MAX_TUF_BYTES`, and the daemon's
copy annotated "the monitor's copy reads the same way". The byte cap is a
defence against the party being audited, so it now exists once, beside the
`Repo` trait; the monitor keeps only its user-agent choice.

### The fetcher's dial loop (`Node::dial_provider`)

`proofs_from` and `fetch_from` each carried the dial-the-provider's-keys loop,
and the copies had already diverged into a bug: the proof path recorded only
successful dials, so a peer that was once fast and is now unreachable kept its
low latency EWMA on that path forever — precisely the "one-way ratchet" the
comment in the transfer path warns about. One loop now owns the dial, both
recordings, and the no-dialable-key error; both paths call it. **This is a
behavior fix as well as a cleanup**: failed dials now penalize the EWMA on the
proof path too.

### The folded-name claim (`mirror::claim_folded_name`)

The §7.2 first-claimant-wins rule — two published paths that fold onto one
local name are not both materializable — was copied verbatim between
`mirror::plan_pass` and `fill`, and the fill's copy carried its explanatory
comment *twice in a row*, in two wordings: evidence the region was being
hand-copied. It is a policy rule that must not differ between the two, so it
is now one function.

### Blocking-pool handoffs use `synch_core::offload`

`synch-store::backend` and `synch-cli::control::server` had each re-implemented
`synch_core::offload` by hand (both even imported `BlockingScope` to do so),
because their error types lacked a `TaskLost` impl. Both now delegate, like
`synch-engine` and `synch-net` already did. `StoreError` gained a `Blocking`
variant in the process: the old copy mapped a lost task onto `Invalid`, which
`reconcile::is_origin_store_fault` classifies as *the origin's fault* — so a
runtime shutting down mid-write could be attributed to the peer whose data was
being written.

### SQLite statement helpers in `synch-store`

- The `config` upsert was written out four times (`Store::set_config`,
  `Txn::set_config`, and two inline copies in `cas`), the delete three times,
  and `Txn::set_self_origin` / `Txn::set_membership_domain` had drifted into
  hand-inlined SQL their `Store` twins compose from helpers. One
  `set_config_in` / `clear_config_in` pair now backs all of them, following
  the file's existing `*_in` convention.
- `Store::all_heads` and `Txn::all_heads` were byte-identical except that one
  copy's warning message had already been truncated relative to the other:
  now one `all_heads_in`.
- The eight-column `blobs` row read was destructured by hand in `blob` and
  `blobs` (with `blob_candidates` deliberately narrower); a reordered schema
  change would compile cleanly and decode the wrong column. `BLOB_COLUMNS` +
  `raw_blob_row` + `blob_row_from` now exist once.
- `hash_column` had three incompatible private variants; `uploads` now uses
  the canonical one from `db`, and `sockets` routes its inline fourth copy
  through its one local `rusqlite`-flavoured helper.

### Trust-boundary parsers in `synch-net`

- `tuf::base64_decode` was byte-for-byte `rekor::base64_decode` (the file
  already imported the *encoder* from `rekor`). Both engines' padding-optional
  decoders now share one `decode_padless` body, so a hardening change to what
  these parsers accept cannot land in one and not the others.
- `tuf::spki_point` re-declared the P-256 and Ed25519 SPKI prefixes as local
  consts whose doc comment pointed at the `rekor` originals; it now uses them.

### `Hash::from_slice` at the edges

`synch-cli::control::client::hash_from`, the completion handler in
`control::server` (which ran `.expect("32")` on wire-supplied bytes behind a
length match), and `synch-s3::parse_root` each re-derived the 32-byte
conversion; all three now sit on `Hash::from_slice`, keeping their own error
semantics. The server no longer has a panic path reachable from a malformed
request.

## Proposed

Ordered by value. Each entry names the duplication, the sites, and the shape
of the abstraction; none is started here.

### 1. Client request/response boilerplate in `synch-net`

Eight near-identical methods (`MptClient::{push_head, get_nodes, get_values,
find_providers, get_bindings, head_exchange}`, `BlobClient::{get_slice,
get_proof}`) repeat open-bi → `write_frame` → `finish` → `read_frame` →
match, under `under_deadline`. The drift is already user-visible: the MPT
methods unwrap `MptMessage::Error { reason }` into `NetError::Unexpected`,
while the blob pair does not, so a blob provider's error text is reported as
"expected ProofEnd" rather than its reason. Proposal: an `exchange` helper in
`frame.rs` returning the decoded first frame plus the still-open `RecvStream`,
with the `Error`-variant unwrapping expressed once over both message enums.

### 2. `Put` / `PartUpload` streaming writes (three layers, six copies)

`synch-cli::control::client` has two ~60-line state machines differing only in
proto types and five error strings — with one real, undocumented asymmetry:
`Put::abort` propagates a send failure, `PartUpload::abort` swallows it.
`synch-s3::daemon::{put, upload_part}` duplicate the body-streaming loop
line-for-line ("The same shape as `Daemon::put`, and for the same reasons"),
and `control::server::{put, upload_part}` duplicate the spawn-and-select
shell (the inner `drain` is already shared and is the model). Proposal: a
small trait over the two proto message families and one generic writer in the
client; one `stream_body` helper in the gateway. Resolve the `abort` asymmetry
deliberately, not by picking whichever copy survives.

### 3. `TufKey` / `LogKey` are one key type written twice

`rekor::LogKey` and `tuf::TufKey` carry the same
`{scheme, uncompressed point}` with the same `verify` (both ECDSA encodings,
documented at length in both places) and the same SPKI strip-and-prepend.
Proposal: a private `pubkey` module with `RawKey { scheme, point }` and
`from_spki` / `from_raw` / `verifies`; `LogKey` keeps its `id`/`origin`
wrapper, `TufKey` becomes a newtype. This is the crate's only signature
verification code — the one place a fix must not have to land twice.

### 4. `synch-sock`'s `Inner` built field-by-field twice

`run_job` and `declare_here` each construct the 24-field invocation state, one
for serving and one for arming. A field defaulted differently between them is
a divergence between what arming showed the operator and what runs. Proposal:
`Inner::serving(..)` / `Inner::declaring(..)` over one base constructor. The
second half of this item — one loader construction and one
load-pin-entrypoint-check shared by both paths — is done (`stack_loader` /
`load_pinned` in `runtime/mod.rs`), which matters more now that the loader
carries a per-declaration stack configuration.

### 5. Unique staging/temp-file naming

Seven-plus sites across `synch-store` and `synch-engine` use three distinct
uniqueness schemes — `(pid, counter)`, `(pid, now_ns)`, and a hashed triple —
and the weakest (`now_ns`, collision within one clock tick) guards the write
path with the strongest stated requirement (`scanner`'s adoption staging).
`synch-net::tuf` and `synch-monitor::state` carry a fourth, byte-identical
`unique_temporary` pair. Proposal: `synch_core::fs::unique_suffix()` —
`(pid, process-local counter)` — used by all of them; fold the atomic
write-fsync-rename-fsync ritual (four copies, disagreeing on temp cleanup and
directory fsync) into a `synch_core::fs::write_atomic` while there.

### 6. The membership gate in `synch-net::sock`

`SockProtocol::accept` re-states `serve_connection`'s trusted-peer gate and
per-stream re-check (`serve.rs` refuses connections one way, `sock.rs` copies
it), in a file whose own docs say "one implementation, because two drift".
The rest of `sock`'s accept loop is deliberately different; only the gate
should be extracted (`admit` / `still_admitted` in `serve.rs`).

### 7. Postcard codec error mapping

`.map_err(|e| EngineError::Record(e.to_string()))` around
`postcard::to_stdvec`/`from_bytes` appears ~17 times in `synch-engine` (which
already has `decode_entry` for one direction of one type) and four times in
`synch-store::views` with `StoreError::Decode`. Proposal: `encode`/`decode`
in `synch_core::record` returning `KeyError`, absorbed by each crate's
existing `From`.

### 8. Smaller, worthwhile

- **`jittered` twice in `synch-engine`** with different distributions and
  seed quality (`aae` is `0.5–1.5×base`, xorshift-mixed; `cloud::attach` is
  `1.0–1.5×base`, raw multiply). Same name, same crate, different semantics:
  a reader trap. If attach genuinely wants never-shorter-than-base, name it.
- **`GetNodes`/`GetValues` answer budget** (`synch-net::mpt`): the
  budget-with-one-oversized-answer rule and the per-hash dedup are stated
  twice, one annotated "as `GetNodes` above". A small accumulator type would
  hold the §12 bound once.
- **Windowed fetch loop** (`synch-net::blob`): `fetch_into` and
  `fetch_proof_into` share the take-window / retire-either-way / barren-count
  skeleton, both copies documenting that the rule must hold on both paths.
- **The trie walk driver** (`synch-mpt`): `collect` and `diff_walk` duplicate
  the explicit-stack descent with the `MAX_DEPTH_NIBBLES` and `FanoutGuard`
  defences; a `Descent` visitor would hold the hostile-trie invariants once.
- **Standing-loop skeleton** (`synch-engine`): `run_mirrors`/`run_replicas`
  are the same wake/interval/shutdown select; eight sites also carry a
  two-line pin dance that `publisher.rs` writes in one.
- **Backend row-or-adopt and size-check** (`synch-store::backend`): the
  adoption fallback twice and the size-mismatch error four times under three
  different predicates that deserve names.
- **Binary entrypoints**: `synch-cli` and `synch-s3` duplicate the TLS
  install / `SYNCH_LOG` subscriber / broken-pipe exit; `synch-monitor` has
  only the first, so `SYNCH_LOG` does nothing there and a broken pipe exits
  30 against its documented exit codes. Consolidating fixes the monitor.
- **`synch-s3` append-only config logs**: `buckets` and `auth` restate the
  fold/last-writer-wins/append-removal invariants; one generic record log
  with one test would state them once.
- **Guest-argument unwrap in `synch-sock::helpers`**: the same four-line
  match ~36 times; a `guest!` macro beside `ret` removes ~110 lines from a
  file whose auditability matters.
- **Coarse duration ladders** (`synch-cli::render`, three variants) and the
  **JSON string escape table** (`render` and `rekor`, identical arms): cheap
  merges, low drift risk.
- **Raw `spawn_blocking` without `BlockingScope`** in `synch-monitor::main`
  and `synch-net::dns`: not duplication but the gap the shared `offload`
  exists to close — `assert_off_runtime` fires spuriously under them in
  debug builds.
