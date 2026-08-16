//// Client for the `synch-rekor` port program: every rekor wire format, in
//// one implementation, in a separate OS process.
////
//// The formats a zone-key entry is made of — the in-toto Statement, the DSSE
//// PAE, the `hashedrekord` body, the certificate and its two extensions, the
//// `RekorProof` v3 record — are the same bytes the client
//// (crates/synch-net) and the monitor read. They used to be written twice,
//// once there and once here, and the two drifted: an entry-kind check this
//// side skipped, an oversized field this side wrapped modulo 65536 while the
//// other clamped it, and a DNS-name comparison rule that was wrong on one
//// side and let an entry every client accepted land in a monitor's silent
//// bin. So there is one implementation now, in Rust, and this module is how
//// the BEAM reaches it.
////
//// The mechanism is the one this service already uses for SQLite
//// (`store/sqlite`, `csqlite/`): a small port program speaking a
//// length-framed stdio protocol, one OS process, {packet,4} both ways, no
//// NIFs. A fault in the parser kills that process and nothing else.
////
//// Unlike csqlite the program is **stateless**: every request carries
//// everything it needs, so a session is opened for the length of one publish
//// run and closed after, and a crashed process costs a reopen and nothing
//// more.
////
//// **Every failure here is a refusal, never a pass.** A missing binary, a
//// crash, a timeout and a verification error all come back as errors the
//// caller must propagate — `rekor/publish` stores nothing it did not get an
//// affirmative answer for, which is the one property the verify-before-store
//// step exists to provide.
////
//// The protocol is documented once, in crates/synch-rekor-port/src/main.rs;
//// the encoders below are its other half.

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result

/// An Erlang port handle (opaque, from cp_port_ffi).
pub type Port

/// Transport-level failures, distinct from the program's own refusals.
pub type PortError {
  Closed
  Timeout
}

@external(erlang, "cp_port_ffi", "priv_path")
fn priv_path(file: String) -> Result(String, Nil)

@external(erlang, "cp_port_ffi", "open")
fn port_open(exe: String, args: List(String)) -> Result(Port, Nil)

@external(erlang, "cp_port_ffi", "rpc")
fn port_rpc(
  port: Port,
  payload: BitArray,
  timeout_ms: Int,
) -> Result(BitArray, PortError)

@external(erlang, "cp_port_ffi", "close")
fn ffi_close(port: Port) -> Nil

/// One open port program, usable only from the process that opened it — the
/// port delivers its replies to its owner and to nobody else.
pub opaque type Session {
  Session(port: Port)
}

/// Why an operation did not produce an answer.
pub type Failure {
  /// The port program refused. `code` is the failure class (see `Class` in
  /// crates/synch-rekor-port/src/main.rs) and `message` is the same sentence
  /// a client would print for the same bytes — deliberately, because this
  /// service's job is to refuse exactly what a client would.
  Refused(code: Int, message: String)
  /// No answer at all: the binary is missing, the process crashed, the reply
  /// did not parse, or the deadline passed. Never a verdict; the caller must
  /// fail closed.
  Unavailable(String)
}

/// Rendered for an operator, who wants the sentence and not the taxonomy.
pub fn describe(failure: Failure) -> String {
  case failure {
    Refused(_, message) -> message
    Unavailable(why) -> why
  }
}

/// One link of the DNSSEC chain an entry carries: a zone, and the
/// uncompressed wire-format RRs it owns. Collected over DoH by `rekor/chain`
/// and DER-encoded by the port program, which is also what validates it.
pub type ChainLink {
  ChainLink(zone: String, rrs: BitArray)
}

/// What a `rekor-publish` run submits to the log.
pub type Minted {
  Minted(
    /// SHA-256 of the zone key's DER SubjectPublicKeyInfo: the identity a
    /// stored record is filed under. A key tag is a 16-bit checksum and two
    /// keys can share one, so the tag selects and this identifies.
    key_id: BitArray,
    /// The canonical in-toto Statement bytes — the DSSE PAE preimage.
    statement: BitArray,
    /// SHA-256 of that PAE: what a `hashedrekord` entry commits to.
    digest: BitArray,
    /// The DER ECDSA signature over the PAE, by the zone key itself.
    signature: BitArray,
    /// The verifier certificate, carrying the apex and the two extensions.
    certificate: BitArray,
    /// True when a previously logged entry already said everything this run
    /// has to say, so its signature and certificate were reused verbatim —
    /// which is what makes a republish a refresh rather than a second claim.
    reused: Bool,
  )
}

/// What verifying a returned entry established.
pub type Verified {
  Verified(
    /// The `RekorProof` v3 record, base64url — the exact string one TXT
    /// record carries. Produced only for an entry that verified.
    proof_txt: String,
    /// SHA-256 of the pinned log key's DER SubjectPublicKeyInfo.
    log_id: BitArray,
    /// True when the entry carries no DNSSEC chain — only ever a `retire`.
    chainless: Bool,
    /// The predecessor key tag the succession countersignature names, if the
    /// entry carries one. Its absence is a tier B alert in every monitor
    /// watching the zone, so the operator is told either way.
    countersigned_by: Option(Int),
    /// The tree size the checkpoint commits to.
    tree_size: Int,
    /// The checkpoint's origin line — which log, in its own words.
    origin: String,
    /// The action the Statement carries, re-read from what was logged.
    action: String,
  )
}

/// How long to wait for one answer. The work is local and bounded — a chain
/// walk over a handful of RRsets — so a deadline this generous can only be
/// reached by a process that is not coming back.
const rpc_timeout_ms = 60_000

/// Starts the port program. One process per publish run.
pub fn open() -> Result(Session, Failure) {
  let missing =
    Unavailable(
      "priv/synch-rekor is missing: build it (make -C rekorport). Nothing is"
      <> " published without it — the entry a client will verify has to be"
      <> " verified here first.",
    )
  use exe <- result.try(result.replace_error(priv_path("synch-rekor"), missing))
  use port <- result.try(result.replace_error(port_open(exe, []), missing))
  Ok(Session(port))
}

pub fn close(session: Session) -> Nil {
  ffi_close(session.port)
}

/// Resolves the pinned log key: the DER SubjectPublicKeyInfo and the log id
/// it implies. An empty path is the embedded key of the default public log.
///
/// Called before anything is submitted, so a key file this service cannot
/// read is an error at the terminal rather than after an entry is already in
/// a permanent public log.
pub fn log_key(
  session: Session,
  path: String,
) -> Result(#(BitArray, BitArray), Failure) {
  use reply <- result.try(rpc(session, <<0x01, text(path):bits>>))
  case reply {
    <<0x81, len:int-size(32), spki:bytes-size(len), log_id:bytes-size(32)>> ->
      Ok(#(spki, log_id))
    other -> Error(expect_error(other))
  }
}

/// Builds the certificate, the Statement and the signature for one entry.
///
/// `priors` are the `(statement, canonicalized_body)` pairs already stored
/// for this key tag and action. The port program reuses one when this run has
/// nothing new to say, which is what makes a republish a refresh rather than
/// a second public claim about one key.
pub fn mint(
  session: Session,
  apex apex: String,
  key_file key_file: String,
  action action: String,
  now now: Int,
  replaces replaces: Option(Int),
  predecessor_key_file predecessor: String,
  anchor_file anchor: String,
  links links: List(ChainLink),
  priors priors: List(#(BitArray, BitArray)),
) -> Result(Minted, Failure) {
  let payload =
    bit_array.concat([
      <<0x02>>,
      text(apex),
      text(key_file),
      text(action),
      <<now:int-size(64)>>,
      case replaces {
        Some(tag) -> <<1:int-size(8), tag:int-size(16)>>
        None -> <<0:int-size(8), 0:int-size(16)>>
      },
      text(predecessor),
      text(anchor),
      <<list.length(links):int-size(16)>>,
      bit_array.concat(
        list.map(links, fn(link) {
          bit_array.concat([text(link.zone), blob(link.rrs)])
        }),
      ),
      <<list.length(priors):int-size(8)>>,
      bit_array.concat(
        list.map(priors, fn(prior) {
          bit_array.concat([blob(prior.0), blob(prior.1)])
        }),
      ),
    ])
  use reply <- result.try(rpc(session, payload))
  case reply {
    <<
      0x82,
      key_id:bytes-size(32),
      sl:int-size(32),
      statement:bytes-size(sl),
      dl:int-size(32),
      digest:bytes-size(dl),
      gl:int-size(32),
      signature:bytes-size(gl),
      cl:int-size(32),
      certificate:bytes-size(cl),
      reused:int-size(8),
    >> ->
      Ok(Minted(key_id, statement, digest, signature, certificate, reused != 0))
    other -> Error(expect_error(other))
  }
}

/// Verifies the entry the log returned, by the rules a client applies, and
/// returns the proof record to serve.
///
/// The record comes back **only** for an entry that verified: there is no
/// path from here to a stored proof that skipped a check.
pub fn verify(
  session: Session,
  apex apex: String,
  public public: BitArray,
  key_tag key_tag: Int,
  log_index log_index: Int,
  statement statement: BitArray,
  canonicalized_body body: BitArray,
  checkpoint checkpoint: BitArray,
  inclusion_path path: List(BitArray),
  log_spki log_spki: BitArray,
  action action: String,
  anchor_file anchor: String,
) -> Result(Verified, Failure) {
  let payload =
    bit_array.concat([
      <<0x03>>,
      text(apex),
      blob(public),
      <<key_tag:int-size(16), log_index:int-size(64)>>,
      blob(statement),
      blob(body),
      blob(checkpoint),
      <<list.length(path):int-size(8)>>,
      bit_array.concat(path),
      blob(log_spki),
      text(action),
      text(anchor),
    ])
  use reply <- result.try(rpc(session, payload))
  case reply {
    <<
      0x83,
      tl:int-size(32),
      proof_txt:bytes-size(tl),
      log_id:bytes-size(32),
      chainless:int-size(8),
      has_countersigner:int-size(8),
      countersigner:int-size(16),
      tree_size:int-size(64),
      ol:int-size(32),
      origin:bytes-size(ol),
      al:int-size(32),
      action_back:bytes-size(al),
    >> -> {
      use proof_txt <- result.try(utf8(proof_txt))
      use origin <- result.try(utf8(origin))
      use action_back <- result.try(utf8(action_back))
      Ok(Verified(
        proof_txt: proof_txt,
        log_id: log_id,
        chainless: chainless != 0,
        countersigned_by: case has_countersigner {
          0 -> None
          _ -> Some(countersigner)
        },
        tree_size: tree_size,
        origin: origin,
        action: action_back,
      ))
    }
    other -> Error(expect_error(other))
  }
}

// ------------------------------------------------------------------- framing

fn rpc(session: Session, payload: BitArray) -> Result(BitArray, Failure) {
  case port_rpc(session.port, payload, rpc_timeout_ms) {
    Ok(reply) -> Ok(reply)
    Error(Closed) ->
      Error(Unavailable("the synch-rekor port program exited without answering"))
    Error(Timeout) ->
      Error(Unavailable(
        "the synch-rekor port program did not answer within the deadline",
      ))
  }
}

fn blob(bytes: BitArray) -> BitArray {
  <<bit_array.byte_size(bytes):int-size(32), bytes:bits>>
}

fn text(value: String) -> BitArray {
  blob(<<value:utf8>>)
}

fn utf8(bytes: BitArray) -> Result(String, Failure) {
  bit_array.to_string(bytes)
  |> result.replace_error(Unavailable(
    "the synch-rekor port program answered with a field that is not UTF-8",
  ))
}

/// Reads an error frame, or reports the reply this client could not read.
///
/// A reply that does not parse is a bug in one of the two halves, not an
/// operational state — but it is still a refusal, because the alternative is
/// storing a proof nobody verified.
fn expect_error(reply: BitArray) -> Failure {
  case reply {
    <<
      0x84,
      code:int-signed-size(32),
      len:int-size(32),
      message:bytes-size(len),
    >> ->
      case bit_array.to_string(message) {
        Ok(text) -> Refused(code, text)
        Error(Nil) -> Unavailable("the port program's error is not UTF-8")
      }
    _ ->
      Unavailable(
        "the synch-rekor port program answered something this build cannot read",
      )
  }
}
