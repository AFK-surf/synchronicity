//// The external DNS provider, as the reconciler needs it: list the TXT
//// records you hold below the apex, apply this change set.
////
//// A record-of-functions, like `rekor/client.Log`:
//// tests drive the reconciler with an in-memory fake, the real legs
//// (`provider/cloudflare`, `provider/bunny`) build the HTTP half, and
//// `log_only` is the mailer-style dry-run for an operator who wants to see
//// the change set before handing over a write credential.
////
//// The scope a leg lists by is structural: every TXT record strictly below
//// the apex, and nothing else (docs/EXTERNAL-DNS-PROVIDER.md §5.2). The apex
//// is a name this deployment owns outright, so everything beneath it is ours
//// to reconcile — and the apex itself is excluded, because that is where the
//// zone's own SOA, NS and DNSKEY live along with whatever a registrar asks
//// for.

import gleam/int
import gleam/io
import gleam/list
import gleam/string

/// The record types external mode manages.
///
/// Every record this deployment publishes is TXT — membership, the
/// transparency proofs, the declaration and the ownership marker — and a leg
/// lists nothing else. A record of any other type below the apex is
/// therefore invisible to the diff rather than something it needs a rule
/// about: it can never collide with a name we publish, and we can never
/// delete what we could not have created.
pub type Rtype {
  Txt
}

/// One desired record, provider-neutral. `value` is the full unchunked
/// string; splitting into 255-byte character-strings is a wire concern each
/// leg handles the way its provider requires.
pub type Record {
  Record(name: String, rtype: Rtype, ttl: Int, value: String)
}

/// A record as the provider holds it. `id` is the provider's handle for
/// updates and deletes — an opaque string, empty where a provider has no
/// per-record ids.
pub type Existing {
  Existing(id: String, record: Record)
}

/// What an apply pass does, in the order it does it.
pub type Changes {
  Changes(
    create: List(Record),
    replace: List(#(Existing, Record)),
    delete: List(Existing),
  )
}

/// One change the provider refused, named so an operator can see which
/// record is stuck without reading the whole zone back.
pub type Failure {
  Failure(name: String, reason: String)
}

/// What an apply pass achieved.
///
/// A refused record does not stop the ones behind it. The diff is
/// idempotent, so the next sweep retries exactly what failed — and nothing
/// this deployment publishes is important enough to be worth holding the
/// rest of the zone hostage to. A proof record too large for its owner name
/// must never delay a membership change.
pub type Applied {
  Applied(ok: Int, failed: List(Failure))
}

pub fn no_changes(changes: Changes) -> Bool {
  changes == Changes([], [], [])
}

pub type Provider {
  Provider(
    /// Every TXT record the provider holds strictly below the apex, after
    /// pagination.
    list: fn() -> Result(List(Existing), String),
    /// Applies every change it can and reports the ones it could not. The
    /// outer `Error` is for a failure that says nothing about any single
    /// record — a rejected credential, an unreachable API — and leaves the
    /// zone exactly as it was.
    apply: fn(Changes) -> Result(Applied, String),
    /// For the boot log, like `mailer.describe`.
    describe: String,
  )
}

/// Whether `name` sits strictly below `apex`: the scope every leg lists by.
///
/// Equality is deliberately not below. DNS names are case-insensitive and
/// providers hand them back lowercased, so both sides are folded before the
/// comparison rather than trusting either.
pub fn below(name: String, apex: String) -> Bool {
  let name = string.lowercase(name)
  let apex = string.lowercase(apex)
  name != apex && string.ends_with(name, "." <> apex)
}

/// Tallies a leg's per-record outcomes into an `Applied`.
pub fn tally(outcomes: List(#(String, Result(Nil, String)))) -> Applied {
  let failed =
    list.filter_map(outcomes, fn(outcome) {
      let #(name, result) = outcome
      case result {
        Ok(Nil) -> Error(Nil)
        Error(reason) -> Ok(Failure(name, reason))
      }
    })
  Applied(list.length(outcomes) - list.length(failed), failed)
}

/// The dry-run leg: lists nothing, applies nothing, prints what it would
/// have done. `list` returning empty means every desired record shows up as
/// a create — which is exactly the preview an operator wants.
pub fn log_only() -> Provider {
  Provider(
    list: fn() { Ok([]) },
    apply: fn(changes) {
      io.println(
        "provider (log-only): would create "
        <> int.to_string(list.length(changes.create))
        <> ", replace "
        <> int.to_string(list.length(changes.replace))
        <> ", delete "
        <> int.to_string(list.length(changes.delete)),
      )
      changes.create
      |> list.each(fn(record) {
        io.println("  + " <> record.name <> " TXT " <> preview(record.value))
      })
      Ok(
        Applied(
          list.length(changes.create)
            + list.length(changes.replace)
            + list.length(changes.delete),
          [],
        ),
      )
    },
    describe: "log-only (no credentials; prints the change set)",
  )
}

fn preview(value: String) -> String {
  case string.length(value) > 60 {
    True -> string.slice(value, 0, 57) <> "..."
    False -> value
  }
}
