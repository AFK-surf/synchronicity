//// The external DNS provider, as the reconciler needs it: list what you
//// hold at these names, apply this change set.
////
//// A record-of-functions, like `rekor/client.Log` and `tuf/fetch.Repo`:
//// tests drive the reconciler with an in-memory fake, the real legs
//// (`provider/cloudflare`, `provider/bunny`) build the HTTP half, and
//// `log_only` is the mailer-style dry-run for an operator who wants to see
//// the change set before handing over a write credential.

import gleam/int
import gleam/io
import gleam/list
import gleam/string

/// The record types external mode manages. Only TXT is ever published — the
/// membership records, the transparency proofs, the TUF relay and the
/// ownership marker are all TXT — but the type is named so the diff can
/// refuse foreign types at managed names by name instead of by accident.
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

pub fn no_changes(changes: Changes) -> Bool {
  changes == Changes([], [], [])
}

pub type Provider {
  Provider(
    /// Every record the provider holds at exactly these names, after
    /// pagination. Names outside the list must not come back — and are
    /// never asked about.
    list: fn(List(String)) -> Result(List(Existing), String),
    /// Applies a change set; sequential per record unless the provider
    /// offers atomicity. The diff is idempotent, so a partial apply is
    /// repaired by the next sweep rather than compensated for.
    apply: fn(Changes) -> Result(Nil, String),
    /// For the boot log, like `mailer.describe`.
    describe: String,
  )
}

/// The dry-run leg: lists nothing, applies nothing, prints what it would
/// have done. `list` returning empty means every desired record shows up as
/// a create — which is exactly the preview an operator wants.
pub fn log_only() -> Provider {
  Provider(
    list: fn(_names) { Ok([]) },
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
      Ok(Nil)
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
