//// The pure half of reconciliation: what the provider holds versus what
//// the zone wants, as a change set — or a refusal.
////
//// Three rules make the reconciler incapable of eating a zone it does not
//// own, and they live here so a table test can hold each one still:
////
////   - **Scope.** Operations are computed only over the names the caller
////     listed; nothing else is ever compared, so nothing else can be
////     touched. The `_synchronicity` prefix makes the managed set disjoint
////     from human-managed records by construction.
////   - **Ownership.** The first sync writes a marker TXT
////     (`_synchronicity-owner.<apex>`). At any managed name holding data we
////     did not render, the diff refuses with a named conflict unless the
////     marker exists — byte-equal records are adopted silently, because
////     re-creating what is already right is how a migration stays boring.
////   - **No foreign types.** A non-TXT record squatting at a managed name
////     is a conflict, never a casualty; external mode only ever publishes
////     TXT and only ever deletes what it could have published.

import gleam/list
import gleam/string
import provider/provider.{type Changes, type Existing, type Record, Changes}

/// The marker's owner label, below the apex.
pub const owner_label = "_synchronicity-owner"

/// The marker's value. The external-dns "heritage" convention, so an
/// operator inspecting the zone can tell whose reconciler claims it.
pub const owner_value = "heritage=synchronicity-cp"

/// The marker record for an apex (no trailing dot in `apex_name`, matching
/// how provider APIs spell names).
pub fn owner_record(apex_name: String) -> Record {
  provider.Record(
    owner_label <> "." <> apex_name,
    provider.Txt,
    300,
    owner_value,
  )
}

pub type Conflict {
  /// A managed name holds a record we did not render, and no ownership
  /// marker says the zone is ours to correct.
  Foreign(name: String, value: String)
}

/// Computes the change set. `existing` must be the provider's records at
/// managed names only — the caller listed exactly those.
pub fn diff(
  desired: List(Record),
  existing: List(Existing),
) -> Result(Changes, Conflict) {
  let owned =
    list.any(existing, fn(e) {
      e.record.value == owner_value
      && starts_with_label(e.record.name, owner_label)
    })

  // A record is matched by content, not by id: (name, value) — type is
  // always TXT on both sides by the scope rule, and TTL alone never makes a
  // record foreign (it makes it a replace).
  let matches = fn(e: Existing, d: Record) {
    e.record.name == d.name && e.record.value == d.value
  }
  let foreign =
    list.filter(existing, fn(e) { !list.any(desired, fn(d) { matches(e, d) }) })

  case owned, foreign {
    False, [first, ..] -> Error(Foreign(first.record.name, first.record.value))
    _, _ -> {
      let create =
        list.filter(desired, fn(d) {
          !list.any(existing, fn(e) { matches(e, d) })
        })
      let replace =
        list.filter_map(existing, fn(e) {
          case
            list.find(desired, fn(d) { matches(e, d) && d.ttl != e.record.ttl })
          {
            Ok(d) -> Ok(#(e, d))
            Error(Nil) -> Error(Nil)
          }
        })
      Ok(Changes(create: create, replace: replace, delete: foreign))
    }
  }
}

/// Whether a fully-qualified name's leftmost label is `label`.
fn starts_with_label(name: String, label: String) -> Bool {
  case string.split_once(name, ".") {
    Ok(#(first, _)) -> first == label
    Error(Nil) -> name == label
  }
}
