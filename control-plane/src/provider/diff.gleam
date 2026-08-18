//// The pure half of reconciliation: what the provider holds below the apex
//// versus what the zone wants, as a change set — or a refusal.
////
//// The apex is a name this deployment owns outright
//// (docs/EXTERNAL-DNS-PROVIDER.md §5.2), which is what lets the scope be
//// structural: every TXT record strictly below it is ours to reconcile, so a
//// record down there that the renderer did not produce is drift and drift is
//// removed. Two rules keep that power from ever pointing at a zone this
//// deployment does not own, and they live here so a table test can hold each
//// one still:
////
////   - **Ownership.** Deletes require the marker at
////     `_synchronicity-owner.<apex>`, carrying the scope it authorizes.
////     Absent it, a record below the apex that we did not render is a named
////     conflict and the pass touches nothing — which is what a first sync
////     against an apex somebody else is using looks like. Byte-equal records
////     are adopted silently, because re-creating what is already right is how
////     a migration stays boring.
////   - **TXT only.** A leg lists nothing else, so a record of another type
////     below the apex never reaches this module: it cannot be deleted and
////     cannot be a conflict. The rule is structural rather than checked.

import gleam/int
import gleam/list
import gleam/order
import gleam/string
import provider/provider.{type Changes, type Existing, type Record, Changes}

/// The marker's owner label, below the apex.
pub const owner_label = "_synchronicity-owner"

/// The marker's value: the external-dns "heritage" convention, plus the
/// scope it authorizes.
///
/// The scope rides in the value because the value is what gates deletes. A
/// reconciler that finds a marker it does not recognise holds a zone whose
/// contents it has no licence to remove, and says so instead of guessing.
pub const owner_value = "heritage=synchronicity-cp,scope=apex"

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
  /// A name below the apex holds a record we did not render, and no
  /// ownership marker says this apex is ours to correct.
  Foreign(name: String, value: String)
  /// The marker name holds something that is not this deployment's marker.
  ///
  /// Its own conflict because its own remedy: every other conflict is a
  /// record that belongs somewhere else, while this one is a marker written
  /// by a different control plane — or by a build whose scope was narrower
  /// than this one's. Overwriting it would hand this reconciler a licence to
  /// delete that nobody granted it, so it is refused until somebody removes
  /// the record and lets this deployment write its own.
  MarkerMismatch(name: String, value: String)
}

/// Computes the change set. `existing` is every TXT record the provider
/// holds strictly below the apex.
///
/// Equivalent to [`diff_gated`] with the transparency gate open, which is
/// what every caller outside the reconciler wants.
pub fn diff(
  desired: List(Record),
  existing: List(Existing),
) -> Result(Changes, Conflict) {
  diff_gated(desired, existing, [])
}

/// The same, told which records the transparency gate withheld.
///
/// `withheld` is what `render_external.render` produced and
/// `render_external.render_gated` then dropped: the membership this pass
/// *would* have published if a live zone key were covered by a verified
/// record. That cannot be recovered from `desired`, because "the gate is
/// armed" and "the last device was revoked" both arrive here as a desired set
/// with no membership in it, and they call for opposite actions.
///
/// It is a list of records rather than a flag, and that distinction is the
/// whole of the safety here. A flag can only say "shield membership", which a
/// name-shaped predicate then reads as "shield anything named like
/// membership" — including a revoked device's record, which is exactly the
/// record the renderer stopped producing, and including a TXT an attacker
/// planted at a `_synchronicity.*` name this deployment never rendered. Both
/// are `foreign`, both match the shape, and both would be frozen in the zone
/// for as long as the gate stayed armed, which is unbounded. Matching the
/// actual withheld records by name *and* value shields the set that was
/// withheld and nothing else.
pub fn diff_gated(
  desired: List(Record),
  existing: List(Existing),
  withheld: List(Record),
) -> Result(Changes, Conflict) {
  // The marker has to be *ours*, by name and by value. Checking only the
  // leftmost label made any control plane's marker satisfy every other one's
  // ownership test, and checking only the value would let an older scope
  // authorize a wider one.
  let ours =
    list.filter_map(desired, fn(d) {
      case d.value == owner_value && starts_with_label(d.name, owner_label) {
        True -> Ok(d.name)
        False -> Error(Nil)
      }
    })
  let owned =
    list.any(existing, fn(e) {
      e.record.value == owner_value && list.contains(ours, e.record.name)
    })

  // A record is matched by content, not by id: (name, value) — type is
  // always TXT on both sides by the scope rule, and TTL alone never makes a
  // record foreign (it makes it a replace).
  let matches = fn(e: Existing, d: Record) {
    e.record.name == d.name && e.record.value == d.value
  }
  let foreign =
    list.filter(existing, fn(e) { !list.any(desired, fn(d) { matches(e, d) }) })

  // A marker that is not ours is reported as itself, ahead of anything else
  // it makes foreign: it is the reason the pass cannot proceed, and it is the
  // one conflict an operator fixes by deleting rather than by moving.
  let stale_marker =
    list.find(foreign, fn(e) { starts_with_label(e.record.name, owner_label) })

  case owned, stale_marker, foreign {
    False, Ok(marker), _ ->
      Error(MarkerMismatch(marker.record.name, marker.record.value))
    False, _, [first, ..] ->
      Error(Foreign(first.record.name, first.record.value))
    _, _, _ -> {
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
      Ok(Changes(
        create: list.sort(create, by_priority),
        replace: replace,
        delete: deletable(foreign, desired, withheld),
      ))
    }
  }
}

/// The drift that may actually be removed.
///
/// Everything foreign, except this: when the desired set carries **no** proof
/// records, the published ones stay where they are. "Nothing to publish" is not
/// "what is published is wrong" — it is what `rekor/store.servable` answers
/// during a transparency gap, when no live key is covered by a verified record.
/// Deleting the proofs there would take the zone's transparency records out at
/// the one moment they are hardest to replace, and it would do it as a side
/// effect of a pass that changed nothing else. Serve mode's posture in the same
/// situation is to refuse to emit and leave the published zone standing, and
/// this is that posture.
///
/// A desired set that *does* carry proofs diffs normally, so a refreshed proof
/// still replaces the chunks it supersedes.
///
/// Membership withheld by the require-gate gets the same shield on the same
/// reasoning. What is published is not wrong — it is the set this control
/// plane rendered from its own tables this very pass and then held back
/// because a live zone key is not yet covered. Deleting it would take the
/// zone's *product* down as a side effect of a transparency gap, and it would
/// do so globally: `omit_members` is armed by any uncovered observed key,
/// including a next key pre-published for a rotation that is not signing
/// anything yet, so the common trigger is a routine RFC 6781 rollover rather
/// than an attack. It would also reach past the policy it enforces —
/// membership TXT *is* the member set, so a client running `RekorPolicy::Off`
/// loses its peers to a gate it opted out of. Withholding leaves
/// last-known-good standing and lets `require` clients fail closed on the
/// missing proof, which is the design working rather than the publisher
/// pre-empting it.
///
/// The shield is the withheld records themselves, matched by name *and*
/// value. It is deliberately not a predicate over names: a revoked device's
/// record and a forged one both carry a membership-shaped name and neither is
/// in `withheld`, because the renderer did not produce them this pass. A
/// name-shaped shield would freeze both in the zone for as long as the gate
/// stayed armed — which is unbounded, and which an attacker who can get one
/// uncovered key observed can arm at will.
fn deletable(
  foreign: List(Existing),
  desired: List(Record),
  withheld: List(Record),
) -> List(Existing) {
  let keep_proofs = !list.any(desired, fn(d) { is_proof_name(d.name) })
  list.filter(foreign, fn(e) {
    let shielded =
      { keep_proofs && is_proof_name(e.record.name) }
      || list.any(withheld, fn(w) {
        w.name == e.record.name && w.value == e.record.value
      })
    !shielded
  })
}

/// Whether a name is one of the proof names: the base name every proof's
/// part 1 shares, or `_synchronicity-rekor-<n>` for a later part.
fn is_proof_name(name: String) -> Bool {
  starts_with_label(name, "_synchronicity-rekor") || is_part(name)
}

/// Creates go out in dependency order rather than name order.
///
/// The marker first, because it is what authorizes everything else and a
/// first sync that stopped after it has still made the zone ours. The
/// declaration next, because every logged claim is a signed copy of it and a
/// zone without one has no working transparency at all. Membership after
/// that, because it is the product. The proofs last, because they are the
/// only records big enough for a provider to refuse on size, and a refused
/// proof must never be the reason a device add did not land.
fn by_priority(a: Record, b: Record) -> order.Order {
  case int.compare(priority(a.name), priority(b.name)) {
    order.Eq ->
      case string.compare(a.name, b.name) {
        order.Eq -> string.compare(a.value, b.value)
        other -> other
      }
    other -> other
  }
}

fn priority(name: String) -> Int {
  case starts_with_label(name, owner_label) {
    True -> 0
    False ->
      case starts_with_label(name, "_synchronicity-transparency") {
        True -> 1
        False ->
          case is_proof_name(name) {
            True -> 3
            False -> 2
          }
      }
  }
}

/// `_synchronicity-rekor-<n>`, the later parts of a proof.
fn is_part(name: String) -> Bool {
  case string.split_once(name, ".") {
    Ok(#(first, _)) -> string.starts_with(first, "_synchronicity-rekor-")
    Error(Nil) -> False
  }
}

/// Whether a fully-qualified name's leftmost label is `label`.
fn starts_with_label(name: String, label: String) -> Bool {
  case string.split_once(name, ".") {
    Ok(#(first, _)) -> first == label
    Error(Nil) -> name == label
  }
}
