//! The append-only config record log `buckets` and `auth` store their state
//! in (§9.4).
//!
//! Records are tab-separated lines under one config key, appended and never
//! rewritten: two gateways editing one value must not be able to undo each
//! other, so "replace this entry" and "remove it" are both expressed by a
//! later record winning. This module is the one statement of the fold rules
//! the two logs restated:
//!
//! - **Later records win.** A record whose first field matches an earlier
//!   entry's id replaces it.
//! - **A lone id is a removal.** The entry it names stops existing from
//!   there on.
//! - **A record nobody can read is skipped rather than fatal.** One
//!   malformed line must not cost every other entry its state — and it
//!   removes nothing, since what it meant to say is exactly what is unknown.

/// Folds a record log into the entries it describes.
///
/// `id_of` names an entry's identifying first field; `parse` builds an entry
/// from an id and the record's remaining fields, or `None` for a record it
/// cannot read.
pub(crate) fn fold<T>(
    records: &[String],
    id_of: impl Fn(&T) -> &str,
    parse: impl Fn(&str, &[&str]) -> Option<T>,
) -> Vec<T> {
    let mut out: Vec<T> = Vec::new();
    for record in records {
        let fields: Vec<&str> = record.split('\t').collect();
        let [id, rest @ ..] = fields.as_slice() else {
            continue;
        };
        if id.is_empty() {
            continue;
        }
        let entry = match rest {
            [] => None,
            rest => match parse(id, rest) {
                Some(entry) => Some(entry),
                None => continue,
            },
        };
        out.retain(|e| id_of(e) != *id);
        if let Some(entry) = entry {
            out.push(entry);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(records: &[&str]) -> Vec<(String, String)> {
        fold(
            &records.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
            |(id, _): &(String, String)| id,
            |id, rest| match rest {
                [value, ..] => Some((id.to_string(), value.to_string())),
                [] => None,
            },
        )
    }

    /// The three rules, each exercised against the others: a later record
    /// replaces, a lone id removes, and a malformed record costs only itself.
    #[test]
    fn later_wins_lone_id_removes_malformed_skips() {
        let folded = pairs(&[
            "a\t1", "b\t2", "a\t3", // later a wins
            "b",    // lone id removes b
            "\tx",  // empty id: skipped, removes nothing
            "a\t4", "b\t5", // re-add after removal
        ]);
        assert_eq!(
            folded,
            vec![
                ("a".to_string(), "4".to_string()),
                ("b".to_string(), "5".to_string())
            ]
        );
    }
}
