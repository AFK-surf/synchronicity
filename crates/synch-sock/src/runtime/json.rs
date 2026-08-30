//! Host-side JSON values, for the `sy_json_*` helper family
//! (`docs/SOCKETS.md` §7.7).
//!
//! A guest has no heap, so structured data crosses the pointer cage as a
//! *handle* to a value the host owns — the same design as [zeroserve]'s JSON
//! API, which this one follows: parse or build a document host-side, navigate
//! and read it through small integer handles, and pay guest memory only for
//! the scalars actually copied out.
//!
//! Every handle owns its own value. Navigation (`sy_json_get`,
//! `sy_json_array_get`) hands back a *copy* as a fresh handle; insertion
//! (`sy_json_set`, `sy_json_array_push`) copies the inserted value into the
//! target. There is deliberately no aliasing: two handles never share
//! structure, so no mutation can act at a distance and no cycle can be
//! constructed. What that costs — a deep copy per navigation step — is bounded
//! by the same per-value size cap that bounds everything else here.
//!
//! [zeroserve]: https://github.com/losfair/zeroserve

use std::cell::RefCell;

use serde_json::Value;

use crate::abi::{errno, json_type};

/// The most serialized bytes one JSON value may reach, as
/// [`json_size`] estimates them.
///
/// The bound exists so the per-mutation size walk stays cheap — every
/// mutating helper re-walks the value it changed — and so a single value
/// cannot claim the whole per-invocation footprint. It is charged against the
/// same 1 MiB footprint the object table uses, so JSON, pending reads and
/// cursors share one documented budget.
pub(crate) const MAX_JSON_BYTES: u64 = 64 * 1024;

/// The deepest nesting one JSON value may reach.
///
/// Enforced on every parse and every mutation, which is what makes the
/// recursive walks here safe: a guest that repeatedly inserts a value into
/// itself doubles its depth per call, and without this cap the host-side
/// recursion — sizing, copying, serializing — would be the thing that broke.
pub(crate) const MAX_JSON_DEPTH: usize = 64;

/// One JSON value the guest holds a handle to.
#[derive(Debug)]
pub(crate) struct JsonSlot {
    pub(crate) value: RefCell<Value>,
    /// What [`json_size`] said when the value was last charged, so the
    /// footprint released on `sy_close` is exactly what was taken.
    pub(crate) charged: std::cell::Cell<u64>,
}

impl JsonSlot {
    pub(crate) fn new(value: Value, charged: u64) -> Self {
        JsonSlot {
            value: RefCell::new(value),
            charged: std::cell::Cell::new(charged),
        }
    }
}

impl Drop for JsonSlot {
    fn drop(&mut self) {
        // Best-effort credential hygiene: an SSH auth event's JSON carries the
        // password the client sent, and the zeroization rule for host-side
        // copies (`docs/SSH-SOCKETS.md` §12.4) covers this copy too. Zeroing
        // every string is cheaper than knowing which one was a secret.
        zeroize_strings(self.value.get_mut());
    }
}

pub(crate) fn zeroize_strings(value: &mut Value) {
    match value {
        Value::String(s) => {
            // All-zero bytes are valid UTF-8, so the invariant `as_mut_vec`
            // asks the caller to keep holds.
            unsafe { s.as_mut_vec() }.fill(0);
        }
        Value::Array(items) => items.iter_mut().for_each(zeroize_strings),
        Value::Object(map) => map.values_mut().for_each(zeroize_strings),
        _ => {}
    }
}

/// The size charged for `value`, or `Err(ELIMIT)` past either bound.
///
/// An estimate of the serialized form, deliberately rounded up: scalars are
/// charged like the pointers that hold them, strings and keys carry the
/// `String` header. Checking depth in the same walk is what lets every other
/// recursive walk here assume a bounded value.
pub(crate) fn json_size(value: &Value) -> Result<u64, i64> {
    fn walk(value: &Value, depth: usize) -> Result<u64, i64> {
        if depth > MAX_JSON_DEPTH {
            return Err(errno::ELIMIT);
        }
        let bytes = match value {
            Value::Null | Value::Bool(_) | Value::Number(_) => 8,
            Value::String(s) => 16 + s.len() as u64,
            Value::Array(items) => {
                let mut total = 16u64;
                for item in items {
                    total = total.saturating_add(walk(item, depth + 1)?);
                }
                total
            }
            Value::Object(map) => {
                let mut total = 16u64;
                for (key, item) in map {
                    total = total
                        .saturating_add(16 + key.len() as u64)
                        .saturating_add(walk(item, depth + 1)?);
                }
                total
            }
        };
        if bytes > MAX_JSON_BYTES {
            return Err(errno::ELIMIT);
        }
        Ok(bytes)
    }
    walk(value, 0)
}

/// The `SY_JSON_*` tag for a value.
pub(crate) fn type_tag(value: &Value) -> i64 {
    match value {
        Value::Null => json_type::NULL,
        Value::Bool(_) => json_type::BOOL,
        Value::Number(_) => json_type::NUMBER,
        Value::String(_) => json_type::STRING,
        Value::Array(_) => json_type::ARRAY,
        Value::Object(_) => json_type::OBJECT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn size_walk_charges_strings_and_refuses_depth() {
        assert_eq!(json_size(&Value::Null).unwrap(), 8);
        assert_eq!(json_size(&json!("abcd")).unwrap(), 20);
        assert!(json_size(&json!({"k": [1, 2]})).unwrap() > 16);

        let mut deep = json!(1);
        for _ in 0..=MAX_JSON_DEPTH {
            deep = Value::Array(vec![deep]);
        }
        assert_eq!(json_size(&deep), Err(errno::ELIMIT));
    }

    #[test]
    fn dropping_a_slot_zeroizes_its_strings() {
        let value = json!({"password": "hunter2", "list": ["secret"]});
        let mut slot = JsonSlot::new(value, 0);
        zeroize_strings(slot.value.get_mut());
        assert_eq!(
            *slot.value.borrow(),
            json!({"password": "\0\0\0\0\0\0\0", "list": ["\0\0\0\0\0\0"]})
        );
    }
}
