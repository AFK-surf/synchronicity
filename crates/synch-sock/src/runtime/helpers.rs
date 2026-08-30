//! The host API (`docs/SOCKETS.md` §7).
//!
//! Every helper is a bare `fn` pointer that can capture nothing, so all state
//! arrives through [`HelperScope`]: guest memory through `user_memory`, and the
//! invocation through `with_resource_mut`.
//!
//! Two rules hold throughout, and both come from async-ebpf's guest memory
//! model:
//!
//! * **A guest argument is not a pointer.** It is a 64-bit integer the guest
//!   chose. `user_memory` and `user_memory_mut` are the only things that turn
//!   one into memory, and every helper here goes through them.
//! * **Bulk output is one contiguous region.** A single helper call may
//!   validate at most 4 mutable and 16 immutable regions, and a mutable region
//!   may not alias another. `sy_poll` therefore takes an array of
//!   `struct sy_pollfd` — one region however many handles it watches — rather
//!   than an out-pointer per handle, which would fail on the fifth.

use std::{rc::Rc, time::Duration};

use async_ebpf::{
    helpers::{write_cstr, Helper},
    program::HelperScope,
};
use base64::Engine as _;

use serde_json::{json, Value};

use crate::{
    abi::{errno, poll, POLLFD_SIZE, SY_SELF},
    limits::{CURSOR_ENTRY_OVERHEAD, MAX_GUEST_DURATION_MS, MAX_LOG_LINE},
    runtime::{
        ctx::{Ctx, CursorSlot, Inner, ObjectSlot, PutCommand, Slot, Slot2, WriterSlot},
        endpoint::{connect_task, Endpoint, EndpointRole, State},
        json::{json_size, type_tag, JsonSlot},
    },
};

/// The table registered with every [`ProgramLoader`](async_ebpf::program::ProgramLoader).
///
/// One table for the whole runtime rather than one per socket: async-ebpf
/// scopes helpers to the loader, and the per-helper entropy it mixes in makes
/// an index unforgeable but is not a capability check. What a *particular*
/// socket may do is decided by [`EffectivePolicy`](crate::EffectivePolicy)
/// inside the helper, not by which helpers exist.
pub(crate) const HELPERS: &[(&str, Helper)] = &[
    // diagnostics and configuration
    ("sy_log", h_log),
    ("sy_now_ms", h_now_ms),
    ("sy_monotonic_ns", h_monotonic_ns),
    ("sy_getrandom", h_getrandom),
    ("sy_version", h_version),
    ("sy_config_get", h_config_get),
    ("sy_metric_add", h_metric_add),
    ("sy_label_set", h_label_set),
    // identity
    ("sy_self_origin", h_self_origin),
    ("sy_socket_path", h_socket_path),
    ("sy_peer_origin", h_peer_origin),
    ("sy_peer_device_key", h_peer_device_key),
    ("sy_peer_info", h_peer_info),
    ("sy_peer_has_space", h_peer_has_space),
    ("sy_peer_addr", h_peer_addr),
    ("sy_conn_meta", h_conn_meta),
    ("sy_stream_index", h_stream_index),
    // JSON values (docs/SOCKETS.md §7.7)
    ("sy_json_parse", h_json_parse),
    ("sy_json_stringify", h_json_stringify),
    ("sy_json_new_object", h_json_new_object),
    ("sy_json_new_array", h_json_new_array),
    ("sy_json_type", h_json_type),
    ("sy_json_len", h_json_len),
    ("sy_json_get", h_json_get),
    ("sy_json_array_get", h_json_array_get),
    ("sy_json_read_string", h_json_read_string),
    ("sy_json_read_i64", h_json_read_i64),
    ("sy_json_read_bool", h_json_read_bool),
    ("sy_json_set", h_json_set),
    ("sy_json_remove", h_json_remove),
    ("sy_json_array_push", h_json_array_push),
    ("sy_json_set_string", h_json_set_string),
    ("sy_json_set_i64", h_json_set_i64),
    ("sy_json_set_bool", h_json_set_bool),
    ("sy_json_set_null", h_json_set_null),
    // endpoint I/O
    ("sy_read", h_read),
    ("sy_write", h_write),
    ("sy_splice", h_splice),
    ("sy_readable", h_readable),
    ("sy_writable", h_writable),
    ("sy_shutdown", h_shutdown),
    ("sy_close", h_close),
    ("sy_errno", h_errno),
    // outbound
    ("sy_tcp_connect", h_tcp_connect),
    ("sy_tcp_connect_ip", h_tcp_connect_ip),
    ("sy_endpoint_info", h_endpoint_info),
    // SSH protocol termination
    ("sy_ssh_start", h_ssh_start),
    ("sy_ssh_next", h_ssh_next),
    ("sy_ssh_event_data", h_ssh_event_data),
    ("sy_ssh_event_done", h_ssh_event_done),
    ("sy_ssh_auth_reply", h_ssh_auth_reply),
    ("sy_ssh_authorized_keys_match", h_ssh_authorized_keys_match),
    ("sy_ssh_channel_accept", h_ssh_channel_accept),
    ("sy_ssh_channel_reject", h_ssh_channel_reject),
    ("sy_ssh_channel_open", h_ssh_channel_open),
    ("sy_ssh_channel_type", h_ssh_channel_type),
    ("sy_ssh_channel_lane", h_ssh_channel_lane),
    ("sy_ssh_request_reply", h_ssh_request_reply),
    ("sy_ssh_exit_status", h_ssh_exit_status),
    ("sy_ssh_exit_signal", h_ssh_exit_signal),
    ("sy_ssh_pty_spec", h_ssh_pty_spec),
    // process and PTY backing
    ("sy_pty_open", h_pty_open),
    ("sy_process_spawn_pty", h_process_spawn_pty),
    ("sy_process_spawn", h_process_spawn),
    ("sy_process_stdio", h_process_stdio),
    ("sy_pty_resize", h_pty_resize),
    ("sy_process_status", h_process_status),
    ("sy_process_signal", h_process_signal),
    ("sy_sftp_open", h_sftp_open),
    // the one that suspends
    ("sy_poll", h_poll),
    // the tree
    ("sy_open", h_open),
    ("sy_open_from", h_open_from),
    ("sy_open_root", h_open_root),
    ("sy_stat", h_stat),
    ("sy_pread", h_pread),
    ("sy_list_open", h_list_open),
    ("sy_list_next", h_list_next),
    // writing the tree (docs/TREE-WRITES.md)
    ("sy_put_open", h_put_open),
    ("sy_put_write", h_put_write),
    ("sy_put_splice", h_put_splice),
    ("sy_put_commit", h_put_commit),
    ("sy_put_commit_if", h_put_commit_if),
    ("sy_put_delete", h_put_delete),
    // state
    ("sy_map_get", h_map_get),
    ("sy_map_set", h_map_set),
    ("sy_map_delete", h_map_delete),
    ("sy_map_incr", h_map_incr),
    ("sy_rate_limit", h_rate_limit),
    // bytes, hashes, encodings
    ("sy_memcpy", h_memcpy),
    ("sy_memcmp", h_memcmp),
    ("sy_memset", h_memset),
    ("sy_ct_eq", h_ct_eq),
    ("sy_blake3", h_blake3),
    ("sy_sha256", h_sha256),
    ("sy_hmac_sha256", h_hmac_sha256),
    ("sy_base64_encode", h_base64_encode),
    ("sy_base64_decode_in_place", h_base64_decode_in_place),
    ("sy_hex_encode", h_hex_encode),
    ("sy_hex_decode_in_place", h_hex_decode_in_place),
    // declarations
    ("sy_declare_name", h_declare_name),
    ("sy_declare_egress", h_declare_egress),
    ("sy_declare_max_streams", h_declare_max_streams),
    ("sy_declare_stack_frame_size", h_declare_stack_frame_size),
    (
        "sy_declare_guarded_stack_frames",
        h_declare_guarded_stack_frames,
    ),
    ("sy_declare_process", h_declare_process),
    ("sy_declare_file_transfer", h_declare_file_transfer),
    ("sy_declare_tree_write", h_declare_tree_write),
    ("sy_ssh_exit_status_lost", h_ssh_exit_status_lost),
];

/// Every helper name, for the SDK-header agreement test.
#[cfg(test)]
pub(crate) fn helper_names() -> Vec<&'static str> {
    HELPERS.iter().map(|(name, _)| *name).collect()
}

// ---- plumbing ------------------------------------------------------------

/// Wraps a signed return for the guest.
fn ret(value: i64) -> Result<u64, ()> {
    Ok(value as u64)
}

/// Unwraps a guest-supplied argument, answering the guest's errno and ending
/// the helper when it does not parse.
///
/// The same four-line match stood at every argument read in this file; in a
/// file whose auditability matters, the pattern deserves one name beside
/// [`ret`], so a reviewer reads the argument, not the plumbing.
macro_rules! guest {
    ($e:expr) => {
        match $e {
            Ok(value) => value,
            Err(e) => return ret(e),
        }
    };
}

/// Runs `f` with the invocation state.
///
/// A missing resource is a runtime bug rather than anything a guest can
/// provoke, and it comes back as `Err(())`, which ends the invocation — the
/// right outcome for a helper that cannot tell what it is helping.
fn with<R>(scope: &HelperScope, f: impl FnOnce(&Rc<Inner>) -> R) -> Result<R, ()> {
    scope.with_resource_mut::<Ctx, _>(|ctx| match ctx {
        Ok(ctx) => Ok(f(&ctx.inner)),
        Err(()) => Err(()),
    })
}

/// Copies a guest buffer out, rather than holding a borrow across other calls.
fn bytes(scope: &HelperScope, ptr: u64, len: u64) -> Result<Vec<u8>, i64> {
    match scope.user_memory(ptr, len) {
        Ok(slice) => Ok(slice.to_vec()),
        Err(()) => Err(errno::EINVAL),
    }
}

/// Copies a guest string out.
fn string(scope: &HelperScope, ptr: u64, len: u64) -> Result<String, i64> {
    let raw = bytes(scope, ptr, len)?;
    String::from_utf8(raw).map_err(|_| errno::EINVAL)
}

/// Writes a NUL-terminated string with `snprintf` semantics.
fn out_str(scope: &HelperScope, ptr: u64, len: u64, value: &str) -> Result<u64, ()> {
    if len == 0 {
        return ret(value.len() as i64);
    }
    let Ok(mut region) = scope.user_memory_mut(ptr, len) else {
        return ret(errno::EINVAL);
    };
    Ok(write_cstr(&[value.as_bytes()], &mut region))
}

/// Writes raw bytes, refusing rather than truncating.
///
/// Unlike a string, a short hash is not a shorter answer — it is a different
/// one, and a guest that compared it would compare something that never
/// existed.
fn out_exact(scope: &HelperScope, ptr: u64, len: u64, value: &[u8]) -> Result<u64, ()> {
    if len < value.len() as u64 {
        return ret(errno::EINVAL);
    }
    let Ok(mut region) = scope.user_memory_mut(ptr, value.len() as u64) else {
        return ret(errno::EINVAL);
    };
    region.copy_from_slice(value);
    ret(value.len() as i64)
}

/// Refuses a helper that has no business running in the given mode.
fn mode_check(inner: &Inner, declaring: bool) -> Option<i64> {
    (inner.init_mode != declaring).then_some(errno::EPERM)
}

/// The gate every `sy_declare_*` helper opens with, **before** it looks at its
/// arguments.
///
/// Declaration helpers are valid only inside `synchronicity.init`, and the
/// check has to come first rather than at the mutation, because reading the
/// arguments is not always free of consequence. `sy_declare_process` resolves
/// its executable against the host filesystem — `canonicalize`, `metadata`, a
/// mode test — and it used to do all three before reaching `mode_check`. A
/// served invocation could therefore call it purely for the return code and
/// tell `SY_ENOENT` (no such path) from `SY_EINVAL` (not a regular file) from
/// `SY_EPERM` (not executable), walking the daemon host's filesystem from an
/// ordinary stream with nothing declared. Gating at the top makes that
/// impossible for every declaration helper, including ones not yet written.
fn declaring_only(scope: &HelperScope) -> Result<Option<u64>, ()> {
    let refused = with(scope, |inner| mode_check(inner, true))?;
    Ok(refused.map(|e| e as u64))
}

/// Runs `body` only inside the init hook, answering `SY_EPERM` outside it.
macro_rules! declaring {
    ($scope:expr) => {
        if let Some(refused) = declaring_only($scope)? {
            return Ok(refused);
        }
    };
}

// ---- diagnostics and configuration ---------------------------------------

fn h_log(scope: &HelperScope, ptr: u64, len: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    let msg = guest!(bytes(scope, ptr, len.min(MAX_LOG_LINE as u64)));
    with(scope, |inner| {
        let mut buf = inner.log_buf.borrow_mut();
        for byte in msg {
            if byte == b'\n' || buf.len() >= MAX_LOG_LINE {
                let line = crate::runtime::ctx::sanitize(&buf);
                buf.clear();
                // Dropped before the emit: `remember_log` reaches the registry,
                // and holding the buffer's borrow across it is a borrow held
                // across a lock for no reason.
                drop(buf);
                inner.remember_log(&line);
                buf = inner.log_buf.borrow_mut();
                if byte == b'\n' {
                    continue;
                }
            }
            buf.push(byte);
        }
        0
    })
    .and_then(ret)
}

fn h_now_ms(_: &HelperScope, _: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    Ok(now.as_millis() as u64)
}

fn h_monotonic_ns(scope: &HelperScope, _: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    with(scope, |inner| inner.started.elapsed().as_nanos() as u64)
}

fn h_getrandom(scope: &HelperScope, ptr: u64, len: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    if len == 0 {
        return ret(0);
    }
    // The destination is the bound: the cage grants at most the guest's own
    // memory, so a length no buffer could hold is refused as an argument
    // rather than allocated for.
    let Ok(mut region) = scope.user_memory_mut(ptr, len) else {
        return ret(errno::EINVAL);
    };
    if aws_lc_rs::rand::fill(&mut region).is_err() {
        return ret(errno::EINVAL);
    }
    ret(len as i64)
}

fn h_version(scope: &HelperScope, ptr: u64, len: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    out_str(scope, ptr, len, synch_core::SOFTWARE)
}

fn h_config_get(
    scope: &HelperScope,
    key_ptr: u64,
    key_len: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = guest!(string(scope, key_ptr, key_len));
    let value = with(scope, |inner| {
        inner.policy.config_get(&key).map(str::to_string)
    })?;
    match value {
        Some(v) => out_str(scope, out_ptr, out_len, &v),
        None => ret(errno::ENOENT),
    }
}

fn h_metric_add(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    delta: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let name = guest!(string(scope, ptr, len));
    if !synch_core::display_text_is_safe(&name) {
        return ret(errno::EINVAL);
    }
    with(scope, |inner| inner.metric(&name, delta as i64)).and_then(ret)
}

fn h_label_set(
    scope: &HelperScope,
    key_ptr: u64,
    key_len: u64,
    val_ptr: u64,
    val_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = guest!(string(scope, key_ptr, key_len));
    let value = guest!(string(scope, val_ptr, val_len));
    if !synch_core::display_text_is_safe(&key) || !synch_core::display_text_is_safe(&value) {
        return ret(errno::EINVAL);
    }
    with(scope, |inner| inner.label(&key, &value)).and_then(ret)
}

// ---- identity ------------------------------------------------------------

fn h_self_origin(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let origin = with(scope, |inner| inner.self_origin.clone())?;
    out_str(scope, ptr, len, &origin)
}

fn h_socket_path(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let path = with(scope, |inner| inner.socket.qualified())?;
    out_str(scope, ptr, len, &path)
}

fn h_peer_origin(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let origin = with(scope, |inner| inner.peer.origin.canonical())?;
    out_str(scope, ptr, len, &origin)
}

fn h_peer_device_key(
    scope: &HelperScope,
    ptr: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = with(scope, |inner| {
        crate::device_key_bytes(&inner.peer.device_key)
    })?;
    out_exact(scope, ptr, 32, &key)
}

/// The caller's whole authenticated identity, as one JSON object.
///
/// `{"origin", "device_key" (hex), "kind" ("member" | "delegate"), "addr",
/// "stream_index"}` — every field a fact the iroh handshake established, and
/// `kind` a name rather than a number: the enum this replaces was the kind of
/// thing a guest compiled against a stale header read wrong silently.
fn h_peer_info(scope: &HelperScope, _: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    let value = json!({
        "origin": inner.peer.origin.canonical(),
        "device_key": hex::encode(crate::device_key_bytes(&inner.peer.device_key)),
        "kind": inner.peer.kind(),
        "addr": inner.peer.addr,
        "stream_index": inner.peer.stream_index,
    });
    ret(insert_json(&inner, value))
}

fn h_peer_has_space(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let space = guest!(string(scope, ptr, len));
    with(scope, |inner| u64::from(inner.peer.has_space(&space)))
}

fn h_peer_addr(scope: &HelperScope, ptr: u64, len: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    let addr = with(scope, |inner| inner.peer.addr.clone())?;
    out_str(scope, ptr, len, &addr)
}

fn h_conn_meta(
    scope: &HelperScope,
    key_ptr: u64,
    key_len: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = guest!(string(scope, key_ptr, key_len));
    let value = with(scope, |inner| {
        inner
            .meta
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.clone())
    })?;
    match value {
        Some(v) => out_str(scope, out_ptr, out_len, &v),
        None => ret(errno::ENOENT),
    }
}

fn h_stream_index(scope: &HelperScope, _: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    with(scope, |inner| inner.peer.stream_index)
}

// ---- JSON values ---------------------------------------------------------
//
// The structured half of the ABI (`docs/SOCKETS.md` §7.7), modeled on
// zeroserve's JSON API: values live host-side, the guest holds handles, and
// every handle owns its own value — navigation copies out, insertion copies
// in, and no two handles ever alias. Handles come out of the same table as
// endpoints and objects and are released with `sy_close`; their bytes are
// charged against the same 1 MiB footprint. Pure data manipulation, so all of
// it is valid in `synchronicity.init` too — the declaration helpers take JSON.

/// The JSON value at `handle`, or `EBADF`.
fn json_slot(inner: &Inner, handle: i64) -> Result<Rc<JsonSlot>, i64> {
    match inner.slot(handle) {
        Some(Slot2::Json(slot)) => Ok(slot),
        _ => Err(errno::EBADF),
    }
}

/// A copy of the JSON value at `handle`, for helpers that consume one.
fn json_value(inner: &Inner, handle: i64) -> Result<Value, i64> {
    json_slot(inner, handle).map(|slot| slot.value.borrow().clone())
}

/// Charges `value` and puts it in the table, returning its handle.
fn insert_json(inner: &Rc<Inner>, value: Value) -> i64 {
    let size = match json_size(&value) {
        Ok(size) => size,
        Err(error) => return error,
    };
    if inner.charge(size).is_err() {
        return errno::ELIMIT;
    }
    match inner.insert(Slot::Json(Rc::new(JsonSlot::new(value, size)))) {
        Ok(handle) => {
            inner.publish_handles();
            handle
        }
        Err(error) => {
            inner.release(size);
            error
        }
    }
}

/// Applies one mutation under the size and depth bounds, atomically.
///
/// The mutation runs on a copy, is re-measured, and replaces the slot's value
/// only once the footprint accepts the difference — so a refused mutation
/// leaves the value exactly as it was, rather than half-changed or
/// over-budget.
fn json_mutate(
    inner: &Inner,
    handle: i64,
    mutate: impl FnOnce(&mut Value) -> Result<(), i64>,
) -> i64 {
    let slot = match json_slot(inner, handle) {
        Ok(slot) => slot,
        Err(error) => return error,
    };
    // Every copy is scrubbed on the way out, not only the slot's own drop:
    // the candidate clone on a refused mutation, and the value a successful
    // one replaces — `sy_json_remove(event, "password")` is exactly the call
    // a hygienic guest makes, and it must not leave the un-scrubbed original
    // on the freed heap (`docs/SSH-SOCKETS.md` §12.4).
    let mut candidate = slot.value.borrow().clone();
    let size = match mutate(&mut candidate).and_then(|()| json_size(&candidate)) {
        Ok(size) => size,
        Err(error) => {
            crate::runtime::json::zeroize_strings(&mut candidate);
            return error;
        }
    };
    let charged = slot.charged.get();
    if size > charged {
        if inner.charge(size - charged).is_err() {
            crate::runtime::json::zeroize_strings(&mut candidate);
            return errno::ELIMIT;
        }
    } else {
        inner.release(charged - size);
    }
    slot.charged.set(size);
    let mut replaced = std::mem::replace(&mut *slot.value.borrow_mut(), candidate);
    crate::runtime::json::zeroize_strings(&mut replaced);
    0
}

fn h_json_parse(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let data = guest!(bytes(scope, ptr, len));
    let Ok(value) = serde_json::from_slice::<Value>(&data) else {
        return ret(errno::EINVAL);
    };
    let inner = with(scope, Rc::clone)?;
    ret(insert_json(&inner, value))
}

fn h_json_stringify(
    scope: &HelperScope,
    handle: u64,
    out: u64,
    out_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let mut value = match with(scope, |inner| json_value(inner, handle as i64))? {
        Ok(value) => value,
        Err(error) => return ret(error),
    };
    let text = serde_json::to_string(&value);
    // The clone and the serialized buffer are host-side copies of a value
    // that may hold a credential; scrub them like the slot's drop does.
    crate::runtime::json::zeroize_strings(&mut value);
    let Ok(mut text) = text else {
        return ret(errno::EINVAL);
    };
    let result = out_str(scope, out, out_len, &text);
    // SAFETY: all-zero bytes are valid UTF-8.
    unsafe { text.as_mut_vec() }.fill(0);
    result
}

fn h_json_new_object(
    scope: &HelperScope,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    ret(insert_json(&inner, Value::Object(serde_json::Map::new())))
}

fn h_json_new_array(
    scope: &HelperScope,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    ret(insert_json(&inner, Value::Array(Vec::new())))
}

fn h_json_type(
    scope: &HelperScope,
    handle: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    match with(scope, |inner| json_slot(inner, handle as i64))? {
        Ok(slot) => ret(type_tag(&slot.value.borrow())),
        Err(error) => ret(error),
    }
}

fn h_json_len(scope: &HelperScope, handle: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    match with(scope, |inner| json_slot(inner, handle as i64))? {
        Ok(slot) => match &*slot.value.borrow() {
            Value::Array(items) => ret(items.len() as i64),
            Value::Object(map) => ret(map.len() as i64),
            Value::String(s) => ret(s.len() as i64),
            _ => ret(errno::EINVAL),
        },
        Err(error) => ret(error),
    }
}

fn h_json_get(
    scope: &HelperScope,
    handle: u64,
    key_ptr: u64,
    key_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = guest!(string(scope, key_ptr, key_len));
    let inner = with(scope, Rc::clone)?;
    let slot = match json_slot(&inner, handle as i64) {
        Ok(slot) => slot,
        Err(error) => return ret(error),
    };
    let member = match &*slot.value.borrow() {
        Value::Object(map) => match map.get(&key) {
            Some(member) => member.clone(),
            None => return ret(errno::ENOENT),
        },
        _ => return ret(errno::EINVAL),
    };
    ret(insert_json(&inner, member))
}

fn h_json_array_get(
    scope: &HelperScope,
    handle: u64,
    index: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    let slot = match json_slot(&inner, handle as i64) {
        Ok(slot) => slot,
        Err(error) => return ret(error),
    };
    let item = match &*slot.value.borrow() {
        Value::Array(items) => match usize::try_from(index).ok().and_then(|i| items.get(i)) {
            Some(item) => item.clone(),
            None => return ret(errno::ENOENT),
        },
        _ => return ret(errno::EINVAL),
    };
    ret(insert_json(&inner, item))
}

fn h_json_read_string(
    scope: &HelperScope,
    handle: u64,
    out: u64,
    out_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let text = match with(scope, |inner| json_slot(inner, handle as i64))? {
        Ok(slot) => match &*slot.value.borrow() {
            Value::String(s) => s.clone(),
            _ => return ret(errno::EINVAL),
        },
        Err(error) => return ret(error),
    };
    out_str(scope, out, out_len, &text)
}

fn h_json_read_i64(
    scope: &HelperScope,
    handle: u64,
    out: u64,
    out_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if out_len < 8 {
        return ret(errno::EINVAL);
    }
    let number = match with(scope, |inner| json_slot(inner, handle as i64))? {
        Ok(slot) => match &*slot.value.borrow() {
            // `as_i64` covers negatives and everything through i64::MAX;
            // larger u64 values do not fit the out-parameter honestly.
            Value::Number(n) => match n.as_i64() {
                Some(value) => value,
                None => return ret(errno::EINVAL),
            },
            _ => return ret(errno::EINVAL),
        },
        Err(error) => return ret(error),
    };
    out_exact(scope, out, out_len.min(8), &number.to_le_bytes())
}

fn h_json_read_bool(
    scope: &HelperScope,
    handle: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    match with(scope, |inner| json_slot(inner, handle as i64))? {
        Ok(slot) => match &*slot.value.borrow() {
            Value::Bool(b) => ret(i64::from(*b)),
            _ => ret(errno::EINVAL),
        },
        Err(error) => ret(error),
    }
}

fn h_json_set(
    scope: &HelperScope,
    handle: u64,
    key_ptr: u64,
    key_len: u64,
    value_handle: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = guest!(string(scope, key_ptr, key_len));
    let inner = with(scope, Rc::clone)?;
    let value = match json_value(&inner, value_handle as i64) {
        Ok(value) => value,
        Err(error) => return ret(error),
    };
    ret(json_mutate(&inner, handle as i64, |target| match target {
        Value::Object(map) => {
            map.insert(key, value);
            Ok(())
        }
        _ => Err(errno::EINVAL),
    }))
}

fn h_json_remove(
    scope: &HelperScope,
    handle: u64,
    key_ptr: u64,
    key_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = guest!(string(scope, key_ptr, key_len));
    let inner = with(scope, Rc::clone)?;
    ret(json_mutate(&inner, handle as i64, |target| match target {
        Value::Object(map) => match map.remove(&key) {
            Some(_) => Ok(()),
            None => Err(errno::ENOENT),
        },
        _ => Err(errno::EINVAL),
    }))
}

fn h_json_array_push(
    scope: &HelperScope,
    handle: u64,
    value_handle: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    let value = match json_value(&inner, value_handle as i64) {
        Ok(value) => value,
        Err(error) => return ret(error),
    };
    ret(json_mutate(&inner, handle as i64, |target| match target {
        Value::Array(items) => {
            items.push(value);
            Ok(())
        }
        _ => Err(errno::EINVAL),
    }))
}

fn h_json_set_string(
    scope: &HelperScope,
    handle: u64,
    ptr: u64,
    len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let text = guest!(string(scope, ptr, len));
    let inner = with(scope, Rc::clone)?;
    ret(json_mutate(&inner, handle as i64, |target| {
        *target = Value::String(text);
        Ok(())
    }))
}

fn h_json_set_i64(
    scope: &HelperScope,
    handle: u64,
    value: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    ret(json_mutate(&inner, handle as i64, |target| {
        *target = json!(value as i64);
        Ok(())
    }))
}

fn h_json_set_bool(
    scope: &HelperScope,
    handle: u64,
    value: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if value > 1 {
        return ret(errno::EINVAL);
    }
    let inner = with(scope, Rc::clone)?;
    ret(json_mutate(&inner, handle as i64, |target| {
        *target = Value::Bool(value == 1);
        Ok(())
    }))
}

fn h_json_set_null(
    scope: &HelperScope,
    handle: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    ret(json_mutate(&inner, handle as i64, |target| {
        *target = Value::Null;
        Ok(())
    }))
}

// ---- endpoint I/O --------------------------------------------------------

fn h_read(scope: &HelperScope, handle: u64, ptr: u64, len: u64, _: u64, _: u64) -> Result<u64, ()> {
    let ep = match with(scope, |inner| inner.endpoint_for_io(handle as i64))? {
        Ok(endpoint) => endpoint,
        Err(error) => return ret(error),
    };
    if len == 0 {
        return ret(0);
    }
    // The destination is the bound: the cage grants at most the guest's own
    // memory, so a length no buffer could hold is refused as an argument
    // rather than allocated for, and the ring is read straight into the
    // region. The borrow ends before `with` runs, as everywhere here.
    let n = {
        let Ok(mut region) = scope.user_memory_mut(ptr, len) else {
            return ret(errno::EINVAL);
        };
        ep.read(&mut region)
    };
    if n <= 0 {
        return ret(n);
    }
    // The caller's raw stream, and the cleartext of SSH channel and lane fds
    // (`docs/SSH-SOCKETS.md` §8): what the invocation received as application
    // bytes. Backends the guest pumps into are not counted, or a proxy would
    // report twice the bytes it moved.
    let counted = ep.role().counts_stream_bytes();
    with(scope, |inner| {
        inner.made_progress();
        if counted {
            inner
                .live
                .bytes_in
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        }
    })?;
    ret(n)
}

fn h_write(
    scope: &HelperScope,
    handle: u64,
    ptr: u64,
    len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let data = guest!(bytes(scope, ptr, len));
    let ep = match with(scope, |inner| inner.endpoint_for_io(handle as i64))? {
        Ok(endpoint) => endpoint,
        Err(error) => return ret(error),
    };
    let n = ep.write(&data);
    if n > 0 {
        // Only the caller-facing side is counted — the raw stream, or the SSH
        // channel and lane cleartext: a proxy moves the same bytes on both
        // sides, and reporting the sum would say a socket did twice the work
        // it did.
        let counted = ep.role().counts_stream_bytes();
        with(scope, |inner| {
            inner.made_progress();
            if counted {
                inner
                    .live
                    .bytes_out
                    .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
            }
        })?;
    }
    ret(n)
}

/// Moves bytes between two endpoints without them entering guest memory.
///
/// The one helper here that touches no guest memory at all, which is what it is
/// for: a proxy that does not need to look at what it forwards pays neither the
/// two copies through the pointer cage nor the stack buffer they would need,
/// and — because the bytes are never picked up out of the rx ring — has no
/// remainder to carry between calls. The move is bounded by the two rings and
/// by what the guest asked for.
fn h_splice(scope: &HelperScope, from: u64, to: u64, max: u64, _: u64, _: u64) -> Result<u64, ()> {
    // Zero would have to mean either "nothing moved" or "the source is at its
    // end", and telling those two apart is the whole of a caller's control
    // flow. So it is refused as the malformed argument it is.
    if max == 0 {
        return ret(errno::EINVAL);
    }
    let inner = with(scope, Rc::clone)?;
    // Both sides go through the same door every other I/O helper uses, so a
    // splice-only proxy can name `SY_SELF` as its first act. An object or a
    // cursor handle is still `SY_EBADF`: the tree is read with `sy_pread`,
    // whose answer may not be here yet, and a splice that could block is not
    // the helper this is.
    let src = match inner.endpoint_for_io(from as i64) {
        Ok(endpoint) => endpoint,
        Err(error) => return ret(error),
    };
    let dst = match inner.endpoint_for_io(to as i64) {
        Ok(endpoint) => endpoint,
        Err(error) => return ret(error),
    };
    let n = src.splice_to(&dst, usize::try_from(max).unwrap_or(usize::MAX));
    if n > 0 {
        inner.made_progress();
        // Counted as `sy_read` and `sy_write` count: only the caller-facing
        // side — the raw stream, or an SSH channel or lane fd — so a proxy is
        // not reported as having moved twice the bytes it moved. A splice
        // between two egress endpoints is neither, and shows up in neither
        // total.
        if src.role().counts_stream_bytes() {
            inner
                .live
                .bytes_in
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        }
        if dst.role().counts_stream_bytes() {
            inner
                .live
                .bytes_out
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        }
    }
    ret(n)
}

fn h_readable(scope: &HelperScope, handle: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    match with(scope, |inner| inner.endpoint_for_io(handle as i64))? {
        Ok(ep) => ret(ep.readable() as i64),
        Err(error) => ret(error),
    }
}

fn h_writable(scope: &HelperScope, handle: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    match with(scope, |inner| inner.endpoint_for_io(handle as i64))? {
        Ok(ep) => ret(ep.writable() as i64),
        Err(error) => ret(error),
    }
}

fn h_shutdown(scope: &HelperScope, handle: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    match with(scope, |inner| inner.endpoint_for_io(handle as i64))? {
        Ok(ep) => {
            ep.shutdown();
            ret(0)
        }
        Err(error) => ret(error),
    }
}

fn h_close(scope: &HelperScope, handle: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    with(scope, |inner| {
        let removed = inner.remove(handle as i64);
        inner.publish_handles();
        if removed {
            0
        } else {
            errno::EBADF
        }
    })
    .and_then(ret)
}

fn h_errno(scope: &HelperScope, handle: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    match with(scope, |inner| inner.slot(handle as i64))? {
        Some(Slot2::Unselected(_)) => ret(0),
        Some(Slot2::Endpoint(ep)) => ret(ep.errno()),
        Some(Slot2::SshControl(ssh)) => ret(ssh.errno()),
        Some(Slot2::Object(obj)) => {
            let code = match &*obj.result.borrow() {
                Some(Err(e)) => *e,
                _ => 0,
            };
            ret(code)
        }
        Some(Slot2::Cursor(_)) => ret(0),
        Some(Slot2::Json(_)) => ret(0),
        Some(Slot2::Process(process)) => ret(process.refresh().err().unwrap_or(0)),
        Some(Slot2::Writer(writer)) => {
            let code = if writer.failed.get() != 0 {
                writer.failed.get()
            } else {
                match &*writer.result.borrow() {
                    Some(Err(e)) => *e,
                    _ => 0,
                }
            };
            ret(code)
        }
        None => ret(errno::EBADF),
    }
}

// ---- outbound ------------------------------------------------------------

/// Opens an outbound endpoint after the policy says yes.
fn open_egress(inner: &Rc<Inner>, host: String, port: u16, literal: bool) -> i64 {
    if inner.init_mode {
        return errno::EPERM;
    }
    if !inner.policy.egress_allowed(&host, port) {
        tracing::warn!(
            socket = %inner.socket.qualified(),
            host,
            port,
            "socket egress refused: the armed program did not declare it"
        );
        return errno::EPERM;
    }
    // A literal address gets the same check a resolved one would, so the two
    // helpers cannot disagree about where a program may reach.
    if literal {
        if let Ok(addr) = host.trim_matches(['[', ']']).parse() {
            if !crate::runtime::endpoint::literal_allowed(&host, addr) {
                return errno::EPERM;
            }
        }
    }
    if inner.egress_open.get() >= inner.limits.max_egress {
        return errno::ELIMIT;
    }

    let ep = Endpoint::new(
        inner.limits.ring_bytes,
        inner.ready.clone(),
        State::Connecting,
        format!("{host}:{port}"),
        EndpointRole::TcpEgress,
    );
    let handle = match inner.insert(Slot::Endpoint(ep.clone())) {
        Ok(h) => h,
        Err(e) => return e,
    };
    let permit =
        crate::runtime::endpoint::EgressPermit::take(std::rc::Rc::clone(&inner.egress_open));
    inner.publish_handles();
    inner.spawn(connect_task(ep, host, port, permit));
    handle
}

fn h_tcp_connect(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    port: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let host = guest!(string(scope, ptr, len));
    if !synch_core::display_text_is_safe(&host) {
        return ret(errno::EINVAL);
    }
    if port == 0 || port > u16::MAX as u64 {
        return ret(errno::EINVAL);
    }
    with(scope, |inner| open_egress(inner, host, port as u16, false)).and_then(ret)
}

fn h_tcp_connect_ip(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    port: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    // Accepts the textual form: a program with no heap builds an address by
    // printing it far more easily than by packing four or sixteen bytes, and
    // the policy list it is checked against is textual anyway.
    let host = guest!(string(scope, ptr, len));
    if host.parse::<std::net::IpAddr>().is_err() {
        return ret(errno::EINVAL);
    }
    if port == 0 || port > u16::MAX as u64 {
        return ret(errno::EINVAL);
    }
    with(scope, |inner| open_egress(inner, host, port as u16, true)).and_then(ret)
}

fn h_endpoint_info(
    scope: &HelperScope,
    handle: u64,
    ptr: u64,
    len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let ep = match with(scope, |inner| inner.endpoint_for_io(handle as i64))? {
        Ok(endpoint) => endpoint,
        Err(error) => return ret(error),
    };
    let state = match ep.state() {
        State::Connecting => "connecting",
        State::Open => "open",
        State::Failed => "failed",
        State::Closed => "closed",
    };
    out_str(scope, ptr, len, &format!("{} {state}", ep.peer()))
}

// ---- SSH protocol --------------------------------------------------------

fn ssh_state(inner: &Inner) -> Result<std::sync::Arc<crate::runtime::ssh::SshState>, i64> {
    match inner.slot(SY_SELF) {
        Some(Slot2::SshControl(state)) => Ok(state),
        Some(_) => Err(errno::ESTATE),
        None => Err(errno::EBADF),
    }
}

/// The `["none" | "publickey" | "password", …]` array `sy_ssh_start` takes and
/// `sy_ssh_auth_reply` optionally takes as `next_methods`, as method bits.
fn method_bits(value: &Value) -> Result<u64, i64> {
    let Value::Array(items) = value else {
        return Err(errno::EINVAL);
    };
    let mut bits = 0;
    for item in items {
        let bit = item
            .as_str()
            .and_then(crate::runtime::ssh::method_name_bit)
            .ok_or(errno::EINVAL)?;
        bits |= bit;
    }
    Ok(bits)
}

fn h_ssh_start(
    scope: &HelperScope,
    stream: u64,
    methods_handle: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if stream as i64 != SY_SELF {
        return ret(errno::EINVAL);
    }
    let methods = match with(scope, |inner| {
        json_value(inner, methods_handle as i64).and_then(|value| method_bits(&value))
    })? {
        Ok(bits) if bits != 0 => bits,
        Ok(_) => return ret(errno::EINVAL),
        Err(error) => return ret(error),
    };
    with(scope, |inner| {
        if let Some(error) = mode_check(inner, false) {
            return error;
        }
        let Some(host_key) = inner.ssh_host_key.clone() else {
            return errno::EPERM;
        };
        let Some(throttle) = inner.ssh_auth_throttle.clone() else {
            return errno::EPERM;
        };
        let state = crate::runtime::ssh::SshState::new(inner.ready.clone());
        let stream = match inner.select_ssh(state.clone()) {
            Ok(stream) => stream,
            Err(error) => return error,
        };
        // The throttle key is the peer's IP, not its "ip:port" address: a
        // reconnect is a fresh port, and a key that included the port would
        // never repeat, making the per-IP cap unreachable. Under `--listen`
        // the peer is the CLI relay's control connection, so every relayed
        // client shares one bucket — that is the intended bound: the relay
        // is the single entry point the throttle must pace.
        let ip = peer_ip(&inner.peer.addr).to_string();
        inner.spawn(crate::runtime::ssh::serve(
            stream,
            state,
            host_key,
            methods,
            inner.limits.idle_deadline,
            crate::runtime::ssh::AuthContext {
                throttle,
                ip,
                socket: inner.socket.qualified(),
            },
        ));
        0
    })
    .and_then(ret)
}

/// The IP half of a peer's "ip:port" address, for the per-IP auth throttle
/// key. Bracketed IPv6 ("[v6]:port") is stripped to the address; an
/// unbracketed v6 (which has no single colon before a port) is kept as-is;
/// a bare address with no port passes through untouched.
pub(crate) fn peer_ip(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        return rest.split_once(']').map_or(rest, |(ip, _)| ip);
    }
    match addr.rsplit_once(':') {
        Some((host, _)) if !host.contains(':') => host,
        _ => addr,
    }
}

/// One event, as a fresh JSON handle.
///
/// Returns the handle (> 0), `SY_EAGAIN` while the queue is empty on a live
/// connection, and `0` once it is empty after HUP: no further event will
/// arrive. The event stays outstanding until it is answered — the JSON is a
/// snapshot the guest closes whenever it likes.
fn h_ssh_next(scope: &HelperScope, conn: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    if conn as i64 != SY_SELF {
        return ret(errno::EINVAL);
    }
    let inner = with(scope, Rc::clone)?;
    let state = match ssh_state(&inner) {
        Ok(state) => state,
        Err(error) => return ret(error),
    };
    let Some(event) = state.next() else {
        return ret(if state.revents() & poll::HUP != 0 {
            0
        } else {
            errno::EAGAIN
        });
    };
    let Some(value) = state.event_json(event.id) else {
        return ret(errno::EAGAIN);
    };
    let handle = insert_json(&inner, value);
    if handle < 0 {
        // No room for the handle: the event goes back to the head of the
        // queue, so a retry after `sy_close` sees it again rather than a
        // stranded outstanding event nothing points at.
        state.requeue(event.id);
    }
    ret(handle)
}

fn h_ssh_event_data(
    scope: &HelperScope,
    event_id: u64,
    name_ptr: u64,
    name_len: u64,
    out: u64,
    out_len: u64,
) -> Result<u64, ()> {
    let name = guest!(string(scope, name_ptr, name_len));
    let Some(field) = crate::runtime::ssh::field_id(&name) else {
        return ret(errno::EINVAL);
    };
    let state = match with(scope, |inner| ssh_state(inner))? {
        Ok(state) => state,
        Err(error) => return ret(error),
    };
    let Some(mut value) = state.field(event_id, field) else {
        return ret(errno::ENOENT);
    };
    let n = value.len().min(out_len as usize);
    if n > 0 {
        let Ok(mut region) = scope.user_memory_mut(out, n as u64) else {
            return ret(errno::EINVAL);
        };
        region.copy_from_slice(&value[..n]);
    }
    let total = value.len() as i64;
    // The credential-zeroization rules (§12.4) cover this host-side copy of
    // the password too, not only the payload attached to the event.
    if field == crate::runtime::ssh::FIELD_PASSWORD {
        value.fill(0);
    }
    ret(total)
}

fn h_ssh_event_done(
    scope: &HelperScope,
    event_id: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let state = match with(scope, |inner| ssh_state(inner))? {
        Ok(state) => state,
        Err(error) => return ret(error),
    };
    match state.reply(event_id, crate::runtime::ssh::Decision::Done) {
        Ok(()) => ret(0),
        Err(()) => ret(errno::ESTATE),
    }
}

/// The kind/result gate `h_ssh_auth_reply` applies to one auth event: which
/// kinds a reply is valid on, and how result 4 (OFFER_ACCEPT) maps.
///
/// A certificate authentication (kind 9) is a real authentication — the SSH
/// library has validated its structure, identity constraints, internal
/// signature, and the client's possession signature. The guest must still
/// authorize the signing CA. Results 1 (accept), 2 (reject), and 3 (partial)
/// are valid on it, as they are on the other auth kinds. OFFER_ACCEPT maps to
/// the SSH library's pre-signature Accept; it is not authentication completion
/// and stays valid only on an offer (kind 3). Any other kind — a signed
/// certificate event (9), a non-offer key event (4), a non-auth kind — is
/// refused with ESTATE, fail-closed.
pub(crate) fn auth_reply_result(kind: u32, result: u64) -> Result<u32, i64> {
    if !matches!(
        kind,
        crate::runtime::ssh::EVENT_AUTH_NONE
            | crate::runtime::ssh::EVENT_AUTH_PASSWORD
            | crate::runtime::ssh::EVENT_AUTH_PUBLICKEY_OFFER
            | crate::runtime::ssh::EVENT_AUTH_PUBLICKEY_VERIFIED
            | crate::runtime::ssh::EVENT_AUTH_OPENSSH_CERT
    ) {
        return Err(errno::ESTATE);
    }
    if kind == crate::runtime::ssh::EVENT_AUTH_PUBLICKEY_OFFER {
        match result {
            2 => Ok(2),
            4 => Ok(1),
            _ => Err(errno::ESTATE),
        }
    } else if result == 4 {
        Err(errno::ESTATE)
    } else {
        Ok(result as u32)
    }
}

/// Answers an auth event with a JSON reply:
/// `{"result": "accept" | "reject" | "partial" | "offer_accept",
///   "next_methods": ["publickey", …]?}`.
///
/// `next_methods` is what a rejection or partial success leaves attemptable;
/// absent means nothing further, which is the fail-closed reading.
fn h_ssh_auth_reply(
    scope: &HelperScope,
    event_id: u64,
    reply_handle: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    let reply = match json_value(&inner, reply_handle as i64) {
        Ok(value) => value,
        Err(error) => return ret(error),
    };
    let result = match reply.get("result").and_then(Value::as_str) {
        Some("accept") => 1,
        Some("reject") => 2,
        Some("partial") => 3,
        Some("offer_accept") => 4,
        _ => return ret(errno::EINVAL),
    };
    let next_methods = match reply.get("next_methods") {
        None | Some(Value::Null) => 0,
        Some(value) => match method_bits(value) {
            Ok(bits) => bits,
            Err(error) => return ret(error),
        },
    };
    let state = match ssh_state(&inner) {
        Ok(state) => state,
        Err(error) => return ret(error),
    };
    let Some(kind) = state.event_kind(event_id) else {
        return ret(errno::ESTATE);
    };
    let result = match auth_reply_result(kind, result) {
        Ok(result) => result,
        Err(error) => return ret(error),
    };
    match state.reply(
        event_id,
        crate::runtime::ssh::Decision::Auth {
            result,
            next_methods,
        },
    ) {
        Ok(()) => ret(0),
        Err(()) => ret(errno::ESTATE),
    }
}

fn h_ssh_authorized_keys_match(
    scope: &HelperScope,
    event_id: u64,
    object: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    const MAX_AUTHORIZED_KEYS: u64 = 256 * 1024;
    const MAX_AUTHORIZED_KEY_LINE: usize = 16 * 1024;

    let inner = with(scope, Rc::clone)?;
    let state = match ssh_state(&inner) {
        Ok(state) => state,
        Err(error) => return ret(error),
    };
    if !matches!(
        state.event_kind(event_id),
        Some(
            crate::runtime::ssh::EVENT_AUTH_PUBLICKEY_OFFER
                | crate::runtime::ssh::EVENT_AUTH_PUBLICKEY_VERIFIED
        )
    ) {
        return ret(errno::ESTATE);
    }
    let Some(wanted) = state.field(event_id, crate::runtime::ssh::FIELD_PUBLIC_KEY_BLOB) else {
        return ret(errno::ESTATE);
    };
    let Some(Slot2::Object(object)) = inner.slot(object as i64) else {
        return ret(errno::EBADF);
    };
    let size = object.info.size;
    if size > MAX_AUTHORIZED_KEYS {
        return ret(errno::ELIMIT);
    }
    if object.want.get() == (0, size) {
        if let Some(result) = object.result.borrow_mut().take() {
            object.want.set((0, 0));
            return match result {
                Err(error) => ret(error),
                Ok(data) => {
                    let mut matched = false;
                    for line in data.split(|byte| *byte == b'\n') {
                        if line.len() > MAX_AUTHORIZED_KEY_LINE {
                            inner.release(data.len() as u64);
                            return ret(errno::ELIMIT);
                        }
                        let Ok(line) = std::str::from_utf8(line) else {
                            continue;
                        };
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        let mut fields = line.split_ascii_whitespace();
                        let Some(key_type) = fields.next() else {
                            continue;
                        };
                        // An options prefix necessarily occupies the first
                        // field. Recognizing only key-type-shaped first fields
                        // makes every option-bearing line fail closed.
                        if !(key_type.starts_with("ssh-")
                            || key_type.starts_with("ecdsa-")
                            || key_type.starts_with("sk-"))
                        {
                            continue;
                        }
                        let Some(encoded) = fields.next() else {
                            continue;
                        };
                        let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(encoded)
                        else {
                            continue;
                        };
                        if blob == wanted {
                            matched = true;
                            break;
                        }
                    }
                    inner.release(data.len() as u64);
                    ret(matched as i64)
                }
            };
        }
    }
    if object.pending.get() {
        return ret(errno::EAGAIN);
    }
    if inner.charge(size).is_err() {
        return ret(errno::ELIMIT);
    }
    object.pending.set(true);
    object.want.set((0, size));
    *object.result.borrow_mut() = None;
    let host = inner.host.clone();
    let slot = object.clone();
    let root = object.info.root;
    let task_inner = inner.clone();
    inner.spawn(async move {
        let result = host.pread(root, 0, size).await;
        slot.pending.set(false);
        match result {
            Ok(data) => {
                task_inner.release(size.saturating_sub(data.len() as u64));
                *slot.result.borrow_mut() = Some(Ok(data));
            }
            Err(error) => {
                task_inner.release(size);
                *slot.result.borrow_mut() = Some(Err(host_errno(&error)));
            }
        }
        slot.ready.bump();
    });
    ret(errno::EAGAIN)
}

fn h_ssh_channel_accept(
    scope: &HelperScope,
    event_id: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    let state = match ssh_state(&inner) {
        Ok(state) => state,
        Err(error) => return ret(error),
    };
    if state.event_kind(event_id) != Some(crate::runtime::ssh::EVENT_CHANNEL_OPEN) {
        return ret(errno::ESTATE);
    }
    if !state.reserve_channel() {
        return ret(errno::ELIMIT);
    }
    let channel_type = state
        .field(event_id, crate::runtime::ssh::FIELD_CHANNEL_TYPE)
        .and_then(|value| String::from_utf8(value).ok())
        .unwrap_or_else(|| "unknown".into());
    // Accepting an inbound open completes locally — sending the confirmation
    // cannot be refused by the peer — so unlike a server-initiated open the
    // fd is born open rather than connecting (§6).
    let endpoint = Endpoint::new(
        inner.limits.ring_bytes.min(64 * 1024),
        inner.ready.clone(),
        State::Open,
        format!("ssh:{channel_type}"),
        EndpointRole::SshChannel {
            channel_type: channel_type.clone(),
        },
    );
    let handle = match inner.insert(Slot::Endpoint(endpoint.clone())) {
        Ok(handle) => handle,
        Err(error) => {
            state.release_channel();
            return ret(error);
        }
    };
    // Bind the accept event to this endpoint fd before replying: the
    // registration on the ssh side is refused unless the token matches, so a
    // closed-and-reused fd can never capture a stale registration. Forgotten
    // below if the reply fails and by the ssh side once the channel closes.
    state.note_accept(handle, event_id);
    let (local, bridge) = tokio::io::duplex(inner.limits.ring_bytes.min(64 * 1024));
    let (reader, writer) = tokio::io::split(local);
    inner.spawn(crate::runtime::endpoint::reader_task(
        endpoint.clone(),
        Box::new(reader),
    ));
    inner.spawn(crate::runtime::endpoint::writer_task(
        endpoint,
        Box::new(writer),
    ));
    if state
        .reply(
            event_id,
            crate::runtime::ssh::Decision::Channel { fd: handle, bridge },
        )
        .is_err()
    {
        // The reply failed, so no registration will consume the token; drop
        // it so the next accept that reuses the fd starts from a clean slate.
        state.forget_accept(handle);
        state.release_channel();
        inner.remove(handle);
        return ret(errno::ESTATE);
    }
    inner.publish_handles();
    ret(handle)
}

fn h_ssh_channel_reject(
    scope: &HelperScope,
    event_id: u64,
    reason_ptr: u64,
    reason_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let reason = match guest!(string(scope, reason_ptr, reason_len)).as_str() {
        "administratively_prohibited" => russh::ChannelOpenFailure::AdministrativelyProhibited,
        "connect_failed" => russh::ChannelOpenFailure::ConnectFailed,
        "unknown_channel_type" => russh::ChannelOpenFailure::UnknownChannelType,
        "resource_shortage" => russh::ChannelOpenFailure::ResourceShortage,
        _ => return ret(errno::EINVAL),
    };
    let state = match with(scope, |inner| ssh_state(inner))? {
        Ok(state) => state,
        Err(error) => return ret(error),
    };
    // Only a channel-open token can be answered with a rejection; consuming
    // an auth or request token here would deliver the wrong decision type and
    // end the connection instead of failing this one call (§5).
    if state.event_kind(event_id) != Some(crate::runtime::ssh::EVENT_CHANNEL_OPEN) {
        return ret(errno::ESTATE);
    }
    match state.reply(
        event_id,
        crate::runtime::ssh::Decision::ChannelReject(reason),
    ) {
        Ok(()) => ret(0),
        Err(()) => ret(errno::ESTATE),
    }
}

fn h_ssh_channel_open(
    scope: &HelperScope,
    conn: u64,
    type_ptr: u64,
    type_len: u64,
    data_ptr: u64,
    data_len: u64,
) -> Result<u64, ()> {
    if conn as i64 != SY_SELF {
        return ret(errno::EINVAL);
    }
    let channel_type = guest!(string(scope, type_ptr, type_len));
    let data = guest!(bytes(scope, data_ptr, data_len));
    if channel_type.is_empty()
        || channel_type.len() > 256
        || !channel_type
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b',')
        || data.len() > 16 * 1024
    {
        return ret(errno::EINVAL);
    }
    let inner = with(scope, Rc::clone)?;
    let state = match ssh_state(&inner) {
        Ok(state) => state,
        Err(error) => return ret(error),
    };
    let Some(session) = state.session() else {
        return ret(errno::ESTATE);
    };
    if !state.reserve_channel() {
        return ret(errno::ELIMIT);
    }
    let endpoint = Endpoint::new(
        inner.limits.ring_bytes.min(64 * 1024),
        inner.ready.clone(),
        State::Connecting,
        format!("ssh:{channel_type}"),
        EndpointRole::SshChannel {
            channel_type: channel_type.clone(),
        },
    );
    let handle = match inner.insert(Slot::Endpoint(endpoint.clone())) {
        Ok(handle) => handle,
        Err(error) => {
            state.release_channel();
            return ret(error);
        }
    };
    let (local, bridge) = tokio::io::duplex(inner.limits.ring_bytes.min(64 * 1024));
    let (reader, writer) = tokio::io::split(local);
    inner.spawn(crate::runtime::endpoint::reader_task(
        endpoint.clone(),
        Box::new(reader),
    ));
    inner.spawn(crate::runtime::endpoint::writer_task(
        endpoint.clone(),
        Box::new(writer),
    ));
    inner.spawn(async move {
        let opened = session
            .channel_open_unknown(channel_type.clone(), data)
            .await;
        match opened {
            Ok(channel) => {
                let guest_closed = state.add_outbound_channel(handle, channel.id(), &channel_type);
                endpoint.set_open();
                crate::runtime::ssh::bridge_channel(channel, bridge, guest_closed).await;
            }
            Err(_) => {
                state.release_channel();
                endpoint.fail(errno::ECONNRESET);
                // The guest owns `handle` once this helper returns it. Keep the
                // failed endpoint in its slot until sy_close: asynchronously
                // freeing and reusing the numeric fd could make the guest's
                // stale handle alias an unrelated later channel.
            }
        }
    });
    inner.publish_handles();
    ret(handle)
}

fn h_ssh_channel_type(
    scope: &HelperScope,
    channel: u64,
    out: u64,
    out_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let Some(endpoint) = with(scope, |inner| inner.endpoint(channel as i64))? else {
        return ret(errno::EBADF);
    };
    let EndpointRole::SshChannel { channel_type } = endpoint.role() else {
        return ret(errno::ESTATE);
    };
    let channel_type = channel_type.clone();
    out_str(scope, out, out_len, &channel_type)
}

fn h_ssh_channel_lane(
    scope: &HelperScope,
    channel: u64,
    data_type: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    let state = match ssh_state(&inner) {
        Ok(state) => state,
        Err(error) => return ret(error),
    };
    let Some((session, channel_id, _)) = state.channel(channel as i64) else {
        return ret(errno::ESTATE);
    };
    let data_type = data_type.min(u32::MAX as u64) as u32;
    if let Some(handle) = state.lane_handle(channel as i64, data_type) {
        if inner.endpoint(handle).is_some() {
            return ret(handle);
        }
    }
    if state.lane_count(channel as i64) >= crate::limits::MAX_LANES_PER_CHANNEL {
        return ret(errno::ELIMIT);
    }
    let lane_ring = inner.limits.ring_bytes.min(64 * 1024);
    let endpoint = Endpoint::new(
        lane_ring,
        inner.ready.clone(),
        State::Open,
        format!("ssh-lane:{}:{data_type}", channel),
        EndpointRole::SshExtendedData,
    );
    let handle = match inner.insert(Slot::Endpoint(endpoint.clone())) {
        Ok(handle) => handle,
        Err(error) => return ret(error),
    };
    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(8);
    state.register_lane(channel as i64, data_type, handle, incoming_tx);
    inner.spawn(crate::runtime::endpoint::reader_task(
        endpoint.clone(),
        Box::new(crate::runtime::process::ChannelReader::new(incoming_rx)),
    ));
    // Outbound goes through a bounded pipe rather than an unbounded queue:
    // when the SSH window or the session task stalls, the pipe fills, the
    // writer pump stops draining the ring, and the guest sees a short write —
    // backpressure end to end, as invariant §12.7 requires.
    let (guest_side, mut bridge) = tokio::io::duplex(lane_ring);
    inner.spawn(crate::runtime::endpoint::writer_task(
        endpoint,
        Box::new(guest_side),
    ));
    inner.spawn(async move {
        let mut chunk = vec![0u8; 16 * 1024];
        loop {
            match tokio::io::AsyncReadExt::read(&mut bridge, &mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if session
                        .extended_data(channel_id, data_type, chunk[..n].to_vec())
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });
    inner.publish_handles();
    ret(handle)
}

fn h_ssh_request_reply(
    scope: &HelperScope,
    event_id: u64,
    result: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if result > 1 {
        return ret(errno::EINVAL);
    }
    let state = match with(scope, |inner| ssh_state(inner))? {
        Ok(state) => state,
        Err(error) => return ret(error),
    };
    if state.event_kind(event_id) != Some(crate::runtime::ssh::EVENT_CHANNEL_REQUEST) {
        return ret(errno::ESTATE);
    }
    match state.reply(
        event_id,
        crate::runtime::ssh::Decision::Request(result == 1),
    ) {
        Ok(()) => ret(0),
        Err(()) => ret(errno::ESTATE),
    }
}

fn h_ssh_exit_status(
    scope: &HelperScope,
    channel: u64,
    status: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    let state = match ssh_state(&inner) {
        Ok(state) => state,
        Err(error) => return ret(error),
    };
    let Some((session, channel_id, kind)) = state.channel(channel as i64) else {
        return ret(errno::ESTATE);
    };
    if kind != "session" || status > u32::MAX as u64 {
        return ret(errno::ESTATE);
    }
    let state = state.clone();
    inner.spawn(async move {
        let sent = tokio::time::timeout(
            Duration::from_secs(1),
            session.exit_status_request(channel_id, status as u32),
        )
        .await;
        // The status can be lost three ways — the channel was already closed
        // by the client, the connection is gone, or the invocation was torn
        // down before the task ran. None of them should come back as an
        // unreported success: count the loss so the guest can tell "status
        // delivered" from "status lost".
        if !matches!(sent, Ok(Ok(()))) {
            state.note_lost_exit_delivery();
        }
    });
    ret(0)
}

fn h_ssh_exit_signal(
    scope: &HelperScope,
    channel: u64,
    name_ptr: u64,
    name_len: u64,
    core_dumped: u64,
    _: u64,
) -> Result<u64, ()> {
    if core_dumped > 1 {
        return ret(errno::EINVAL);
    }
    let name = guest!(string(scope, name_ptr, name_len));
    if name.is_empty() || name.len() > 32 || !name.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return ret(errno::EINVAL);
    }
    let inner = with(scope, Rc::clone)?;
    let state = match ssh_state(&inner) {
        Ok(state) => state,
        Err(error) => return ret(error),
    };
    let Some((session, channel_id, kind)) = state.channel(channel as i64) else {
        return ret(errno::ESTATE);
    };
    if kind != "session" {
        return ret(errno::ESTATE);
    }
    let state = state.clone();
    inner.spawn(async move {
        let sent = tokio::time::timeout(
            Duration::from_secs(1),
            session.exit_signal_request(
                channel_id,
                russh::Sig::Custom(name),
                core_dumped == 1,
                String::new(),
                String::new(),
            ),
        )
        .await;
        // Same accounting as h_ssh_exit_status: a signal the client can never
        // see is counted, never silently claimed as delivered.
        if !matches!(sent, Ok(Ok(()))) {
            state.note_lost_exit_delivery();
        }
    });
    ret(0)
}

fn h_ssh_exit_status_lost(
    scope: &HelperScope,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let state = match with(scope, |inner| ssh_state(inner))? {
        Ok(state) => state,
        Err(error) => return ret(error),
    };
    ret(state.lost_exit_deliveries() as i64)
}

/// A `pty-req`'s terminal parameters, as the JSON `sy_pty_open` takes back:
/// `{"term", "columns", "rows", "pixel_width", "pixel_height",
///   "modes": [{"opcode", "value"}, …]}`.
///
/// The mode opcodes stay numeric on purpose: they are SSH wire values
/// (RFC 4254 §8), not an enum of this ABI's invention.
fn h_ssh_pty_spec(
    scope: &HelperScope,
    event_id: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    let state = match ssh_state(&inner) {
        Ok(state) => state,
        Err(error) => return ret(error),
    };
    let Some(pty) = state.pty(event_id) else {
        return ret(errno::ESTATE);
    };
    if pty.term.len() > MAX_PTY_TERM_BYTES || pty.modes.len() > MAX_PTY_MODES {
        return ret(errno::ELIMIT);
    }
    let modes: Vec<Value> = pty
        .modes
        .iter()
        .map(|(opcode, value)| json!({"opcode": opcode, "value": value}))
        .collect();
    let value = json!({
        "term": pty.term,
        "columns": pty.columns,
        "rows": pty.rows,
        "pixel_width": pty.pixel_width,
        "pixel_height": pty.pixel_height,
        "modes": modes,
    });
    ret(insert_json(&inner, value))
}

// ---- declared process and PTY backing -----------------------------------

fn process_capability(inner: &Inner, id: u32) -> Result<synch_core::ProcessCapability, i64> {
    inner
        .policy
        .processes
        .iter()
        .find(|capability| capability.id == id)
        .cloned()
        .ok_or(errno::EPERM)
}

/// The most bytes a terminal name may carry, through either direction of the
/// PTY spec JSON.
const MAX_PTY_TERM_BYTES: usize = 64;

/// The most `(opcode, value)` terminal modes one PTY spec may carry.
const MAX_PTY_MODES: usize = 64;

/// Reads the JSON `sy_ssh_pty_spec` writes — or one the guest built itself —
/// back into a [`PtyRequest`](crate::runtime::ssh::PtyRequest).
fn parse_pty_spec(value: &Value) -> Result<crate::runtime::ssh::PtyRequest, i64> {
    let Value::Object(map) = value else {
        return Err(errno::EINVAL);
    };
    let number = |key: &str| -> Result<u32, i64> {
        match map.get(key) {
            None => Ok(0),
            Some(value) => value
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or(errno::EINVAL),
        }
    };
    let term = match map.get("term") {
        None => String::new(),
        Some(Value::String(term)) => term.clone(),
        Some(_) => return Err(errno::EINVAL),
    };
    // Empty is legitimate: a client with no local terminal — `ssh -tt` from a
    // script or ProxyCommand — sends an empty name, and refusing it would
    // refuse the PTY. The child then simply gets no TERM variable.
    if term.len() > MAX_PTY_TERM_BYTES
        || !term
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.+".contains(&byte))
    {
        return Err(errno::EINVAL);
    }
    let mut modes = Vec::new();
    match map.get("modes") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            if items.len() > MAX_PTY_MODES {
                return Err(errno::EINVAL);
            }
            for item in items {
                let opcode = item
                    .get("opcode")
                    .and_then(Value::as_u64)
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or(errno::EINVAL)?;
                let value = item
                    .get("value")
                    .and_then(Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or(errno::EINVAL)?;
                modes.push((opcode, value));
            }
        }
        Some(_) => return Err(errno::EINVAL),
    }
    Ok(crate::runtime::ssh::PtyRequest {
        term,
        columns: number("columns")?,
        rows: number("rows")?,
        pixel_width: number("pixel_width")?,
        pixel_height: number("pixel_height")?,
        modes,
    })
}

/// How many live child-process handles the invocation holds.
///
/// The handle table alone must not bound OS children ([`crate::limits::MAX_LIVE_PROCESSES`]).
fn live_processes(inner: &Inner) -> usize {
    inner
        .slots
        .borrow()
        .iter()
        .flatten()
        .filter(|slot| matches!(slot, Slot::Process(_)))
        .count()
}

fn h_pty_open(
    scope: &HelperScope,
    capability_id: u64,
    spec_handle: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    let spec = match json_value(&inner, spec_handle as i64).and_then(|v| parse_pty_spec(&v)) {
        Ok(spec) => spec,
        Err(error) => return ret(error),
    };
    if inner.init_mode {
        return ret(errno::EPERM);
    }
    let capability = match process_capability(&inner, capability_id as u32) {
        Ok(capability) if capability.flags & 0x01 != 0 => capability,
        Ok(_) | Err(_) => return ret(errno::EPERM),
    };
    if inner.ptys.borrow().len() >= crate::limits::MAX_OPEN_PTYS {
        return ret(errno::ELIMIT);
    }
    let (master, slave) = match crate::runtime::process::open_pty(
        spec.columns,
        spec.rows,
        spec.pixel_width,
        spec.pixel_height,
    ) {
        Ok(pair) => pair,
        Err(error) => return ret(error),
    };
    if let Err(error) = crate::runtime::process::apply_pty_modes(&slave, &spec.modes) {
        return ret(error);
    }
    let reader = match crate::runtime::process::pty_reader(&master) {
        Ok(reader) => reader,
        Err(error) => return ret(error),
    };
    let writer = match crate::runtime::process::pty_writer(&master) {
        Ok(writer) => writer,
        Err(error) => return ret(error),
    };
    let endpoint = Endpoint::new(
        inner.limits.ring_bytes,
        inner.ready.clone(),
        State::Open,
        format!("pty:{}", capability.id),
        EndpointRole::Pty,
    );
    let handle = match inner.insert(Slot::Endpoint(endpoint.clone())) {
        Ok(handle) => handle,
        Err(error) => return ret(error),
    };
    inner.spawn(crate::runtime::endpoint::reader_task(
        endpoint.clone(),
        Box::new(reader),
    ));
    // Writes reach the PTY through a bounded pipe and one blocking write at a
    // time, so a stalled terminal backpressures the guest ring rather than
    // growing an unbounded queue (invariant §12.7).
    let (guest_side, mut bridge) = tokio::io::duplex(inner.limits.ring_bytes.min(64 * 1024));
    inner.spawn(crate::runtime::endpoint::writer_task(
        endpoint,
        Box::new(guest_side),
    ));
    inner.spawn(async move {
        let mut chunk = vec![0u8; 16 * 1024];
        loop {
            match tokio::io::AsyncReadExt::read(&mut bridge, &mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let writer = writer.clone();
                    let owned = chunk[..n].to_vec();
                    match tokio::task::spawn_blocking(move || {
                        crate::runtime::process::pty_write_all(&writer, &owned)
                    })
                    .await
                    {
                        Ok(true) => {}
                        _ => break,
                    }
                }
            }
        }
    });
    inner.ptys.borrow_mut().insert(
        handle,
        Rc::new(crate::runtime::process::PtySlot {
            master,
            slave: std::cell::RefCell::new(Some(slave)),
            endpoint: handle,
            capability: capability.id,
            spawned: std::cell::Cell::new(false),
            term: spec.term,
        }),
    );
    inner.publish_handles();
    ret(handle)
}

fn h_process_spawn_pty(
    scope: &HelperScope,
    capability_id: u64,
    pty_handle: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    let capability = match process_capability(&inner, capability_id as u32) {
        Ok(capability) if capability.flags & 0x01 != 0 => capability,
        Ok(_) | Err(_) => return ret(errno::EPERM),
    };
    if live_processes(&inner) >= crate::limits::MAX_LIVE_PROCESSES {
        return ret(errno::ELIMIT);
    }
    let Some(pty) = inner.ptys.borrow().get(&(pty_handle as i64)).cloned() else {
        return ret(errno::EBADF);
    };
    if pty.capability != capability.id || pty.spawned.replace(true) {
        return ret(errno::ESTATE);
    }
    let child_events = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child()) {
        Ok(events) => events,
        Err(_) => {
            pty.spawned.set(false);
            return ret(errno::ECONNRESET);
        }
    };
    let Some(slave) = pty.slave.borrow_mut().take() else {
        return ret(errno::ESTATE);
    };
    let child = match crate::runtime::process::spawn_pty(&capability, slave, &pty.term) {
        Ok(child) => child,
        Err(error) => {
            pty.spawned.set(false);
            return ret(error);
        }
    };
    let process = Rc::new(crate::runtime::process::ProcessSlot {
        child: std::cell::RefCell::new(Some(crate::runtime::process::Child::Pty(child))),
        status: std::cell::RefCell::new(Default::default()),
        allowed_signals: capability.allowed_signals,
        main: pty.endpoint,
        stderr: None,
    });
    let handle = match inner.insert(Slot::Process(process.clone())) {
        Ok(handle) => handle,
        Err(error) => {
            process.kill();
            return ret(error);
        }
    };
    inner.spawn(crate::runtime::process::watch_exit(
        Rc::downgrade(&process),
        inner.ready.clone(),
        child_events,
    ));
    inner.publish_handles();
    ret(handle)
}

fn h_process_spawn(
    scope: &HelperScope,
    capability_id: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    let capability = match process_capability(&inner, capability_id as u32) {
        Ok(capability) if capability.flags & 0x02 != 0 => capability,
        Ok(_) | Err(_) => return ret(errno::EPERM),
    };
    if live_processes(&inner) >= crate::limits::MAX_LIVE_PROCESSES {
        return ret(errno::ELIMIT);
    }
    let child_events = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child()) {
        Ok(events) => events,
        Err(_) => return ret(errno::ECONNRESET),
    };
    let (child, stdout, stdin, stderr) = match crate::runtime::process::spawn_pipe(&capability) {
        Ok(parts) => parts,
        Err(error) => return ret(error),
    };
    let main_endpoint = Endpoint::new(
        inner.limits.ring_bytes,
        inner.ready.clone(),
        State::Open,
        format!("process:{}:stdio", capability.id),
        EndpointRole::ProcessStdio,
    );
    let main = match inner.insert(Slot::Endpoint(main_endpoint.clone())) {
        Ok(handle) => handle,
        Err(error) => return ret(error),
    };
    let stderr_endpoint = Endpoint::new(
        inner.limits.ring_bytes,
        inner.ready.clone(),
        State::Open,
        format!("process:{}:stderr", capability.id),
        EndpointRole::ProcessStdio,
    );
    stderr_endpoint.set_read_only();
    let stderr_handle = match inner.insert(Slot::Endpoint(stderr_endpoint.clone())) {
        Ok(handle) => handle,
        Err(error) => {
            inner.remove(main);
            return ret(error);
        }
    };
    inner.spawn(crate::runtime::endpoint::reader_task(
        main_endpoint.clone(),
        Box::new(stdout),
    ));
    inner.spawn(crate::runtime::endpoint::writer_task(
        main_endpoint,
        Box::new(stdin),
    ));
    inner.spawn(crate::runtime::endpoint::reader_task(
        stderr_endpoint.clone(),
        Box::new(stderr),
    ));
    inner.spawn(crate::runtime::endpoint::writer_task(
        stderr_endpoint,
        Box::new(tokio::io::sink()),
    ));
    let process = Rc::new(crate::runtime::process::ProcessSlot {
        child: std::cell::RefCell::new(Some(crate::runtime::process::Child::Pipe(child))),
        status: std::cell::RefCell::new(Default::default()),
        allowed_signals: capability.allowed_signals,
        main,
        stderr: Some(stderr_handle),
    });
    let handle = match inner.insert(Slot::Process(process.clone())) {
        Ok(handle) => handle,
        Err(error) => {
            process.kill();
            inner.remove(main);
            inner.remove(stderr_handle);
            return ret(error);
        }
    };
    inner.spawn(crate::runtime::process::watch_exit(
        Rc::downgrade(&process),
        inner.ready.clone(),
        child_events,
    ));
    inner.publish_handles();
    ret(handle)
}

fn h_process_stdio(
    scope: &HelperScope,
    process: u64,
    stream_ptr: u64,
    stream_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let stream = guest!(string(scope, stream_ptr, stream_len));
    let Some(Slot2::Process(process)) = with(scope, |inner| inner.slot(process as i64))? else {
        return ret(errno::EBADF);
    };
    match stream.as_str() {
        "main" => ret(process.main),
        "stderr" => process.stderr.map_or_else(|| ret(errno::ENOENT), ret),
        _ => ret(errno::EINVAL),
    }
}

fn h_pty_resize(
    scope: &HelperScope,
    pty: u64,
    columns: u64,
    rows: u64,
    pixel_width: u64,
    pixel_height: u64,
) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    let Some(pty) = inner.ptys.borrow().get(&(pty as i64)).cloned() else {
        return ret(errno::EBADF);
    };
    match pty.resize(
        columns.min(u32::MAX as u64) as u32,
        rows.min(u32::MAX as u64) as u32,
        pixel_width.min(u32::MAX as u64) as u32,
        pixel_height.min(u32::MAX as u64) as u32,
    ) {
        Ok(()) => ret(0),
        Err(error) => ret(error),
    }
}

/// Terminal status as a JSON handle: `{"exited": true, "exit_code",
/// "signaled", "core_dumped", "signal"?}`.
///
/// `SY_EAGAIN` while the process is running; the status is repeatable — each
/// call after exit hands back a fresh handle — until the process handle is
/// closed.
fn h_process_status(
    scope: &HelperScope,
    process: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    let Some(Slot2::Process(process)) = inner.slot(process as i64) else {
        return ret(errno::EBADF);
    };
    let status = match process.refresh() {
        Ok(status) => status,
        Err(error) => return ret(error),
    };
    if !status.exited {
        return ret(errno::EAGAIN);
    }
    let mut value = json!({
        "exited": true,
        "exit_code": status.exit_code,
        "signaled": status.signal.is_some(),
        "core_dumped": status.core_dumped,
    });
    if let Some(signal) = status.signal {
        value["signal"] = json!(signal);
    }
    ret(insert_json(&inner, value))
}

fn h_process_signal(
    scope: &HelperScope,
    process: u64,
    name_ptr: u64,
    name_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let name = guest!(string(scope, name_ptr, name_len));
    let Some((bit, signal)) = crate::runtime::process::signal_number(&name) else {
        return ret(errno::EINVAL);
    };
    let Some(Slot2::Process(process)) = with(scope, |inner| inner.slot(process as i64))? else {
        return ret(errno::EBADF);
    };
    if process.allowed_signals & bit == 0 {
        return ret(errno::EPERM);
    }
    let Some(pid) = process.pid() else {
        return ret(errno::ESTATE);
    };
    let result = unsafe { libc::kill(-(pid as i32), signal) };
    ret(if result == 0 { 0 } else { errno::ECONNRESET })
}

fn h_sftp_open(
    scope: &HelperScope,
    capability_id: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    if inner.init_mode {
        return ret(errno::EPERM);
    }
    let Some(capability) = inner
        .policy
        .file_transfers
        .iter()
        .find(|capability| capability.id == capability_id as u32)
        .cloned()
    else {
        return ret(errno::EPERM);
    };
    if capability.protocol != 1 || capability.access & 0x01 == 0 {
        return ret(errno::EPERM);
    }
    let open = inner
        .slots
        .borrow()
        .iter()
        .flatten()
        .filter(|slot| {
            matches!(slot, Slot::Endpoint(ep) if matches!(ep.role(), EndpointRole::FileTransfer))
        })
        .count();
    if open >= crate::limits::MAX_OPEN_FILE_TRANSFERS {
        return ret(errno::ELIMIT);
    }
    let endpoint = Endpoint::new(
        inner.limits.ring_bytes,
        inner.ready.clone(),
        State::Open,
        format!("sftp:{}", capability.scope),
        EndpointRole::FileTransfer,
    );
    let handle = match inner.insert(Slot::Endpoint(endpoint.clone())) {
        Ok(handle) => handle,
        Err(error) => return ret(error),
    };
    let (local, service) = tokio::io::duplex(inner.limits.ring_bytes.min(256 * 1024));
    let (reader, writer) = tokio::io::split(local);
    inner.spawn(crate::runtime::endpoint::reader_task(
        endpoint.clone(),
        Box::new(reader),
    ));
    inner.spawn(crate::runtime::endpoint::writer_task(
        endpoint,
        Box::new(writer),
    ));
    let handler = crate::runtime::sftp::TreeSftp::new(
        inner.host.clone(),
        capability.scope,
        capability.access,
    );
    inner.spawn(async move {
        russh_sftp::server::run(service, handler).await;
    });
    inner.publish_handles();
    ret(handle)
}

// ---- poll: the only helper that suspends ---------------------------------

fn h_poll(
    scope: &HelperScope,
    fds_ptr: u64,
    n: u64,
    timeout_ms: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let timeout_ms = timeout_ms as i64;
    let inner = with(scope, Rc::clone)?;
    if n == 0 || n > inner.limits.max_handles as u64 {
        return ret(errno::EINVAL);
    }
    let (watch, requested, epoch) = {
        // This array is both the request and the reply. Register it as mutable
        // once: async-ebpf keeps every guest-memory registration for the whole
        // helper invocation, so reading it through `bytes` and registering it
        // again for the immediate reply would be an overlapping write.
        let mut region = match scope.user_memory_mut(fds_ptr, n * POLLFD_SIZE) {
            Ok(r) => r,
            Err(()) => return ret(errno::EINVAL),
        };

        // (handle, interest) pairs, read once. The guest's array is not read
        // again until the answer is written back: what it does to it in
        // between is its own business, and re-reading would make the reply
        // describe a request nobody made.
        let mut watch = Vec::with_capacity(n as usize);
        // The remainder is discarded rather than refused: the length was
        // checked against `n * POLLFD_SIZE` when it was read, so there is never
        // one.
        let (frames, _) = region.as_chunks::<{ POLLFD_SIZE as usize }>();
        for chunk in frames {
            let handle = i64::from_le_bytes(chunk[0..8].try_into().expect("8 bytes"));
            let events = u32::from_le_bytes(chunk[8..12].try_into().expect("4 bytes"));
            if events & !poll::ALL != 0 {
                return ret(errno::EINVAL);
            }
            watch.push((handle, events));
        }
        // Poll is itself the first ordinary endpoint operation. Selecting raw
        // mode here starts the pumps before readiness is sampled; fd zero in
        // SSH mode remains a control object and is deliberately left alone.
        if watch.iter().any(|(handle, _)| *handle == SY_SELF)
            && matches!(inner.slot(SY_SELF), Some(Slot2::Unselected(_)))
        {
            if let Err(error) = inner.select_raw() {
                return ret(error);
            }
        }

        let now = std::time::Instant::now();
        let until_deadline = inner.deadline.get().saturating_duration_since(now);
        let requested = if timeout_ms < 0 {
            until_deadline
        } else {
            Duration::from_millis(timeout_ms as u64).min(until_deadline)
        };

        inner
            .live
            .polls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let epoch = inner.ready.epoch();
        if let Some(count) = ready_now(&inner, &watch) {
            // Not progress: readiness on a terminal or bogus handle is
            // permanent with no work behind it, and counting it as progress
            // would let a guest re-poll a dead handle forever and keep the
            // idle deadline at arm's length. Progress is bytes moved
            // (`sy_read`/`sy_write`/`sy_splice`), which the helpers that move
            // them record. A poll that comes back ready with real work to do
            // records that work on the call that does it.
            return finish_poll(&mut region, &inner, &watch, count);
        }
        // Nothing can ever become ready, so waiting is waiting for nothing.
        // Told now rather than at the deadline: a program whose peers have all
        // hung up is finished, not idle.
        if inner.all_quiet() {
            return finish_poll(&mut region, &inner, &watch, 0);
        }

        // Leaving this scope releases the view before the suspended task. Its
        // completion callback gets a fresh HelperScope and guest-memory
        // registration set.
        (watch, requested, epoch)
    };
    let posted = inner.clone();
    let watch_for_task = watch;
    scope.post_task(async move {
        let deadline = std::time::Instant::now() + requested;
        let mut epoch = epoch;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            if !posted.ready.wait(epoch, remaining).await {
                break;
            }
            epoch = posted.ready.epoch();
            if ready_now(&posted, &watch_for_task).is_some() || posted.all_quiet() {
                break;
            }
        }
        let count = ready_now(&posted, &watch_for_task).unwrap_or(0);
        // Not progress, for the same reason as the immediate path above:
        // readiness alone says nothing about work done, and a readiness that
        // never goes away must not postpone the idle deadline forever.
        move |scope: &HelperScope| {
            write_revents(scope, fds_ptr, &posted, &watch_for_task)?;
            Ok(count)
        }
    });
    ret(0)
}

/// How many of the watched handles are ready, or `None` if none are.
fn ready_now(inner: &Inner, watch: &[(i64, u32)]) -> Option<u64> {
    let mut count = 0;
    for (handle, events) in watch {
        if revents_for(inner, *handle, *events) != 0 {
            count += 1;
        }
    }
    (count > 0).then_some(count)
}

/// The bits to report for one watched handle.
///
/// `ERR` and terminal `HUP` are reported whether or not they were asked for,
/// as poll(2) does: a program that did not ask about failure still needs to be
/// told, or it waits on a handle that will never do anything again. `RDHUP`,
/// like Linux's event of that name, remains subject to the requested mask. A
/// bad handle is `ERR` too, rather than a refusal of the whole call — one stale
/// handle in an array should not blind a program to the fifteen live ones
/// beside it.
fn revents_for(inner: &Inner, handle: i64, events: u32) -> u32 {
    match inner.slot(handle) {
        Some(Slot2::Unselected(_)) => 0,
        Some(Slot2::Endpoint(ep)) => ep.poll_revents(events),
        Some(Slot2::SshControl(ssh)) => ssh.revents() & (events | poll::ERR | poll::HUP),
        Some(Slot2::Object(obj)) => {
            let bits = match &*obj.result.borrow() {
                Some(Ok(_)) => poll::IN,
                Some(Err(_)) => poll::ERR,
                None => 0,
            };
            bits & (events | poll::ERR)
        }
        Some(Slot2::Cursor(_)) => poll::IN & events,
        // Inert data: nothing about a JSON value will ever become ready, and
        // reporting it would spin a poll loop that watches one by mistake.
        Some(Slot2::Json(_)) => 0,
        Some(Slot2::Writer(writer)) => writer.poll_revents(events),
        Some(Slot2::Process(process)) => match process.refresh() {
            Ok(status) if status.exited => poll::IN & events,
            Ok(_) => 0,
            Err(_) => poll::ERR,
        },
        None => poll::ERR,
    }
}

/// Writes the answer back into the guest's array.
fn write_revents(
    scope: &HelperScope,
    fds_ptr: u64,
    inner: &Inner,
    watch: &[(i64, u32)],
) -> Result<(), ()> {
    let len = watch.len() as u64 * POLLFD_SIZE;
    let mut region = scope.user_memory_mut(fds_ptr, len)?;
    write_revents_into(&mut region, inner, watch);
    Ok(())
}

fn write_revents_into(region: &mut [u8], inner: &Inner, watch: &[(i64, u32)]) {
    for (i, (handle, events)) in watch.iter().enumerate() {
        let bits = revents_for(inner, *handle, *events);
        let at = i * POLLFD_SIZE as usize + 12;
        region[at..at + 4].copy_from_slice(&bits.to_le_bytes());
    }
}

fn finish_poll(
    region: &mut [u8],
    inner: &Inner,
    watch: &[(i64, u32)],
    count: u64,
) -> Result<u64, ()> {
    write_revents_into(region, inner, watch);
    ret(count as i64)
}

// ---- the tree ------------------------------------------------------------

/// Turns a host answer into a handle.
fn insert_object(inner: &Rc<Inner>, info: crate::ObjectInfo) -> i64 {
    let slot = ObjectSlot {
        info,
        pending: std::cell::Cell::new(false),
        result: std::cell::RefCell::new(None),
        want: std::cell::Cell::new((0, 0)),
        ready: inner.ready.clone(),
    };
    match inner.insert(Slot::Object(Rc::new(slot))) {
        Ok(h) => h,
        Err(e) => e,
    }
}

/// The shared body of `sy_open` and `sy_open_from`.
///
/// Blocking here rather than returning `EAGAIN` and making the open pollable:
/// an open is a metadata lookup against state this node already holds, so it
/// completes without the network, and giving it the two-step shape `pread` has
/// would cost every program a state machine for a call that never waits.
fn open_common(scope: &HelperScope, origin: Option<String>, path: String) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    if inner.init_mode {
        return ret(errno::EPERM);
    }
    match inner.host.open(origin.as_deref(), &path) {
        Ok(info) => ret(insert_object(&inner, info)),
        Err(e) => ret(host_errno(&e)),
    }
}

fn host_errno(e: &crate::HostError) -> i64 {
    match e {
        crate::HostError::NotFound => errno::ENOENT,
        crate::HostError::NotReadable(_) => errno::EPERM,
        crate::HostError::Unavailable(_) => errno::ECONNRESET,
        crate::HostError::Denied(_) => errno::EPERM,
        crate::HostError::Conflict(_) => errno::ESTALE,
        crate::HostError::Io(_) => errno::EIO,
    }
}

fn h_open(scope: &HelperScope, ptr: u64, len: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    match string(scope, ptr, len) {
        Ok(path) => open_common(scope, None, path),
        Err(e) => ret(e),
    }
}

fn h_open_from(
    scope: &HelperScope,
    origin_ptr: u64,
    origin_len: u64,
    path_ptr: u64,
    path_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let origin = guest!(string(scope, origin_ptr, origin_len));
    match string(scope, path_ptr, path_len) {
        Ok(path) => open_common(scope, Some(origin), path),
        Err(e) => ret(e),
    }
}

fn h_open_root(scope: &HelperScope, ptr: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    let raw = guest!(bytes(scope, ptr, 32));
    let Ok(root) = synch_core::Hash::from_slice(&raw) else {
        return ret(errno::EINVAL);
    };
    let inner = with(scope, Rc::clone)?;
    if inner.init_mode {
        return ret(errno::EPERM);
    }
    match inner.host.open_root(&root) {
        Ok(info) => ret(insert_object(&inner, info)),
        Err(e) => ret(host_errno(&e)),
    }
}

/// An object's metadata as a JSON handle: `{"size", "mtime_ns", "mode",
/// "kind" ("file" | "dir" | "symlink" | "tombstone" | "socket"), "root"
/// (the BLAKE3 content root, hex)}`.
fn h_stat(scope: &HelperScope, handle: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    let Some(Slot2::Object(obj)) = inner.slot(handle as i64) else {
        return ret(errno::EBADF);
    };
    let kind = match obj.info.kind {
        0 => "file",
        1 => "dir",
        2 => "symlink",
        3 => "tombstone",
        4 => "socket",
        _ => "unknown",
    };
    let value = json!({
        "size": obj.info.size,
        "mtime_ns": obj.info.mtime_ns,
        "mode": obj.info.mode,
        "kind": kind,
        "root": obj.info.root.to_hex(),
    });
    ret(insert_json(&inner, value))
}

fn h_pread(
    scope: &HelperScope,
    handle: u64,
    ptr: u64,
    len: u64,
    offset: u64,
    _: u64,
) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    let Some(Slot2::Object(obj)) = inner.slot(handle as i64) else {
        return ret(errno::EBADF);
    };
    if len == 0 {
        return ret(0);
    }

    // An answer for exactly this range is what a retry after `EAGAIN` collects.
    // A different range starts a new read, because returning the previous
    // answer to a different question is worse than making the guest wait.
    let matching = obj.want.get() == (offset, len);
    if matching {
        let taken = obj.result.borrow_mut().take();
        match taken {
            Some(Ok(data)) => {
                inner.release(data.len() as u64);
                obj.want.set((0, 0));
                if data.is_empty() {
                    return ret(0);
                }
                let n = data.len().min(len as usize);
                let Ok(mut region) = scope.user_memory_mut(ptr, n as u64) else {
                    return ret(errno::EINVAL);
                };
                region.copy_from_slice(&data[..n]);
                return ret(n as i64);
            }
            Some(Err(e)) => {
                obj.want.set((0, 0));
                return ret(e);
            }
            None => {}
        }
    }
    if obj.pending.get() {
        return ret(errno::EAGAIN);
    }

    // Charge before the read is issued, so a program cannot queue a megabyte
    // of pending answers it has no budget to collect.
    if inner.charge(len).is_err() {
        return ret(errno::ELIMIT);
    }
    obj.pending.set(true);
    obj.want.set((offset, len));
    *obj.result.borrow_mut() = None;

    let host = inner.host.clone();
    let root = obj.info.root;
    let slot = obj.clone();
    let charged = len;
    let inner_for_task = inner.clone();
    inner.spawn(async move {
        let outcome = host.pread(root, offset, charged).await;
        slot.pending.set(false);
        match outcome {
            Ok(data) => {
                // The charge was for what was asked; settle up for what came.
                inner_for_task.release(charged.saturating_sub(data.len() as u64));
                *slot.result.borrow_mut() = Some(Ok(data));
            }
            Err(e) => {
                inner_for_task.release(charged);
                *slot.result.borrow_mut() = Some(Err(host_errno(&e)));
            }
        }
        slot.ready.bump();
    });
    ret(errno::EAGAIN)
}

fn h_list_open(scope: &HelperScope, ptr: u64, len: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    const PAGE_ENTRIES: usize = 256;
    const MAX_LIST_PAGES: usize = 256;
    let prefix = guest!(string(scope, ptr, len));
    if !synch_core::display_text_is_safe(&prefix) {
        return ret(errno::EINVAL);
    }
    let inner = with(scope, Rc::clone)?;
    if inner.init_mode {
        return ret(errno::EPERM);
    }
    let mut names = Vec::new();
    let mut cursor: Option<String> = None;
    let mut bytes = 0u64;
    let mut pages = 0usize;
    loop {
        if pages == MAX_LIST_PAGES {
            inner.release(bytes);
            return ret(errno::ELIMIT);
        }
        pages += 1;
        let page = match inner
            .host
            .list_page(&prefix, cursor.as_deref(), PAGE_ENTRIES)
        {
            Ok(page) if page.entries.len() <= PAGE_ENTRIES => page,
            Ok(_) => {
                inner.release(bytes);
                return ret(errno::ECONNRESET);
            }
            Err(error) => {
                inner.release(bytes);
                return ret(host_errno(&error));
            }
        };
        let page_bytes = page.entries.iter().fold(0u64, |total, name| {
            total.saturating_add(name.len() as u64 + CURSOR_ENTRY_OVERHEAD)
        });
        if inner.charge(page_bytes).is_err() {
            inner.release(bytes);
            return ret(errno::ELIMIT);
        }
        bytes = bytes.saturating_add(page_bytes);
        names.extend(page.entries);
        match page.next {
            Some(next) if cursor.as_ref().is_none_or(|before| next > *before) => {
                cursor = Some(next);
            }
            Some(_) => {
                inner.release(bytes);
                return ret(errno::ECONNRESET);
            }
            None => break,
        }
    }
    let slot = CursorSlot {
        names,
        at: std::cell::Cell::new(0),
    };
    match inner.insert(Slot::Cursor(Rc::new(slot))) {
        Ok(h) => ret(h),
        Err(e) => {
            inner.release(bytes);
            ret(e)
        }
    }
}

fn h_list_next(
    scope: &HelperScope,
    handle: u64,
    ptr: u64,
    len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let Some(Slot2::Cursor(cur)) = with(scope, |inner| inner.slot(handle as i64))? else {
        return ret(errno::EBADF);
    };
    let at = cur.at.get();
    let Some(name) = cur.names.get(at) else {
        return ret(0);
    };
    let result = out_str(scope, ptr, len, name);
    // `out_str` has snprintf semantics: a sizing call or truncated write has
    // not consumed the entry. Advance only after its bytes and NUL all fit.
    if len > name.len() as u64 && result == Ok(name.len() as u64) {
        cur.at.set(at + 1);
    }
    result
}

// ---- writing the tree (docs/TREE-WRITES.md) ------------------------------

/// Drains a writer's staging buffer into the host and performs its one
/// command, in order, off the guest's back.
///
/// The pump owns the [`SocketWriter`](crate::SocketWriter): a guest that
/// closes the handle uncommitted makes this task exit, and dropping the host
/// writer is what removes the staging behind it. An operation already
/// dispatched still runs to completion — a commit is atomic engine-side —
/// with its result discarded, exactly as an invocation killed mid-commit
/// leaves the tree either committed or untouched, never half-written.
async fn writer_pump(
    inner: Rc<Inner>,
    slot: Rc<WriterSlot>,
    mut host_writer: Box<dyn crate::SocketWriter>,
) {
    loop {
        if slot.closed.get() {
            return;
        }
        let chunk: Vec<u8> = {
            let mut buf = slot.buf.borrow_mut();
            let n = buf.len().min(64 * 1024);
            buf.drain(..n).collect()
        };
        if !chunk.is_empty() {
            match host_writer.write(chunk).await {
                Ok(()) => {
                    // Room appeared; a guest parked on OUT can continue.
                    slot.ready.bump();
                    continue;
                }
                Err(e) => {
                    slot.failed.set(host_errno(&e));
                    slot.ready.bump();
                    return;
                }
            }
        }
        if let Some(command) = slot.command.take() {
            let outcome = match command {
                PutCommand::Commit(condition) => host_writer
                    .commit(condition)
                    .await
                    .map(|receipt| Some(receipt.root)),
                PutCommand::Delete => host_writer.delete().await.map(|_| None),
            };
            slot.op_pending.set(false);
            let parked = outcome.map_err(|e| host_errno(&e));
            let succeeded = parked.is_ok();
            // A refusal (`SY_ESTALE`, `SY_EPERM`) leaves the host's staging
            // intact by contract — evaluated before anything is consumed —
            // so the guest may repair and re-dispatch. Anything else (disk,
            // CAS, a vanished space) may have consumed the staging on its
            // way down, and a retry over unknown staging is how an empty
            // file gets published under a valid receipt: sticky instead.
            let retryable = matches!(parked, Err(code)
                if code == errno::ESTALE || code == errno::EPERM);
            if succeeded || retryable {
                *slot.result.borrow_mut() = Some(parked);
            } else if let Err(code) = parked {
                slot.failed.set(code);
            }
            // A commit landing is progress in exactly the idle deadline's
            // sense, and a refused one is the answer the guest was parked on.
            inner.made_progress();
            slot.ready.bump();
            if succeeded || !retryable {
                // Spent on success, broken on a sticky failure; either way
                // nothing further will be asked of this writer.
                return;
            }
            continue;
        }
        slot.work.notified().await;
    }
}

/// Why a writer cannot take more bytes right now, or `None` if it can.
///
/// Sticky failure first — nothing recovers a broken staging — then the
/// lifecycle states: a dispatched, parked, or delivered operation makes
/// further writes a program bug, which is what `SY_ESTATE` is for.
fn writer_not_accepting(writer: &WriterSlot) -> Option<i64> {
    if writer.failed.get() != 0 {
        return Some(writer.failed.get());
    }
    if writer.delivered.get()
        || writer.op_pending.get()
        || writer.command.get().is_some()
        || writer.result.borrow().is_some()
    {
        return Some(errno::ESTATE);
    }
    None
}

fn h_put_open(
    scope: &HelperScope,
    capability_id: u64,
    path_ptr: u64,
    path_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let raw = guest!(string(scope, path_ptr, path_len));
    let inner = with(scope, Rc::clone)?;
    if inner.init_mode {
        return ret(errno::EPERM);
    }
    let Ok(path) = synch_core::normalize_path(&raw) else {
        return ret(errno::EINVAL);
    };
    // A write names a file inside a space, never a space itself.
    if !path
        .split_once('/')
        .is_some_and(|(space, rest)| !space.is_empty() && !rest.is_empty())
    {
        return ret(errno::EINVAL);
    }
    let Some(capability) = inner
        .policy
        .tree_writes
        .iter()
        .find(|capability| capability.id == capability_id as u32)
        .cloned()
    else {
        return ret(errno::EPERM);
    };
    if !capability.covers(&path) {
        tracing::warn!(
            socket = %inner.socket.qualified(),
            path,
            prefix = capability.prefix,
            "socket tree write refused: the path is outside the armed prefix"
        );
        return ret(errno::EPERM);
    }
    let writers = inner
        .slots
        .borrow()
        .iter()
        .flatten()
        .filter(|slot| matches!(slot, Slot::Writer(_)))
        .count();
    if writers >= crate::limits::MAX_OPEN_WRITERS {
        return ret(errno::ELIMIT);
    }
    // The engine's own gates — the declared-socket refusal, `.syncignore`,
    // recovery — are re-taken behind this call; the grant above is the
    // runtime's half of the check.
    let host_writer = match inner.host.put_open(&path, capability.modes) {
        Ok(writer) => writer,
        Err(e) => {
            tracing::warn!(
                socket = %inner.socket.qualified(),
                path,
                "socket tree write refused: {e}"
            );
            return ret(host_errno(&e));
        }
    };
    let slot = Rc::new(WriterSlot {
        path,
        capability,
        buf: std::cell::RefCell::new(std::collections::VecDeque::new()),
        work: Rc::new(tokio::sync::Notify::new()),
        command: std::cell::Cell::new(None),
        dispatched: std::cell::Cell::new(None),
        op_pending: std::cell::Cell::new(false),
        result: std::cell::RefCell::new(None),
        delivered: std::cell::Cell::new(false),
        failed: std::cell::Cell::new(0),
        accepted: std::cell::Cell::new(0),
        closed: std::cell::Cell::new(false),
        ready: inner.ready.clone(),
    });
    let handle = match inner.insert(Slot::Writer(slot.clone())) {
        Ok(handle) => handle,
        Err(error) => return ret(error),
    };
    inner.spawn(writer_pump(inner.clone(), slot, host_writer));
    inner.publish_handles();
    ret(handle)
}

fn h_put_write(
    scope: &HelperScope,
    handle: u64,
    ptr: u64,
    len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let data = guest!(bytes(scope, ptr, len));
    let inner = with(scope, Rc::clone)?;
    let Some(Slot2::Writer(writer)) = inner.slot(handle as i64) else {
        return ret(errno::EBADF);
    };
    if let Some(code) = writer_not_accepting(&writer) {
        return ret(code);
    }
    // The declared per-commit bound is enforced as bytes enter staging, before
    // the disk holds more than the grant allows — never at commit, when it
    // already does.
    let max = writer.capability.max_bytes;
    if max > 0 && writer.accepted.get().saturating_add(len) > max {
        return ret(errno::ELIMIT);
    }
    let room = writer.room();
    if room == 0 {
        return ret(errno::EAGAIN);
    }
    let n = data.len().min(room);
    writer.buf.borrow_mut().extend(&data[..n]);
    writer.accepted.set(writer.accepted.get() + n as u64);
    writer.work.notify_one();
    inner.made_progress();
    ret(n as i64)
}

/// Moves bytes from an endpoint's rx ring into a writer's staging, host-side.
///
/// `sy_splice` with a writer destination, and for the same reason: a drop-box
/// that never inspects the payload has no reason to lift it over the pointer
/// cage. Same returns too — a count, `0` at the source's clean EOF,
/// `SY_EAGAIN` when nothing could move — and the writer is checked before
/// anything leaves the source.
fn h_put_splice(
    scope: &HelperScope,
    handle: u64,
    from: u64,
    max: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    // Zero would have to mean both "moved nothing" and "the source ended";
    // refused as the malformed argument it is, exactly as `sy_splice` does.
    if max == 0 {
        return ret(errno::EINVAL);
    }
    let inner = with(scope, Rc::clone)?;
    let Some(Slot2::Writer(writer)) = inner.slot(handle as i64) else {
        return ret(errno::EBADF);
    };
    if let Some(code) = writer_not_accepting(&writer) {
        return ret(code);
    }
    let src = match inner.endpoint_for_io(from as i64) {
        Ok(endpoint) => endpoint,
        Err(error) => return ret(error),
    };
    let avail = src.readable();
    if avail == 0 {
        // The same answer `sy_read` gives an empty ring: `0` at a clean EOF,
        // the endpoint's errno, `SY_EAGAIN` while it may still fill. Checked
        // before the grant bound, so a payload of exactly `max_bytes` ends at
        // its clean EOF instead of tripping `SY_ELIMIT` with nothing left.
        return ret(src.read(&mut []));
    }
    let mut room = writer
        .room()
        .min(usize::try_from(max).unwrap_or(usize::MAX));
    let bound = writer.capability.max_bytes;
    if bound > 0 {
        let remaining = bound.saturating_sub(writer.accepted.get());
        if remaining == 0 {
            return ret(errno::ELIMIT);
        }
        room = room.min(usize::try_from(remaining).unwrap_or(usize::MAX));
    }
    let n = avail.min(room);
    if n == 0 {
        return ret(errno::EAGAIN);
    }
    let mut moved = vec![0u8; n];
    let took = src.read(&mut moved);
    if took <= 0 {
        return ret(took);
    }
    writer.buf.borrow_mut().extend(&moved[..took as usize]);
    writer.accepted.set(writer.accepted.get() + took as u64);
    writer.work.notify_one();
    inner.made_progress();
    // Counted as sy_splice counts its source: caller-facing bytes only.
    if src.role().counts_stream_bytes() {
        inner
            .live
            .bytes_in
            .fetch_add(took as u64, std::sync::atomic::Ordering::Relaxed);
    }
    ret(took)
}

/// The shared body of the three dispatch helpers: deliver a parked answer, or
/// validate and dispatch the command — `sy_pread`'s repeat-the-call shape.
fn put_op(
    scope: &HelperScope,
    handle: u64,
    command: PutCommand,
    out_ptr: Option<u64>,
) -> Result<u64, ()> {
    let inner = with(scope, Rc::clone)?;
    let Some(Slot2::Writer(writer)) = inner.slot(handle as i64) else {
        return ret(errno::EBADF);
    };
    if writer.failed.get() != 0 {
        return ret(writer.failed.get());
    }
    // An in-flight or parked answer belongs to the call that dispatched it:
    // a commit collecting a delete's bare success would return 0 with the
    // root buffer unwritten, and a delete collecting a commit would discard
    // the receipt. The wrong collector is the lifecycle bug `SY_ESTATE`
    // names, and the parked answer stays for the right one.
    let kind = command.kind();
    if writer
        .dispatched
        .get()
        .is_some_and(|dispatched| dispatched != kind)
    {
        return ret(errno::ESTATE);
    }
    // A parked answer is what the repeated call collects, before anything new
    // is dispatched.
    let parked = writer.result.borrow_mut().take();
    if let Some(outcome) = parked {
        match outcome {
            Ok(root) => {
                if let (Some(ptr), Some(root)) = (out_ptr, root) {
                    let Ok(mut region) = scope.user_memory_mut(ptr, 32) else {
                        // Park it again: a corrected retry can still collect.
                        *writer.result.borrow_mut() = Some(Ok(Some(root)));
                        return ret(errno::EINVAL);
                    };
                    region.copy_from_slice(root.as_bytes());
                }
                writer.dispatched.set(None);
                writer.delivered.set(true);
                return ret(0);
            }
            // A failed operation is not the writer's end: a lost condition is
            // retryable once the guest has read the tree again.
            Err(code) => {
                writer.dispatched.set(None);
                return ret(code);
            }
        }
    }
    if writer.op_pending.get() || writer.command.get().is_some() {
        return ret(errno::EAGAIN);
    }
    if writer.delivered.get() {
        return ret(errno::ESTATE);
    }
    match command {
        PutCommand::Delete => {
            if writer.capability.modes & synch_core::TREE_WRITE_DELETE == 0 {
                tracing::warn!(
                    socket = %inner.socket.qualified(),
                    path = writer.path,
                    "socket tree delete refused: the armed grant carries no delete mode"
                );
                return ret(errno::EPERM);
            }
            // A delete publishes no bytes; a writer that staged some was
            // going to commit them, and this call is a program bug.
            if writer.accepted.get() != 0 {
                return ret(errno::ESTATE);
            }
        }
        PutCommand::Commit(_) => {
            let writes = synch_core::TREE_WRITE_CREATE | synch_core::TREE_WRITE_REPLACE;
            if writer.capability.modes & writes == 0 {
                tracing::warn!(
                    socket = %inner.socket.qualified(),
                    path = writer.path,
                    "socket tree commit refused: the armed grant is delete-only"
                );
                return ret(errno::EPERM);
            }
        }
    }
    if inner.put_commits.get() >= crate::limits::MAX_PUT_COMMITS {
        return ret(errno::ELIMIT);
    }
    inner.put_commits.set(inner.put_commits.get() + 1);
    writer.command.set(Some(command));
    writer.dispatched.set(Some(kind));
    writer.op_pending.set(true);
    writer.work.notify_one();
    ret(errno::EAGAIN)
}

fn h_put_commit(
    scope: &HelperScope,
    handle: u64,
    out_ptr: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    put_op(
        scope,
        handle,
        PutCommand::Commit(crate::PutCondition::Any),
        Some(out_ptr),
    )
}

fn h_put_commit_if(
    scope: &HelperScope,
    handle: u64,
    expected_ptr: u64,
    out_ptr: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let raw = guest!(bytes(scope, expected_ptr, 32));
    // All-zero is a safe sentinel for "no live version of ours": it is not
    // the BLAKE3 of anything, the empty input included.
    let condition = if raw.iter().all(|byte| *byte == 0) {
        crate::PutCondition::Absent
    } else {
        match synch_core::Hash::from_slice(&raw) {
            Ok(root) => crate::PutCondition::Root(root),
            Err(_) => return ret(errno::EINVAL),
        }
    };
    put_op(scope, handle, PutCommand::Commit(condition), Some(out_ptr))
}

fn h_put_delete(
    scope: &HelperScope,
    handle: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    put_op(scope, handle, PutCommand::Delete, None)
}

// ---- state ---------------------------------------------------------------

fn h_map_get(
    scope: &HelperScope,
    key_ptr: u64,
    key_len: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = guest!(bytes(scope, key_ptr, key_len));
    let value = with(scope, |inner| {
        inner
            .maps
            .get(&inner.map_namespace(), &key, std::time::Instant::now())
    })?;
    match value {
        Some(v) => {
            if out_len < v.len() as u64 {
                // A value is not a string: half of it is a different value, so
                // the length is reported and nothing is copied.
                return ret(v.len() as i64);
            }
            out_exact(scope, out_ptr, out_len, &v)
        }
        None => ret(errno::ENOENT),
    }
}

fn h_map_set(
    scope: &HelperScope,
    key_ptr: u64,
    key_len: u64,
    val_ptr: u64,
    val_len: u64,
    ttl_ms: u64,
) -> Result<u64, ()> {
    let key = guest!(bytes(scope, key_ptr, key_len));
    let value = guest!(bytes(scope, val_ptr, val_len));
    with(scope, |inner| {
        // Clamped, not refused: a TTL beyond ~49.7 days is indistinguishable
        // from the program's intent, and the clamp keeps the expiry inside
        // every duration computation the store performs.
        let ttl = (ttl_ms > 0).then(|| Duration::from_millis(ttl_ms.min(MAX_GUEST_DURATION_MS)));
        match inner.maps.set(
            &inner.map_namespace(),
            &key,
            &value,
            ttl,
            std::time::Instant::now(),
            &inner.limits,
        ) {
            Ok(()) => 0,
            Err(()) => errno::ELIMIT,
        }
    })
    .and_then(ret)
}

fn h_map_delete(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = guest!(bytes(scope, ptr, len));
    with(scope, |inner| {
        i64::from(inner.maps.delete(&inner.map_namespace(), &key))
    })
    .and_then(ret)
}

fn h_map_incr(
    scope: &HelperScope,
    key_ptr: u64,
    key_len: u64,
    delta: u64,
    ttl_ms: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = guest!(bytes(scope, key_ptr, key_len));
    with(scope, |inner| {
        // Clamped as in `h_map_set`: the expiry must stay inside every
        // duration computation the store performs.
        let ttl = (ttl_ms > 0).then(|| Duration::from_millis(ttl_ms.min(MAX_GUEST_DURATION_MS)));
        match inner.maps.incr(
            &inner.map_namespace(),
            &key,
            delta as i64,
            ttl,
            std::time::Instant::now(),
            &inner.limits,
        ) {
            Ok(v) => v,
            Err(()) => errno::ELIMIT,
        }
    })
    .and_then(ret)
}

fn h_rate_limit(
    scope: &HelperScope,
    key_ptr: u64,
    key_len: u64,
    limit: u64,
    window_ms: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = guest!(bytes(scope, key_ptr, key_len));
    with(scope, |inner| {
        // Clamped: a window whose nanoseconds truncate to zero in the
        // limiter's `as u64` would divide by zero (2^58 ms is 15625 * 2^64
        // ns exactly), and one near `u64::MAX` ms overflows the internal
        // `Instant + Duration` on nanosecond-repr platforms. The clamp keeps
        // the width positive and the arithmetic in range.
        let window = Duration::from_millis(window_ms.clamp(1, MAX_GUEST_DURATION_MS));
        match inner.maps.rate_limit(
            &inner.map_namespace(),
            &key,
            limit,
            window,
            std::time::Instant::now(),
            &inner.limits,
        ) {
            Ok(()) => 0,
            Err(()) => errno::ELIMIT,
        }
    })
    .and_then(ret)
}

// ---- bytes, hashes, encodings --------------------------------------------

fn h_memcpy(scope: &HelperScope, dst: u64, src: u64, n: u64, _: u64, _: u64) -> Result<u64, ()> {
    if n == 0 {
        return Ok(dst);
    }
    if dst == src {
        // A compiler can emit `memcpy(p, p, n)` for a self-assignment, and
        // the cage would refuse the identical region read-then-written. It
        // is the identity, whatever the length says.
        return Ok(dst);
    }
    let data = guest!(bytes(scope, src, n));
    let Ok(mut region) = scope.user_memory_mut(dst, n) else {
        return ret(errno::EINVAL);
    };
    region.copy_from_slice(&data);
    Ok(dst)
}

fn h_memcmp(scope: &HelperScope, a: u64, b: u64, n: u64, _: u64, _: u64) -> Result<u64, ()> {
    if n == 0 {
        return ret(0);
    }
    let left = guest!(bytes(scope, a, n));
    let right = guest!(bytes(scope, b, n));
    for (l, r) in left.iter().zip(right.iter()) {
        if l != r {
            return ret(i64::from(*l) - i64::from(*r));
        }
    }
    ret(0)
}

fn h_memset(scope: &HelperScope, dst: u64, byte: u64, n: u64, _: u64, _: u64) -> Result<u64, ()> {
    if n == 0 {
        return Ok(dst);
    }
    let Ok(mut region) = scope.user_memory_mut(dst, n) else {
        return ret(errno::EINVAL);
    };
    region.fill(byte as u8);
    Ok(dst)
}

/// Constant-time equality, and the one helper whose failure must not be
/// truthy.
///
/// Every other helper reports a bad argument as a negative errno. This one is
/// written as `if (sy_ct_eq(secret, offered, n))` in C — the natural spelling
/// for a token check — and `-3` is as true as `1` there, so an unreadable
/// buffer or an over-long `n` would *grant* what it was asked to guard. It
/// therefore answers only `1` (equal) or `0` (not equal, or the comparison
/// could not be made), which makes the failure mode the closed one under both
/// the correct spelling and the natural one.
fn h_ct_eq(scope: &HelperScope, a: u64, b: u64, n: u64, _: u64, _: u64) -> Result<u64, ()> {
    let (Ok(left), Ok(right)) = (bytes(scope, a, n), bytes(scope, b, n)) else {
        return ret(0);
    };
    if left.len() != right.len() {
        return ret(0);
    }
    let mut diff = 0u8;
    for (l, r) in left.iter().zip(right.iter()) {
        diff |= l ^ r;
    }
    ret(i64::from(diff == 0))
}

fn h_blake3(scope: &HelperScope, ptr: u64, len: u64, out: u64, _: u64, _: u64) -> Result<u64, ()> {
    let data = guest!(bytes(scope, ptr, len));
    out_exact(scope, out, 32, blake3::hash(&data).as_bytes())
}

fn h_sha256(scope: &HelperScope, ptr: u64, len: u64, out: u64, _: u64, _: u64) -> Result<u64, ()> {
    let data = guest!(bytes(scope, ptr, len));
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &data);
    out_exact(scope, out, 32, digest.as_ref())
}

fn h_hmac_sha256(
    scope: &HelperScope,
    key_ptr: u64,
    key_len: u64,
    msg_ptr: u64,
    msg_len: u64,
    out: u64,
) -> Result<u64, ()> {
    let key = guest!(bytes(scope, key_ptr, key_len));
    let msg = guest!(bytes(scope, msg_ptr, msg_len));
    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &key);
    let tag = aws_lc_rs::hmac::sign(&key, &msg);
    out_exact(scope, out, 32, tag.as_ref())
}

/// The base64 engine for a `SY_BASE64_*` flag set.
///
/// Two orthogonal booleans rather than a four-value enum: `SY_BASE64_URL`
/// selects the URL-safe alphabet and `SY_BASE64_NO_PAD` drops the padding,
/// alone or together. Anything else set is refused.
fn engine(flags: u64) -> Option<base64::engine::GeneralPurpose> {
    use base64::engine::general_purpose::*;
    match flags {
        0 => Some(STANDARD),
        crate::abi::base64_flag::NO_PAD => Some(STANDARD_NO_PAD),
        crate::abi::base64_flag::URL => Some(URL_SAFE),
        crate::abi::base64_flag::URL_NO_PAD => Some(URL_SAFE_NO_PAD),
        _ => None,
    }
}

fn h_base64_encode(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    out: u64,
    out_len: u64,
    flags: u64,
) -> Result<u64, ()> {
    let data = guest!(bytes(scope, ptr, len));
    let Some(engine) = engine(flags) else {
        return ret(errno::EINVAL);
    };
    out_str(scope, out, out_len, &engine.encode(&data))
}

fn h_base64_decode_in_place(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    flags: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let Some(engine) = engine(flags) else {
        return ret(errno::EINVAL);
    };
    // One registration, read and write through it. The cage refuses to write
    // a region this call has already read, so the encoded bytes are taken out
    // of the single mutable view rather than read separately — the two
    // register as the same region, which is the whole point of "in place".
    let mut region = match scope.user_memory_mut(ptr, len) {
        Ok(region) => region,
        Err(()) => return ret(errno::EINVAL),
    };
    let data = region.to_vec();
    let Ok(decoded) = engine.decode(&data) else {
        return ret(errno::EINVAL);
    };
    // In place because there is no heap to decode into. The decoded form is
    // always shorter, so it always fits where the encoded form was.
    region[..decoded.len()].copy_from_slice(&decoded);
    ret(decoded.len() as i64)
}

fn h_hex_encode(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    out: u64,
    out_len: u64,
    upper: u64,
) -> Result<u64, ()> {
    let data = guest!(bytes(scope, ptr, len));
    let text = if upper == 0 {
        hex::encode(&data)
    } else {
        hex::encode_upper(&data)
    };
    out_str(scope, out, out_len, &text)
}

fn h_hex_decode_in_place(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    // One registration, read and write through it, as in
    // [`h_base64_decode_in_place`].
    let mut region = match scope.user_memory_mut(ptr, len) {
        Ok(region) => region,
        Err(()) => return ret(errno::EINVAL),
    };
    let data = region.to_vec();
    let Ok(decoded) = hex::decode(&data) else {
        return ret(errno::EINVAL);
    };
    // The decoded form is always shorter, so it always fits where the encoded
    // form was.
    region[..decoded.len()].copy_from_slice(&decoded);
    ret(decoded.len() as i64)
}

// ---- declarations --------------------------------------------------------

fn h_declare_name(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    declaring!(scope);
    let name = guest!(string(scope, ptr, len));
    if !synch_core::display_text_is_safe(&name) {
        return ret(errno::EINVAL);
    }
    with(scope, |inner| {
        inner.declaration.borrow_mut().name = name;
        0
    })
    .and_then(ret)
}

fn h_declare_egress(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    port: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    declaring!(scope);
    let host = guest!(string(scope, ptr, len));
    if !synch_core::display_text_is_safe(&host) {
        return ret(errno::EINVAL);
    }
    if port > u16::MAX as u64 {
        return ret(errno::EINVAL);
    }
    with(scope, |inner| {
        let mut decl = inner.declaration.borrow_mut();
        if decl.egress.len() >= synch_core::MAX_DECLARED_EGRESS {
            return errno::ELIMIT;
        }
        // Port 0 means "any port on this host" and is rendered as a bare host,
        // which is exactly how the operator's own list spells the same thing.
        decl.egress.push(if port == 0 {
            host
        } else {
            format!("{host}:{port}")
        });
        0
    })
    .and_then(ret)
}

fn h_declare_max_streams(
    scope: &HelperScope,
    n: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    declaring!(scope);
    with(scope, |inner| {
        inner.declaration.borrow_mut().max_streams = Some(n.min(u32::MAX as u64) as u32);
        0
    })
    .and_then(ret)
}

fn h_declare_stack_frame_size(
    scope: &HelperScope,
    size: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    declaring!(scope);
    with(scope, |inner| {
        let Ok(size) = u32::try_from(size) else {
            return errno::ELIMIT;
        };
        if size > synch_core::MAX_EBPF_STACK_FRAME_SIZE {
            return errno::ELIMIT;
        }
        if !synch_core::valid_ebpf_stack_frame_size(size) {
            return errno::EINVAL;
        }
        inner.declaration.borrow_mut().stack_frame_size = Some(size);
        0
    })
    .and_then(ret)
}

fn h_declare_guarded_stack_frames(
    scope: &HelperScope,
    enabled: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    declaring!(scope);
    with(scope, |inner| {
        let enabled = match enabled {
            0 => false,
            1 => true,
            _ => return errno::EINVAL,
        };
        inner.declaration.borrow_mut().guarded_stack_frames = Some(enabled);
        0
    })
    .and_then(ret)
}

/// A nonzero program-local capability id out of a JSON object.
fn capability_id_field(map: &serde_json::Map<String, Value>) -> Result<u32, i64> {
    map.get("id")
        .and_then(Value::as_u64)
        .and_then(|id| u32::try_from(id).ok())
        .filter(|id| *id != 0)
        .ok_or(errno::EINVAL)
}

/// Named-flag bits out of a JSON string array: every name must be known.
fn flag_bits(value: Option<&Value>, name_bit: impl Fn(&str) -> Option<u64>) -> Result<u64, i64> {
    let items = match value {
        None | Some(Value::Null) => return Ok(0),
        Some(Value::Array(items)) => items,
        Some(_) => return Err(errno::EINVAL),
    };
    let mut bits = 0;
    for item in items {
        bits |= item.as_str().and_then(&name_bit).ok_or(errno::EINVAL)?;
    }
    Ok(bits)
}

/// Declares one exact process capability from its JSON form:
/// `{"id", "allow": ["pty" | "pipe", …], "executable", "argv": [...],
///   "allowed_signals": ["HUP" | "INT" | "TERM", …]?}`.
fn h_declare_process(
    scope: &HelperScope,
    handle: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    declaring!(scope);
    let inner = with(scope, Rc::clone)?;
    let value = match json_value(&inner, handle as i64) {
        Ok(value) => value,
        Err(error) => return ret(error),
    };
    let Value::Object(map) = value else {
        return ret(errno::EINVAL);
    };
    let id = match capability_id_field(&map) {
        Ok(id) => id,
        Err(error) => return ret(error),
    };
    let flags = match flag_bits(map.get("allow"), |name| match name {
        "pty" => Some(0x01),
        "pipe" => Some(0x02),
        _ => None,
    }) {
        Ok(bits) => bits as u32,
        Err(error) => return ret(error),
    };
    let allowed_signals = match flag_bits(map.get("allowed_signals"), |name| {
        crate::runtime::process::signal_number(name).map(|(bit, _)| bit)
    }) {
        Ok(bits) => bits,
        Err(error) => return ret(error),
    };
    let Some(executable) = map.get("executable").and_then(Value::as_str) else {
        return ret(errno::EINVAL);
    };
    let argv: Vec<String> = match map.get("argv") {
        Some(Value::Array(items)) => {
            let mut argv = Vec::with_capacity(items.len());
            for item in items {
                match item.as_str() {
                    Some(arg) => argv.push(arg.to_owned()),
                    None => return ret(errno::EINVAL),
                }
            }
            argv
        }
        _ => return ret(errno::EINVAL),
    };
    if argv.is_empty() || argv.len() > synch_core::sock::MAX_PROCESS_ARGS {
        return ret(errno::EINVAL);
    }
    let canonical = match std::fs::canonicalize(executable) {
        Ok(path) => path,
        Err(_) => return ret(errno::ENOENT),
    };
    let Ok(metadata) = std::fs::metadata(&canonical) else {
        return ret(errno::ENOENT);
    };
    if !metadata.is_file() {
        return ret(errno::EINVAL);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o111 == 0 {
            return ret(errno::EPERM);
        }
    }
    let Some(executable) = canonical.to_str().map(str::to_owned) else {
        return ret(errno::EINVAL);
    };
    let capability = synch_core::ProcessCapability {
        id,
        flags,
        executable,
        argv,
        allowed_signals,
    };
    with(scope, |inner| {
        let mut declaration = inner.declaration.borrow_mut();
        if declaration.processes.len() >= synch_core::MAX_DECLARED_PROCESSES {
            return errno::ELIMIT;
        }
        if declaration
            .processes
            .iter()
            .any(|item| item.id == capability.id)
        {
            return errno::EINVAL;
        }
        declaration.processes.push(capability);
        match declaration.validate() {
            Ok(()) => 0,
            Err(_) => {
                declaration.processes.pop();
                errno::EINVAL
            }
        }
    })
    .and_then(ret)
}

/// Declares one scoped file-transfer capability from its JSON form:
/// `{"id", "protocol": "sftp", "access": ["read", "recursive"?],
///   "scope": "space/prefix"}`.
fn h_declare_file_transfer(
    scope: &HelperScope,
    handle: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    declaring!(scope);
    let inner = with(scope, Rc::clone)?;
    let value = match json_value(&inner, handle as i64) {
        Ok(value) => value,
        Err(error) => return ret(error),
    };
    let Value::Object(map) = value else {
        return ret(errno::EINVAL);
    };
    let id = match capability_id_field(&map) {
        Ok(id) => id,
        Err(error) => return ret(error),
    };
    let protocol = match map.get("protocol").and_then(Value::as_str) {
        Some("sftp") => 0x01,
        _ => return ret(errno::EINVAL),
    };
    let access = match flag_bits(map.get("access"), |name| match name {
        "read" => Some(0x01),
        "recursive" => Some(0x04),
        _ => None,
    }) {
        Ok(bits) => bits as u32,
        Err(error) => return ret(error),
    };
    let Some(transfer_scope) = map.get("scope").and_then(Value::as_str) else {
        return ret(errno::EINVAL);
    };
    let capability = synch_core::FileTransferCapability {
        id,
        protocol,
        access,
        scope: transfer_scope.to_owned(),
    };
    with(scope, |inner| {
        let mut declaration = inner.declaration.borrow_mut();
        if declaration.file_transfers.len() >= synch_core::MAX_DECLARED_FILE_TRANSFERS {
            return errno::ELIMIT;
        }
        if declaration
            .file_transfers
            .iter()
            .any(|item| item.id == capability.id)
        {
            return errno::EINVAL;
        }
        declaration.file_transfers.push(capability);
        match declaration.validate() {
            Ok(()) => 0,
            Err(_) => {
                declaration.file_transfers.pop();
                errno::EINVAL
            }
        }
    })
    .and_then(ret)
}

/// Declares one prefix-scoped tree-write capability from its JSON form:
/// `{"id", "prefix": "space/dir", "allow": ["create" | "replace" | "delete"],
///   "max_bytes"?}` (`docs/TREE-WRITES.md` §3).
fn h_declare_tree_write(
    scope: &HelperScope,
    handle: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    declaring!(scope);
    let inner = with(scope, Rc::clone)?;
    let value = match json_value(&inner, handle as i64) {
        Ok(value) => value,
        Err(error) => return ret(error),
    };
    let Value::Object(map) = value else {
        return ret(errno::EINVAL);
    };
    let id = match capability_id_field(&map) {
        Ok(id) => id,
        Err(error) => return ret(error),
    };
    let modes = match flag_bits(map.get("allow"), |name| match name {
        "create" => Some(synch_core::TREE_WRITE_CREATE as u64),
        "replace" => Some(synch_core::TREE_WRITE_REPLACE as u64),
        "delete" => Some(synch_core::TREE_WRITE_DELETE as u64),
        _ => None,
    }) {
        Ok(bits) => bits as u32,
        Err(error) => return ret(error),
    };
    let Some(prefix) = map.get("prefix").and_then(Value::as_str) else {
        return ret(errno::EINVAL);
    };
    // Absent means the modest default; `0` is the explicit "unbounded", which
    // the arm prompt prints loudly.
    let max_bytes = match map.get("max_bytes") {
        None | Some(Value::Null) => synch_core::DEFAULT_TREE_WRITE_MAX_BYTES,
        Some(value) => match value.as_u64() {
            Some(bytes) => bytes,
            None => return ret(errno::EINVAL),
        },
    };
    let capability = synch_core::TreeWriteCapability {
        id,
        modes,
        prefix: prefix.to_owned(),
        max_bytes,
    };
    with(scope, |inner| {
        let mut declaration = inner.declaration.borrow_mut();
        if declaration.tree_writes.len() >= synch_core::MAX_DECLARED_TREE_WRITES {
            return errno::ELIMIT;
        }
        if declaration
            .tree_writes
            .iter()
            .any(|item| item.id == capability.id)
        {
            return errno::EINVAL;
        }
        declaration.tree_writes.push(capability);
        match declaration.validate() {
            Ok(()) => 0,
            Err(_) => {
                declaration.tree_writes.pop();
                errno::EINVAL
            }
        }
    })
    .and_then(ret)
}

// The `SY_SELF` constant is part of the ABI rather than an implementation
// detail, so it is asserted here beside the code that assumes it.
const _: () = assert!(SY_SELF == 0);
