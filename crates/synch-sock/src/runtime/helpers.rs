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

use crate::{
    abi::{base64_kind, errno, poll, POLLFD_SIZE, STAT_SIZE, SY_SELF},
    limits::{MAX_COPY, MAX_LOG_LINE},
    runtime::{
        ctx::{Ctx, CursorSlot, Inner, ObjectSlot, Slot, Slot2},
        endpoint::{connect_task, Endpoint, State},
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
    ("sy_peer_kind", h_peer_kind),
    ("sy_peer_has_space", h_peer_has_space),
    ("sy_peer_addr", h_peer_addr),
    ("sy_conn_meta", h_conn_meta),
    ("sy_stream_index", h_stream_index),
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
    ("sy_declare_tree_read", h_declare_tree_read),
    ("sy_declare_max_streams", h_declare_max_streams),
    ("sy_declare_stack_frame_size", h_declare_stack_frame_size),
    (
        "sy_declare_guarded_stack_frames",
        h_declare_guarded_stack_frames,
    ),
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
    if len > MAX_COPY {
        return Err(errno::EINVAL);
    }
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
    if len > MAX_COPY {
        return ret(errno::EINVAL);
    }
    let mut buf = vec![0u8; len as usize];
    if aws_lc_rs::rand::fill(&mut buf).is_err() {
        return ret(errno::EINVAL);
    }
    out_exact(scope, ptr, len, &buf)
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

fn h_peer_kind(scope: &HelperScope, _: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    with(scope, |inner| inner.peer.kind())
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

// ---- endpoint I/O --------------------------------------------------------

fn h_read(scope: &HelperScope, handle: u64, ptr: u64, len: u64, _: u64, _: u64) -> Result<u64, ()> {
    let len = len.min(MAX_COPY);
    let Some(ep) = with(scope, |inner| inner.endpoint(handle as i64))? else {
        return ret(errno::EBADF);
    };
    if len == 0 {
        return ret(0);
    }
    let mut buf = vec![0u8; len as usize];
    let n = ep.read(&mut buf);
    if n <= 0 {
        return ret(n);
    }
    with(scope, |inner| {
        inner.made_progress();
        if handle as i64 == SY_SELF {
            inner
                .live
                .bytes_in
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        }
    })?;
    let Ok(mut region) = scope.user_memory_mut(ptr, n as u64) else {
        return ret(errno::EINVAL);
    };
    region.copy_from_slice(&buf[..n as usize]);
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
    let data = guest!(bytes(scope, ptr, len.min(MAX_COPY)));
    let Some(ep) = with(scope, |inner| inner.endpoint(handle as i64))? else {
        return ret(errno::EBADF);
    };
    let n = ep.write(&data);
    if n > 0 {
        with(scope, |inner| {
            inner.made_progress();
            // Only the caller's stream is counted: a proxy moves the same bytes
            // on both sides, and reporting the sum would say a socket did twice
            // the work it did.
            if handle as i64 == SY_SELF {
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
/// remainder to carry between calls. [`MAX_COPY`] therefore does not apply; the
/// move is bounded by the two rings and by what the guest asked for.
fn h_splice(scope: &HelperScope, from: u64, to: u64, max: u64, _: u64, _: u64) -> Result<u64, ()> {
    // Zero would have to mean either "nothing moved" or "the source is at its
    // end", and telling those two apart is the whole of a caller's control
    // flow. So it is refused as the malformed argument it is.
    if max == 0 {
        return ret(errno::EINVAL);
    }
    let inner = with(scope, Rc::clone)?;
    let (Some(src), Some(dst)) = (inner.endpoint(from as i64), inner.endpoint(to as i64)) else {
        // Including an object or a cursor handle: the tree is read with
        // `sy_pread`, whose answer may not be here yet, and a splice that could
        // block is not the helper this is.
        return ret(errno::EBADF);
    };
    let n = src.splice_to(&dst, usize::try_from(max).unwrap_or(usize::MAX));
    if n > 0 {
        inner.made_progress();
        // Counted as `sy_read` and `sy_write` count: only the caller's own
        // stream, so a proxy is not reported as having moved twice the bytes it
        // moved. A splice between two egress endpoints is neither, and shows up
        // in neither total.
        if from as i64 == SY_SELF {
            inner
                .live
                .bytes_in
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        }
        if to as i64 == SY_SELF {
            inner
                .live
                .bytes_out
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        }
    }
    ret(n)
}

fn h_readable(scope: &HelperScope, handle: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    match with(scope, |inner| inner.endpoint(handle as i64))? {
        Some(ep) => ret(ep.readable() as i64),
        None => ret(errno::EBADF),
    }
}

fn h_writable(scope: &HelperScope, handle: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    match with(scope, |inner| inner.endpoint(handle as i64))? {
        Some(ep) => ret(ep.writable() as i64),
        None => ret(errno::EBADF),
    }
}

fn h_shutdown(scope: &HelperScope, handle: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    match with(scope, |inner| inner.endpoint(handle as i64))? {
        Some(ep) => {
            ep.shutdown();
            ret(0)
        }
        None => ret(errno::EBADF),
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
        Some(Slot2::Endpoint(ep)) => ret(ep.errno()),
        Some(Slot2::Object(obj)) => {
            let code = match &*obj.result.borrow() {
                Some(Err(e)) => *e,
                _ => 0,
            };
            ret(code)
        }
        Some(Slot2::Cursor(_)) => ret(0),
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
    );
    let handle = match inner.insert(Slot::Endpoint(ep.clone())) {
        Ok(h) => h,
        Err(e) => return e,
    };
    inner.egress_open.set(inner.egress_open.get() + 1);
    inner.publish_handles();
    inner.spawn(connect_task(ep, host, port));
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
    let Some(ep) = with(scope, |inner| inner.endpoint(handle as i64))? else {
        return ret(errno::EBADF);
    };
    let state = match ep.state() {
        State::Connecting => "connecting",
        State::Open => "open",
        State::Failed => "failed",
        State::Closed => "closed",
    };
    out_str(scope, ptr, len, &format!("{} {state}", ep.peer()))
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
            inner.made_progress();
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
        if count > 0 {
            posted.made_progress();
        }
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
        Some(Slot2::Endpoint(ep)) => ep.poll_revents(events),
        Some(Slot2::Object(obj)) => {
            let bits = match &*obj.result.borrow() {
                Some(Ok(_)) => poll::IN,
                Some(Err(_)) => poll::ERR,
                None => 0,
            };
            bits & (events | poll::ERR)
        }
        Some(Slot2::Cursor(_)) => poll::IN & events,
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
    if let Some(origin) = &origin {
        if !inner.policy.tree_read_allowed(&path) {
            tracing::warn!(
                socket = %inner.socket.qualified(),
                origin,
                path,
                "socket tree read refused: the armed program did not declare it"
            );
            return ret(errno::EPERM);
        }
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

fn h_stat(scope: &HelperScope, handle: u64, ptr: u64, len: u64, _: u64, _: u64) -> Result<u64, ()> {
    if len < STAT_SIZE {
        return ret(errno::EINVAL);
    }
    let Some(Slot2::Object(obj)) = with(scope, |inner| inner.slot(handle as i64))? else {
        return ret(errno::EBADF);
    };
    let mut buf = [0u8; STAT_SIZE as usize];
    buf[0..8].copy_from_slice(&obj.info.size.to_le_bytes());
    buf[8..16].copy_from_slice(&obj.info.mtime_ns.to_le_bytes());
    buf[16..20].copy_from_slice(&obj.info.mode.to_le_bytes());
    buf[20..24].copy_from_slice(&obj.info.kind.to_le_bytes());
    buf[24..56].copy_from_slice(obj.info.root.as_bytes());
    out_exact(scope, ptr, STAT_SIZE, &buf)
}

fn h_pread(
    scope: &HelperScope,
    handle: u64,
    ptr: u64,
    len: u64,
    offset: u64,
    _: u64,
) -> Result<u64, ()> {
    let len = len.min(MAX_COPY);
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
    let prefix = guest!(string(scope, ptr, len));
    if !synch_core::display_text_is_safe(&prefix) {
        return ret(errno::EINVAL);
    }
    let inner = with(scope, Rc::clone)?;
    if inner.init_mode {
        return ret(errno::EPERM);
    }
    let names = match inner.host.list(&prefix) {
        Ok(names) => names,
        Err(e) => return ret(host_errno(&e)),
    };
    let bytes: u64 = names.iter().map(|n| n.len() as u64).sum();
    if inner.charge(bytes).is_err() {
        return ret(errno::ELIMIT);
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
        let ttl = (ttl_ms > 0).then(|| Duration::from_millis(ttl_ms));
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
        let ttl = (ttl_ms > 0).then(|| Duration::from_millis(ttl_ms));
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
        match inner.maps.rate_limit(
            &inner.map_namespace(),
            &key,
            limit,
            Duration::from_millis(window_ms.max(1)),
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
    if n > MAX_COPY {
        return ret(errno::EINVAL);
    }
    let Ok(mut region) = scope.user_memory_mut(dst, n) else {
        return ret(errno::EINVAL);
    };
    region.fill(byte as u8);
    Ok(dst)
}

fn h_ct_eq(scope: &HelperScope, a: u64, b: u64, n: u64, _: u64, _: u64) -> Result<u64, ()> {
    let left = guest!(bytes(scope, a, n));
    let right = guest!(bytes(scope, b, n));
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

fn engine(kind: u64) -> Option<base64::engine::GeneralPurpose> {
    use base64::engine::general_purpose::*;
    match kind {
        base64_kind::STANDARD => Some(STANDARD),
        base64_kind::STANDARD_NO_PAD => Some(STANDARD_NO_PAD),
        base64_kind::URL => Some(URL_SAFE),
        base64_kind::URL_NO_PAD => Some(URL_SAFE_NO_PAD),
        _ => None,
    }
}

fn h_base64_encode(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    out: u64,
    out_len: u64,
    kind: u64,
) -> Result<u64, ()> {
    let data = guest!(bytes(scope, ptr, len));
    let Some(engine) = engine(kind) else {
        return ret(errno::EINVAL);
    };
    out_str(scope, out, out_len, &engine.encode(&data))
}

fn h_base64_decode_in_place(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    kind: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if len > MAX_COPY {
        return ret(errno::EINVAL);
    }
    let Some(engine) = engine(kind) else {
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
    if len > MAX_COPY {
        return ret(errno::EINVAL);
    }
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
    let name = guest!(string(scope, ptr, len));
    if !synch_core::display_text_is_safe(&name) {
        return ret(errno::EINVAL);
    }
    with(scope, |inner| {
        if let Some(e) = mode_check(inner, true) {
            return e;
        }
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
    let host = guest!(string(scope, ptr, len));
    if !synch_core::display_text_is_safe(&host) {
        return ret(errno::EINVAL);
    }
    if port > u16::MAX as u64 {
        return ret(errno::EINVAL);
    }
    with(scope, |inner| {
        if let Some(e) = mode_check(inner, true) {
            return e;
        }
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

fn h_declare_tree_read(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let prefix = guest!(string(scope, ptr, len));
    if !synch_core::display_text_is_safe(&prefix) {
        return ret(errno::EINVAL);
    }
    // The everything-spelling is not a declaration: an operator approving
    // `tree-read /` would be approving every path in every origin.
    if !synch_core::sock::tree_read_prefix_grants_something(&prefix) {
        return ret(errno::EINVAL);
    }
    with(scope, |inner| {
        if let Some(e) = mode_check(inner, true) {
            return e;
        }
        let mut decl = inner.declaration.borrow_mut();
        if decl.tree_reads.len() >= synch_core::MAX_DECLARED_TREE_READS {
            return errno::ELIMIT;
        }
        decl.tree_reads.push(prefix);
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
    with(scope, |inner| {
        if let Some(e) = mode_check(inner, true) {
            return e;
        }
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
    with(scope, |inner| {
        if let Some(e) = mode_check(inner, true) {
            return e;
        }
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
    with(scope, |inner| {
        if let Some(e) = mode_check(inner, true) {
            return e;
        }
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

// The `SY_SELF` constant is part of the ABI rather than an implementation
// detail, so it is asserted here beside the code that assumes it.
const _: () = assert!(SY_SELF == 0);
