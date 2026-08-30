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
    abi::{
        base64_kind, errno, poll, FILE_TRANSFER_CAPABILITY_SIZE, POLLFD_SIZE,
        PROCESS_CAPABILITY_SIZE, PROCESS_STATUS_SIZE, PTY_SPEC_SIZE, SSH_EVENT_SIZE, STAT_SIZE,
        SY_SELF,
    },
    limits::{CURSOR_ENTRY_OVERHEAD, MAX_GUEST_DURATION_MS, MAX_LOG_LINE},
    runtime::{
        ctx::{Ctx, CursorSlot, Inner, ObjectSlot, Slot, Slot2},
        endpoint::{connect_task, Endpoint, EndpointRole, State},
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
    // appended last: helper ids are table positions resolved by name, so this
    // is additive and cannot collide with an existing id
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
        Some(Slot2::Process(process)) => ret(process.refresh().err().unwrap_or(0)),
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

fn h_ssh_start(
    scope: &HelperScope,
    stream: u64,
    methods: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if stream as i64 != SY_SELF || methods == 0 || methods & !crate::runtime::ssh::AUTH_ALL != 0 {
        return ret(errno::EINVAL);
    }
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

fn h_ssh_next(
    scope: &HelperScope,
    conn: u64,
    out: u64,
    out_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if conn as i64 != SY_SELF || out_len < SSH_EVENT_SIZE {
        return ret(errno::EINVAL);
    }
    let state = match with(scope, |inner| ssh_state(inner))? {
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
    let Ok(mut region) = scope.user_memory_mut(out, SSH_EVENT_SIZE) else {
        return ret(errno::EINVAL);
    };
    region[0..8].copy_from_slice(&event.id.to_le_bytes());
    region[8..16].copy_from_slice(&event.fd.to_le_bytes());
    for (offset, value) in [
        (16, event.kind),
        (20, event.flags),
        (24, event.data_len),
        (28, event.aux_len),
        (32, event.a),
        (36, event.b),
        (40, event.c),
        (44, event.d),
    ] {
        region[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    ret(1)
}

fn h_ssh_event_data(
    scope: &HelperScope,
    event_id: u64,
    field: u64,
    out: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let state = match with(scope, |inner| ssh_state(inner))? {
        Ok(state) => state,
        Err(error) => return ret(error),
    };
    let Some(mut value) = state.field(event_id, field as u32) else {
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
    if field as u32 == crate::runtime::ssh::FIELD_PASSWORD {
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

fn h_ssh_auth_reply(
    scope: &HelperScope,
    event_id: u64,
    result: u64,
    next_methods: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if !(1..=4).contains(&result) || next_methods & !crate::runtime::ssh::AUTH_ALL != 0 {
        return ret(errno::EINVAL);
    }
    let state = match with(scope, |inner| ssh_state(inner))? {
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
    reason: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let reason = match reason {
        1 => russh::ChannelOpenFailure::AdministrativelyProhibited,
        2 => russh::ChannelOpenFailure::ConnectFailed,
        3 => russh::ChannelOpenFailure::UnknownChannelType,
        4 => russh::ChannelOpenFailure::ResourceShortage,
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

fn h_ssh_pty_spec(
    scope: &HelperScope,
    event_id: u64,
    out: u64,
    out_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if out_len < PTY_SPEC_SIZE {
        return ret(errno::EINVAL);
    }
    let state = match with(scope, |inner| ssh_state(inner))? {
        Ok(state) => state,
        Err(error) => return ret(error),
    };
    let Some(pty) = state.pty(event_id) else {
        return ret(errno::ESTATE);
    };
    if pty.term.len() > 64 || pty.modes.len() > 64 {
        return ret(errno::ELIMIT);
    }
    let Ok(mut region) = scope.user_memory_mut(out, PTY_SPEC_SIZE) else {
        return ret(errno::EINVAL);
    };
    region.fill(0);
    region[..pty.term.len()].copy_from_slice(pty.term.as_bytes());
    for (offset, value) in [
        (64, pty.term.len() as u32),
        (68, pty.columns),
        (72, pty.rows),
        (76, pty.pixel_width),
        (80, pty.pixel_height),
        (84, pty.modes.len() as u32),
    ] {
        region[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (index, (opcode, value)) in pty.modes.iter().enumerate() {
        let offset = 88 + index * 8;
        region[offset..offset + 4].copy_from_slice(&(*opcode as u32).to_le_bytes());
        region[offset + 4..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    ret(0)
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

fn parse_pty_spec(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
) -> Result<crate::runtime::ssh::PtyRequest, i64> {
    if len != PTY_SPEC_SIZE {
        return Err(errno::EINVAL);
    }
    let raw = bytes(scope, ptr, len)?;
    let term_len = le_u32(&raw, 64) as usize;
    let mode_count = le_u32(&raw, 84) as usize;
    if term_len > 64 || mode_count > 64 {
        return Err(errno::EINVAL);
    }
    let term = String::from_utf8(raw[..term_len].to_vec()).map_err(|_| errno::EINVAL)?;
    // Empty is legitimate: a client with no local terminal — `ssh -tt` from a
    // script or ProxyCommand — sends an empty name, and refusing it would
    // refuse the PTY. The child then simply gets no TERM variable.
    if !term
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.+".contains(&byte))
    {
        return Err(errno::EINVAL);
    }
    let mut modes = Vec::with_capacity(mode_count);
    for index in 0..mode_count {
        let offset = 88 + index * 8;
        modes.push((le_u32(&raw, offset) as u8, le_u32(&raw, offset + 4)));
    }
    Ok(crate::runtime::ssh::PtyRequest {
        term,
        columns: le_u32(&raw, 68),
        rows: le_u32(&raw, 72),
        pixel_width: le_u32(&raw, 76),
        pixel_height: le_u32(&raw, 80),
        modes,
    })
}

fn h_pty_open(
    scope: &HelperScope,
    capability_id: u64,
    spec_ptr: u64,
    spec_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let spec = guest!(parse_pty_spec(scope, spec_ptr, spec_len));
    let inner = with(scope, Rc::clone)?;
    if inner.init_mode {
        return ret(errno::EPERM);
    }
    let capability = match process_capability(&inner, capability_id as u32) {
        Ok(capability) if capability.flags & 0x01 != 0 => capability,
        Ok(_) | Err(_) => return ret(errno::EPERM),
    };
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
    stream: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let Some(Slot2::Process(process)) = with(scope, |inner| inner.slot(process as i64))? else {
        return ret(errno::EBADF);
    };
    match stream {
        0 => ret(process.main),
        1 => process.stderr.map_or_else(|| ret(errno::ENOENT), ret),
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

fn h_process_status(
    scope: &HelperScope,
    process: u64,
    out: u64,
    out_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if out_len < PROCESS_STATUS_SIZE {
        return ret(errno::EINVAL);
    }
    let Some(Slot2::Process(process)) = with(scope, |inner| inner.slot(process as i64))? else {
        return ret(errno::EBADF);
    };
    let status = match process.refresh() {
        Ok(status) => status,
        Err(error) => return ret(error),
    };
    if !status.exited {
        return ret(errno::EAGAIN);
    }
    let Ok(mut region) = scope.user_memory_mut(out, PROCESS_STATUS_SIZE) else {
        return ret(errno::EINVAL);
    };
    region.fill(0);
    for (offset, value) in [
        (0, status.exited as u32),
        (4, status.exit_code),
        (8, status.signal.is_some() as u32),
        (12, status.core_dumped as u32),
    ] {
        region[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    if let Some(signal) = status.signal {
        let bytes = signal.as_bytes();
        let n = bytes.len().min(32);
        region[16..16 + n].copy_from_slice(&bytes[..n]);
        region[48..52].copy_from_slice(&(n as u32).to_le_bytes());
    }
    ret(1)
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

fn le_u32(raw: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        raw[offset..offset + 4]
            .try_into()
            .expect("validated ABI field"),
    )
}

fn le_u64(raw: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        raw[offset..offset + 8]
            .try_into()
            .expect("validated ABI field"),
    )
}

fn fixed_string(raw: &[u8], offset: usize, capacity: usize, len: u32) -> Result<String, i64> {
    let len = len as usize;
    if len > capacity {
        return Err(errno::EINVAL);
    }
    String::from_utf8(raw[offset..offset + len].to_vec()).map_err(|_| errno::EINVAL)
}

fn h_declare_process(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    declaring!(scope);
    if len != PROCESS_CAPABILITY_SIZE {
        return ret(errno::EINVAL);
    }
    let raw = guest!(bytes(scope, ptr, len));
    let executable = guest!(fixed_string(&raw, 8, 256, le_u32(&raw, 264)));
    let argc = le_u32(&raw, 268) as usize;
    if argc == 0 || argc > synch_core::sock::MAX_PROCESS_ARGS {
        return ret(errno::EINVAL);
    }
    let mut argv = Vec::with_capacity(argc);
    for index in 0..argc {
        argv.push(guest!(fixed_string(
            &raw,
            272 + index * synch_core::sock::MAX_PROCESS_ARG_BYTES,
            synch_core::sock::MAX_PROCESS_ARG_BYTES,
            le_u32(&raw, 1296 + index * 4),
        )));
    }
    let canonical = match std::fs::canonicalize(&executable) {
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
        id: le_u32(&raw, 0),
        flags: le_u32(&raw, 4),
        executable,
        argv,
        allowed_signals: le_u64(&raw, 1328),
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

fn h_declare_file_transfer(
    scope: &HelperScope,
    ptr: u64,
    len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    declaring!(scope);
    if len != FILE_TRANSFER_CAPABILITY_SIZE {
        return ret(errno::EINVAL);
    }
    let raw = guest!(bytes(scope, ptr, len));
    let capability = synch_core::FileTransferCapability {
        id: le_u32(&raw, 0),
        protocol: le_u32(&raw, 4),
        access: le_u32(&raw, 8),
        scope: guest!(fixed_string(&raw, 12, 256, le_u32(&raw, 268))),
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

// The `SY_SELF` constant is part of the ABI rather than an implementation
// detail, so it is asserted here beside the code that assumes it.
const _: () = assert!(SY_SELF == 0);
