/* Only ABI marshalling, initialization and ownership live here. Every policy
 * decision is a Lean export. The pinned generated prototypes are tested by
 * linking and exercising the exports; Lean objects never escape this crate. */
#include <lean/lean.h>
#include <stdint.h>
#include <string.h>

extern void lean_initialize_runtime_module(void);
extern void lean_initialize_thread(void);
extern void lean_finalize_thread(void);
extern lean_object *initialize_VerifiedCore(uint8_t);
/* Matches the private Rust repr(C) slice. A zero length never dereferences ptr. */
typedef struct { const uint8_t *ptr; size_t len; } synch_slice;

uint8_t synch_adapter_initialize(void) {
    lean_initialize_runtime_module();
    lean_object *result = initialize_VerifiedCore(1);
    uint8_t ok = lean_io_result_is_ok(result);
    if (!ok) lean_io_result_show_error(result);
    lean_dec(result);
    if (ok) lean_io_mark_end_initialization();
    return ok;
}

void synch_adapter_thread_initialize(void) { lean_initialize_thread(); }
void synch_adapter_thread_finalize(void) { lean_finalize_thread(); }

static lean_object *bytes(synch_slice slice) {
    lean_object *result = lean_alloc_sarray(1, slice.len, slice.len);
    if (slice.len != 0) memcpy(lean_sarray_cptr(result), slice.ptr, slice.len);
    return result;
}

extern lean_object *synch_lean_cas_acquire(lean_object *, lean_object *, uint64_t, uint8_t);
extern lean_object *synch_lean_cas_delete(lean_object *, uint8_t, uint64_t);
extern lean_object *synch_lean_cas_unpin(lean_object *, lean_object *, uint8_t);
extern lean_object *synch_lean_cas_expire(lean_object *, uint8_t, uint64_t);
extern lean_object *synch_lean_cas_read(lean_object *, uint8_t, uint64_t, uint64_t);
extern lean_object *synch_lean_cas_ingest(uint8_t, uint64_t, uint64_t, uint8_t, uint8_t);
extern lean_object *synch_lean_trie_get(lean_object *, uint64_t);
extern lean_object *synch_lean_history_prune(lean_object *, uint64_t);
extern lean_object *synch_lean_operation_packet(lean_object *);
extern lean_object *synch_lean_operation_resume(lean_object *, lean_object *);

/* Operation handles are private, synchronous and thread-confined. Packet
 * inspection borrows a state reference; resume consumes one owned reference.
 * No continuation is interpreted by Rust. */
void *synch_adapter_operation_acquire(synch_slice root, synch_slice holder,
                                     uint64_t now, uint8_t possession) {
    return synch_lean_cas_acquire(bytes(root), bytes(holder), now, possession);
}

void *synch_adapter_operation_delete(synch_slice root, uint8_t has_before, uint64_t before) {
    return synch_lean_cas_delete(bytes(root), has_before, before);
}

void *synch_adapter_operation_unpin(synch_slice root, synch_slice payload, uint8_t kind) {
    return synch_lean_cas_unpin(bytes(root), bytes(payload), kind);
}

void *synch_adapter_operation_expire(synch_slice payload, uint8_t kind, uint64_t now) {
    return synch_lean_cas_expire(bytes(payload), kind, now);
}

void *synch_adapter_operation_read(synch_slice root, uint8_t all,
                                  uint64_t offset, uint64_t length) {
    return synch_lean_cas_read(bytes(root), all, offset, length);
}

void *synch_adapter_operation_ingest(uint8_t kind, uint64_t size, int64_t now,
                                    uint8_t cache, uint8_t allow_unsupported) {
    return synch_lean_cas_ingest(kind, size, (uint64_t)now, cache, allow_unsupported);
}

void *synch_adapter_operation_packet(void *state) {
    lean_inc((lean_object *)state);
    return synch_lean_operation_packet((lean_object *)state);
}

void *synch_adapter_operation_trie_get(synch_slice root, uint64_t key_size) {
    return synch_lean_trie_get(bytes(root), key_size);
}

void *synch_adapter_operation_history_prune(synch_slice origin, uint64_t before) {
    return synch_lean_history_prune(bytes(origin), before);
}

void *synch_adapter_operation_resume(void *state, synch_slice reply) {
    /* state ownership was transferred by Rust. The generated Lean export
     * consumes it on every branch; do not retain the previous continuation
     * while applying it, since that forces avoidable copy-on-write buffers. */
    return synch_lean_operation_resume((lean_object *)state, bytes(reply));
}


void synch_adapter_object_drop(void *value) { lean_dec((lean_object *)value); }
size_t synch_adapter_bytes_len(void *value) { return lean_sarray_size((lean_object *)value); }
const uint8_t *synch_adapter_bytes_data(void *value) { return lean_sarray_cptr((lean_object *)value); }
