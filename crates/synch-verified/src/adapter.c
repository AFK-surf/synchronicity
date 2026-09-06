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

extern lean_object *synch_lean_start(lean_object *);
extern lean_object *synch_lean_operation_packet(lean_object *);
extern lean_object *synch_lean_operation_resume(lean_object *, lean_object *);

/* One entry point: the command packet is decoded in Lean. Operation handles
 * are private, synchronous and thread-confined. Packet inspection borrows a
 * state reference; resume consumes one owned reference. No continuation is
 * interpreted by Rust. */
void *synch_adapter_start(synch_slice command) {
    return synch_lean_start(bytes(command));
}

void *synch_adapter_operation_packet(void *state) {
    lean_inc((lean_object *)state);
    return synch_lean_operation_packet((lean_object *)state);
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
