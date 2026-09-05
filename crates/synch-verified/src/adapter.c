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
extern lean_object *synch_lean_scope_new(uint8_t, lean_object *, lean_object *);
extern uint8_t synch_lean_scope_path(lean_object *, lean_object *);
extern uint8_t synch_lean_scope_subtree(lean_object *, lean_object *);
extern uint8_t synch_lean_scope_key(lean_object *, lean_object *);
extern uint8_t synch_lean_scope_node(lean_object *, lean_object *, uint8_t, uint8_t, lean_object *);
extern uint8_t synch_lean_scope_value(lean_object *, lean_object *, uint8_t, lean_object *);
extern lean_object *synch_lean_cache_new(uint64_t);
extern uint64_t synch_lean_cache_epoch(lean_object *);
extern uint8_t synch_lean_cache_can_certify(lean_object *, uint64_t);
extern uint8_t synch_lean_cache_known(lean_object *, lean_object *);
extern lean_object *synch_lean_cache_begin(lean_object *, lean_object *);
extern lean_object *synch_lean_cache_finish(lean_object *);
extern lean_object *synch_lean_cache_certify(lean_object *, uint64_t, lean_object *);
extern lean_object *synch_lean_walk_new(lean_object *, lean_object *, lean_object *, uint64_t);
extern uint8_t synch_lean_walk_exhausted(lean_object *);
extern uint8_t synch_lean_walk_status(lean_object *);
extern uint64_t synch_lean_walk_depth(lean_object *);
extern lean_object *synch_lean_walk_field(lean_object *, uint8_t);
extern lean_object *synch_lean_walk_poll(lean_object *);
extern lean_object *synch_lean_walk_defer(lean_object *);
extern lean_object *synch_lean_walk_resume(lean_object *);
extern lean_object *synch_lean_walk_batch(lean_object *);
extern lean_object *synch_lean_walk_enqueue(lean_object *, lean_object *, lean_object *, lean_object *);
extern uint8_t synch_lean_walk_requires_branch(lean_object *, lean_object *);
extern lean_object *synch_lean_walk_branch(lean_object *, lean_object *, uint8_t);
extern uint8_t synch_lean_walk_unasked(lean_object *, lean_object *);
extern lean_object *synch_lean_walk_ask(lean_object *, lean_object *);
extern lean_object *synch_lean_walk_node(uint8_t, lean_object *, lean_object *, lean_object *);
extern lean_object *synch_lean_walk_expand(lean_object *, lean_object *, lean_object *);

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

static lean_object *paths(const synch_slice *items, size_t count) {
    lean_object *result = lean_alloc_array(0, count);
    for (size_t i = 0; i < count; ++i) result = lean_array_push(result, bytes(items[i]));
    return result;
}

void *synch_adapter_scope_new(uint8_t full, const synch_slice *prefixes, size_t np,
                             const synch_slice *exact, size_t ne) {
    lean_object *scope = synch_lean_scope_new(full, paths(prefixes, np), paths(exact, ne));
    /* Rust shares this immutable object via Arc. Its complete reachable graph
     * must use multi-threaded reference counting before publication. */
    lean_mark_mt(scope);
    return scope;
}

void synch_adapter_scope_drop(void *scope) { lean_dec((lean_object *)scope); }

void *synch_adapter_walk_node(uint8_t tag, const synch_slice *children, size_t count,
                             synch_slice prefix, synch_slice child) {
    lean_object *node = synch_lean_walk_node(tag, paths(children, count), bytes(prefix), bytes(child));
    lean_mark_mt(node);
    return node;
}

void *synch_adapter_walk_expand(void *walk, void *reference, void *node) {
    lean_inc((lean_object *)walk);
    lean_inc((lean_object *)reference);
    lean_inc((lean_object *)node);
    lean_object *s = synch_lean_walk_expand(walk, reference, node);
    lean_mark_mt(s);
    return s;
}

void *synch_adapter_walk_new(void *scope, synch_slice reference, synch_slice root, uint64_t max_depth) {
    lean_inc((lean_object *)scope);
    lean_object *s = synch_lean_walk_new((lean_object *)scope, bytes(reference), bytes(root), max_depth);
    lean_mark_mt(s);
    return s;
}

uint64_t synch_adapter_walk_query(void *walk, uint8_t operation, synch_slice hash) {
    lean_object *s = (lean_object *)walk;
    lean_inc(s);
    switch (operation) {
    case 0: return synch_lean_walk_exhausted(s);
    case 1: return synch_lean_walk_status(s);
    case 2: return synch_lean_walk_depth(s);
    case 3: return synch_lean_walk_requires_branch(s, bytes(hash));
    case 4: return synch_lean_walk_unasked(s, bytes(hash));
    default: lean_dec(s); return 0;
    }
}

void *synch_adapter_walk_update(void *walk, uint8_t operation, synch_slice reference,
                               synch_slice hash, synch_slice step) {
    lean_object *s = (lean_object *)walk;
    lean_inc(s);
    switch (operation) {
    case 0: s = synch_lean_walk_poll(s); break;
    case 1: s = synch_lean_walk_defer(s); break;
    case 2: s = synch_lean_walk_resume(s); break;
    case 3: s = synch_lean_walk_batch(s); break;
    case 4: s = synch_lean_walk_enqueue(s, bytes(reference), bytes(hash), bytes(step)); break;
    case 5: s = synch_lean_walk_branch(s, bytes(hash), 1); break;
    case 6: s = synch_lean_walk_branch(s, bytes(hash), 0); break;
    case 7: s = synch_lean_walk_ask(s, bytes(hash)); break;
    default: break;
    }
    lean_mark_mt(s);
    return s;
}

void *synch_adapter_walk_field(void *walk, uint8_t field) {
    lean_inc((lean_object *)walk);
    lean_object *result = synch_lean_walk_field((lean_object *)walk, field);
    lean_mark_mt(result);
    return result;
}

size_t synch_adapter_bytes_len(void *value) { return lean_sarray_size((lean_object *)value); }
const uint8_t *synch_adapter_bytes_data(void *value) { return lean_sarray_cptr((lean_object *)value); }

void *synch_adapter_cache_new(uint64_t capacity) {
    lean_object *s = synch_lean_cache_new(capacity);
    lean_mark_mt(s);
    return s;
}

uint64_t synch_adapter_cache_epoch(void *cache) {
    lean_inc((lean_object *)cache);
    return synch_lean_cache_epoch((lean_object *)cache);
}

uint8_t synch_adapter_cache_can_certify(void *cache, uint64_t epoch) {
    lean_inc((lean_object *)cache);
    return synch_lean_cache_can_certify((lean_object *)cache, epoch);
}

uint8_t synch_adapter_cache_known(void *cache, synch_slice key) {
    lean_inc((lean_object *)cache);
    return synch_lean_cache_known((lean_object *)cache, bytes(key));
}

/* Supply a fresh reference to each pure state transition. Mark its result
 * before Rust publishes the replacement under the caller's mutex. */
void *synch_adapter_cache_update(void *cache, uint8_t operation, uint64_t epoch,
                                synch_slice key, const synch_slice *keep, size_t count) {
    lean_object *s = (lean_object *)cache;
    lean_inc(s);
    switch (operation) {
    case 0: s = synch_lean_cache_begin(s, paths(keep, count)); break;
    case 1: s = synch_lean_cache_finish(s); break;
    case 2: s = synch_lean_cache_certify(s, epoch, bytes(key)); break;
    default: break;
    }
    lean_mark_mt(s);
    return s;
}

uint8_t synch_adapter_scope_query(void *scope, uint8_t operation, synch_slice path,
                                  uint8_t tag, uint8_t inline_value, synch_slice suffix) {
    lean_object *s = (lean_object *)scope;
    /* Exports consume their arguments, so supply a fresh reference for each call. */
    lean_inc(s);
    switch (operation) {
    case 0: return synch_lean_scope_path(s, bytes(path));
    case 1: return synch_lean_scope_subtree(s, bytes(path));
    case 2: return synch_lean_scope_key(s, bytes(path));
    case 3: return synch_lean_scope_node(s, bytes(path), tag, inline_value, bytes(suffix));
    case 4: return synch_lean_scope_value(s, bytes(path), tag, bytes(suffix));
    default: lean_dec(s); return 0;
    }
}
