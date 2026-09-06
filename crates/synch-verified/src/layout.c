/* Checks, against the real lean.h, the object layout that native.rs copies.
 * Nothing here runs: the asserts fail the compile if a toolchain bump moves
 * a field, and the probe is a constant whose bytes a Rust test compares with
 * its own reading of the header. */
#include <lean/lean.h>
#include <stddef.h>

_Static_assert(sizeof(lean_object) == 8, "lean_object is a word");
_Static_assert(offsetof(lean_object, m_rc) == 0, "the reference count leads");
_Static_assert(sizeof(lean_sarray_object) == 24, "scalar array elements start at 24");
_Static_assert(offsetof(lean_sarray_object, m_size) == 8, "scalar array size");
_Static_assert(offsetof(lean_sarray_object, m_capacity) == 16, "scalar array capacity");
_Static_assert(offsetof(lean_sarray_object, m_data) == 24, "scalar array elements");
_Static_assert(LeanScalarArray == 248, "ByteArray tag");

/* How this compiler packs the header bitfields: native.rs expects m_cs_sz in
 * bytes 4-5, m_other in byte 6 and m_tag in byte 7. */
const lean_object synch_layout_probe = {
    .m_rc = 1, .m_cs_sz = 0x1234, .m_other = 0x56, .m_tag = 0x78,
};
