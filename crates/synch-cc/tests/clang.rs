//! The clang pipeline, end to end: source in, eBPF object out.
//!
//! Unlike `compile.rs` these need a toolchain — a `clang` and `llc` with the
//! BPF backend on `PATH` — so they skip where there is none, the same
//! bargain `synch-sock`'s clang test strikes: a red test that means "no
//! compiler" teaches people to ignore red tests. Whether the objects *run*
//! is `synch-sock`'s question, answered in its `tests/examples.rs`.

use std::sync::OnceLock;

/// Whether compatible clang and llc executables exist with the BPF backend.
///
/// Checked by compiling rather than by running `--version`: Apple's clang is
/// present on every macOS and cannot emit BPF, so "clang exists" answers the
/// wrong question.
fn clang_targets_bpf() -> bool {
    static ANSWER: OnceLock<bool> = OnceLock::new();
    *ANSWER.get_or_init(|| {
        synch_cc::compile_with_clang("int probe(void) { return 0; }\n", "probe.c", &[], &[]).is_ok()
    })
}

/// A stand-in for the SDK header, as in `compile.rs` — this crate knows how
/// to compile C, not what a socket is. `sy_memset` and `sy_memcpy` are here
/// because they are what the lowered intrinsics link against.
const FAKE_SDK: &str = r#"
#ifndef FAKE_SDK_H
#define FAKE_SDK_H
typedef unsigned long long sy_u64;
typedef long long sy_s64;
#define SY_ENTRY __attribute__((section("synchronicity.stream")))
extern void *sy_memset(void *dst, int c, sy_u64 n);
extern void *sy_memcpy(void *dst, const void *src, sy_u64 n);
extern sy_s64 sy_write(sy_s64 handle, const void *buf, sy_u64 len);
#endif
"#;

fn sdk() -> [(&'static str, &'static str); 1] {
    [("synch.h", FAKE_SDK)]
}

/// The shape `examples/ssh-shell.c` failed with: a `= {0}` local past llc's
/// store budget. Clang compiles the initializer to an `llvm.memset` intrinsic
/// and llc, unable to expand ~1.3 KiB into stores, would make it a call to
/// libc — which the BPF backend refuses to emit. The struct escapes through
/// `sy_write` so the zeroing cannot be optimized away.
const BIG_ZERO_INITIALIZER: &str = r#"
#include <synch.h>

struct capability {
  unsigned id;
  char argv[10][128];
};

SY_ENTRY sy_s64 entry(void) {
  struct capability cap = {0};
  cap.id = 7;
  return sy_write(0, &cap, sizeof cap);
}
"#;

#[test]
fn a_zero_initializer_past_llcs_store_budget_still_compiles() {
    if !clang_targets_bpf() {
        eprintln!("skipping: no compatible clang/llc BPF toolchain");
        return;
    }
    let object = synch_cc::compile_with_clang(BIG_ZERO_INITIALIZER, "big-zero.c", &sdk(), &[])
        .expect("a large zero-initializer compiles through the clang pipeline");
    assert_eq!(&object[0..4], b"\x7fELF", "not an ELF object");
}

/// The copying twin: a struct assignment past the budget becomes
/// `llvm.memcpy`, and takes the same road to `sy_memcpy`.
const BIG_STRUCT_ASSIGNMENT: &str = r#"
#include <synch.h>

struct frame {
  char payload[2048];
};

SY_ENTRY sy_s64 entry(void) {
  struct frame in = {0}, out;
  /* An extern call the optimizer cannot see through, so `in` is unknown
     after it and the assignment below stays a real 2 KiB copy. */
  if (sy_write(0, &in, sizeof in) < 0) return 1;
  out = in;
  return sy_write(0, &out, sizeof out);
}
"#;

#[test]
fn a_struct_assignment_past_llcs_store_budget_still_compiles() {
    if !clang_targets_bpf() {
        return;
    }
    synch_cc::compile_with_clang(BIG_STRUCT_ASSIGNMENT, "big-copy.c", &sdk(), &[])
        .expect("a large struct assignment compiles through the clang pipeline");
}
