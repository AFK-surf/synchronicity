//! The embedded compiler, end to end: source in, eBPF object out.
//!
//! These need no toolchain — that is the whole of what this crate is for — so
//! unlike `synch-sock`'s runtime tests they never skip on a bare machine.
//!
//! What they do *not* do is run anything. The programs the examples compile to
//! are executed in `synch-sock`'s `tests/examples.rs`, which has a runtime to
//! run them with; keeping the two apart is also what keeps the two crates from
//! dev-depending on each other in a circle.

use synch_cc::{CcError, SUPPORTED};

/// A stand-in for the SDK header. Deliberately not `synch-sock`'s real one:
/// this crate knows how to compile C, not what a socket is.
const FAKE_SDK: &str = r#"
#ifndef FAKE_SDK_H
#define FAKE_SDK_H
typedef long long sy_s64;
#define SY_ENTRY __attribute__((section("synchronicity.stream")))
extern sy_s64 sy_shutdown(sy_s64 handle);
#endif
"#;

fn sdk() -> [(&'static str, &'static str); 1] {
    [("synch.h", FAKE_SDK)]
}

/// Section names, in order, out of an ELF64 relocatable.
fn sections(object: &[u8]) -> Vec<String> {
    assert_eq!(&object[0..4], b"\x7fELF", "not an ELF object");
    assert_eq!(object[4], 2, "not ELF64");
    let u16at = |off: usize| u16::from_le_bytes(object[off..off + 2].try_into().unwrap()) as usize;
    let u32at = |off: usize| u32::from_le_bytes(object[off..off + 4].try_into().unwrap()) as usize;
    let u64at = |off: usize| u64::from_le_bytes(object[off..off + 8].try_into().unwrap()) as usize;

    // EM_BPF. The one assertion that says the compiler targeted what it was
    // built to target rather than the machine it is running on.
    assert_eq!(u16at(18), 247, "not an eBPF object");
    let shoff = u64at(40);
    let shnum = u16at(60);
    let shstrndx = u16at(62);
    let header = |i: usize| shoff + i * 64;
    let names = u64at(header(shstrndx) + 24);

    (0..shnum)
        .map(|i| {
            let at = names + u32at(header(i));
            let end = at + object[at..].iter().position(|b| *b == 0).unwrap();
            String::from_utf8_lossy(&object[at..end]).into_owned()
        })
        .collect()
}

const PROGRAM: &str = r#"
#include <synch.h>

SY_ENTRY sy_s64 entry(void) {
  sy_shutdown(0);
  return 0;
}
"#;

#[test]
fn c_compiles_to_an_ebpf_object_with_the_section_the_source_asked_for() {
    if !SUPPORTED {
        eprintln!("skipping: this build has no compiler in it");
        return;
    }
    let object = synch_cc::compile(PROGRAM, "prog.c", &sdk(), &[]).expect("the program compiles");
    let sections = sections(&object);
    assert!(
        sections.iter().any(|s| s == "synchronicity.stream"),
        "the entrypoint section is missing: {sections:?}"
    );
}

#[test]
fn a_diagnostic_names_the_source_the_caller_named() {
    if !SUPPORTED {
        return;
    }
    let err = synch_cc::compile("int f(void) { return nope; }", "broken.c", &sdk(), &[])
        .expect_err("a reference to an undeclared name is an error");
    let CcError::Diagnostics(text) = &err else {
        panic!("expected diagnostics, got {err:?}");
    };
    // The name the *caller* passed, not the scratch file the compiler saw.
    assert!(text.contains("broken.c"), "{text}");
}

#[test]
fn there_is_no_libc_on_the_other_side_of_this() {
    if !SUPPORTED {
        return;
    }
    // The failure a guest must get here, at compile time, rather than as an
    // unresolved symbol when somebody arms it.
    let err = synch_cc::compile(
        "#include <stdio.h>\nint f(void){return 0;}",
        "libc.c",
        &sdk(),
        &[],
    )
    .expect_err("stdio.h is not available to a guest");
    assert!(
        matches!(&err, CcError::Diagnostics(text) if text.contains("stdio.h")),
        "{err:?}"
    );
}

#[test]
fn the_freestanding_headers_are_there_because_the_language_promises_them() {
    if !SUPPORTED {
        return;
    }
    let source = r#"
        #include <stddef.h>
        #include <stdbool.h>
        int f(void) {
          char buf[8];
          size_t n = sizeof buf;
          bool empty = (n == 0);
          return empty ? 1 : (int)n;
        }
    "#;
    synch_cc::compile(source, "freestanding.c", &[], &[]).expect("stddef and stdbool are there");
}

#[test]
fn a_define_reaches_the_source_and_a_guard_lets_the_source_win() {
    if !SUPPORTED {
        return;
    }
    let source = r#"
        #ifndef PORT
        #define PORT 9418
        #endif
        int port(void) { return PORT; }
        #if PORT != 9419
        #error "the define did not reach the source"
        #endif
    "#;
    synch_cc::compile(source, "defines.c", &[], &[("PORT", "9419")]).expect("PORT was overridden");
    // And without it, the `#ifndef` default stands — which is the same check
    // read the other way, and the reason an example can carry a real value.
    let err = synch_cc::compile(source, "defines.c", &[], &[]).expect_err("the default stands");
    assert!(matches!(err, CcError::Diagnostics(_)), "{err:?}");
}

#[test]
fn a_header_name_cannot_be_a_path_and_a_macro_name_cannot_be_a_flag() {
    if !SUPPORTED {
        return;
    }
    let err = synch_cc::compile("int f(void){return 0;}", "x.c", &[("../escape.h", "")], &[])
        .expect_err("a header name with a path in it is refused");
    assert!(matches!(err, CcError::Invalid(_)), "{err:?}");

    let err = synch_cc::compile("int f(void){return 0;}", "x.c", &[], &[("-nostdinc", "")])
        .expect_err("a macro name that is not an identifier is refused");
    assert!(matches!(err, CcError::Invalid(_)), "{err:?}");
}
