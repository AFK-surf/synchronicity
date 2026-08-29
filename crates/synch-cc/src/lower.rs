//! Rewrites clang's memory intrinsics into host-helper calls.
//!
//! `synch.h` defines `memset`, `memcpy` and `memmove` forwarding to the host
//! helpers, because a struct initializer or an array assignment is enough to
//! make a C compiler emit a call to one. Clang, though, does not emit a
//! *call*: its frontend compiles `struct big s = {0};` straight into an
//! `llvm.memset` intrinsic, which never meets those definitions. llc expands
//! a small intrinsic into stores, but one past its store budget becomes a
//! call to libc — and the BPF backend, having no libc to call into, refuses
//! to emit it:
//!
//! ```text
//! error: <unknown>:0:0: in function declare i64 ():
//!        A call to built-in function 'memset' is not supported.
//! ```
//!
//! So the clang pipeline stages through textual IR, and this pass rewrites
//! each intrinsic call llc could not expand into the call the SDK's own
//! `memset` would have made: `sy_memset(dst, c, n)`, or `sy_memcpy` for a
//! copy — `memmove` included, exactly as `synch.h` maps it, with the same
//! overlap semantics. The object gains nothing the runtime has not always
//! loaded; it links at arm time like any program that called the helpers
//! by name.
//!
//! Calls llc *can* expand are left for it to turn into stores, so a small
//! `= {0}` costs what it always cost; [`fits_llcs_budget`] draws that line.
//! A constant length past what the host will copy is refused here, with the
//! line that caused it, rather than compiled into a call that must fail.
//! Everything else this pass does not positively recognize — a volatile
//! intrinsic among them — it leaves untouched: the failure mode is llc's
//! own diagnostic, never a miscompile.

use std::fmt::Write as _;

use crate::CcError;

/// The intrinsic call prefixes clang emits, and the helper each forwards to.
///
/// `memmove` goes to `sy_memcpy` because that is where `synch.h` sends it:
/// the host copies through a buffer of its own, and genuine overlap is
/// refused by the pointer cage rather than papered over.
const LOWERINGS: [(&str, Helper); 3] = [
    ("@llvm.memset.", Helper::Memset),
    ("@llvm.memcpy.", Helper::Memcpy),
    ("@llvm.memmove.", Helper::Memcpy),
];

/// llc's inline-expansion budget: the BPF backend's `MaxStoresPerMemset`
/// and `MaxStoresPerMemcpy`, 128 for as long as the backend has existed.
const LLC_STORE_BUDGET: u64 = 128;

/// The most the host will fill or copy in one helper call.
///
/// `synch-sock`'s `MAX_COPY`: the byte-copy helpers refuse a longer request
/// with `SY_EINVAL` rather than shorten it. A constant length past this is
/// a call that cannot succeed, so it is refused at compile time — silently
/// unzeroed memory is the one outcome this pass may never produce.
const HOST_COPY_LIMIT: u64 = 64 * 1024;

#[derive(Clone, Copy, PartialEq)]
enum Helper {
    Memset,
    Memcpy,
}

/// Whether llc will expand an intrinsic of this length into stores.
///
/// llc uses stores as wide as the operands' alignment allows, capped at 8
/// bytes, then powers of two for the tail. Today's backend goes further —
/// BPF permits misaligned access, so llc 18 uses 8-byte stores whatever the
/// alignment — but this model deliberately does not lean on that: counting
/// with alignment-limited widths admits a subset of what any llc inlines,
/// so a stricter future backend degrades a call to a host round-trip, never
/// to the libcall error this pass exists to remove.
fn fits_llcs_budget(len: u64, align: u64) -> bool {
    let width = if align.is_power_of_two() {
        align.min(8)
    } else {
        1
    };
    let stores = len / width + u64::from((len % width).count_ones());
    stores <= LLC_STORE_BUDGET
}

/// The `align N` a pointer argument carries, or 1 where it carries none.
fn alignment(argument: &str) -> u64 {
    let mut tokens = argument.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "align" {
            return tokens.next().and_then(|n| n.parse().ok()).unwrap_or(1);
        }
    }
    1
}

/// Whether the module already declares or defines `@<symbol>` itself.
///
/// An exact-name match on a declaration line, not a substring of the module:
/// `@sy_memset` is also a prefix of names a program is free to use, and a
/// `sy_memset_secure` of its own must not swallow the declaration the
/// rewritten calls need.
fn module_names(ir: &str, symbol: &str) -> bool {
    let needle = format!("@{symbol}(");
    ir.lines().any(|line| {
        let body = line.trim_start();
        (body.starts_with("declare ") || body.starts_with("define ")) && body.contains(&needle)
    })
}

/// Rewrites the memory-intrinsic calls in one module of textual IR.
///
/// `name` is what diagnostics call the source, as everywhere in this crate.
pub(crate) fn lower_mem_intrinsics(ir: &str, name: &str) -> Result<String, CcError> {
    let mut out = String::with_capacity(ir.len() + 256);
    // LLVM 14 and older spell `ptr` as `i8*`; one module never mixes them.
    let mut typed_pointers = false;
    let mut helpers_called = Vec::new();
    // Numbers the values these rewrites introduce. Globally unique, so no
    // per-function bookkeeping; `.` keeps them out of C's identifier space.
    let mut fresh = 0usize;

    for line in ir.lines() {
        match lower_line(line, name, &mut fresh)? {
            Some(lowered) => {
                typed_pointers |= lowered.typed_pointers;
                if !helpers_called.contains(&lowered.helper) {
                    helpers_called.push(lowered.helper);
                }
                out.push_str(&lowered.text);
            }
            None => out.push_str(line),
        }
        out.push('\n');
    }

    if !helpers_called.is_empty() {
        let p = if typed_pointers { "i8*" } else { "ptr" };
        out.push_str(
            "\n; Appended by synch-cc: the BPF backend cannot emit the libc call a\n\
             ; large memory intrinsic becomes, so those calls were rewritten to the\n\
             ; host helpers the SDK's own memset and memcpy forward to.\n",
        );
        if helpers_called.contains(&Helper::Memset) && !module_names(ir, "sy_memset") {
            let _ = writeln!(out, "declare {p} @sy_memset({p}, i32, i64)");
        }
        if helpers_called.contains(&Helper::Memcpy) && !module_names(ir, "sy_memcpy") {
            let _ = writeln!(out, "declare {p} @sy_memcpy({p}, {p}, i64)");
        }
    }
    Ok(out)
}

struct Lowered {
    text: String,
    helper: Helper,
    typed_pointers: bool,
}

/// Rewrites one line, keeps it byte-for-byte, or refuses the compile.
fn lower_line(line: &str, name: &str, fresh: &mut usize) -> Result<Option<Lowered>, CcError> {
    let body = line.trim_start();
    // The intrinsic's own `declare` stays: call sites within the budget
    // still use it, and an unreferenced declaration is nothing.
    if body.starts_with("declare ") {
        return Ok(None);
    }

    // Printed IR holds one instruction per line, so at most one call.
    let Some((at, helper)) = LOWERINGS
        .iter()
        .find_map(|(prefix, helper)| Some((line.find(prefix)?, *helper)))
    else {
        return Ok(None);
    };
    let Some(name_end) = line[at..].find('(').map(|i| at + i) else {
        return Ok(None);
    };
    let callee = &line[at..name_end];
    // The spellings clang emits for C all continue `p0…` (address space
    // zero, then the length type). What does not — `llvm.memset.inline`,
    // the element-atomic family — has different rules or arguments, cannot
    // come from this SDK's C, and stays llc's problem.
    let Some(suffix) = callee
        .strip_prefix("@llvm.memset.")
        .or_else(|| callee.strip_prefix("@llvm.memcpy."))
        .or_else(|| callee.strip_prefix("@llvm.memmove."))
    else {
        return Ok(None);
    };
    if !suffix.starts_with("p0") {
        return Ok(None);
    }

    // (dst, src|byte, len, volatile) — anything else is not the shape this
    // pass knows, and stays. So does a volatile intrinsic: the helpers make
    // no volatility promise, and declining is honester than dropping it.
    let Some(arguments) = split_arguments(&line[name_end..]) else {
        return Ok(None);
    };
    let [dst, source_or_byte, len, volatile] = arguments.as_slice() else {
        return Ok(None);
    };
    if !len.starts_with("i64 ") || last_token(volatile) != Some("false") {
        return Ok(None);
    }
    if let Some(Ok(n)) = last_token(len).map(str::parse::<u64>) {
        let align = match helper {
            Helper::Memset => alignment(dst),
            Helper::Memcpy => alignment(dst).min(alignment(source_or_byte)),
        };
        if fits_llcs_budget(n, align) {
            return Ok(None); // llc will expand this one into stores
        }
        if n > HOST_COPY_LIMIT {
            let what = match helper {
                Helper::Memset => "fill",
                Helper::Memcpy => "copy",
            };
            return Err(CcError::Diagnostics(format!(
                "{name}: a {n}-byte {what} (from an initializer, assignment or \
                 builtin the compiler turned into one operation) is more than \
                 the host moves in one helper call (64 KiB); do it in pieces"
            )));
        }
    }

    let typed_pointers = suffix.contains("p0i8");
    let p = if typed_pointers { "i8*" } else { "ptr" };
    let indent = &line[..line.len() - body.len()];
    let mut text = String::new();
    match helper {
        Helper::Memset => {
            // `sy_memset` takes the fill byte as an i32. A constant widens
            // here; a value needs the instruction spelled out.
            let Some(byte) = last_token(source_or_byte) else {
                return Ok(None);
            };
            let widened = match byte.parse::<i64>() {
                Ok(value) => format!("{}", value as u8),
                Err(_) => {
                    let _ = writeln!(text, "{indent}%synch.cc.{fresh} = zext i8 {byte} to i32");
                    format!("%synch.cc.{fresh}")
                }
            };
            let _ = write!(
                text,
                "{indent}%synch.cc.{fresh}.set = call {p} @sy_memset({dst}, i32 {widened}, {len})"
            );
        }
        Helper::Memcpy => {
            let _ = write!(
                text,
                "{indent}%synch.cc.{fresh}.cpy = call {p} @sy_memcpy({dst}, {source_or_byte}, {len})"
            );
        }
    }
    *fresh += 1;
    Ok(Some(Lowered {
        text,
        helper,
        typed_pointers,
    }))
}

/// Splits a parenthesized argument list at its top-level commas.
///
/// Arguments arrive verbatim, attributes and all — `ptr noundef nonnull
/// align 8 dereferenceable(1336) %4` is one argument — because a call to a
/// declared function carries them as legally as the intrinsic did.
fn split_arguments(from_paren: &str) -> Option<Vec<&str>> {
    let inner = from_paren.strip_prefix('(')?;
    let mut depth = 0usize;
    let mut start = 0;
    let mut arguments = Vec::new();
    for (i, c) in inner.char_indices() {
        match c {
            '(' => depth += 1,
            ')' if depth > 0 => depth -= 1,
            ')' => {
                arguments.push(inner[start..i].trim());
                return Some(arguments);
            }
            ',' if depth == 0 => {
                arguments.push(inner[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    None // never closed: not a shape this pass rewrites
}

/// The value at the end of an argument, past its type and attributes.
fn last_token(argument: &str) -> Option<&str> {
    argument.split_whitespace().last()
}

#[cfg(test)]
mod tests {
    use crate::CcError;

    fn lower(ir: &str) -> String {
        super::lower_mem_intrinsics(ir, "t.c").expect("this module lowers")
    }

    const BIG_MEMSET: &str = "  call void @llvm.memset.p0.i64(ptr noundef nonnull align 8 dereferenceable(1336) %4, i8 0, i64 1328, i1 false)";

    #[test]
    fn a_memset_past_the_store_budget_goes_to_the_host() {
        let lowered = lower(BIG_MEMSET);
        assert!(
            lowered.contains(
                "call ptr @sy_memset(ptr noundef nonnull align 8 dereferenceable(1336) %4, i32 0, i64 1328)"
            ),
            "{lowered}"
        );
        assert!(!lowered.contains("@llvm.memset"), "{lowered}");
        assert!(lowered.contains("declare ptr @sy_memset(ptr, i32, i64)"));
    }

    /// llc's budget is 128 stores as wide as the alignment allows: an
    /// aligned kilobyte fits (verified against llc 18, which inlines to
    /// exactly this boundary for 8-aligned operands), an unaligned one
    /// only fits byte-wise.
    #[test]
    fn what_llc_will_expand_into_stores_is_left_alone() {
        let kept = [
            "  call void @llvm.memset.p0.i64(ptr align 8 %1, i8 0, i64 64, i1 false)\n",
            "  call void @llvm.memset.p0.i64(ptr align 8 %1, i8 0, i64 1017, i1 false)\n",
            "  call void @llvm.memset.p0.i64(ptr %1, i8 0, i64 100, i1 false)\n",
            "  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %d, ptr align 8 %s, i64 1000, i1 false)\n",
        ];
        for ir in kept {
            assert_eq!(lower(ir), ir);
        }
        let rewritten = [
            "  call void @llvm.memset.p0.i64(ptr align 8 %1, i8 0, i64 1023, i1 false)",
            "  call void @llvm.memset.p0.i64(ptr %1, i8 0, i64 129, i1 false)",
            "  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %d, ptr %s, i64 129, i1 false)",
        ];
        for ir in rewritten {
            assert!(lower(ir).contains("@sy_mem"), "not lowered: {ir}");
        }
    }

    #[test]
    fn a_length_only_known_at_run_time_goes_to_the_host() {
        let ir = "  call void @llvm.memset.p0.i64(ptr %1, i8 0, i64 %n, i1 false)";
        let lowered = lower(ir);
        assert!(
            lowered.contains("call ptr @sy_memset(ptr %1, i32 0, i64 %n)"),
            "{lowered}"
        );
    }

    /// The host refuses a fill or copy past 64 KiB with `SY_EINVAL`, and the
    /// rewritten call has nowhere to surface that: the honest outcome for a
    /// constant length is a compile error naming the source, not an object
    /// that leaves memory unzeroed at run time.
    #[test]
    fn a_constant_past_what_the_host_will_move_is_refused() {
        let ir = "  call void @llvm.memset.p0.i64(ptr @g, i8 0, i64 100000, i1 false)";
        let err = super::lower_mem_intrinsics(ir, "huge.c").expect_err("past MAX_COPY");
        let CcError::Diagnostics(text) = &err else {
            panic!("expected diagnostics, got {err:?}");
        };
        assert!(
            text.contains("huge.c") && text.contains("100000") && text.contains("64 KiB"),
            "{text}"
        );
    }

    #[test]
    fn a_fill_byte_only_known_at_run_time_is_widened_first() {
        let ir = "  call void @llvm.memset.p0.i64(ptr %1, i8 %c, i64 4096, i1 false)";
        let lowered = lower(ir);
        assert!(lowered.contains("= zext i8 %c to i32"), "{lowered}");
        assert!(
            lowered.contains("call ptr @sy_memset(ptr %1, i32 %synch.cc.0, i64 4096)"),
            "{lowered}"
        );
    }

    #[test]
    fn a_negative_constant_fill_byte_widens_as_the_byte_it_is() {
        let ir = "  call void @llvm.memset.p0.i64(ptr %1, i8 -1, i64 4096, i1 false)";
        let lowered = lower(ir);
        assert!(
            lowered.contains("call ptr @sy_memset(ptr %1, i32 255, i64 4096)"),
            "{lowered}"
        );
    }

    #[test]
    fn memcpy_and_memmove_both_copy_through_the_host() {
        let ir = "\
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %d, ptr align 8 %s, i64 2048, i1 false)
  call void @llvm.memmove.p0.p0.i64(ptr %d, ptr %s, i64 2048, i1 false)";
        let lowered = lower(ir);
        assert!(
            lowered.contains("call ptr @sy_memcpy(ptr align 8 %d, ptr align 8 %s, i64 2048)"),
            "{lowered}"
        );
        assert!(
            lowered.contains("call ptr @sy_memcpy(ptr %d, ptr %s, i64 2048)"),
            "{lowered}"
        );
        // One declaration serves both rewrites.
        assert_eq!(lowered.matches("declare ptr @sy_memcpy").count(), 1);
    }

    /// The dressing a real clang puts on a call site — `tail`, an attribute
    /// group, trailing metadata, a constant-expression source with commas
    /// nested in it — none of it survives into the rewritten call, and none
    /// of it derails the parse. llc 18 emits every one of these shapes.
    #[test]
    fn call_site_dressing_is_parsed_around_and_dropped() {
        let ir = "  tail call void @llvm.memset.p0.i64(ptr align 8 %1, i8 0, i64 2048, i1 false) #4, !tbaa.struct !8";
        assert_eq!(
            lower(ir).lines().next().unwrap(),
            "  %synch.cc.0.set = call ptr @sy_memset(ptr align 8 %1, i32 0, i64 2048)"
        );

        let ir = "  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %d, ptr align 8 getelementptr inbounds ({ [2048 x i8] }, ptr @g, i64 0, i32 0, i64 64), i64 2048, i1 false)";
        assert_eq!(
            lower(ir).lines().next().unwrap(),
            "  %synch.cc.0.cpy = call ptr @sy_memcpy(ptr align 8 %d, ptr align 8 getelementptr \
             inbounds ({ [2048 x i8] }, ptr @g, i64 0, i32 0, i64 64), i64 2048)"
        );
    }

    #[test]
    fn a_helper_the_program_already_called_is_not_redeclared() {
        let ir = "\
declare ptr @sy_memset(ptr noundef, i32 noundef, i64 noundef) #2
  call void @llvm.memset.p0.i64(ptr %1, i8 0, i64 4096, i1 false)";
        let lowered = lower(ir);
        assert_eq!(
            lowered.matches("declare ptr @sy_memset").count(),
            1,
            "{lowered}"
        );
    }

    /// A program's own `sy_memset_secure` is not a declaration of
    /// `sy_memset`: the exact symbol decides, or the rewritten calls are
    /// left calling an undefined value and llc points at a line the user
    /// never wrote.
    #[test]
    fn a_name_that_merely_starts_with_a_helpers_is_not_its_declaration() {
        let ir = "\
define internal void @sy_memset_secure(ptr %p, i64 %n) {
  ret void
}
  call void @llvm.memset.p0.i64(ptr %1, i8 0, i64 4096, i1 false)";
        let lowered = lower(ir);
        assert!(
            lowered.contains("declare ptr @sy_memset(ptr, i32, i64)"),
            "{lowered}"
        );
    }

    #[test]
    fn the_intrinsics_own_declaration_survives_for_the_small_calls() {
        let ir = "\
  call void @llvm.memset.p0.i64(ptr %1, i8 0, i64 8, i1 false)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly, i8, i64, i1 immarg) #3
  call void @llvm.memset.p0.i64(ptr %2, i8 0, i64 4096, i1 false)";
        let lowered = lower(ir);
        assert!(
            lowered.contains("declare void @llvm.memset.p0.i64"),
            "{lowered}"
        );
        assert!(
            lowered.contains("call void @llvm.memset.p0.i64(ptr %1, i8 0, i64 8, i1 false)"),
            "{lowered}"
        );
        assert!(
            lowered.contains("call ptr @sy_memset(ptr %2, i32 0, i64 4096)"),
            "{lowered}"
        );
    }

    #[test]
    fn typed_pointer_modules_are_rewritten_in_their_own_spelling() {
        let ir = "  call void @llvm.memset.p0i8.i64(i8* align 8 %1, i8 0, i64 4096, i1 false)";
        let lowered = lower(ir);
        assert!(
            lowered.contains("call i8* @sy_memset(i8* align 8 %1, i32 0, i64 4096)"),
            "{lowered}"
        );
        assert!(lowered.contains("declare i8* @sy_memset(i8*, i32, i64)"));
    }

    #[test]
    fn what_this_pass_does_not_recognize_it_does_not_touch() {
        let unrecognized = "\
  call void @llvm.memset.inline.p0.i64(ptr %1, i8 0, i64 4096, i1 false)
  call void @llvm.memset.element.unordered.atomic.p0.i64(ptr %1, i8 0, i64 4096, i32 1)
  call void @llvm.memset.p0.i32(ptr %1, i8 0, i32 4096, i1 false)
  call void @llvm.memset.p0.i64(ptr %1, i8 0, i64 4096, i1 true)
  %5 = call i64 @sy_read(i64 0, ptr %1, i64 4096)";
        for line in unrecognized.lines() {
            let with_newline = format!("{line}\n");
            assert_eq!(lower(&with_newline), with_newline);
        }
    }
}
