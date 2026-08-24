//! Compiles C to an eBPF object, with no toolchain on the machine.
//!
//! A socket is an eBPF ELF object (`docs/SOCKETS.md`). Producing one from C
//! normally means a clang built with the BPF backend — which the distributions
//! ship inconsistently, which macOS's system clang does not have at all, and
//! which is a large thing to ask somebody to install before they can write
//! twenty lines of C. So the compiler travels with the binary: a build of
//! [tinycc] targeting eBPF, linked in, reached through [`compile`]. Programs
//! that benefit from optimized code can instead use [`compile_with_clang`],
//! which drives `clang` and `llc` from the host.
//!
//! [tinycc]: https://github.com/losfair/tinycc
//!
//! # What this is not
//!
//! It is not an optimizing compiler and it is not clang. It compiles C99
//! without the extensions clang's BPF target accepts, it does not inline, and
//! the code it emits is larger and slower than clang's. For a socket — an
//! event loop around helper calls, where the host does the work — that is a
//! trade worth making, and a program that outgrows it can still be built with
//! clang and armed exactly the same way: the runtime loads an ELF object and
//! does not care which compiler wrote it.
//!
//! # Licensing
//!
//! tinycc is LGPL-2.1. Linking it into an MIT/Apache-2.0 binary is what
//! §6 of that licence permits, and it carries §6's obligation: a distributor
//! must let a recipient relink the work against a modified tinycc. The pinned
//! upstream and commit are in `build.rs`, and the object files this crate
//! produces are in the build directory, which is what makes that possible.
//!
//! # Platforms
//!
//! Everywhere the workspace builds, except MSVC — see [`SUPPORTED`].

#![deny(missing_docs)]

use std::path::Path;

mod clang;
#[cfg(tinycc)]
mod fold;
#[cfg(tinycc)]
mod tinycc;

/// Whether this build has a compiler in it.
///
/// False only on MSVC targets, where the tinycc sources have not been built
/// and [`compile`] answers [`CcError::Unsupported`]. Nothing is lost that a
/// Windows host could have used anyway beyond cross-compiling *for* a node:
/// serving sockets needs an eBPF runtime, which Windows has none of.
pub const SUPPORTED: bool = cfg!(tinycc);

/// The eBPF stack frame size clang-built programs are compiled for.
///
/// This must equal the socket runtime's default local-call frame
/// (`synch_core::DEFAULT_EBPF_STACK_FRAME_SIZE`): a program compiled against
/// a larger frame than the runtime provides would overflow its stack. The
/// two crates stay independent — this crate does not know what a socket is —
/// so the equality is enforced by a test in `synch-sock` instead of a
/// dependency.
pub const STACK_FRAME_SIZE: u32 = 16 * 1024;

/// Why a compile did not produce an object.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CcError {
    /// The program does not compile. Carries the compiler's own diagnostics.
    #[error("{0}")]
    Diagnostics(String),
    /// A path or a source contains a NUL, or a name is not usable as a file.
    #[error("{0}")]
    Invalid(String),
    /// Source or scratch files could not be accessed, or an external compiler
    /// could not be started.
    #[error("{0}")]
    Io(String),
    /// This build has no compiler in it.
    #[error("this build has no C compiler in it: synch-cc is not built for MSVC targets")]
    Unsupported,
}

/// A header made available to the program being compiled, as `<name>`.
///
/// A pair rather than a path, because the header this exists for —
/// `synch_sock::sdk::HEADER` — is compiled into the binary and has no path.
/// The compiler is handed a scratch directory holding these and nothing else,
/// so `#include <synch.h>` resolves and `#include <stdio.h>` does not.
pub type Header<'a> = (&'a str, &'a str);

/// A macro defined on the command line, as `-D name=value`.
///
/// An empty value defines the name with no replacement, which is what a
/// program tests with `#ifdef`. Together with the `#ifndef` guard an example
/// puts around a constant, this is how one source builds against two upstreams
/// without an edit — and, because a socket's declarations are compiled in, why
/// changing one is a rebuild and a rearm rather than a setting.
pub type Define<'a> = (&'a str, &'a str);

/// Compiles one translation unit to an eBPF relocatable object.
///
/// `name` is what diagnostics call the source, so give it the name the user
/// typed. `headers` are made includable by their names; tinycc's freestanding
/// headers (`stddef.h`, `stdbool.h`, `stdarg.h`, …) are always present, and
/// nothing else is — there is no libc on the other side of this, and a program
/// that included one would fail to link at arm time instead of here.
///
/// # Example
///
/// ```no_run
/// let object = synch_cc::compile(
///     "SY_ENTRY sy_s64 entry(void) { return 0; }",
///     "empty.c",
///     &[("synch.h", "…the SDK header…")],
///     &[("MAX_STREAMS", "8")],
/// )?;
/// # Ok::<(), synch_cc::CcError>(())
/// ```
pub fn compile(
    source: &str,
    name: &str,
    headers: &[Header<'_>],
    defines: &[Define<'_>],
) -> Result<Vec<u8>, CcError> {
    #[cfg(tinycc)]
    {
        tinycc::compile(source, name, headers, defines)
    }
    #[cfg(not(tinycc))]
    {
        let _ = (source, name, headers, defines);
        Err(CcError::Unsupported)
    }
}

/// Compiles a file, naming diagnostics after it.
pub fn compile_file(
    path: &Path,
    headers: &[Header<'_>],
    defines: &[Define<'_>],
) -> Result<Vec<u8>, CcError> {
    let (source, name) = read_source(path)?;
    compile(&source, &name, headers, defines)
}

/// Reads a source file and derives the name diagnostics use for it.
fn read_source(path: &Path) -> Result<(String, String), CcError> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| CcError::Io(format!("cannot read {}: {e}", path.display())))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    Ok((source, name))
}

/// Compiles one translation unit with the host's `clang` and `llc`.
///
/// Clang optimizes the program at `-O2` into LLVM bitcode. `llc` then emits a
/// BPF v3 relocatable object with the 16 KiB stack frames expected by the
/// socket runtime. Both executables must be on `PATH` and come from compatible
/// LLVM installations.
pub fn compile_with_clang(
    source: &str,
    name: &str,
    headers: &[Header<'_>],
    defines: &[Define<'_>],
) -> Result<Vec<u8>, CcError> {
    clang::compile(source, name, headers, defines)
}

/// Compiles a file with the host's `clang` and `llc`, naming diagnostics after
/// it.
pub fn compile_file_with_clang(
    path: &Path,
    headers: &[Header<'_>],
    defines: &[Define<'_>],
) -> Result<Vec<u8>, CcError> {
    let (source, name) = read_source(path)?;
    compile_with_clang(&source, &name, headers, defines)
}
