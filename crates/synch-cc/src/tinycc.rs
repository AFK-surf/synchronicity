//! The FFI onto the linked-in tinycc.
//!
//! libtcc keeps a global `tcc_state` for diagnostics and is built here with
//! its semaphores off, so one compile at a time — [`COMPILING`] is what makes
//! that true rather than hoped for. Compiles are milliseconds and nobody runs
//! them in a loop, so a lock costs nothing worth measuring.

use std::{
    ffi::{c_char, c_int, c_void, CStr, CString},
    path::Path,
    ptr::NonNull,
    sync::Mutex,
};

use crate::{CcError, Define, Header};

include!(concat!(env!("OUT_DIR"), "/freestanding_headers.rs"));

/// `TCC_OUTPUT_OBJ` from `libtcc.h`.
const TCC_OUTPUT_OBJ: c_int = 3;

/// The options every socket program is compiled with.
///
/// `-nostdinc` because there is no libc: the scratch include directory holds
/// the SDK header and tinycc's freestanding headers, and a program that
/// reaches past them should be told so here rather than fail to link at arm
/// time. `-fno-builtin` because a builtin expansion assumes a libc symbol
/// exists to fall back on. `-mcpu=v3` is the instruction set async-ebpf runs.
const OPTIONS: &str = "-Wall -mcpu=v3 -fno-builtin -nostdinc";

/// One compile at a time. See the module comment.
static COMPILING: Mutex<()> = Mutex::new(());

#[repr(C)]
struct TccState {
    _opaque: [u8; 0],
}

type ErrorFn = unsafe extern "C" fn(*mut c_void, *const c_char);

unsafe extern "C" {
    fn tcc_new() -> *mut TccState;
    fn tcc_delete(state: *mut TccState);
    fn tcc_set_error_func(state: *mut TccState, opaque: *mut c_void, func: Option<ErrorFn>);
    fn tcc_set_options(state: *mut TccState, options: *const c_char) -> c_int;
    fn tcc_add_include_path(state: *mut TccState, path: *const c_char) -> c_int;
    fn tcc_define_symbol(state: *mut TccState, symbol: *const c_char, value: *const c_char);
    fn tcc_set_output_type(state: *mut TccState, output_type: c_int) -> c_int;
    fn tcc_add_file(state: *mut TccState, filename: *const c_char) -> c_int;
    fn tcc_output_file(state: *mut TccState, filename: *const c_char) -> c_int;
}

pub(crate) fn compile(
    source: &str,
    name: &str,
    headers: &[Header<'_>],
    defines: &[Define<'_>],
) -> Result<Vec<u8>, CcError> {
    let scratch = tempfile::tempdir()
        .map_err(|e| CcError::Io(format!("cannot create a scratch directory: {e}")))?;
    let include = scratch.path().join("include");
    std::fs::create_dir(&include)
        .map_err(|e| CcError::Io(format!("cannot create {}: {e}", include.display())))?;

    for (header_name, body) in FREESTANDING_HEADERS.iter().chain(headers.iter()) {
        write_header(&include, header_name, body)?;
    }

    // Named after the caller's `name` so `#line` markers, `__FILE__` and every
    // diagnostic say what the user typed rather than `source.c`.
    let stem = sanitize(name);
    let source_path = scratch.path().join(&stem);
    std::fs::write(&source_path, source)
        .map_err(|e| CcError::Io(format!("cannot write {}: {e}", source_path.display())))?;
    let object_path = scratch.path().join(format!("{stem}.o"));

    let _guard = COMPILING.lock().unwrap_or_else(|e| e.into_inner());
    let mut compiler = Compiler::new()?;
    compiler.add_include_path(&include)?;
    for (symbol, value) in defines {
        compiler.define(symbol, value)?;
    }
    compiler.add_file(&source_path)?;
    compiler.output_file(&object_path)?;
    drop(compiler);

    let object = std::fs::read(&object_path)
        .map_err(|e| CcError::Io(format!("cannot read {}: {e}", object_path.display())))?;
    if object.is_empty() {
        return Err(CcError::Diagnostics(format!(
            "{name}: the compiler produced an empty object"
        )));
    }

    // The one thing between tinycc's output and a loadable guest: see `fold`.
    match crate::fold::fold_text(&object)
        .map_err(|e| CcError::Diagnostics(format!("{name}: {e}")))?
    {
        Some(folded) => Ok(folded),
        None => Ok(object),
    }
}

/// Writes one header into the scratch include directory.
///
/// A name with a separator in it is refused rather than joined: these names
/// reach here from a caller's `#include`-facing table, and a header called
/// `../../etc/passwd` is a write outside the scratch directory.
fn write_header(dir: &Path, name: &str, body: &str) -> Result<(), CcError> {
    if name.is_empty() || name.contains(['/', '\\']) || name.contains("..") {
        return Err(CcError::Invalid(format!(
            "{name:?} is not usable as a header name"
        )));
    }
    let path = dir.join(name);
    std::fs::write(&path, body)
        .map_err(|e| CcError::Io(format!("cannot write {}: {e}", path.display())))
}

/// Reduces a caller-supplied name to something usable as a file name.
fn sanitize(name: &str) -> String {
    let stem: String = Path::new(name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let stem = stem.trim_matches('.').to_string();
    if stem.is_empty() {
        "program.c".to_string()
    } else if stem.ends_with(".c") {
        stem
    } else {
        format!("{stem}.c")
    }
}

/// A `TCCState`, plus the diagnostics it has emitted.
struct Compiler {
    state: NonNull<TccState>,
    /// Boxed because its *address* is handed to C, and this struct is returned
    /// by value from `new` — so the `Vec` itself moves and only the box's heap
    /// allocation stays where libtcc was told it is.
    #[allow(clippy::box_collection)]
    diagnostics: Box<Vec<String>>,
}

impl Compiler {
    fn new() -> Result<Compiler, CcError> {
        // SAFETY: `tcc_new` allocates a state or returns null.
        let state = NonNull::new(unsafe { tcc_new() }).ok_or_else(|| {
            CcError::Io("the compiler could not allocate its own state".to_string())
        })?;
        let mut compiler = Compiler {
            state,
            diagnostics: Box::new(Vec::new()),
        };
        let sink = compiler.diagnostics.as_mut() as *mut Vec<String> as *mut c_void;
        // SAFETY: `sink` points at a box this struct owns and outlives the
        // state, which is deleted in `Drop` before the box is dropped.
        unsafe {
            tcc_set_error_func(compiler.state.as_ptr(), sink, Some(collect));
        }

        let options = cstring(OPTIONS)?;
        // SAFETY: a live state and a NUL-terminated string.
        compiler.check("the compiler rejected its own options", unsafe {
            tcc_set_options(compiler.state.as_ptr(), options.as_ptr())
        })?;
        // SAFETY: as above.
        compiler.check("the compiler rejected its output type", unsafe {
            tcc_set_output_type(compiler.state.as_ptr(), TCC_OUTPUT_OBJ)
        })?;
        Ok(compiler)
    }

    fn add_include_path(&mut self, path: &Path) -> Result<(), CcError> {
        let path = cpath(path)?;
        // SAFETY: a live state and a NUL-terminated string.
        self.check("the compiler rejected its include path", unsafe {
            tcc_add_include_path(self.state.as_ptr(), path.as_ptr())
        })
    }

    /// Defines a macro, as `-D symbol=value`.
    ///
    /// A symbol that is not an identifier is refused here rather than passed
    /// on: libtcc takes a define it cannot parse without complaining, and the
    /// program then fails somewhere that says nothing about the flag.
    fn define(&mut self, symbol: &str, value: &str) -> Result<(), CcError> {
        let usable = !symbol.is_empty()
            && !symbol.starts_with(|c: char| c.is_ascii_digit())
            && symbol
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !usable {
            return Err(CcError::Invalid(format!(
                "{symbol:?} is not usable as a macro name"
            )));
        }
        let symbol = cstring(symbol)?;
        let value = cstring(value)?;
        // SAFETY: a live state and two NUL-terminated strings. `tcc_define_symbol`
        // reports nothing, so there is no return code to check.
        unsafe { tcc_define_symbol(self.state.as_ptr(), symbol.as_ptr(), value.as_ptr()) };
        Ok(())
    }

    fn add_file(&mut self, path: &Path) -> Result<(), CcError> {
        let cpath = cpath(path)?;
        // SAFETY: a live state and a NUL-terminated string.
        self.check("compilation failed", unsafe {
            tcc_add_file(self.state.as_ptr(), cpath.as_ptr())
        })
    }

    fn output_file(&mut self, path: &Path) -> Result<(), CcError> {
        let cpath = cpath(path)?;
        // SAFETY: a live state and a NUL-terminated string.
        self.check("the compiler could not write its object", unsafe {
            tcc_output_file(self.state.as_ptr(), cpath.as_ptr())
        })
    }

    /// Turns a non-zero return into the diagnostics that explain it.
    fn check(&self, context: &str, code: c_int) -> Result<(), CcError> {
        if code == 0 {
            return Ok(());
        }
        if self.diagnostics.is_empty() {
            return Err(CcError::Diagnostics(context.to_string()));
        }
        Err(CcError::Diagnostics(self.diagnostics.join("\n")))
    }
}

impl Drop for Compiler {
    fn drop(&mut self) {
        // SAFETY: the state was created by `tcc_new` and is deleted once.
        unsafe { tcc_delete(self.state.as_ptr()) }
    }
}

/// The error callback libtcc calls, once per diagnostic.
unsafe extern "C" fn collect(opaque: *mut c_void, message: *const c_char) {
    if opaque.is_null() || message.is_null() {
        return;
    }
    // SAFETY: `opaque` is the `Vec<String>` installed in `Compiler::new`, and
    // libtcc calls this only from inside a call this thread is making.
    let diagnostics = unsafe { &mut *(opaque as *mut Vec<String>) };
    // SAFETY: libtcc passes a NUL-terminated string it owns.
    let message = unsafe { CStr::from_ptr(message) };
    diagnostics.push(message.to_string_lossy().into_owned());
}

fn cstring(value: &str) -> Result<CString, CcError> {
    CString::new(value).map_err(|_| CcError::Invalid("an argument contains a NUL".to_string()))
}

fn cpath(path: &Path) -> Result<CString, CcError> {
    cstring(
        path.to_str()
            .ok_or_else(|| CcError::Invalid(format!("{} is not UTF-8", path.display())))?,
    )
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn a_source_name_cannot_escape_the_scratch_directory() {
        assert_eq!(sanitize("echo.c"), "echo.c");
        assert_eq!(sanitize("code/echo.c"), "echo.c");
        assert_eq!(sanitize("../../etc/passwd"), "passwd.c");
        assert_eq!(sanitize(".."), "program.c");
        assert_eq!(sanitize(""), "program.c");
        assert_eq!(sanitize("a b;rm -rf.c"), "a_b_rm_-rf.c");
    }
}
