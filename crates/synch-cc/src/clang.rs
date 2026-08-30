//! The optional system-Clang compiler path.

use std::process::{Command, Stdio};

use crate::lower::lower_mem_intrinsics;
use crate::scratch::{sanitize, write_header};
use crate::{CcError, Define, Header, STACK_FRAME_SIZE};

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
    for (header_name, body) in headers {
        write_header(&include, header_name, body)?;
    }

    let stem = sanitize(name);
    let source_path = scratch.path().join(&stem);
    std::fs::write(&source_path, source)
        .map_err(|e| CcError::Io(format!("cannot write {}: {e}", source_path.display())))?;
    let ir_path = scratch.path().join("program.ll");
    let object_path = scratch.path().join("program.o");

    let mut clang = Command::new("clang");
    clang.args([
        "-O2",
        "-Wall",
        "-target",
        "bpf",
        "-fno-builtin",
        // The runtime loads each entrypoint section as a self-contained
        // program: a local call must land in the caller's own section, which
        // is why tinycc copies a static function into every section that
        // calls it. Clang instead leaves an uninlined static in `.text`, and
        // the object then fails to *load* ("local call target out of range")
        // — `whoami.c`'s `field` did. Raising the inline cost threshold far
        // past any socket-sized function makes clang fold statics into their
        // callers, which is the same duplication tinycc does, minus the call.
        // Cold call sites — an error path's `return finish(...)`, say — use
        // their own threshold that the main one does not lift, and one
        // surviving cold call puts the static right back in `.text`
        // (`ssh-shell.c`'s `finish` did), so both get raised.
        "-mllvm",
        "-inline-threshold=2000000",
        "-mllvm",
        "-inline-cold-callsite-threshold=2000000",
        "-emit-llvm",
        "-S",
    ]);
    clang.arg("-I").arg(&include);
    for (symbol, value) in defines {
        validate_define(symbol)?;
        clang.arg(format!("-D{symbol}={value}"));
    }
    clang
        .arg(&source_path)
        .arg("-o")
        .arg(&ir_path)
        .stdout(Stdio::null());
    run(&mut clang, "clang", name)?;

    // Textual IR rather than bitcode, because a pass of ours runs between the
    // two tools: clang compiles a large `= {0}` or a struct assignment into a
    // memory intrinsic, llc would turn one past its store budget into a call
    // to libc, and the BPF backend refuses to emit that call. `lower.rs`
    // rewrites those to the host helpers the SDK's own memset forwards to.
    // (Text does not carry bitcode's use-list order, so llc's instruction
    // scheduling — and the object's bytes — can differ from the old pipeline
    // even for a program the pass leaves alone; object bytes were never
    // stable across LLVM versions either, and nothing hashes them but the
    // tree, which versions content like any other file's.)
    let ir = std::fs::read_to_string(&ir_path)
        .map_err(|e| CcError::Io(format!("cannot read {}: {e}", ir_path.display())))?;
    std::fs::write(&ir_path, lower_mem_intrinsics(&ir))
        .map_err(|e| CcError::Io(format!("cannot write {}: {e}", ir_path.display())))?;

    let mut llc = Command::new("llc");
    llc.args([
        "-march=bpf",
        "-mcpu=v3",
        "-filetype=obj",
        &format!("-bpf-stack-size={STACK_FRAME_SIZE}"),
    ])
    .arg(&ir_path)
    .arg("-o")
    .arg(&object_path)
    .stdout(Stdio::null());
    run(&mut llc, "llc", name)?;

    let object = std::fs::read(&object_path)
        .map_err(|e| CcError::Io(format!("cannot read {}: {e}", object_path.display())))?;
    if object.is_empty() {
        return Err(CcError::Diagnostics(format!(
            "{name}: clang produced an empty object"
        )));
    }
    Ok(object)
}

fn run(command: &mut Command, tool: &str, name: &str) -> Result<(), CcError> {
    let output = command.output().map_err(|e| {
        CcError::Io(format!(
            "cannot run {tool} while compiling {name}: {e}; is {tool} on PATH?"
        ))
    })?;
    if output.status.success() {
        Ok(())
    } else {
        let diagnostics = String::from_utf8_lossy(&output.stderr);
        Err(CcError::Diagnostics(format!(
            "{name}: {tool} exited with {}\n{}",
            output.status,
            diagnostics.trim_end()
        )))
    }
}

fn validate_define(symbol: &str) -> Result<(), CcError> {
    let usable = !symbol.is_empty()
        && !symbol.starts_with(|c: char| c.is_ascii_digit())
        && symbol
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_');
    if usable {
        Ok(())
    } else {
        Err(CcError::Invalid(format!(
            "{symbol:?} is not usable as a macro name"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::validate_define;

    #[test]
    fn compiler_arguments_cannot_escape_the_scratch_directory() {
        assert!(validate_define("UPSTREAM_PORT").is_ok());
        assert!(validate_define("not-a-name").is_err());
    }
}
