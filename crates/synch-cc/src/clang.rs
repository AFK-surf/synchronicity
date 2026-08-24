//! The optional system-Clang compiler path.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::{CcError, Define, Header};

use crate::STACK_FRAME_SIZE;

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
    let bitcode_path = scratch.path().join("program.bc");
    let object_path = scratch.path().join("program.o");

    let mut clang = Command::new("clang");
    clang.args([
        "-O2",
        "-Wall",
        "-target",
        "bpf",
        "-fno-builtin",
        "-emit-llvm",
        "-c",
    ]);
    clang.arg("-I").arg(&include);
    for (symbol, value) in defines {
        validate_define(symbol)?;
        clang.arg(format!("-D{symbol}={value}"));
    }
    clang
        .arg(&source_path)
        .arg("-o")
        .arg(&bitcode_path)
        .stdout(Stdio::null());
    run(&mut clang, "clang", name)?;

    let mut llc = Command::new("llc");
    llc.args([
        "-march=bpf",
        "-mcpu=v3",
        "-filetype=obj",
        &format!("-bpf-stack-size={STACK_FRAME_SIZE}"),
    ])
    .arg(&bitcode_path)
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

fn sanitize(name: &str) -> String {
    let stem: String = PathBuf::from(name)
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

#[cfg(test)]
mod tests {
    use super::{sanitize, validate_define};

    #[test]
    fn compiler_arguments_cannot_escape_the_scratch_directory() {
        assert_eq!(sanitize("code/echo.c"), "echo.c");
        assert_eq!(sanitize("../../etc/passwd"), "passwd.c");
        assert!(validate_define("UPSTREAM_PORT").is_ok());
        assert!(validate_define("not-a-name").is_err());
    }
}
