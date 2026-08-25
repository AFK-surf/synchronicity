//! The scratch-directory hygiene both compiler backends stage through: one
//! spelling of "a caller-supplied name may not escape the directory", because
//! the two copies of it were a policy that had to agree to be correct.

use std::path::Path;

use crate::CcError;

/// Writes one header into the scratch include directory.
///
/// A name with a separator in it is refused rather than joined: these names
/// reach here from a caller's `#include`-facing table, and a header called
/// `../../etc/passwd` is a write outside the scratch directory.
pub(crate) fn write_header(dir: &Path, name: &str, body: &str) -> Result<(), CcError> {
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
pub(crate) fn sanitize(name: &str) -> String {
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
