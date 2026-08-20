//! Path normalization rules for the `f:` namespace (§4.1).
//!
//! Paths are UTF-8, NFC-normalized, `/`-separated, with no leading slash and no
//! `.` or `..` components.

use unicode_normalization::{is_nfc, UnicodeNormalization};

/// Maximum length of a trie key, in bytes (§12: key length is bounded to 4 KiB).
pub const MAX_KEY_LEN: usize = 4096;

/// Error returned when a path cannot be normalized into a valid trie path.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PathError {
    /// The path was empty after normalization.
    #[error("path is empty")]
    Empty,
    /// The path started with `/`.
    #[error("path must not start with '/'")]
    LeadingSlash,
    /// The path contained an empty component (`a//b`) or a trailing slash.
    #[error("path must not contain empty components")]
    EmptyComponent,
    /// The path contained a `.` or `..` component.
    #[error("path must not contain '.' or '..' components")]
    DotComponent,
    /// The path contained a NUL byte or another control character.
    #[error("path contains a control character")]
    ControlCharacter,
    /// The path was longer than [`MAX_KEY_LEN`].
    #[error("path is too long (max {MAX_KEY_LEN} bytes)")]
    TooLong,
}

/// Normalizes a slash-separated relative path into canonical trie form.
///
/// Backslashes are *not* treated as separators here: callers converting from
/// native paths should use [`normalize_native_path`], which splits on the
/// platform separator first.
pub fn normalize_path(path: &str) -> Result<String, PathError> {
    if path.is_empty() {
        return Err(PathError::Empty);
    }
    if path.starts_with('/') {
        return Err(PathError::LeadingSlash);
    }
    if path.chars().any(|c| c.is_control()) {
        return Err(PathError::ControlCharacter);
    }
    let normalized: String = if is_nfc(path) {
        path.to_string()
    } else {
        path.nfc().collect()
    };
    let mut out = String::with_capacity(normalized.len());
    for component in normalized.split('/') {
        if component.is_empty() {
            return Err(PathError::EmptyComponent);
        }
        if component == "." || component == ".." {
            return Err(PathError::DotComponent);
        }
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(component);
    }
    if out.is_empty() {
        return Err(PathError::Empty);
    }
    if out.len() > MAX_KEY_LEN {
        return Err(PathError::TooLong);
    }
    Ok(out)
}

/// Normalizes a native relative path (as produced by walking a directory) into
/// canonical trie form, mapping the platform separator onto `/`.
pub fn normalize_native_path(path: &std::path::Path) -> Result<String, PathError> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => {
                let part = part.to_str().ok_or(PathError::ControlCharacter)?;
                parts.push(part.to_string());
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => return Err(PathError::DotComponent),
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(PathError::LeadingSlash)
            }
        }
    }
    normalize_path(&parts.join("/"))
}

/// Returns true if `path` is already in canonical form.
pub fn is_normalized(path: &str) -> bool {
    matches!(normalize_path(path), Ok(p) if p == path)
}

/// Splits a normalized path into its parent directory prefix (with trailing
/// slash, empty at the root) and its final component.
pub fn split_parent(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(idx) => (&path[..idx + 1], &path[idx + 1..]),
        None => ("", path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_paths() {
        // The happy paths are the control rows of the same table.
        assert_eq!(normalize_path("a/b/c.txt").unwrap(), "a/b/c.txt");
        assert_eq!(normalize_path("file").unwrap(), "file");

        assert_eq!(normalize_path("").unwrap_err(), PathError::Empty);
        assert_eq!(normalize_path("/abs").unwrap_err(), PathError::LeadingSlash);
        assert_eq!(
            normalize_path("a//b").unwrap_err(),
            PathError::EmptyComponent
        );
        assert_eq!(normalize_path("a/").unwrap_err(), PathError::EmptyComponent);
        assert_eq!(
            normalize_path("a/./b").unwrap_err(),
            PathError::DotComponent
        );
        assert_eq!(normalize_path("../a").unwrap_err(), PathError::DotComponent);
        assert_eq!(
            normalize_path("a\0b").unwrap_err(),
            PathError::ControlCharacter
        );
        assert_eq!(
            normalize_path(&"x".repeat(MAX_KEY_LEN + 1)).unwrap_err(),
            PathError::TooLong
        );
    }

    #[test]
    fn applies_nfc() {
        // "é" as e + combining acute (NFD) must normalize to the single code point.
        let nfd = "cafe\u{0301}/x";
        let out = normalize_path(nfd).unwrap();
        assert_eq!(out, "caf\u{00e9}/x");
        assert!(is_normalized(&out));
        assert!(!is_normalized(nfd));
    }

    #[test]
    fn native_paths_map_to_slashes() {
        let p = std::path::Path::new("a").join("b").join("c.txt");
        assert_eq!(normalize_native_path(&p).unwrap(), "a/b/c.txt");
    }
}
