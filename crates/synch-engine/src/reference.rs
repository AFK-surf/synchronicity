//! Parsing the `[<origin>:]<space>[/<path>]` references the CLI and the S3
//! gateway both take (§9.2, §9.4).

use std::str::FromStr;

use synch_core::{normalize_path, validate_space, OriginId};

use crate::error::EngineError;

/// A reference to a space, a directory, or a single path, optionally scoped to
/// one origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRef {
    /// The origin, or `None` for the merged view across all origins.
    pub origin: Option<OriginId>,
    /// The space id.
    pub space: String,
    /// The normalized path within the space, empty for the space root.
    pub path: String,
}

impl EntryRef {
    /// True if this reference names the space root rather than a path.
    pub fn is_space_root(&self) -> bool {
        self.path.is_empty()
    }

    /// The prefix to scan for a listing: the path plus a trailing slash, or
    /// empty at the space root.
    pub fn dir_prefix(&self) -> String {
        if self.path.is_empty() || self.path.ends_with('/') {
            self.path.clone()
        } else {
            format!("{}/", self.path)
        }
    }

    /// Renders the reference back to its canonical text form.
    pub fn render(&self) -> String {
        let body = if self.path.is_empty() {
            self.space.clone()
        } else {
            format!("{}/{}", self.space, self.path)
        };
        match &self.origin {
            Some(origin) => format!("{}:{body}", origin.canonical()),
            None => body,
        }
    }
}

impl std::fmt::Display for EntryRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render())
    }
}

impl FromStr for EntryRef {
    type Err = EngineError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.is_empty() {
            return Err(EngineError::invalid("empty reference"));
        }
        // The origin is everything before the last ':' that precedes the first
        // '/', which keeps the `key:<z-base-32>` form unambiguous.
        let boundary = text.find('/').unwrap_or(text.len());
        let (origin, rest) = match text[..boundary].rfind(':') {
            Some(idx) => {
                let origin = OriginId::from_str(&text[..idx])
                    .map_err(|e| EngineError::invalid(format!("bad origin: {e}")))?;
                (Some(origin), &text[idx + 1..])
            }
            None => (None, text),
        };

        let (space, path) = match rest.split_once('/') {
            Some((space, path)) => (space, path),
            None => (rest, ""),
        };
        validate_space(space)?;
        let path = if path.is_empty() {
            String::new()
        } else {
            // A trailing slash names a directory; keep it off the normalized
            // form and let `dir_prefix` put it back.
            normalize_path(path.trim_end_matches('/'))
                .map_err(|e| EngineError::invalid(e.to_string()))?
        };
        Ok(EntryRef {
            origin,
            space: space.to_string(),
            path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_reference() {
        let r: EntryRef = "nas@cluster.example:media/talks/keynote.mp4"
            .parse()
            .unwrap();
        assert_eq!(
            r.origin,
            Some(OriginId::named("nas", "cluster.example").unwrap())
        );
        assert_eq!(r.space, "media");
        assert_eq!(r.path, "talks/keynote.mp4");
        assert_eq!(r.render(), "nas@cluster.example:media/talks/keynote.mp4");
    }

    #[test]
    fn parses_the_merged_view() {
        let r: EntryRef = "media/talks".parse().unwrap();
        assert_eq!(r.origin, None);
        assert_eq!(r.space, "media");
        assert_eq!(r.path, "talks");
        assert_eq!(r.dir_prefix(), "talks/");
        assert_eq!(r.render(), "media/talks");
    }

    #[test]
    fn parses_a_bare_space() {
        let r: EntryRef = "media".parse().unwrap();
        assert!(r.is_space_root());
        assert_eq!(r.dir_prefix(), "");
        assert_eq!(r.render(), "media");
    }

    #[test]
    fn key_origins_keep_their_colon() {
        let key = iroh_base::SecretKey::generate().public();
        let text = format!("key:{}:media/a.txt", key.to_z32());
        let r: EntryRef = text.parse().unwrap();
        assert_eq!(r.origin, Some(OriginId::Key(key)));
        assert_eq!(r.space, "media");
        assert_eq!(r.path, "a.txt");
        assert_eq!(r.render(), text);
    }

    #[test]
    fn trailing_slashes_name_directories() {
        let r: EntryRef = "media/talks/".parse().unwrap();
        assert_eq!(r.path, "talks");
        assert_eq!(r.dir_prefix(), "talks/");
    }

    #[test]
    fn paths_are_normalized() {
        let r: EntryRef = "media/cafe\u{0301}.txt".parse().unwrap();
        assert_eq!(r.path, "caf\u{00e9}.txt");
    }

    #[test]
    fn rejects_bad_references() {
        assert!("".parse::<EntryRef>().is_err());
        assert!("media/../escape".parse::<EntryRef>().is_err());
        assert!("not an origin:media/a".parse::<EntryRef>().is_err());
        assert!("nas@x.example:/media".parse::<EntryRef>().is_err());
    }
}
