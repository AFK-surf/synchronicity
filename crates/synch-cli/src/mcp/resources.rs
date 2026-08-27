//! The unified tree as MCP resources.
//!
//! A resource is a URI a client can list, show in a picker, and read. That is
//! what the unified tree already is, so it is exposed as one rather than only
//! through tools: `synch://<space>/<path>`, listed page by page and read
//! through the same `Resolve` and `Read` calls [`super::tools`] uses.
//!
//! Listing maps onto the control surface exactly rather than approximately.
//! MCP's opaque `cursor` becomes `ListRequest.start_after` and the page size
//! becomes `ListRequest.limit`, so a space with a million paths is paged by the
//! daemon and never assembled here.

use base64::Engine as _;
use serde_json::{json, Value};
use synch_core::EntryKind;

use crate::{
    control::proto::pb,
    mcp::{
        rpc,
        tools::{Context, ToolError},
    },
};

/// The URI scheme this server owns.
const SCHEME: &str = "synch://";

/// How many paths one page of `resources/list` carries.
const PAGE: u64 = 200;

/// The largest resource `resources/read` will return whole.
///
/// A resource read takes no offset — the protocol has no way to express one —
/// so an object past this is refused with the tool that *can* window it named
/// in the message, rather than silently truncated into something that looks
/// like the whole file.
const MAX_RESOURCE_BYTES: u64 = 1024 * 1024;

/// Builds the URI naming one path.
pub(crate) fn uri(space: &str, path: &str) -> String {
    match path.is_empty() {
        true => format!("{SCHEME}{}/", encode(space)),
        false => format!("{SCHEME}{}/{}", encode(space), encode_path(path)),
    }
}

/// Splits a `synch://` URI back into a space and a path.
pub(crate) fn parse(text: &str) -> Result<(String, String), rpc::Error> {
    let rest = text.strip_prefix(SCHEME).ok_or_else(|| {
        rpc::Error::invalid_params(format!("{text:?} is not a synch:// URI"))
            .with_data(json!({ "uri": text }))
    })?;
    // A query or fragment names nothing here, and accepting one would make two
    // URIs for one path — which a client that caches by URI would treat as two
    // resources.
    if rest.contains(['?', '#']) {
        return Err(
            rpc::Error::invalid_params("a synch:// URI carries no query or fragment")
                .with_data(json!({ "uri": text })),
        );
    }
    let (space, path) = match rest.split_once('/') {
        Some((space, path)) => (space, path),
        None => (rest, ""),
    };
    let space = decode(space).map_err(|e| {
        rpc::Error::invalid_params(format!("the space in {text:?} is not valid: {e}"))
            .with_data(json!({ "uri": text }))
    })?;
    let path = decode(path).map_err(|e| {
        rpc::Error::invalid_params(format!("the path in {text:?} is not valid: {e}"))
            .with_data(json!({ "uri": text }))
    })?;
    if space.is_empty() {
        return Err(
            rpc::Error::invalid_params(format!("{text:?} names no space"))
                .with_data(json!({ "uri": text })),
        );
    }
    Ok((space, path.trim_end_matches('/').to_string()))
}

/// Percent-encodes one URI segment.
///
/// RFC 3986 unreserved characters pass through; everything else is escaped,
/// including the delimiters a path may legitimately contain. `/` is escaped
/// here too, which is why paths go through [`encode_path`] instead.
fn encode(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Percent-encodes a path, keeping its separators as separators.
fn encode_path(path: &str) -> String {
    path.split('/').map(encode).collect::<Vec<_>>().join("/")
}

/// Reverses [`encode`], keeping `/` as it is.
fn decode(text: &str) -> Result<String, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .ok_or_else(|| "a % escape needs two hex digits".to_string())?;
                let hex = std::str::from_utf8(hex).map_err(|_| "bad % escape".to_string())?;
                out.push(
                    u8::from_str_radix(hex, 16)
                        .map_err(|_| format!("%{hex} is not a hex escape"))?,
                );
                i += 3;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| "the escapes did not decode to UTF-8".to_string())
}

/// The MIME type a path's extension implies.
///
/// Advisory, and deliberately short: the point is to help a client decide
/// whether to show something, not to be a type database. Anything unrecognized
/// is `application/octet-stream`, and a read that finds valid UTF-8 says so
/// through the content block it chooses rather than through this.
pub(crate) fn mime_for(path: &str) -> &'static str {
    let extension = path
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default();
    match extension.as_str() {
        "txt" | "log" => "text/plain",
        "md" | "markdown" => "text/markdown",
        "json" => "application/json",
        "yaml" | "yml" => "application/yaml",
        "toml" => "application/toml",
        "csv" => "text/csv",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "text/javascript",
        "ts" => "text/typescript",
        "rs" => "text/x-rust",
        "py" => "text/x-python",
        "go" => "text/x-go",
        "c" | "h" => "text/x-c",
        "sh" => "application/x-sh",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "wasm" => "application/wasm",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "tar" => "application/x-tar",
        _ => "application/octet-stream",
    }
}

/// The templates that describe what this server's URIs look like.
pub(crate) fn templates() -> Value {
    json!({
        "resourceTemplates": [
            {
                "uriTemplate": "synch://{space}/{+path}",
                "name": "synchronicity path",
                "title": "A path in the unified tree",
                "description": "Any path in any space this node holds, read at the \
                                version the default policy selects. Percent-encode \
                                anything outside the URI unreserved set.",
                "mimeType": "application/octet-stream",
            }
        ]
    })
}

/// A page of `resources/list`.
///
/// The cursor carries the space and the path within it, so paging walks the
/// spaces in order and resumes mid-space. It is base64 so a client treats it as
/// the opaque token the spec says it is, rather than as something to construct.
pub(crate) async fn list(ctx: &Context, cursor: Option<&str>) -> Result<Value, ToolError> {
    let resume = match cursor {
        Some(cursor) => Some(Cursor::decode(cursor)?),
        None => None,
    };

    let spaces: Vec<String> = ctx
        .session
        .call(|mut client| async move { client.list_spaces().await })
        .await?
        .into_iter()
        .map(|space| space.id)
        .filter(|id| ctx.in_scope(id))
        .collect();

    // Alphabetical, not insertion order: paging has to walk a stable sequence,
    // and the daemon's row order is the store's, which a `space add` reorders.
    let mut spaces = spaces;
    spaces.sort();

    let start = match &resume {
        Some(cursor) => spaces
            .iter()
            .position(|id| *id == cursor.space)
            // The space was removed between pages. Resuming at the next one by
            // name keeps the walk moving forward rather than restarting it.
            .unwrap_or_else(|| spaces.partition_point(|id| *id < cursor.space)),
        None => 0,
    };

    let mut resources = Vec::new();
    // Where the walk has got to, and therefore what the next page resumes
    // from. Updated per batch rather than per resource, because a batch whose
    // every row was a directory still moved the walk forward.
    let mut reached: Option<Cursor> = None;

    for (offset, space) in spaces.iter().enumerate().skip(start) {
        let mut after = match (&resume, offset == start) {
            (Some(cursor), true) if !cursor.path.is_empty() => Some(cursor.path.clone()),
            _ => None,
        };
        loop {
            if resources.len() as u64 >= PAGE {
                // The page is full, and `reached` names the last path it
                // accounted for.
                return Ok(page(resources, reached));
            }
            let remaining = PAGE.saturating_sub(resources.len() as u64);
            let entries = ctx
                .session
                .call(|mut client| {
                    let request = pb::ListRequest {
                        space: space.clone(),
                        prefix: String::new(),
                        start_after: after.clone(),
                        limit: Some(remaining),
                        policy: None,
                    };
                    async move {
                        let mut stream = client.list(request).await?;
                        let mut entries = Vec::new();
                        while let Some(entry) = stream.next().await? {
                            entries.push(entry);
                        }
                        Ok(entries)
                    }
                })
                .await?;

            // An *empty* batch is the end of this space, not a short one: the
            // daemon fills a page past what its filters drop but only within a
            // scan budget, so a short batch can still have paths behind it.
            let Some(last) = entries.last().map(|entry| entry.path.clone()) else {
                break;
            };
            for entry in entries {
                // A directory is not a resource: it has no bytes, and a client
                // that tried to read one would get an error where a listing was
                // meant.
                if entry.kind == EntryKind::Dir || entry.kind == EntryKind::Tombstone {
                    continue;
                }
                resources.push(json!({
                    "uri": uri(&entry.space, &entry.path),
                    "name": entry.path.rsplit('/').next().unwrap_or(&entry.path),
                    "title": format!("{}/{}", entry.space, entry.path),
                    "description": describe(&entry),
                    "mimeType": mime_for(&entry.path),
                    "size": entry.size,
                }));
            }
            reached = Some(Cursor {
                space: space.clone(),
                path: last.clone(),
            });
            after = Some(last);
        }
    }

    // Every space walked to its end: this is the last page, and it says so by
    // carrying no cursor.
    Ok(page(resources, None))
}

/// Renders a page with its cursor.
fn page(resources: Vec<Value>, next: Option<Cursor>) -> Value {
    let mut body = json!({ "resources": resources });
    if let (Some(cursor), Value::Object(map)) = (next, &mut body) {
        map.insert("nextCursor".into(), Value::String(cursor.encode()));
    }
    body
}

/// A one-line account of an entry, for a resource picker.
fn describe(entry: &crate::control::EntryInfo) -> String {
    let kind = match entry.kind {
        EntryKind::Socket => "socket, ",
        EntryKind::Symlink => "symlink, ",
        _ => "",
    };
    match entry.versions {
        1 => format!("{kind}{} bytes, from {}", entry.size, entry.origin),
        n => format!(
            "{kind}{} bytes, from {} — {n} versions exist",
            entry.size, entry.origin
        ),
    }
}

/// Where a listing left off.
#[derive(Debug, PartialEq, Eq)]
struct Cursor {
    /// The space being walked.
    space: String,
    /// The last path returned from it.
    path: String,
}

impl Cursor {
    /// Encodes the cursor into the opaque token a client carries.
    fn encode(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!("{}\n{}", self.space, self.path))
    }

    /// Reads a cursor back, refusing one this server did not write.
    fn decode(text: &str) -> Result<Cursor, ToolError> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| ToolError::Protocol(bad_cursor()))?;
        let text = String::from_utf8(bytes).map_err(|_| ToolError::Protocol(bad_cursor()))?;
        let (space, path) = text
            .split_once('\n')
            .ok_or_else(|| ToolError::Protocol(bad_cursor()))?;
        Ok(Cursor {
            space: space.to_string(),
            path: path.to_string(),
        })
    }
}

/// The error a cursor from somewhere else earns.
fn bad_cursor() -> rpc::Error {
    rpc::Error::invalid_params(
        "that cursor did not come from this server; omit it to start the listing again",
    )
}

/// `resources/read`.
pub(crate) async fn read(ctx: &Context, uri_text: &str) -> Result<Value, ToolError> {
    let (space, path) = parse(uri_text).map_err(ToolError::Protocol)?;
    if !ctx.in_scope(&space) {
        // Not-found rather than out-of-scope: a resource this server does not
        // serve should not be distinguishable from one that does not exist, and
        // the spec fixes the code for a resource that is not there.
        return Err(ToolError::Protocol(
            rpc::Error::invalid_params(format!("no such resource: {uri_text}"))
                .with_data(json!({ "uri": uri_text })),
        ));
    }

    let entry = ctx
        .session
        .call(|mut client| {
            let request = pb::ResolveRequest {
                space: space.clone(),
                path: path.clone(),
                policy: None,
            };
            async move { client.resolve(request).await }
        })
        .await
        .map_err(|e| match e.code {
            // The spec is explicit that a missing resource is -32602, and that
            // an empty `contents` array must never stand in for one.
            crate::control::ErrorCode::NotFound => ToolError::Protocol(
                rpc::Error::invalid_params(format!("no such resource: {uri_text}"))
                    .with_data(json!({ "uri": uri_text })),
            ),
            _ => ToolError::from(e),
        })?;

    if entry.kind == EntryKind::Symlink {
        return Ok(json!({
            "contents": [{
                "uri": uri_text,
                "mimeType": "text/plain",
                "text": entry.symlink_target.unwrap_or_default(),
            }]
        }));
    }
    if entry.kind != EntryKind::File && entry.kind != EntryKind::Socket {
        return Err(ToolError::execution(format!(
            "{uri_text} is a {}, which has no bytes to read",
            match entry.kind {
                EntryKind::Dir => "directory",
                EntryKind::Tombstone => "deleted path",
                _ => "non-file",
            }
        )));
    }
    if entry.size > MAX_RESOURCE_BYTES {
        return Err(ToolError::execution(format!(
            "{uri_text} is {} bytes, and a resource read has no way to ask for \
             part of one. Use the synch_read tool, which takes an offset and a \
             length.",
            entry.size
        )));
    }

    let bytes = ctx
        .session
        .call(|mut client| {
            let request = pb::ReadRequest {
                space: space.clone(),
                path: path.clone(),
                policy: None,
                start: 0,
                len: Some(MAX_RESOURCE_BYTES),
            };
            async move {
                let mut chunks = client.read(request).await?;
                let mut bytes = Vec::new();
                while let Some(chunk) = chunks.next().await? {
                    bytes.extend_from_slice(&chunk);
                }
                Ok(bytes)
            }
        })
        .await?;

    let mime = mime_for(&path);
    let body = match String::from_utf8(bytes) {
        Ok(text) => json!({ "uri": uri_text, "mimeType": mime, "text": text }),
        Err(e) => json!({
            "uri": uri_text,
            "mimeType": mime,
            "blob": base64::engine::general_purpose::STANDARD.encode(e.as_bytes()),
        }),
    };
    Ok(json!({ "contents": [body] }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uris_round_trip_through_every_character_a_path_can_hold() {
        for (space, path) in [
            ("media", "notes/plan.md"),
            ("media", ""),
            ("code", "a b/c#d?e.txt"),
            ("code", "2024:07:01.bin"),
            ("odd space", "π/ünïcode.txt"),
            ("code", "100%/done.txt"),
        ] {
            let uri = uri(space, path);
            assert!(!uri.contains('#') && !uri.contains('?'), "{uri}");
            assert_eq!(parse(&uri).unwrap(), (space.to_string(), path.to_string()));
        }
    }

    #[test]
    fn separators_survive_encoding_and_nothing_else_does() {
        assert_eq!(uri("media", "a/b/c.txt"), "synch://media/a/b/c.txt");
        assert_eq!(encode("a/b"), "a%2Fb");
        assert_eq!(encode_path("a/b"), "a/b");
        assert_eq!(decode("a%2Fb").unwrap(), "a/b");
        assert!(decode("%zz").is_err());
        assert!(decode("%A").is_err());
    }

    #[test]
    fn a_uri_from_elsewhere_is_refused_with_its_own_code() {
        for bad in [
            "file:///etc/passwd",
            "synch://",
            "synch://media/a.txt?v=1",
            "synch://media/a.txt#top",
        ] {
            let error = parse(bad).unwrap_err();
            assert_eq!(error.code, rpc::INVALID_PARAMS, "{bad}");
        }
    }

    #[test]
    fn a_trailing_slash_names_the_same_path() {
        assert_eq!(
            parse("synch://media/dir/").unwrap(),
            ("media".to_string(), "dir".to_string())
        );
    }

    #[test]
    fn cursors_are_opaque_and_only_ours_decode() {
        let cursor = Cursor {
            space: "media".into(),
            path: "notes/plan.md".into(),
        };
        let encoded = cursor.encode();
        assert!(
            !encoded.contains('/'),
            "a cursor travels in JSON and in logs"
        );
        assert_eq!(Cursor::decode(&encoded).unwrap(), cursor);
        for bad in ["", "not base64!", "aGVsbG8"] {
            assert!(Cursor::decode(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn mime_types_are_guessed_from_the_extension_and_never_guessed_wrong() {
        assert_eq!(mime_for("a/b/plan.md"), "text/markdown");
        assert_eq!(mime_for("PLAN.MD"), "text/markdown");
        assert_eq!(mime_for("archive.tar"), "application/x-tar");
        assert_eq!(mime_for("no-extension"), "application/octet-stream");
        assert_eq!(mime_for(".hidden"), "application/octet-stream");
    }
}
