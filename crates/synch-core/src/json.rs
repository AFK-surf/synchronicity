//! Hand-formatted JSON output, shared where serde would be a dependency for
//! one string.
//!
//! Two writers hand-format JSON — the CLI's `--json` render and the canonical
//! in-toto Statement writer — and each carried this escape table. An escape
//! table is a place where a divergent edit is silent until an unescaped
//! control character reaches a parser, so it exists once.

/// Appends `value` as a JSON string literal, quotes included, escaping what
/// JSON requires escaped.
pub fn json_string_into(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}
