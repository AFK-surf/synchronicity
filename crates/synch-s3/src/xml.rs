//! Minimal S3 XML rendering.

/// Escapes text for an XML element body or attribute.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// One object in a `ListObjectsV2` result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedObject {
    /// The object key.
    pub key: String,
    /// Its size in bytes.
    pub size: u64,
    /// Its ETag: the quoted BLAKE3 root hex (§9.4).
    pub etag: String,
    /// Its last-modified time, RFC 3339.
    pub last_modified: String,
}

/// A `ListObjectsV2` result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListResult {
    /// The bucket listed.
    pub bucket: String,
    /// The prefix filter.
    pub prefix: String,
    /// The delimiter, if any.
    pub delimiter: Option<String>,
    /// The maximum keys requested.
    pub max_keys: usize,
    /// The objects found.
    pub contents: Vec<ListedObject>,
    /// The common prefixes rolled up by the delimiter.
    pub common_prefixes: Vec<String>,
    /// The continuation token supplied by the client.
    pub continuation_token: Option<String>,
    /// The token to resume from, when the listing is truncated.
    pub next_continuation_token: Option<String>,
    /// True if more results remain.
    pub is_truncated: bool,
}

impl ListResult {
    /// Renders the S3 XML body.
    pub fn to_xml(&self) -> String {
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        xml.push_str("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
        xml.push_str(&format!("<Name>{}</Name>", escape(&self.bucket)));
        xml.push_str(&format!("<Prefix>{}</Prefix>", escape(&self.prefix)));
        xml.push_str(&format!("<KeyCount>{}</KeyCount>", self.contents.len()));
        xml.push_str(&format!("<MaxKeys>{}</MaxKeys>", self.max_keys));
        if let Some(delimiter) = &self.delimiter {
            xml.push_str(&format!("<Delimiter>{}</Delimiter>", escape(delimiter)));
        }
        xml.push_str(&format!("<IsTruncated>{}</IsTruncated>", self.is_truncated));
        if let Some(token) = &self.continuation_token {
            xml.push_str(&format!(
                "<ContinuationToken>{}</ContinuationToken>",
                escape(token)
            ));
        }
        if let Some(token) = &self.next_continuation_token {
            xml.push_str(&format!(
                "<NextContinuationToken>{}</NextContinuationToken>",
                escape(token)
            ));
        }
        for object in &self.contents {
            xml.push_str("<Contents>");
            xml.push_str(&format!("<Key>{}</Key>", escape(&object.key)));
            xml.push_str(&format!(
                "<LastModified>{}</LastModified>",
                escape(&object.last_modified)
            ));
            xml.push_str(&format!("<ETag>{}</ETag>", escape(&object.etag)));
            xml.push_str(&format!("<Size>{}</Size>", object.size));
            xml.push_str("<StorageClass>STANDARD</StorageClass>");
            xml.push_str("</Contents>");
        }
        for prefix in &self.common_prefixes {
            xml.push_str(&format!(
                "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                escape(prefix)
            ));
        }
        xml.push_str("</ListBucketResult>");
        xml
    }
}

/// Renders a `ListBuckets` result.
pub fn list_buckets_xml(names: &[String]) -> String {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    xml.push_str("<ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    xml.push_str("<Owner><ID>synchronicity</ID><DisplayName>synchronicity</DisplayName></Owner>");
    xml.push_str("<Buckets>");
    for name in names {
        xml.push_str(&format!(
            "<Bucket><Name>{}</Name><CreationDate>1970-01-01T00:00:00.000Z</CreationDate></Bucket>",
            escape(name)
        ));
    }
    xml.push_str("</Buckets></ListAllMyBucketsResult>");
    xml
}

/// Formats unix nanoseconds as the RFC 3339 timestamp S3 clients expect.
pub fn format_timestamp(nanos: i64) -> String {
    // A small civil-from-days conversion keeps the gateway free of a date
    // library for the one field that needs one.
    let nanos = nanos.max(0);
    let seconds = nanos / 1_000_000_000;
    let millis = (nanos % 1_000_000_000) / 1_000_000;
    let days = seconds / 86_400;
    let time = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        time / 3600,
        (time % 3600) / 60,
        time % 60,
    )
}

/// Howard Hinnant's `civil_from_days`, for the epoch-days to Y/M/D conversion.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping() {
        assert_eq!(escape("a<b>c&d\"e'f"), "a&lt;b&gt;c&amp;d&quot;e&apos;f");
        assert_eq!(escape("plain"), "plain");
    }

    #[test]
    fn list_result_renders() {
        let result = ListResult {
            bucket: "photos".into(),
            prefix: "2024/".into(),
            delimiter: Some("/".into()),
            max_keys: 1000,
            contents: vec![ListedObject {
                key: "2024/a.jpg".into(),
                size: 42,
                etag: "\"abc\"".into(),
                last_modified: "2024-01-02T03:04:05.000Z".into(),
            }],
            common_prefixes: vec!["2024/summer/".into()],
            continuation_token: None,
            next_continuation_token: Some("2024/a.jpg".into()),
            is_truncated: true,
        };
        let xml = result.to_xml();
        assert!(xml.contains("<Name>photos</Name>"), "{xml}");
        assert!(xml.contains("<Key>2024/a.jpg</Key>"), "{xml}");
        assert!(xml.contains("<Size>42</Size>"), "{xml}");
        assert!(xml.contains("<ETag>&quot;abc&quot;</ETag>"), "{xml}");
        assert!(xml.contains("<IsTruncated>true</IsTruncated>"), "{xml}");
        assert!(
            xml.contains("<CommonPrefixes><Prefix>2024/summer/</Prefix></CommonPrefixes>"),
            "{xml}"
        );
        assert!(
            xml.contains("<NextContinuationToken>2024/a.jpg</NextContinuationToken>"),
            "{xml}"
        );
        assert!(xml.contains("<KeyCount>1</KeyCount>"), "{xml}");
    }

    #[test]
    fn bucket_list_renders() {
        let xml = list_buckets_xml(&["a".into(), "b".into()]);
        assert!(xml.contains("<Name>a</Name>"), "{xml}");
        assert!(xml.contains("<Name>b</Name>"), "{xml}");
    }

    #[test]
    fn timestamps_format_as_rfc3339() {
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00.000Z");
        // 2024-01-02T03:04:05.678Z
        let nanos = 1_704_164_645_678_000_000i64;
        assert_eq!(format_timestamp(nanos), "2024-01-02T03:04:05.678Z");
        // Leap day.
        let leap = 1_709_208_000_000_000_000i64;
        assert!(format_timestamp(leap).starts_with("2024-02-29T"));
        // Negative input clamps rather than panicking.
        assert_eq!(format_timestamp(-1), "1970-01-01T00:00:00.000Z");
    }
}
