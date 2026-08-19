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

/// The `Initiator`/`Owner` pair every multipart listing carries.
///
/// S3 models these as the IAM identity behind the upload. This gateway has one
/// identity — the node — and says so rather than leaving the elements out,
/// because `aws s3api` prints an incomplete record when they are missing.
const OWNERSHIP: &str = "<Initiator><ID>synchronicity</ID>\
     <DisplayName>synchronicity</DisplayName></Initiator>\
     <Owner><ID>synchronicity</ID><DisplayName>synchronicity</DisplayName></Owner>";

/// Renders an `InitiateMultipartUploadResult` (§9.4).
pub fn initiate_upload_xml(bucket: &str, key: &str, upload_id: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId>\
         </InitiateMultipartUploadResult>",
        escape(bucket),
        escape(key),
        escape(upload_id)
    )
}

/// Renders a `CompleteMultipartUploadResult` (§9.4).
///
/// `Location` is the key's URL. Clients read it back, and some log it, so it is
/// rendered rather than left out — but the gateway has no idea what host it is
/// reached at, so it is the path form, which is what a path-style client asked
/// on anyway.
pub fn complete_upload_xml(bucket: &str, key: &str, etag: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Location>/{}/{}</Location><Bucket>{}</Bucket><Key>{}</Key><ETag>{}</ETag>\
         </CompleteMultipartUploadResult>",
        escape(bucket),
        escape(key),
        escape(bucket),
        escape(key),
        escape(etag)
    )
}

/// One part in a `ListPartsResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedPart {
    /// The part number.
    pub number: u32,
    /// Its size in bytes.
    pub size: u64,
    /// Its ETag, already quoted.
    pub etag: String,
    /// When it was uploaded, RFC 3339.
    pub last_modified: String,
}

/// Renders a `ListPartsResult` (§9.4).
///
/// Paginated like every other listing, because `aws s3api list-parts` walks the
/// markers whether or not there are 10 000 parts to walk.
pub fn list_parts_xml(
    bucket: &str,
    key: &str,
    upload_id: &str,
    parts: &[ListedPart],
    max_parts: usize,
    marker: u32,
    truncated: bool,
) -> String {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    xml.push_str("<ListPartsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    xml.push_str(&format!("<Bucket>{}</Bucket>", escape(bucket)));
    xml.push_str(&format!("<Key>{}</Key>", escape(key)));
    xml.push_str(&format!("<UploadId>{}</UploadId>", escape(upload_id)));
    xml.push_str(&format!("<PartNumberMarker>{marker}</PartNumberMarker>"));
    xml.push_str(&format!("<MaxParts>{max_parts}</MaxParts>"));
    xml.push_str(&format!("<IsTruncated>{truncated}</IsTruncated>"));
    // Always emitted, `0` when the listing ends here — S3 does, and a client
    // that reads the field unconditionally should not have to special-case us.
    xml.push_str(&format!(
        "<NextPartNumberMarker>{}</NextPartNumberMarker>",
        parts.last().filter(|_| truncated).map_or(0, |p| p.number)
    ));
    xml.push_str(&format!("<StorageClass>STANDARD</StorageClass>{OWNERSHIP}"));
    for part in parts {
        xml.push_str("<Part>");
        xml.push_str(&format!("<PartNumber>{}</PartNumber>", part.number));
        xml.push_str(&format!(
            "<LastModified>{}</LastModified>",
            escape(&part.last_modified)
        ));
        xml.push_str(&format!("<ETag>{}</ETag>", escape(&part.etag)));
        xml.push_str(&format!("<Size>{}</Size>", part.size));
        xml.push_str("</Part>");
    }
    xml.push_str("</ListPartsResult>");
    xml
}

/// One upload in a `ListMultipartUploadsResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedUpload {
    /// The key it will publish to.
    pub key: String,
    /// The upload id.
    pub upload_id: String,
    /// When it was created, RFC 3339.
    pub initiated: String,
}

/// Renders a `ListMultipartUploadsResult` (§9.4).
pub fn list_uploads_xml(
    bucket: &str,
    prefix: &str,
    markers: (&str, &str),
    uploads: &[ListedUpload],
    max_uploads: usize,
    truncated: bool,
) -> String {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    xml.push_str("<ListMultipartUploadsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    xml.push_str(&format!("<Bucket>{}</Bucket>", escape(bucket)));
    xml.push_str(&format!("<Prefix>{}</Prefix>", escape(prefix)));
    xml.push_str(&format!(
        "<KeyMarker>{}</KeyMarker><UploadIdMarker>{}</UploadIdMarker>",
        escape(markers.0),
        escape(markers.1)
    ));
    xml.push_str(&format!("<MaxUploads>{max_uploads}</MaxUploads>"));
    xml.push_str(&format!("<IsTruncated>{truncated}</IsTruncated>"));
    if let Some(last) = uploads.last().filter(|_| truncated) {
        xml.push_str(&format!(
            "<NextKeyMarker>{}</NextKeyMarker><NextUploadIdMarker>{}</NextUploadIdMarker>",
            escape(&last.key),
            escape(&last.upload_id)
        ));
    }
    for upload in uploads {
        xml.push_str("<Upload>");
        xml.push_str(&format!("<Key>{}</Key>", escape(&upload.key)));
        xml.push_str(&format!(
            "<UploadId>{}</UploadId>",
            escape(&upload.upload_id)
        ));
        xml.push_str(&format!(
            "<Initiated>{}</Initiated>",
            escape(&upload.initiated)
        ));
        xml.push_str("<StorageClass>STANDARD</StorageClass>");
        xml.push_str("</Upload>");
    }
    xml.push_str("</ListMultipartUploadsResult>");
    xml
}

/// The most bytes a `CompleteMultipartUpload` body may carry.
///
/// Derived rather than quoted from S3's figure, which assumes 32-hex MD5
/// ETags: this gateway's are 64-hex blake3 roots, quoted and then XML-escaped
/// by whatever echoes them back, so a legitimate 10 000-part completion runs
/// past S3's number. 256 bytes a part leaves room for that and for the
/// checksum elements clients add.
pub const MAX_COMPLETE_BODY: usize = 10_000 * 256;

/// One part a `CompleteMultipartUpload` body named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedPart {
    /// The part number the client named.
    pub number: u32,
    /// The ETag it expects that part to have, unquoted.
    pub etag: String,
}

/// Reads the `CompleteMultipartUpload` request body.
///
/// A deliberately small pull parser rather than a dependency, and a suspicious
/// one: the body is attacker-controlled, so a `DOCTYPE` or an entity — the
/// shapes an XXE turns on — is refused outright rather than expanded, and
/// anything this gateway does not recognize is skipped rather than guessed at.
pub fn parse_complete_upload(body: &str) -> Result<Vec<RequestedPart>, String> {
    if body.len() > MAX_COMPLETE_BODY {
        return Err(format!(
            "the completion body is larger than the {MAX_COMPLETE_BODY}-byte maximum"
        ));
    }
    // An entity reference cannot appear in a document this gateway would
    // produce and has no legitimate use in one it accepts, so both the
    // declaration and any use of one end the parse.
    if body.contains("<!DOCTYPE") || body.contains("<!ENTITY") {
        return Err("the completion body carries a document type declaration".into());
    }
    let mut parts = Vec::new();
    let mut number: Option<u32> = None;
    let mut etag: Option<String> = None;
    for element in Elements::new(body) {
        let text = element.text;
        match (element.closing, element.name) {
            (false, "PartNumber") => {
                let value = text.trim();
                // Digits only: `str::parse` would take `+5` as 5, and a client
                // that spelled a part number that way disagrees with this
                // gateway about something worth finding out now.
                if value.is_empty() || !value.chars().all(|c| c.is_ascii_digit()) {
                    return Err(format!("{value:?} is not a part number"));
                }
                let parsed: u32 = value
                    .parse()
                    .map_err(|_| format!("{value:?} is not a part number"))?;
                if parsed == 0 || parsed > 10_000 {
                    return Err(format!("part number {parsed} is outside 1..=10000"));
                }
                number = Some(parsed);
            }
            // An `<ETag>` that is present but is not a root this gateway could
            // have issued is a malformed body, not an absence of opinion.
            // Reading it as "no opinion" silently turns off the one check the
            // element exists for.
            (false, "ETag") => {
                let value = unescape(text.trim()).trim_matches('"').to_string();
                if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(format!("{value:?} is not an ETag this gateway issued"));
                }
                etag = Some(value);
            }
            // The close of a part is what commits the pair, so a `<Part>` that
            // named only one of them is a malformed body rather than a part
            // with a default in it.
            (true, "Part") => match (number.take(), etag.take()) {
                (Some(number), Some(etag)) => parts.push(RequestedPart { number, etag }),
                _ => return Err("a <Part> named no number or no ETag".into()),
            },
            _ => {}
        }
        if parts.len() > 10_000 {
            return Err("the completion names more than 10000 parts".into());
        }
    }
    if parts.is_empty() {
        return Err("the completion names no parts".into());
    }
    Ok(parts)
}

/// One element start or end, with the text that follows it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Element<'a> {
    /// The local name, with any namespace prefix removed.
    name: &'a str,
    /// True for a closing tag.
    closing: bool,
    /// The text between this tag and the next one.
    text: &'a str,
}

/// Walks a document as elements and the text that follows them.
///
/// Enough for the one body shape this gateway reads, and nothing more: no
/// attribute values, no namespace resolution, no nesting model. What it does
/// have to get right is that `<Part foo="bar">` and `<s3:PartNumber>` are the
/// elements they say they are — both are legal S3, and both would otherwise
/// read as unrecognized and turn a valid completion into `MalformedXML`.
struct Elements<'a> {
    rest: &'a str,
}

impl<'a> Elements<'a> {
    fn new(body: &'a str) -> Elements<'a> {
        Elements { rest: body }
    }
}

impl<'a> Iterator for Elements<'a> {
    type Item = Element<'a>;

    fn next(&mut self) -> Option<Element<'a>> {
        loop {
            let open = self.rest.find('<')?;
            let close = self.rest[open..].find('>')? + open;
            let tag = &self.rest[open + 1..close];
            self.rest = &self.rest[close + 1..];
            // Declarations, comments and processing instructions carry no text
            // this parser wants.
            if tag.starts_with('?') || tag.starts_with('!') {
                continue;
            }
            let token = tag
                .split([' ', '\t', '\r', '\n'])
                .next()
                .unwrap_or("")
                .trim_end_matches('/');
            let closing = token.starts_with('/');
            let bare = token.trim_start_matches('/');
            let name = bare.rsplit_once(':').map_or(bare, |(_, local)| local);
            let text = match self.rest.find('<') {
                Some(next) => &self.rest[..next],
                None => self.rest,
            };
            return Some(Element {
                name,
                closing,
                text,
            });
        }
    }
}

/// Reverses [`escape`], for text read back off the wire.
fn unescape(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
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

/// Formats unix nanoseconds as the RFC 7231 HTTP-date the `Last-Modified`
/// *header* requires: `Thu, 13 Aug 2026 17:05:17 GMT`.
///
/// The XML body wants RFC 3339 and the header wants HTTP-date, and they are
/// not interchangeable: AWS SDKs parse the header strictly, so an RFC 3339
/// value there broke rclone outright.
pub fn format_http_date(nanos: i64) -> String {
    const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let nanos = nanos.max(0);
    let seconds = nanos / 1_000_000_000;
    let days = seconds / 86_400;
    let time = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    // 1970-01-01 was a Thursday.
    let weekday = WEEKDAYS[(days + 4).rem_euclid(7) as usize];
    format!(
        "{weekday}, {day:02} {} {year:04} {:02}:{:02}:{:02} GMT",
        MONTHS[(month - 1) as usize],
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
    fn completion_bodies_parse() {
        const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let body = format!(
            "<CompleteMultipartUpload>\
             <Part><PartNumber>1</PartNumber><ETag>&quot;{A}&quot;</ETag></Part>\
             <Part><PartNumber>2</PartNumber><ETag>\"{B}\"</ETag></Part>\
             </CompleteMultipartUpload>"
        );
        let parts = parse_complete_upload(&body).unwrap();
        assert_eq!(parts.len(), 2);
        // Quotes come off however they were spelled, escaped or not.
        assert_eq!(parts[0].etag, A);
        assert_eq!(parts[1].etag, B);
        assert_eq!(parts[1].number, 2);

        // Namespaces and attributes are legal S3 and must not read as
        // unrecognized elements.
        let decorated = format!(
            "<s3:CompleteMultipartUpload xmlns:s3=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <s3:Part foo=\"bar\"><s3:PartNumber>7</s3:PartNumber>\
             <s3:ETag>\"{A}\"</s3:ETag></s3:Part></s3:CompleteMultipartUpload>"
        );
        let parts = parse_complete_upload(&decorated).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].number, 7);
    }

    #[test]
    fn unknown_elements_are_skipped_but_broken_parts_are_not() {
        // A checksum element the gateway does not read must not derail the parse.
        let root = "c".repeat(64);
        let body = format!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>\
             <ChecksumCRC32C>aaaa</ChecksumCRC32C><ETag>\"{root}\"</ETag></Part>\
             </CompleteMultipartUpload>"
        );
        assert_eq!(parse_complete_upload(&body).unwrap().len(), 1);
        // An ETag this gateway could never have issued is a malformed body, not
        // an absence of opinion — reading it as "no opinion" silently turns off
        // the one check the element exists for.
        assert!(parse_complete_upload(&body.replace(&root, "abc")).is_err());
        assert!(parse_complete_upload(&body.replace(&format!("\"{root}\""), "")).is_err());
        // Part numbers outside S3's range, or spelled oddly, are refused where
        // they are read.
        for bad in ["0", "10001", "-1", "+5", ""] {
            let body = body.replace("<PartNumber>1<", &format!("<PartNumber>{bad}<"));
            assert!(parse_complete_upload(&body).is_err(), "{bad}");
        }
        // A part missing half of itself is a malformed body, not a default.
        let broken = "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber></Part>\
            </CompleteMultipartUpload>";
        assert!(parse_complete_upload(broken).is_err());
        assert!(parse_complete_upload("<CompleteMultipartUpload/>").is_err());
    }

    #[test]
    fn hostile_completion_bodies_are_refused() {
        let xxe = "<!DOCTYPE foo [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>\
            <CompleteMultipartUpload><Part><PartNumber>1</PartNumber>\
            <ETag>&x;</ETag></Part></CompleteMultipartUpload>";
        assert!(parse_complete_upload(xxe).is_err());
        // The guard is belt-and-braces: there is no entity table to expand
        // into, so a lower-case declaration that slips past the substring check
        // still yields the literal text and fails as a malformed ETag rather
        // than reading a file.
        assert!(parse_complete_upload(&xxe.replace("<!DOCTYPE", "<!doctype")).is_err());
        // The cap is on the body, before anything is parsed out of it.
        let huge = format!("<a>{}</a>", "x".repeat(MAX_COMPLETE_BODY));
        assert!(parse_complete_upload(&huge).is_err());
    }

    #[test]
    fn multipart_results_render() {
        let xml = initiate_upload_xml("media", "a/b.bin", "deadbeef");
        assert!(xml.contains("<UploadId>deadbeef</UploadId>"), "{xml}");
        let xml = complete_upload_xml("media", "a/b.bin", "\"abc\"");
        assert!(xml.contains("<Location>/media/a/b.bin</Location>"), "{xml}");
        assert!(xml.contains("<ETag>&quot;abc&quot;</ETag>"), "{xml}");
        let parts = [ListedPart {
            number: 1,
            size: 5,
            etag: "\"a\"".into(),
            last_modified: "1970-01-01T00:00:00.000Z".into(),
        }];
        let xml = list_parts_xml("media", "k", "u", &parts, 1000, 0, true);
        assert!(
            xml.contains("<NextPartNumberMarker>1</NextPartNumberMarker>"),
            "{xml}"
        );
        assert!(xml.contains("<PartNumber>1</PartNumber>"), "{xml}");
        let uploads = [ListedUpload {
            key: "k".into(),
            upload_id: "u".into(),
            initiated: "1970-01-01T00:00:00.000Z".into(),
        }];
        let xml = list_uploads_xml("media", "", ("", ""), &uploads, 1000, false);
        assert!(xml.contains("<UploadId>u</UploadId>"), "{xml}");
        assert!(xml.contains("<IsTruncated>false</IsTruncated>"), "{xml}");
    }

    #[test]
    fn timestamps_format_as_rfc3339() {
        // Epoch, an arbitrary instant, a leap day, and the negative clamp —
        // each in both the XML and the HTTP-date shapes. The epoch was a
        // Thursday, and the header format carries no millis.
        let nanos = 1_704_164_645_678_000_000i64;
        let leap = 1_709_208_000_000_000_000i64;
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(format_timestamp(nanos), "2024-01-02T03:04:05.678Z");
        assert!(format_timestamp(leap).starts_with("2024-02-29T"));
        assert_eq!(format_timestamp(-1), "1970-01-01T00:00:00.000Z");
        assert_eq!(format_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(format_http_date(nanos), "Tue, 02 Jan 2024 03:04:05 GMT");
        assert_eq!(format_http_date(leap), "Thu, 29 Feb 2024 12:00:00 GMT");
        assert_eq!(format_http_date(-1), "Thu, 01 Jan 1970 00:00:00 GMT");
    }
}
