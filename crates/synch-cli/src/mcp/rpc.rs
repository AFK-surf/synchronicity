//! JSON-RPC 2.0 and the two MCP protocol eras.
//!
//! MCP changed shape in revision `2026-07-28`. Through `2025-11-25` a client
//! opened with an `initialize` handshake and the connection carried the
//! negotiated version; from `2026-07-28` there is no handshake at all — the
//! protocol is stateless, every request declares its own version in `_meta`,
//! and `server/discover` is mandatory. The spec calls the two **modern** and
//! **legacy** and permits one server to answer both, selecting by how the
//! client opens.
//!
//! That is what this does, because refusing either would refuse real clients:
//! the modern era is where the protocol is going and the legacy era is what
//! most installed clients still speak. The era decides how a message is read
//! and how its result is stamped, and nothing else — both land on the same
//! tool registry in [`super::tools`].

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

/// The protocol revisions this server implements, newest first.
///
/// Order matters twice: it is the order `supportedVersions` is advertised in,
/// and the first entry is what a legacy `initialize` is answered with when the
/// client asks for something we do not have.
pub(crate) const SUPPORTED_VERSIONS: &[&str] = &["2026-07-28", "2025-11-25", "2025-06-18"];

/// The newest revision, which is what this server prefers.
pub(crate) const LATEST_VERSION: &str = SUPPORTED_VERSIONS[0];

/// The first revision that carries its version per request rather than
/// negotiating one for the connection.
///
/// A version at or after this is modern; anything before it is legacy. The
/// comparison is a string compare, which is exactly right for `YYYY-MM-DD`.
pub(crate) const FIRST_MODERN_VERSION: &str = "2026-07-28";

/// The `_meta` key carrying a request's protocol version.
pub(crate) const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";

/// The `_meta` key carrying the client's capabilities. Required on a modern
/// request, and the reason a modern request is distinguishable from a legacy
/// one that happens to carry a version.
pub(crate) const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";

/// The `_meta` key a server stamps its identity into.
pub(crate) const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

// ---- error codes -----------------------------------------------------------

/// Malformed JSON.
pub(crate) const PARSE_ERROR: i64 = -32700;
/// A well-formed message that is not a valid request.
pub(crate) const INVALID_REQUEST: i64 = -32600;
/// No such method.
pub(crate) const METHOD_NOT_FOUND: i64 = -32601;
/// The parameters were missing, malformed, or named something absent.
pub(crate) const INVALID_PARAMS: i64 = -32602;
/// The server failed while serving a well-formed request.
pub(crate) const INTERNAL_ERROR: i64 = -32603;
/// The requested protocol version is not one this server implements.
pub(crate) const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// A JSON-RPC request id.
///
/// Ids are opaque and travel back exactly as they arrived, so this keeps the
/// number/string distinction rather than normalizing to one of them: a client
/// that sent `"7"` and got back `7` cannot correlate the response.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum RequestId {
    /// A numeric id.
    Number(i64),
    /// A string id.
    Text(String),
}

/// Which era a request is being served under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Era {
    /// Stateless, per-request metadata: revision `2026-07-28` and later.
    Modern {
        /// The version the request declared.
        version: String,
    },
    /// The `initialize` handshake: `2025-11-25` and earlier.
    Legacy {
        /// The version the handshake settled on.
        version: String,
    },
}

impl Era {
    /// Whether results carry `resultType`.
    ///
    /// Introduced with the modern era. A legacy client is required to treat an
    /// absent `resultType` as `"complete"`, so sending it would be harmless —
    /// but sending a field the negotiated revision does not define is how a
    /// strict client's schema validation fails, and there is nothing to gain.
    pub(crate) fn stamps_result_type(&self) -> bool {
        matches!(self, Era::Modern { .. })
    }
}

/// One message read off the stream.
#[derive(Debug)]
pub(crate) enum Incoming {
    /// A request, which is owed exactly one response.
    Request(Request),
    /// A notification, which is owed none.
    Notification {
        /// The method.
        method: String,
        /// The parameters, or `Value::Null`.
        params: Value,
    },
    /// A response to a request we never sent.
    ///
    /// The stdio binding says a client MUST NOT write responses, and this
    /// server never sends a request for one to answer. Kept as a case rather
    /// than an error because dropping a stray message is the behavior that
    /// keeps a well-behaved client working next to a buggy one.
    Stray,
}

/// A request, with everything the dispatcher needs to answer it.
#[derive(Debug)]
pub(crate) struct Request {
    /// The id to answer under.
    pub(crate) id: RequestId,
    /// The method name.
    pub(crate) method: String,
    /// The parameters, or `Value::Null` when there were none.
    pub(crate) params: Value,
    /// The `_meta` object from the parameters, if there was one.
    pub(crate) meta: Map<String, Value>,
}

impl Request {
    /// The protocol version this request declares, if it declares one.
    pub(crate) fn declared_version(&self) -> Option<&str> {
        self.meta.get(META_PROTOCOL_VERSION).and_then(Value::as_str)
    }

    /// Whether this request carries modern per-request metadata.
    ///
    /// Both required fields, not just the version: the version alone appeared
    /// in legacy `initialize` params too, and a server that read it as modern
    /// metadata would answer a legacy handshake in the wrong era.
    pub(crate) fn is_modern(&self) -> bool {
        self.meta.contains_key(META_PROTOCOL_VERSION)
            && self.meta.contains_key(META_CLIENT_CAPABILITIES)
    }

    /// A named parameter, or `Value::Null`.
    pub(crate) fn param(&self, name: &str) -> &Value {
        self.params.get(name).unwrap_or(&Value::Null)
    }
}

/// Reads one line into a message.
///
/// Every shape that is not a request is folded into [`Incoming`] rather than
/// rejected, because the only failure a caller can act on here is "this was
/// not JSON at all" — and that one is a protocol error carrying no id, which
/// is what JSON-RPC says to send when the id could not be read.
pub(crate) fn parse(line: &str) -> Result<Incoming, Error> {
    let value: Value = serde_json::from_str(line)
        .map_err(|e| Error::new(PARSE_ERROR, format!("the line was not JSON: {e}")))?;
    let Value::Object(mut object) = value else {
        return Err(Error::new(
            INVALID_REQUEST,
            "a JSON-RPC message is an object",
        ));
    };

    let id = match object.remove("id") {
        // JSON-RPC 2.0 allows a null id; MCP forbids it, so it is not an id.
        None | Some(Value::Null) => None,
        Some(Value::Number(n)) => Some(RequestId::Number(n.as_i64().ok_or_else(|| {
            Error::new(INVALID_REQUEST, "a numeric request id must be an integer")
        })?)),
        Some(Value::String(s)) => Some(RequestId::Text(s)),
        Some(_) => {
            return Err(Error::new(
                INVALID_REQUEST,
                "a request id is a string or a number",
            ))
        }
    };

    let method = match object.remove("method") {
        Some(Value::String(method)) => Some(method),
        // A message with no method and an id is a response to something we
        // never asked.
        None => None,
        Some(_) => {
            return Err(Error::new(INVALID_REQUEST, "a method name is a string"));
        }
    };

    let params = object.remove("params").unwrap_or(Value::Null);
    let meta = match params.get("_meta") {
        Some(Value::Object(meta)) => meta.clone(),
        _ => Map::new(),
    };

    Ok(match (id, method) {
        (Some(id), Some(method)) => Incoming::Request(Request {
            id,
            method,
            params,
            meta,
        }),
        (None, Some(method)) => Incoming::Notification { method, params },
        (Some(_), None) | (None, None) => Incoming::Stray,
    })
}

/// A failure carrying the code it travels to the client as.
#[derive(Debug, Clone)]
pub(crate) struct Error {
    /// The JSON-RPC error code.
    pub(crate) code: i64,
    /// What went wrong, in the words the client shows.
    pub(crate) message: String,
    /// Structured detail, for the codes that define one.
    pub(crate) data: Option<Value>,
}

impl Error {
    /// Builds an error with no structured detail.
    pub(crate) fn new(code: i64, message: impl Into<String>) -> Error {
        Error {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Builds an [`INVALID_PARAMS`] error.
    pub(crate) fn invalid_params(message: impl Into<String>) -> Error {
        Error::new(INVALID_PARAMS, message)
    }

    /// The error a request for a version we do not implement is refused with.
    ///
    /// `data.supported` is the point of it: the client picks a version from
    /// there and retries, which is the whole of version negotiation in the
    /// modern era.
    pub(crate) fn unsupported_version(requested: &str) -> Error {
        Error {
            code: UNSUPPORTED_PROTOCOL_VERSION,
            message: "Unsupported protocol version".into(),
            data: Some(json!({
                "supported": SUPPORTED_VERSIONS,
                "requested": requested,
            })),
        }
    }

    /// Attaches structured detail.
    pub(crate) fn with_data(mut self, data: Value) -> Error {
        self.data = Some(data);
        self
    }
}

/// This server's identity, as `serverInfo`.
pub(crate) fn server_info() -> Value {
    json!({ "name": "synchronicity", "version": env!("CARGO_PKG_VERSION") })
}

/// Renders a successful response.
///
/// `resultType` and `_meta.serverInfo` are stamped here rather than by each
/// handler, so a new tool cannot forget them.
pub(crate) fn response(id: &RequestId, era: &Era, mut result: Value) -> Value {
    if let Value::Object(map) = &mut result {
        if era.stamps_result_type() {
            map.entry("resultType")
                .or_insert_with(|| Value::String("complete".into()));
        }
        match map.entry("_meta") {
            serde_json::map::Entry::Occupied(mut slot) => {
                if let Value::Object(meta) = slot.get_mut() {
                    meta.entry(META_SERVER_INFO).or_insert_with(server_info);
                }
            }
            serde_json::map::Entry::Vacant(slot) => {
                slot.insert(json!({ META_SERVER_INFO: server_info() }));
            }
        }
    }
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// Renders an error response.
pub(crate) fn error_response(id: Option<&RequestId>, error: &Error) -> Value {
    let mut body = json!({ "code": error.code, "message": error.message });
    if let (Some(data), Value::Object(map)) = (&error.data, &mut body) {
        map.insert("data".into(), data.clone());
    }
    json!({ "jsonrpc": "2.0", "id": id, "error": body })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_modern_request_needs_both_meta_fields_to_be_modern() {
        // The version alone is what a legacy `initialize` also carries, in its
        // params rather than its `_meta` — but a client that puts it in both
        // must still be read as legacy, or the handshake is answered in the
        // wrong era.
        let with_both = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":{}}}}"#;
        let Incoming::Request(request) = parse(with_both).unwrap() else {
            panic!("a request");
        };
        assert!(request.is_modern());
        assert_eq!(request.declared_version(), Some("2026-07-28"));

        let version_only = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"_meta":{
            "io.modelcontextprotocol/protocolVersion":"2025-06-18"}}}"#;
        let Incoming::Request(request) = parse(version_only).unwrap() else {
            panic!("a request");
        };
        assert!(!request.is_modern());
    }

    #[test]
    fn ids_keep_the_type_they_arrived_as() {
        for (line, expected) in [
            (
                r#"{"jsonrpc":"2.0","id":7,"method":"x"}"#,
                RequestId::Number(7),
            ),
            (
                r#"{"jsonrpc":"2.0","id":"7","method":"x"}"#,
                RequestId::Text("7".into()),
            ),
        ] {
            let Incoming::Request(request) = parse(line).unwrap() else {
                panic!("a request");
            };
            assert_eq!(request.id, expected);
            let rendered = response(
                &request.id,
                &Era::Modern {
                    version: LATEST_VERSION.into(),
                },
                json!({}),
            );
            assert_eq!(rendered["id"], serde_json::to_value(&expected).unwrap());
        }
    }

    #[test]
    fn notifications_and_stray_responses_are_told_apart() {
        assert!(matches!(
            parse(r#"{"jsonrpc":"2.0","method":"notifications/cancelled"}"#).unwrap(),
            Incoming::Notification { .. }
        ));
        assert!(matches!(
            parse(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#).unwrap(),
            Incoming::Stray
        ));
        assert_eq!(parse("not json").unwrap_err().code, PARSE_ERROR);
        assert_eq!(parse("[1,2]").unwrap_err().code, INVALID_REQUEST);
        assert!(
            matches!(
                parse(r#"{"jsonrpc":"2.0","id":null,"method":"x"}"#).unwrap(),
                Incoming::Notification { .. }
            ),
            "MCP forbids a null id, so it is not an id"
        );
    }

    #[test]
    fn results_are_stamped_by_era() {
        let modern = response(
            &RequestId::Number(1),
            &Era::Modern {
                version: LATEST_VERSION.into(),
            },
            json!({ "tools": [] }),
        );
        assert_eq!(modern["result"]["resultType"], "complete");
        assert_eq!(
            modern["result"]["_meta"][META_SERVER_INFO]["name"],
            "synchronicity"
        );

        let legacy = response(
            &RequestId::Number(1),
            &Era::Legacy {
                version: "2025-06-18".into(),
            },
            json!({ "tools": [] }),
        );
        assert!(
            legacy["result"].get("resultType").is_none(),
            "a revision that does not define the field must not be sent it"
        );
    }

    #[test]
    fn every_supported_version_sorts_the_way_the_era_test_reads_it() {
        // The era split is a string compare against FIRST_MODERN_VERSION, which
        // is only correct while every version is a zero-padded YYYY-MM-DD.
        for version in SUPPORTED_VERSIONS {
            assert_eq!(version.len(), 10, "{version}");
            assert!(
                version.bytes().enumerate().all(|(i, b)| match i {
                    4 | 7 => b == b'-',
                    _ => b.is_ascii_digit(),
                }),
                "{version}"
            );
        }
        assert!(SUPPORTED_VERSIONS.contains(&FIRST_MODERN_VERSION));
        assert_eq!(LATEST_VERSION, FIRST_MODERN_VERSION);
    }
}
