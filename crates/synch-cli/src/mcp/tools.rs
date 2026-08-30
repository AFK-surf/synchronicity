//! The tool surface: what a model may ask this node to do, and how.
//!
//! Every tool is a translation of a call the control service already answers.
//! Where a typed RPC exists — `List`, `Resolve`, `Read`, `Put`, `Delete`,
//! `ListSpaces` — the tool returns `structuredContent` against a declared
//! `outputSchema`. Where only the rendered CLI surface exists, the tool runs
//! `Run(Command)` and returns the daemon's own lines, so no renderer is
//! reimplemented here and no output drifts from what `synch` prints.
//!
//! # Tiers
//!
//! The surface is split by whether a tool changes state, not by how alarming
//! it sounds. [`Tier::Read`] observes; [`Tier::Write`] mutates, and is served
//! only under `--allow-write`. The tool *list* reflects the tier, so a client
//! is shown exactly the authority it was given rather than discovering the
//! boundary by being refused at it.
//!
//! Two placements are worth stating because they are not obvious:
//!
//! - **The socket lifecycle is on the surface.** `socket add`, `arm`, `disarm`,
//!   `rm` and `kill` are writes and sit in the write tier. Arming is not a
//!   blind approval of bytes: the program declares its external effects in a
//!   `synchronicity.init` section, the review step prints that declaration, and
//!   the approval token binds the content root, the authorization revision and
//!   the init result together (`docs/SOCKETS.md` §3.1). Capabilities that were
//!   not declared are denied, and editing the program changes its root, which
//!   disarms it. That is a policy boundary, so it is exposed like any other
//!   write rather than withheld.
//!
//! - **Connecting is a read.** `synch_connect` sits in the read tier because
//!   the connecting side executes nothing (`docs/SOCKETS.md` §1): it names a
//!   path and pipes bytes. What the program does is bounded by the declaration
//!   the *serving* node armed, which is that node's decision and not this
//!   process's to re-take.

use std::time::Duration;

use base64::Engine as _;
use serde_json::{json, Map, Value};
use synch_core::EntryKind;
use synch_engine::EntryRef;

use crate::{
    control::{
        proto::{pb, CHUNK_SIZE},
        Command as Cmd, ControlError, EntryInfo, ErrorCode, Frame,
    },
    mcp::{rpc, session::Session, Options, Reporter},
};

/// How much rendered text one tool result may carry.
///
/// Independent of `--max-read-bytes`, which bounds a payload the caller asked
/// for by size and offset. This bounds output whose size the caller cannot
/// predict — a listing, a doctor report, a socket log — and a result that hits
/// it says so rather than ending mid-sentence.
const MAX_RENDERED_BYTES: usize = 1024 * 1024;

/// The default ceiling on one `synch_connect` invocation.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest a `synch_connect` invocation may be given.
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(300);

/// The default page size of a listing.
const DEFAULT_PAGE: u64 = 200;

/// The largest page a listing will return.
const MAX_PAGE: u64 = 1000;

/// The most C source one `synch_socket_build` may carry.
///
/// A socket program is a page or two of C; this is orders of magnitude above
/// anything that compiles into one. The line ceiling alone would let a request
/// carry megabytes into a compiler that holds a process-wide lock while it
/// runs, and the compile is not something a caller can be given back partway.
const MAX_SOURCE_BYTES: usize = 256 * 1024;

/// Which authority a tool needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tier {
    /// Observes; always served.
    Read,
    /// Changes state; served only under `--allow-write`.
    Write,
}

/// Everything a tool call runs against.
#[derive(Debug)]
pub(crate) struct Context {
    /// The control connection.
    pub(crate) session: Session,
    /// The authority and bounds this process was given.
    pub(crate) options: Options,
}

impl Context {
    /// Refuses a space the `--space` filter does not name.
    ///
    /// The check runs before the request reaches the daemon, and the message
    /// names the spaces that *are* in scope: a model that guessed wrong can
    /// correct itself, and one that was never told about a space learns only
    /// that it is out of scope.
    fn scope(&self, space: &str) -> Result<(), ToolError> {
        if self.options.spaces.is_empty() || self.options.spaces.iter().any(|s| s == space) {
            return Ok(());
        }
        Err(ToolError::execution(format!(
            "space {space:?} is out of scope for this server; it was started with \
             --space {}",
            self.options.spaces.join(" --space ")
        )))
    }

    /// The space to send for a request that named none.
    ///
    /// An omitted space means *every* space to the daemon, which is the one
    /// thing `--space` exists to prevent: the filter it builds is `None`, and
    /// the answer covers the whole node. So an unconfined server keeps the
    /// wildcard, a server confined to exactly one space fills it in, and one
    /// confined to several asks which — the daemon's filter names a single
    /// space, and there is no way to say "these three" that does not also say
    /// "and the rest".
    fn scoped_default(&self) -> Result<String, ToolError> {
        match self.options.spaces.as_slice() {
            [] => Ok(String::new()),
            [only] => Ok(only.clone()),
            several => Err(ToolError::execution(format!(
                "this server is confined to more than one space, and a request \
                 naming none would reach every space on the node; name one of: {}",
                several.join(", ")
            ))),
        }
    }

    /// Refuses an operation that has no space to be confined to.
    ///
    /// Some commands take no space at all and act on everything the node
    /// holds. There is nothing to narrow, so under `--space` the only honest
    /// answers are to refuse or to act outside the confinement, and a
    /// confinement that the write tools step around is not one.
    fn whole_node(&self, what: &str) -> Result<(), ToolError> {
        if self.options.spaces.is_empty() {
            return Ok(());
        }
        Err(ToolError::execution(format!(
            "{what} acts on every space this node holds and cannot be narrowed \
             to one, so it is refused by a server started with --space {}",
            self.options.spaces.join(" --space ")
        )))
    }

    /// Whether a space may be served at all, for filtering listings.
    pub(crate) fn in_scope(&self, space: &str) -> bool {
        self.options.spaces.is_empty() || self.options.spaces.iter().any(|s| s == space)
    }

    /// The tools this process serves, in a stable order.
    pub(crate) fn catalog(&self) -> Vec<&'static Tool> {
        catalog()
            .iter()
            .filter(|tool| self.options.allow_write || tool.tier == Tier::Read)
            .collect()
    }
}

/// Why a tool call did not produce a result.
#[derive(Debug)]
pub(crate) enum ToolError {
    /// A problem with the request itself: no such tool. Travels as a JSON-RPC
    /// error, which the spec reserves for what a model is unlikely to fix.
    Protocol(rpc::Error),
    /// Something a model can act on: a bad argument, a daemon that is not
    /// running, a path with several versions. Travels as `isError: true`,
    /// which the spec reserves for exactly that.
    Execution {
        /// What went wrong, in words a model can read.
        message: String,
        /// Structured detail, when there is any.
        data: Option<Value>,
    },
}

impl ToolError {
    /// Builds an execution error with no structured detail.
    pub(crate) fn execution(message: impl Into<String>) -> ToolError {
        ToolError::Execution {
            message: message.into(),
            data: None,
        }
    }
}

impl From<ControlError> for ToolError {
    /// Turns a daemon failure into something a model can act on.
    ///
    /// Every code becomes an execution error rather than a protocol one,
    /// because every one of them describes the world rather than the request's
    /// shape — and two of them carry a next step worth spelling out, since the
    /// daemon's own message assumes a reader who can see a terminal.
    fn from(e: ControlError) -> ToolError {
        let hint = match e.code {
            ErrorCode::Divergent => Some(
                " — several origins publish this path. Name one with \
                 policy=\"origin=<id>\" to read a specific version, or use \
                 synch_versions to see them all.",
            ),
            ErrorCode::Unavailable => Some(
                " — the tools that need the daemon will keep failing until it \
                 is running.",
            ),
            ErrorCode::NotInitialized => Some(
                " — this data directory has no identity yet; `synch init` \
                 creates one.",
            ),
            _ => None,
        };
        ToolError::Execution {
            message: format!("{}{}", e.message, hint.unwrap_or_default()),
            data: Some(json!({ "code": e.code.as_str() })),
        }
    }
}

/// What a tool produced.
#[derive(Debug)]
pub(crate) struct Outcome {
    /// The content blocks, in the order the client shows them.
    pub(crate) content: Vec<Value>,
    /// The structured result, for tools that declare an output schema.
    pub(crate) structured: Option<Value>,
}

impl Outcome {
    /// A result that is one block of text.
    fn text(body: impl Into<String>) -> Outcome {
        Outcome {
            content: vec![json!({ "type": "text", "text": body.into() })],
            structured: None,
        }
    }

    /// A result that is text plus a structured body.
    ///
    /// The serialized structure goes in the text block too, which the spec
    /// recommends for clients that do not read `structuredContent`.
    fn structured(structured: Value) -> Outcome {
        Outcome {
            content: vec![json!({
                "type": "text",
                "text": serde_json::to_string_pretty(&structured)
                    .unwrap_or_else(|_| structured.to_string()),
            })],
            structured: Some(structured),
        }
    }

    /// A result whose text a human reads and whose structure a model reads.
    fn both(text: impl Into<String>, structured: Value) -> Outcome {
        Outcome {
            content: vec![json!({ "type": "text", "text": text.into() })],
            structured: Some(structured),
        }
    }
}

/// One tool, as `tools/list` renders it.
#[derive(Debug)]
pub(crate) struct Tool {
    /// The name a call names.
    pub(crate) name: &'static str,
    /// The display name.
    pub(crate) title: &'static str,
    /// What it does, written for the model that has to choose it.
    pub(crate) description: String,
    /// Which authority it needs.
    pub(crate) tier: Tier,
    /// The JSON Schema of its arguments.
    pub(crate) input: Value,
    /// The JSON Schema of its structured result, when it has one.
    pub(crate) output: Option<Value>,
}

impl Tool {
    /// Renders this tool as the protocol carries it.
    pub(crate) fn to_json(&self) -> Value {
        let mut value = json!({
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input,
            "annotations": {
                "title": self.title,
                "readOnlyHint": self.tier == Tier::Read,
                // Nothing here destroys data without saying so: a delete
                // publishes a tombstone, which the version model can outlive.
                // The one tool that can overwrite a local file is synch_adopt_tree
                // with force, and it declares itself below.
                "destructiveHint": false,
                "openWorldHint": true,
            },
        });
        if let (Some(output), Value::Object(map)) = (&self.output, &mut value) {
            map.insert("outputSchema".into(), output.clone());
        }
        value
    }
}

// ---- argument helpers ------------------------------------------------------

/// A required string argument.
fn need_str<'a>(args: &'a Value, name: &str) -> Result<&'a str, ToolError> {
    match args.get(name) {
        Some(Value::String(text)) if !text.is_empty() => Ok(text),
        Some(Value::String(_)) => Err(ToolError::execution(format!("{name} must not be empty"))),
        Some(_) => Err(ToolError::execution(format!("{name} must be a string"))),
        None => Err(ToolError::execution(format!("{name} is required"))),
    }
}

/// An optional string argument. An empty string counts as absent, because
/// that is what a model that "left it blank" produces.
fn opt_str<'a>(args: &'a Value, name: &str) -> Result<Option<&'a str>, ToolError> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.is_empty() => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(ToolError::execution(format!("{name} must be a string"))),
    }
}

/// An optional unsigned argument.
fn opt_u64(args: &Value, name: &str) -> Result<Option<u64>, ToolError> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| {
                ToolError::execution(format!("{name} must be a whole number, not negative"))
            })
            .map(Some),
        Some(_) => Err(ToolError::execution(format!("{name} must be a number"))),
    }
}

/// An optional boolean argument, defaulting to `false`.
fn opt_bool(args: &Value, name: &str) -> Result<bool, ToolError> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(ToolError::execution(format!(
            "{name} must be true or false"
        ))),
    }
}

/// A path argument, which may legitimately be empty at a space root.
fn opt_path<'a>(args: &'a Value, name: &str) -> Result<&'a str, ToolError> {
    Ok(opt_str(args, name)?.unwrap_or(""))
}

/// The `policy` argument, validated here so a typo is refused with the three
/// forms spelled out rather than by the daemon mid-listing.
fn opt_policy(args: &Value) -> Result<Option<String>, ToolError> {
    let Some(policy) = opt_str(args, "policy")? else {
        return Ok(None);
    };
    let ok = policy == "newest" || policy == "strict" || policy.starts_with("origin=");
    if !ok {
        return Err(ToolError::execution(format!(
            "{policy:?} is not a version policy: use \"newest\", \"strict\", or \
             \"origin=<id>\""
        )));
    }
    Ok(Some(policy.to_string()))
}

/// Builds a `<space>/<path>` reference the rendered commands take, going
/// through `EntryRef` so the text is canonical and the path is normalized.
fn reference(space: &str, path: &str, origin: Option<&str>) -> Result<String, ToolError> {
    let text = match (origin, path.is_empty()) {
        (Some(origin), true) => format!("{origin}:{space}"),
        (Some(origin), false) => format!("{origin}:{space}/{path}"),
        (None, true) => space.to_string(),
        (None, false) => format!("{space}/{path}"),
    };
    text.parse::<EntryRef>()
        .map(|reference| reference.render())
        .map_err(|e| ToolError::execution(e.to_string()))
}

/// The payload of a tool that takes either text or base64 bytes.
fn payload(args: &Value) -> Result<Vec<u8>, ToolError> {
    match (opt_str(args, "text")?, opt_str(args, "base64")?) {
        (Some(_), Some(_)) => Err(ToolError::execution(
            "give text or base64, not both — they are two spellings of one payload",
        )),
        (Some(text), None) => Ok(text.as_bytes().to_vec()),
        (None, Some(encoded)) => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| ToolError::execution(format!("base64 did not decode: {e}"))),
        (None, None) => Ok(Vec::new()),
    }
}

// ---- the catalogue ---------------------------------------------------------

/// The schema fragment for a version policy.
fn policy_schema() -> Value {
    json!({
        "type": "string",
        "description": "Which version to select where origins disagree: \
                        \"newest\" (default), \"origin=<id>\" to pin one \
                        origin, or \"strict\" to refuse a divergent path.",
    })
}

/// The schema of one entry of the unified tree.
fn entry_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "origin": { "type": "string", "description": "The origin whose version was selected." },
            "space": { "type": "string" },
            "path": { "type": "string" },
            "kind": {
                "type": "string",
                "enum": ["file", "dir", "symlink", "tombstone", "socket"],
            },
            "size": { "type": "integer", "description": "Content length in bytes." },
            "mtime_ns": { "type": "integer", "description": "Observed mtime, unix nanoseconds." },
            "content_root": {
                "type": ["string", "null"],
                "description": "The BLAKE3 object root, hex, for files.",
            },
            "symlink_target": { "type": ["string", "null"] },
            "versions": {
                "type": "integer",
                "description": "How many distinct versions the path carries. \
                                More than one means origins disagree and the \
                                policy chose a side.",
            },
        },
        "required": ["origin", "space", "path", "kind", "size", "mtime_ns", "versions"],
    })
}

/// Every tool this build knows, in a stable order.
///
/// Order is deterministic because `tools/list` is cached by clients and
/// included in model context: a list that reshuffles between calls costs a
/// prompt-cache hit for nothing.
///
/// Built once. The schemas are a few hundred JSON values and nothing about
/// them varies per call — the tier filter is applied to this by
/// [`Context::catalog`], and the flags behind it are fixed at startup.
fn catalog() -> &'static [Tool] {
    static CATALOG: std::sync::OnceLock<Vec<Tool>> = std::sync::OnceLock::new();
    CATALOG.get_or_init(build_catalog)
}

/// The catalogue itself, called once through [`catalog`].
fn build_catalog() -> Vec<Tool> {
    let no_args = json!({ "type": "object", "additionalProperties": false });
    vec![
        Tool {
            name: "synch_node",
            title: "Node identity and status",
            description: "This node's origin, device keys, membership domain, and the \
                          running daemon's current state. Start here when you do not \
                          know what node you are talking to."
                .into(),
            tier: Tier::Read,
            input: no_args.clone(),
            output: None,
        },
        Tool {
            name: "synch_spaces",
            title: "List spaces",
            description: "Every known namespace and this node's independent source and \
                          replica roles for it."
                .into(),
            tier: Tier::Read,
            input: no_args.clone(),
            output: Some(json!({
                "type": "object",
                "properties": {
                    "spaces": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": { "type": "string" },
                                "source_path": { "type": ["string", "null"] },
                                "source_kind": { "type": ["string", "null"], "enum": ["filesystem", "api", null] },
                                "retention": { "type": ["string", "null"], "enum": ["current", "forever", null] },
                                "grace_secs": { "type": "integer" },
                                "budget": { "type": ["integer", "null"] },
                                "held_bytes": { "type": ["integer", "null"] },
                                "wanted": { "type": ["integer", "null"] },
                                "checkout_path": { "type": ["string", "null"] },
                            },
                            "required": ["id", "grace_secs"],
                        },
                    },
                },
                "required": ["spaces"],
            })),
        },
        Tool {
            name: "synch_list",
            title: "List paths",
            description: "The unified tree under a prefix: one entry per path, with the \
                          version the policy selects. Paginated — pass the returned \
                          next_cursor to continue."
                .into(),
            tier: Tier::Read,
            input: json!({
                "type": "object",
                "properties": {
                    "space": { "type": "string", "description": "The space to list in." },
                    "prefix": { "type": "string", "description": "Path prefix, or omit for the whole space." },
                    "cursor": { "type": "string", "description": "next_cursor from a previous call." },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_PAGE,
                        "description": "Paths per page, default 200.",
                    },
                    "policy": policy_schema(),
                },
                "required": ["space"],
                "additionalProperties": false,
            }),
            output: Some(json!({
                "type": "object",
                "properties": {
                    "entries": { "type": "array", "items": entry_schema() },
                    "next_cursor": {
                        "type": ["string", "null"],
                        "description": "Pass back as cursor for the next page; null at the end.",
                    },
                },
                "required": ["entries"],
            })),
        },
        Tool {
            name: "synch_stat",
            title: "Describe one path",
            description: "The version a policy selects for one path — origin, size, \
                          content root, and how many versions exist — with no content \
                          fetched."
                .into(),
            tier: Tier::Read,
            input: json!({
                "type": "object",
                "properties": {
                    "space": { "type": "string" },
                    "path": { "type": "string" },
                    "policy": policy_schema(),
                },
                "required": ["space", "path"],
                "additionalProperties": false,
            }),
            output: Some(entry_schema()),
        },
        Tool {
            name: "synch_read",
            title: "Read a file",
            description: "A verified byte range of the version a policy selects. Reads \
                          are windowed: pass offset and length to walk an object larger \
                          than one result can carry. Text comes back as text; anything \
                          that is not valid UTF-8 comes back base64-encoded in an \
                          embedded resource."
                .into(),
            tier: Tier::Read,
            input: json!({
                "type": "object",
                "properties": {
                    "space": { "type": "string" },
                    "path": { "type": "string" },
                    "offset": { "type": "integer", "minimum": 0, "description": "First byte to read, default 0." },
                    "length": { "type": "integer", "minimum": 1, "description": "Bytes to read, capped by the server's --max-read-bytes." },
                    "policy": policy_schema(),
                },
                "required": ["space", "path"],
                "additionalProperties": false,
            }),
            output: Some(json!({
                "type": "object",
                "properties": {
                    "space": { "type": "string" },
                    "path": { "type": "string" },
                    "origin": { "type": "string" },
                    "size": { "type": "integer", "description": "The whole object's size." },
                    "offset": { "type": "integer" },
                    "length": { "type": "integer", "description": "Bytes this result carries." },
                    "eof": { "type": "boolean", "description": "Whether this result reaches the end of the object." },
                    "encoding": { "type": "string", "enum": ["text", "base64"] },
                    "versions": { "type": "integer" },
                    "content_root": { "type": ["string", "null"] },
                },
                "required": ["space", "path", "origin", "size", "offset", "length", "eof", "encoding"],
            })),
        },
        Tool {
            name: "synch_versions",
            title: "Compare versions of a path",
            description: "Every version of a path side by side, with the origins \
                          attesting each. This is what to call when a read reports a \
                          divergent path."
                .into(),
            tier: Tier::Read,
            input: json!({
                "type": "object",
                "properties": {
                    "space": { "type": "string" },
                    "path": { "type": "string", "description": "Omit for a summary of the whole space." },
                },
                "required": ["space"],
                "additionalProperties": false,
            }),
            output: None,
        },
        Tool {
            name: "synch_history",
            title: "Publish history",
            description: "The per-origin publish history for one path: every root that \
                          origin has published for it, newest first."
                .into(),
            tier: Tier::Read,
            input: json!({
                "type": "object",
                "properties": {
                    "space": { "type": "string" },
                    "path": { "type": "string" },
                    "origin": { "type": "string", "description": "Restrict to one origin's history." },
                },
                "required": ["space", "path"],
                "additionalProperties": false,
            }),
            output: None,
        },
        Tool {
            name: "synch_compare",
            title: "Compare two origins' trees",
            description: "Which files differ between two origins' published trees, as \
                          created/modified/deleted. Name-status only — no content is \
                          fetched."
                .into(),
            tier: Tier::Read,
            input: json!({
                "type": "object",
                "properties": {
                    "space": { "type": "string" },
                    "dir": { "type": "string", "description": "A directory within the space, or omit for all of it." },
                    "to": { "type": "string", "description": "The origin to compare against." },
                    "from": { "type": "string", "description": "The baseline origin; defaults to this node." },
                },
                "required": ["space", "to"],
                "additionalProperties": false,
            }),
            output: Some(json!({
                "type": "object",
                "description": "The comparison, as the daemon renders it with --json.",
            })),
        },
        Tool {
            name: "synch_peers",
            title: "List peers",
            description: "Live peers: addresses, when each last synced, and how far \
                          behind this node believes they are."
                .into(),
            tier: Tier::Read,
            input: no_args.clone(),
            output: None,
        },
        Tool {
            name: "synch_doctor",
            title: "Health report",
            description: "Connectivity, membership, equivocation and garbage-collection \
                          report. The first thing to run when something is not \
                          converging."
                .into(),
            tier: Tier::Read,
            input: no_args.clone(),
            output: None,
        },
        Tool {
            name: "synch_socket_list",
            title: "List sockets",
            description: "Every socket this node has declared: whether it is armed, what \
                          the armed program declared, and its stream cap. A socket is a \
                          path whose content is an eBPF program this node runs for peers \
                          that connect to it."
                .into(),
            tier: Tier::Read,
            input: json!({
                "type": "object",
                "properties": {
                    "space": { "type": "string", "description": "Only this space." },
                    "long": { "type": "boolean", "description": "Include the armed root, declaration and policy." },
                },
                "additionalProperties": false,
            }),
            output: None,
        },
        Tool {
            name: "synch_socket_ps",
            title: "Running invocations",
            description: "The socket invocations running right now, with the id \
                          synch_socket_kill takes."
                .into(),
            tier: Tier::Read,
            input: json!({
                "type": "object",
                "properties": {
                    "space": { "type": "string" },
                    "path": { "type": "string" },
                },
                "additionalProperties": false,
            }),
            output: None,
        },
        Tool {
            name: "synch_socket_log",
            title: "Socket log",
            description: "What a socket's programs have written with sy_log.".into(),
            tier: Tier::Read,
            input: json!({
                "type": "object",
                "properties": {
                    "space": { "type": "string" },
                    "path": { "type": "string" },
                },
                "required": ["space", "path"],
                "additionalProperties": false,
            }),
            output: None,
        },
        Tool {
            name: "synch_socket_sdk",
            title: "Socket SDK header",
            description: "The C header a socket program is compiled against: the whole \
                          host API, with no libc. Read this before writing a program for \
                          synch_socket_build."
                .into(),
            tier: Tier::Read,
            input: no_args.clone(),
            output: None,
        },
        Tool {
            name: "synch_socket_build",
            title: "Compile a socket program",
            description: "Compiles C source to the eBPF object a socket is made of, and \
                          returns it base64-encoded. Nothing is written or published: \
                          write the bytes into a space with synch_write, then declare \
                          and arm the path. synch.h is included automatically."
                .into(),
            tier: Tier::Read,
            input: json!({
                "type": "object",
                "properties": {
                    "source": { "type": "string", "description": "The C source text." },
                    "name": { "type": "string", "description": "The name diagnostics use, default \"socket.c\"." },
                    "defines": {
                        "type": "object",
                        "description": "Preprocessor defines, as a name-to-value map. A \
                                        socket's declarations are compiled in, so a value \
                                        here is part of what gets approved at arm time.",
                        "additionalProperties": { "type": "string" },
                    },
                },
                "required": ["source"],
                "additionalProperties": false,
            }),
            output: Some(json!({
                "type": "object",
                "properties": {
                    "object_base64": { "type": "string" },
                    "size": { "type": "integer" },
                },
                "required": ["object_base64", "size"],
            })),
        },
        Tool {
            name: "synch_socket_review",
            title: "Review a socket program",
            description: "Prints what a declared socket's current program declares — its \
                          name, egress destinations and stream cap — and the \
                          review token that approves exactly it. Approving is a separate \
                          call, synch_socket_arm, and the token binds the content root, \
                          the authorization revision, and this init result together."
                .into(),
            tier: Tier::Read,
            input: json!({
                "type": "object",
                "properties": {
                    "space": { "type": "string" },
                    "path": { "type": "string" },
                },
                "required": ["space", "path"],
                "additionalProperties": false,
            }),
            output: None,
        },
        Tool {
            name: "synch_connect",
            title: "Call a socket",
            description: "Opens one invocation of a socket on any node, sends the input, \
                          and returns everything the program wrote before it closed. The \
                          connecting side executes nothing: what runs is state the named \
                          node already holds and armed."
                .into(),
            tier: Tier::Read,
            input: json!({
                "type": "object",
                "properties": {
                    "origin": { "type": "string", "description": "The node serving the socket. Required — a socket is served by whoever published it." },
                    "space": { "type": "string" },
                    "path": { "type": "string" },
                    "text": { "type": "string", "description": "Input to send, as text." },
                    "base64": { "type": "string", "description": "Input to send, as base64 bytes." },
                    "meta": {
                        "type": "object",
                        "description": "Metadata the program can read with sy_conn_meta. Untrusted by the program, which is told so.",
                        "additionalProperties": { "type": "string" },
                    },
                    "timeout_ms": { "type": "integer", "minimum": 1, "description": "Give up after this long, default 30000, maximum 300000." },
                },
                "required": ["origin", "space", "path"],
                "additionalProperties": false,
            }),
            output: Some(json!({
                "type": "object",
                "properties": {
                    "exit_code": { "type": "integer" },
                    "status": { "type": "string" },
                    "encoding": { "type": "string", "enum": ["text", "base64"] },
                    "output": { "type": "string" },
                    "bytes": { "type": "integer" },
                    "truncated": { "type": "boolean" },
                    "timed_out": { "type": "boolean" },
                },
                "required": ["exit_code", "status", "encoding", "output", "bytes", "truncated", "timed_out"],
            })),
        },
        // ---- write tier ----------------------------------------------------
        Tool {
            name: "synch_write",
            title: "Write a file",
            description: "Writes a file into one of this node's own spaces and publishes \
                          it as this node's version. Replaces whatever this node \
                          previously published at that path."
                .into(),
            tier: Tier::Write,
            input: json!({
                "type": "object",
                "properties": {
                    "space": { "type": "string" },
                    "path": { "type": "string" },
                    "text": { "type": "string", "description": "The content, as text." },
                    "base64": { "type": "string", "description": "The content, as base64 bytes." },
                },
                "required": ["space", "path"],
                "additionalProperties": false,
            }),
            output: Some(entry_schema()),
        },
        Tool {
            name: "synch_delete",
            title: "Delete a file",
            description: "Removes this node's copy of a path and publishes a tombstone. \
                          Other origins may still publish the path, and the result says \
                          whether they do."
                .into(),
            tier: Tier::Write,
            input: json!({
                "type": "object",
                "properties": {
                    "space": { "type": "string" },
                    "path": { "type": "string" },
                },
                "required": ["space", "path"],
                "additionalProperties": false,
            }),
            output: Some(json!({
                "type": "object",
                "properties": {
                    "space": { "type": "string" },
                    "path": { "type": "string" },
                    "still_published": {
                        "type": "boolean",
                        "description": "Whether some other origin still publishes this path.",
                    },
                },
                "required": ["space", "path", "still_published"],
            })),
        },
        Tool {
            name: "synch_adopt_path",
            title: "Adopt a peer's version",
            description: "Adopts another origin's version of a path as this node's own, \
                          publishing it under this node's name."
                .into(),
            tier: Tier::Write,
            input: json!({
                "type": "object",
                "properties": {
                    "select": { "type": "string", "description": "newest, strict, or origin=<origin-id>." },
                    "space": { "type": "string" },
                    "path": { "type": "string" },
                },
                "required": ["space", "path"],
                "additionalProperties": false,
            }),
            output: None,
        },
        Tool {
            name: "synch_adopt_tree",
            title: "Fill a space directory",
            description: "Writes the unified tree's content into a space's own local \
                          directory. Additive: a missing path is written, a matching one \
                          left alone, a differing one reported. Defaults to a dry run — \
                          pass dry_run false to actually write."
                .into(),
            tier: Tier::Write,
            input: json!({
                "type": "object",
                "properties": {
                    "space": { "type": "string" },
                    "dir": { "type": "string", "description": "A directory within the space, or omit for all of it." },
                    "select": { "type": "string", "description": "newest, strict, or origin=<origin-id>." },
                    "replace": { "type": "boolean", "description": "Replace local files whose content differs. This overwrites bytes on disk." },
                    "dry_run": { "type": "boolean", "description": "Decide everything and write nothing. Defaults to true here." },
                },
                "required": ["space"],
                "additionalProperties": false,
            }),
            output: None,
        },
        Tool {
            name: "synch_pin",
            title: "Pin or unpin content",
            description: "Keeps content in the local store regardless of policy, or stops \
                          keeping it. Names either a hex object root or a path whose \
                          selected version's root is pinned."
                .into(),
            tier: Tier::Write,
            input: json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["add", "rm"] },
                    "space": { "type": "string", "description": "With path, names the version to pin." },
                    "path": { "type": "string" },
                    "root": { "type": "string", "description": "A hex object root, instead of space and path." },
                    "select": { "type": "string", "description": "For a path: newest, strict, or origin=<origin-id>." },
                },
                "required": ["action"],
                "additionalProperties": false,
            }),
            output: None,
        },
        Tool {
            name: "synch_source_scan",
            title: "Scan and publish",
            description: "Scans every configured space and publishes the result. Run this \
                          after changing files on disk outside of synch_write."
                .into(),
            tier: Tier::Write,
            input: no_args.clone(),
            output: None,
        },
        Tool {
            name: "synch_sync",
            title: "Sync with peers now",
            description: "Runs one anti-entropy exchange with every dialable peer, now, \
                          rather than waiting for the next interval."
                .into(),
            tier: Tier::Write,
            input: no_args.clone(),
            output: None,
        },
        Tool {
            name: "synch_socket_add",
            title: "Declare a socket",
            description: "Declares that a path in one of this node's spaces is a socket, \
                          so the scanner publishes it as one. Declaring is not arming: \
                          the program does not run until synch_socket_arm approves a \
                          reviewed declaration."
                .into(),
            tier: Tier::Write,
            input: json!({
                "type": "object",
                "properties": {
                    "space": { "type": "string" },
                    "path": { "type": "string" },
                    "config": {
                        "type": "object",
                        "description": "Configuration the program reads with sy_config_get.",
                        "additionalProperties": { "type": "string" },
                    },
                    "max_streams": { "type": "integer", "minimum": 1, "description": "A concurrency cap for this socket." },
                    "auto": {
                        "type": "boolean",
                        "description": "Re-arm on every content change, skipping review forever. \
                                        Correct only for a path you are the only writer of — \
                                        wrong for any path a fill, a take, or an S3 key can reach.",
                    },
                    "note": { "type": "string" },
                },
                "required": ["space", "path"],
                "additionalProperties": false,
            }),
            output: None,
        },
        Tool {
            name: "synch_socket_arm",
            title: "Arm a socket",
            description: "Approves the reviewed declaration a review token names, so this \
                          node will run the program for peers that connect. Call \
                          synch_socket_review first: the token binds the content root, \
                          the authorization revision, and the init result, and approval \
                          fails if any of them has changed since."
                .into(),
            tier: Tier::Write,
            input: json!({
                "type": "object",
                "properties": {
                    "space": { "type": "string" },
                    "path": { "type": "string" },
                    "review_token": { "type": "string", "description": "The token synch_socket_review printed." },
                },
                "required": ["space", "path", "review_token"],
                "additionalProperties": false,
            }),
            output: None,
        },
        Tool {
            name: "synch_socket_disarm",
            title: "Disarm a socket",
            description: "Withdraws an approval, leaving the socket declared and \
                          published but not runnable."
                .into(),
            tier: Tier::Write,
            input: json!({
                "type": "object",
                "properties": {
                    "space": { "type": "string" },
                    "path": { "type": "string" },
                },
                "required": ["space", "path"],
                "additionalProperties": false,
            }),
            output: None,
        },
        Tool {
            name: "synch_socket_remove",
            title: "Undeclare a socket",
            description: "Undeclares a path; the next scan republishes it as an ordinary \
                          file."
                .into(),
            tier: Tier::Write,
            input: json!({
                "type": "object",
                "properties": {
                    "space": { "type": "string" },
                    "path": { "type": "string" },
                },
                "required": ["space", "path"],
                "additionalProperties": false,
            }),
            output: None,
        },
        Tool {
            name: "synch_socket_kill",
            title: "End an invocation",
            description: "Ends one running invocation. The caller's stream closes as \
                          killed; what the program already wrote still reaches them."
                .into(),
            tier: Tier::Write,
            input: json!({
                "type": "object",
                "properties": {
                    "invocation": { "type": "integer", "minimum": 0, "description": "The id synch_socket_ps printed." },
                },
                "required": ["invocation"],
                "additionalProperties": false,
            }),
            output: None,
        },
    ]
}

// ---- dispatch --------------------------------------------------------------

/// Runs one tool call.
pub(crate) async fn call(
    ctx: &Context,
    name: &str,
    args: &Value,
    reporter: &Reporter,
) -> Result<Outcome, ToolError> {
    let Some(tool) = catalog().iter().find(|tool| tool.name == name) else {
        return Err(ToolError::Protocol(rpc::Error::new(
            rpc::INVALID_PARAMS,
            format!("Unknown tool: {name}"),
        )));
    };
    if tool.tier == Tier::Write && !ctx.options.allow_write {
        // Not a protocol error: the tool exists, and saying so plainly is what
        // lets a model report the actual remedy instead of guessing at a typo.
        return Err(ToolError::execution(format!(
            "{name} changes state, and this server was started read-only. \
             Restart it with --allow-write to serve it."
        )));
    }

    match name {
        "synch_node" => node(ctx, reporter).await,
        "synch_spaces" => spaces(ctx).await,
        "synch_list" => list(ctx, args).await,
        "synch_stat" => stat(ctx, args).await,
        "synch_read" => read(ctx, args).await,
        "synch_versions" => versions(ctx, args, reporter).await,
        "synch_history" => history(ctx, args, reporter).await,
        "synch_compare" => compare(ctx, args, reporter).await,
        "synch_peers" => rendered(ctx, Cmd::Peers(pb::Peers {}), reporter).await,
        "synch_doctor" => rendered(ctx, Cmd::Doctor(pb::Doctor {}), reporter).await,
        "synch_socket_list" => socket_list(ctx, args, reporter).await,
        "synch_socket_ps" => socket_ps(ctx, args, reporter).await,
        "synch_socket_log" => socket_log(ctx, args, reporter).await,
        "synch_socket_sdk" => rendered(ctx, Cmd::SocketSdk(pb::SocketSdk {}), reporter).await,
        "synch_socket_build" => socket_build(args).await,
        "synch_socket_review" => socket_arm(ctx, args, reporter, None).await,
        "synch_connect" => connect(ctx, args).await,

        "synch_write" => write(ctx, args).await,
        "synch_delete" => delete(ctx, args).await,
        "synch_adopt_path" => take(ctx, args, reporter).await,
        "synch_adopt_tree" => fill(ctx, args, reporter).await,
        "synch_pin" => pin(ctx, args, reporter).await,
        "synch_source_scan" => {
            ctx.whole_node("synch_source_scan")?;
            rendered(
                ctx,
                Cmd::SourceScan(pb::SourceScan {
                    space: String::new(),
                }),
                reporter,
            )
            .await
        }
        "synch_sync" => {
            ctx.whole_node("synch_sync")?;
            rendered(ctx, Cmd::SyncNow(pb::SyncNow {}), reporter).await
        }
        "synch_socket_add" => socket_add(ctx, args, reporter).await,
        "synch_socket_arm" => {
            let token = need_str(args, "review_token")?.to_string();
            socket_arm(ctx, args, reporter, Some(token)).await
        }
        "synch_socket_disarm" => {
            socket_target(ctx, args, reporter, |target| {
                Cmd::SocketDisarm(pb::SocketDisarm { target })
            })
            .await
        }
        "synch_socket_remove" => {
            socket_target(ctx, args, reporter, |target| {
                Cmd::SocketRm(pb::SocketRm { target })
            })
            .await
        }
        "synch_socket_kill" => {
            let invocation = opt_u64(args, "invocation")?
                .ok_or_else(|| ToolError::execution("invocation is required"))?;
            rendered(
                ctx,
                Cmd::SocketKill(pb::SocketKill { invocation }),
                reporter,
            )
            .await
        }
        // Unreachable: the catalogue lookup above already rejected the name.
        _ => Err(ToolError::Protocol(rpc::Error::new(
            rpc::INTERNAL_ERROR,
            format!("{name} is listed but not dispatched"),
        ))),
    }
}

/// Runs a rendered command and returns its lines.
async fn rendered(ctx: &Context, command: Cmd, reporter: &Reporter) -> Result<Outcome, ToolError> {
    Ok(Outcome::text(run_text(ctx, command, reporter).await?))
}

/// Collects a rendered command's output as text.
///
/// Progress frames are dropped, exactly as the CLI drops them: they report what
/// a command is doing, not what it produced. Byte frames are folded in lossily
/// — no tool here runs a command that emits them, and dropping bytes silently
/// would be the wrong way to find that out.
async fn run_text(ctx: &Context, command: Cmd, reporter: &Reporter) -> Result<String, ToolError> {
    let text = ctx
        .session
        .call(|mut client| {
            let command = command.clone();
            async move {
                let mut frames = client.run(command).await?;
                let mut out = String::new();
                let mut truncated = false;
                while let Some(frame) = frames.next().await? {
                    if out.len() >= MAX_RENDERED_BYTES {
                        truncated = true;
                        // Keep draining: dropping the stream mid-command would
                        // leave the daemon cancelling work the caller asked for.
                        continue;
                    }
                    match frame {
                        Frame::Line(line) => {
                            out.push_str(&line);
                            out.push('\n');
                        }
                        Frame::Chunk(bytes) => {
                            out.push_str(&String::from_utf8_lossy(&bytes));
                        }
                        // The daemon says what a long command is doing; a
                        // client that asked to hear about it, hears about it.
                        Frame::Progress(text) => reporter.report(&text).await,
                    }
                }
                if truncated {
                    out.push_str(&format!(
                        "\n[output truncated at {MAX_RENDERED_BYTES} bytes]\n"
                    ));
                }
                Ok(out)
            }
        })
        .await?;
    Ok(text)
}

/// `synch_node`.
async fn node(ctx: &Context, reporter: &Reporter) -> Result<Outcome, ToolError> {
    let id = run_text(ctx, Cmd::Id(pb::Id {}), reporter).await?;
    let status = run_text(ctx, Cmd::DaemonStatus(pb::DaemonStatus {}), reporter).await?;
    Ok(Outcome::text(format!("{id}\n{status}")))
}

/// `synch_spaces`.
async fn spaces(ctx: &Context) -> Result<Outcome, ToolError> {
    let spaces = ctx
        .session
        .call(|mut client| async move { client.list_spaces().await })
        .await?;
    let rows: Vec<Value> = spaces
        .into_iter()
        .filter(|space| ctx.in_scope(&space.id))
        .map(|space| {
            json!({
                "id": space.id,
                "source_path": space.source_path,
                "source_kind": space.source_kind,
                "retention": space.retention,
                "grace_secs": space.grace_secs,
                "budget": space.budget,
                "held_bytes": space.held_bytes,
                "wanted": space.wanted,
                "checkout_path": space.checkout_path,
            })
        })
        .collect();
    Ok(Outcome::structured(json!({ "spaces": rows })))
}

/// Renders one entry the way every structured tool returns it.
fn entry_json(entry: &EntryInfo) -> Value {
    json!({
        "origin": entry.origin,
        "space": entry.space,
        "path": entry.path,
        "kind": kind_name(entry.kind),
        "size": entry.size,
        "mtime_ns": entry.mtime_ns,
        "content_root": entry.content.map(|root| root.to_hex().to_string()),
        "symlink_target": entry.symlink_target,
        "versions": entry.versions,
    })
}

/// The stable lowercase name of an entry kind.
fn kind_name(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::File => "file",
        EntryKind::Dir => "dir",
        EntryKind::Symlink => "symlink",
        EntryKind::Tombstone => "tombstone",
        EntryKind::Socket => "socket",
    }
}

/// `synch_list`.
async fn list(ctx: &Context, args: &Value) -> Result<Outcome, ToolError> {
    let space = need_str(args, "space")?.to_string();
    ctx.scope(&space)?;
    let prefix = opt_path(args, "prefix")?.to_string();
    let cursor = opt_str(args, "cursor")?.map(str::to_string);
    let limit = opt_u64(args, "limit")?
        .unwrap_or(DEFAULT_PAGE)
        .clamp(1, MAX_PAGE);
    let policy = opt_policy(args)?;

    let (entries, scan_cursor) = ctx
        .session
        .call(|mut client| {
            let request = pb::ListRequest {
                space: space.clone(),
                prefix: prefix.clone(),
                start_after: cursor.clone(),
                limit: Some(limit),
                policy: policy.clone(),
            };
            async move {
                let mut stream = client.list(request).await?;
                let mut entries = Vec::new();
                while let Some(entry) = stream.next().await? {
                    entries.push(entry);
                }
                // Read once the stream is drained, which is the only point it
                // is settled.
                let scan_cursor = stream.scan_cursor().map(str::to_owned);
                Ok((entries, scan_cursor))
            }
        })
        .await?;

    // The daemon fills a page past the paths its filters drop, but only within
    // a scan budget, so a page that came back short — empty included — may
    // still have more behind it. When it stopped there rather than at the end
    // of the listing it says where, and that is the cursor: a run of dropped
    // paths longer than the budget leaves no entry to resume from, and this is
    // the case where reading the end off what arrived loses the rest of the
    // space entirely.
    //
    // Otherwise a cursor comes back for every page that had anything in it,
    // not only for a full one, so the end of a listing is an *empty* page with
    // no cursor. Stopping on a short page would silently truncate it; stopping
    // on that costs at most one extra call and cannot.
    let next_cursor = scan_cursor.or_else(|| entries.last().map(|entry| entry.path.clone()));

    Ok(Outcome::structured(json!({
        "entries": entries.iter().map(entry_json).collect::<Vec<_>>(),
        "next_cursor": next_cursor,
    })))
}

/// `synch_stat`.
async fn stat(ctx: &Context, args: &Value) -> Result<Outcome, ToolError> {
    let space = need_str(args, "space")?.to_string();
    ctx.scope(&space)?;
    let path = need_str(args, "path")?.to_string();
    let policy = opt_policy(args)?;
    let entry = resolve(ctx, &space, &path, policy.as_deref()).await?;
    Ok(Outcome::structured(entry_json(&entry)))
}

/// The version a policy selects, with no content fetched.
async fn resolve(
    ctx: &Context,
    space: &str,
    path: &str,
    policy: Option<&str>,
) -> Result<EntryInfo, ToolError> {
    Ok(ctx
        .session
        .call(|mut client| {
            let request = pb::ResolveRequest {
                space: space.to_string(),
                path: path.to_string(),
                policy: policy.map(str::to_string),
            };
            async move { client.resolve(request).await }
        })
        .await?)
}

/// `synch_read`.
async fn read(ctx: &Context, args: &Value) -> Result<Outcome, ToolError> {
    let space = need_str(args, "space")?.to_string();
    ctx.scope(&space)?;
    let path = need_str(args, "path")?.to_string();
    let policy = opt_policy(args)?;
    let offset = opt_u64(args, "offset")?.unwrap_or(0);
    let requested = opt_u64(args, "length")?.unwrap_or(ctx.options.max_read_bytes);
    if requested == 0 {
        // The schema says `minimum: 1`, but nothing here validates against the
        // schema, and a zero-length window is worse than useless: it comes
        // back empty with `eof: false`, so a caller walking the object by
        // `offset += length` never advances and asks again forever.
        return Err(ToolError::execution(
            "length must be at least 1; omit it to read up to the server's \
             --max-read-bytes",
        ));
    }
    let length = requested.min(ctx.options.max_read_bytes);

    // Resolved first, so the result can report the whole object's size and the
    // origin the policy chose — and so a divergent path is refused before any
    // bytes move.
    let entry = resolve(ctx, &space, &path, policy.as_deref()).await?;
    if entry.kind != EntryKind::File && entry.kind != EntryKind::Socket {
        return Err(ToolError::execution(format!(
            "{space}/{path} is a {}, which has no bytes to read",
            kind_name(entry.kind)
        )));
    }

    // A window that starts at or past the end is empty, and saying so is
    // friendlier than whatever the daemon makes of a range outside the object
    // — a caller walking a file by offset lands here on its last step.
    let bytes = if offset >= entry.size {
        Vec::new()
    } else {
        ctx.session
            .call(|mut client| {
                let request = pb::ReadRequest {
                    space: space.clone(),
                    path: path.clone(),
                    policy: policy.clone(),
                    start: offset,
                    len: Some(length),
                };
                async move {
                    let mut chunks = client.read(request).await?;
                    let mut bytes = Vec::new();
                    while let Some(chunk) = chunks.next().await? {
                        bytes.extend_from_slice(&chunk);
                        if bytes.len() as u64 >= length {
                            bytes.truncate(length as usize);
                            break;
                        }
                    }
                    Ok(bytes)
                }
            })
            .await?
    };

    let end = offset.saturating_add(bytes.len() as u64);
    let mut structured = json!({
        "space": space,
        "path": path,
        "origin": entry.origin,
        "size": entry.size,
        "offset": offset,
        "length": bytes.len(),
        "eof": end >= entry.size,
        "versions": entry.versions,
        "content_root": entry.content.map(|root| root.to_hex().to_string()),
    });

    match String::from_utf8(bytes) {
        Ok(text) => {
            structured["encoding"] = json!("text");
            Ok(Outcome {
                content: vec![json!({ "type": "text", "text": text })],
                structured: Some(structured),
            })
        }
        Err(e) => {
            let bytes = e.into_bytes();
            structured["encoding"] = json!("base64");
            let uri = super::resources::uri(&space, &path);
            Ok(Outcome {
                // An embedded resource is how the protocol carries bytes out of
                // a tool: `blob` is defined to be base64, and the block keeps
                // the URI and MIME type with the payload instead of leaving a
                // client to reassemble them from the structured half.
                content: vec![json!({
                    "type": "resource",
                    "resource": {
                        "uri": uri,
                        "mimeType": super::resources::mime_for(&path),
                        "blob": base64::engine::general_purpose::STANDARD.encode(&bytes),
                    },
                })],
                structured: Some(structured),
            })
        }
    }
}

/// `synch_versions`.
async fn versions(ctx: &Context, args: &Value, reporter: &Reporter) -> Result<Outcome, ToolError> {
    let space = need_str(args, "space")?;
    ctx.scope(space)?;
    let path = opt_path(args, "path")?;
    let reference = reference(space, path, None)?;
    rendered(
        ctx,
        Cmd::Status(pb::Status {
            reference: Some(reference),
        }),
        reporter,
    )
    .await
}

/// `synch_history`.
async fn history(ctx: &Context, args: &Value, reporter: &Reporter) -> Result<Outcome, ToolError> {
    let space = need_str(args, "space")?;
    ctx.scope(space)?;
    let path = need_str(args, "path")?;
    let reference = reference(space, path, opt_str(args, "origin")?)?;
    rendered(ctx, Cmd::Log(pb::Log { reference }), reporter).await
}

/// `synch_compare`.
async fn compare(ctx: &Context, args: &Value, reporter: &Reporter) -> Result<Outcome, ToolError> {
    let space = need_str(args, "space")?;
    ctx.scope(space)?;
    let dir = opt_path(args, "dir")?;
    let reference = reference(space, dir, None)?;
    let to = need_str(args, "to")?.to_string();
    let from = opt_str(args, "from")?.map(str::to_string);
    let text = run_text(
        ctx,
        Cmd::Compare(pb::Compare {
            reference,
            from,
            to,
            json: true,
        }),
        reporter,
    )
    .await?;
    // The daemon renders this one as JSON already, so it is handed back as
    // structure rather than re-parsed into a shape of this crate's invention.
    match serde_json::from_str::<Value>(text.trim()) {
        Ok(value) => Ok(Outcome::structured(value)),
        Err(e) => Err(ToolError::execution(format!(
            "the daemon's comparison did not parse as JSON: {e}"
        ))),
    }
}

/// `synch_socket_list`.
async fn socket_list(
    ctx: &Context,
    args: &Value,
    reporter: &Reporter,
) -> Result<Outcome, ToolError> {
    let space = match opt_str(args, "space")?.filter(|s| !s.is_empty()) {
        Some(space) => {
            ctx.scope(space)?;
            space.to_string()
        }
        // An empty space is the daemon's wildcard, so a confined server has to
        // put its own space there rather than pass the omission through.
        None => ctx.scoped_default()?,
    };
    let long = opt_bool(args, "long")?;
    rendered(ctx, Cmd::SocketLs(pb::SocketLs { space, long }), reporter).await
}

/// `synch_socket_ps`.
async fn socket_ps(ctx: &Context, args: &Value, reporter: &Reporter) -> Result<Outcome, ToolError> {
    let target = match opt_str(args, "space")?.filter(|s| !s.is_empty()) {
        Some(space) => {
            ctx.scope(space)?;
            reference(space, need_str(args, "path")?, None)?
        }
        // The daemon filters invocations by an exact `space/path`, so there is
        // no narrowing to a space alone: either this names one socket or it
        // answers for every space on the node, and the second is not something
        // a confined server may do.
        None => {
            ctx.whole_node("synch_socket_ps without a space")?;
            String::new()
        }
    };
    rendered(ctx, Cmd::SocketPs(pb::SocketPs { target }), reporter).await
}

/// `synch_socket_log`.
async fn socket_log(
    ctx: &Context,
    args: &Value,
    reporter: &Reporter,
) -> Result<Outcome, ToolError> {
    socket_target(ctx, args, reporter, |target| {
        Cmd::SocketLog(pb::SocketLog { target })
    })
    .await
}

/// The shape every `<space>/<path>` socket command shares.
async fn socket_target(
    ctx: &Context,
    args: &Value,
    reporter: &Reporter,
    build: impl Fn(String) -> Cmd,
) -> Result<Outcome, ToolError> {
    let space = need_str(args, "space")?;
    ctx.scope(space)?;
    let target = reference(space, need_str(args, "path")?, None)?;
    rendered(ctx, build(target), reporter).await
}

/// `synch_socket_build` — no daemon involved, and nothing written to disk.
async fn socket_build(args: &Value) -> Result<Outcome, ToolError> {
    let source = need_str(args, "source")?.to_string();
    let name = opt_str(args, "name")?.unwrap_or("socket.c").to_string();
    if !synch_cc::SUPPORTED {
        return Err(ToolError::execution(
            "this build has no embedded C compiler, and the system-clang path \
             needs a source file on disk — compile with `synch socket build \
             --clang` instead",
        ));
    }
    if source.len() > MAX_SOURCE_BYTES {
        return Err(ToolError::execution(format!(
            "the source is {} bytes, over the {MAX_SOURCE_BYTES}-byte ceiling \
             on a build over this bridge",
            source.len()
        )));
    }
    let defines = string_map(args, "defines")?;
    // Off the runtime: the compiler writes its headers to a tempdir, takes a
    // process-wide lock and runs to completion through FFI, none of which
    // yields. Left on a worker it stops the reader loop and the writer with
    // it, so requests already in flight go unanswered and a `cancelled`
    // notification cannot even be read until the compile is over.
    let compiled = tokio::task::spawn_blocking({
        let name = name.clone();
        move || {
            let defines: Vec<(&str, &str)> = defines
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            let headers = [("synch.h", synch_sock::sdk::HEADER)];
            synch_cc::compile(&source, &name, &headers, &defines).map_err(|e| e.to_string())
        }
    })
    .await
    .map_err(|e| ToolError::execution(format!("the compile of {name} did not finish: {e}")))?;
    let object = compiled.map_err(|e| ToolError::execution(format!("compiling {name}: {e}")))?;
    Ok(Outcome::both(
        format!("compiled {name}: {} bytes of eBPF object", object.len()),
        json!({
            "object_base64": base64::engine::general_purpose::STANDARD.encode(&object),
            "size": object.len(),
        }),
    ))
}

/// Reads a `{"k": "v"}` argument into pairs, in a stable order.
fn string_map(args: &Value, name: &str) -> Result<Vec<(String, String)>, ToolError> {
    let map = match args.get(name) {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Object(map)) => map,
        Some(_) => {
            return Err(ToolError::execution(format!(
                "{name} must be an object of string values"
            )))
        }
    };
    let mut out = Vec::with_capacity(map.len());
    for (key, value) in map {
        match value {
            Value::String(value) => out.push((key.clone(), value.clone())),
            _ => {
                return Err(ToolError::execution(format!(
                    "{name}.{key} must be a string"
                )))
            }
        }
    }
    // A map has no order and a declaration compiled from one has to be
    // reproducible, so the pairs are sorted rather than left to iteration.
    out.sort();
    Ok(out)
}

/// `synch_socket_review` and `synch_socket_arm`, which are one call with and
/// without the token that turns inspection into approval.
async fn socket_arm(
    ctx: &Context,
    args: &Value,
    reporter: &Reporter,
    review: Option<String>,
) -> Result<Outcome, ToolError> {
    let space = need_str(args, "space")?;
    ctx.scope(space)?;
    let target = reference(space, need_str(args, "path")?, None)?;
    rendered(
        ctx,
        Cmd::SocketArm(pb::SocketArm {
            target,
            review: review.unwrap_or_default(),
        }),
        reporter,
    )
    .await
}

/// `synch_socket_add`.
async fn socket_add(
    ctx: &Context,
    args: &Value,
    reporter: &Reporter,
) -> Result<Outcome, ToolError> {
    let space = need_str(args, "space")?;
    ctx.scope(space)?;
    let target = reference(space, need_str(args, "path")?, None)?;
    let config = string_map(args, "config")?
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    let max_streams = match opt_u64(args, "max_streams")? {
        Some(n) => u32::try_from(n)
            .map_err(|_| ToolError::execution("max_streams is larger than this node allows"))?,
        None => 0,
    };
    rendered(
        ctx,
        Cmd::SocketAdd(pb::SocketAdd {
            target,
            config,
            max_streams,
            auto: opt_bool(args, "auto")?,
            note: opt_str(args, "note")?.unwrap_or_default().to_string(),
        }),
        reporter,
    )
    .await
}

/// `synch_connect` — one invocation, driven to its close.
async fn connect(ctx: &Context, args: &Value) -> Result<Outcome, ToolError> {
    let origin = need_str(args, "origin")?;
    let space = need_str(args, "space")?;
    // The `--space` filter names the spaces this process may touch, wherever
    // they live: a socket on a peer is still addressed by space, and letting
    // one through would make the filter a local-only fiction.
    ctx.scope(space)?;
    let reference = reference(space, need_str(args, "path")?, Some(origin))?;
    let input = payload(args)?;
    let meta: Vec<pb::MetaPair> = string_map(args, "meta")?
        .into_iter()
        .map(|(key, value)| pb::MetaPair { key, value })
        .collect();
    let timeout = match opt_u64(args, "timeout_ms")? {
        Some(ms) => Duration::from_millis(ms).min(MAX_CONNECT_TIMEOUT),
        None => DEFAULT_CONNECT_TIMEOUT,
    };

    let call = ctx.session.call(|mut client| {
        let (reference, input, meta) = (reference.clone(), input.clone(), meta.clone());
        async move {
            let (requests, rx) = tokio::sync::mpsc::channel(4);
            let mut responses = client
                .open_socket(tokio_stream::wrappers::ReceiverStream::new(rx))
                .await?;

            // The whole input is known up front, so the uplink is a task that
            // finishes rather than a pump: it sends the open, the payload, and
            // the half-close, then goes away. The half-close matters — a
            // program that answers only after its input ends never would
            // otherwise.
            let uplink = tokio::spawn(async move {
                let open = pb::ConnectRequest {
                    kind: Some(pb::connect_request::Kind::Open(pb::ConnectOpen {
                        reference,
                        meta,
                    })),
                };
                if requests.send(open).await.is_err() {
                    return;
                }
                for chunk in input.chunks(CHUNK_SIZE) {
                    let message = pb::ConnectRequest {
                        kind: Some(pb::connect_request::Kind::Data(chunk.to_vec())),
                    };
                    if requests.send(message).await.is_err() {
                        return;
                    }
                }
                let _ = requests
                    .send(pb::ConnectRequest {
                        kind: Some(pb::connect_request::Kind::Fin(pb::ConnectFin {})),
                    })
                    .await;
            });

            let mut output = Vec::new();
            let mut truncated = false;
            let mut exit_code = 0;
            let mut status = String::new();
            while let Some(message) = responses.message().await? {
                match message.kind {
                    Some(pb::connect_response::Kind::Data(bytes)) => {
                        let room = MAX_RENDERED_BYTES.saturating_sub(output.len());
                        if bytes.len() > room {
                            truncated = true;
                        }
                        output.extend_from_slice(&bytes[..bytes.len().min(room)]);
                    }
                    Some(pb::connect_response::Kind::Closed(closed)) => {
                        exit_code = closed.exit_code;
                        status = closed.status;
                    }
                    Some(pb::connect_response::Kind::Opened(_)) | None => {}
                }
            }
            uplink.abort();
            Ok((output, truncated, exit_code, status))
        }
    });

    let (output, truncated, exit_code, status, timed_out) =
        match tokio::time::timeout(timeout, call).await {
            Ok(result) => {
                let (output, truncated, exit_code, status) = result?;
                (output, truncated, exit_code, status, false)
            }
            // The timeout drops the call, which drops the control stream, which
            // is how the daemon learns to stop the invocation. Reported as a
            // result rather than an error: a program that ran and did not
            // finish said something, and that something is worth returning.
            Err(_) => (
                Vec::new(),
                false,
                -1,
                format!("timed out after {}ms", timeout.as_millis()),
                true,
            ),
        };

    let bytes = output.len();
    let (encoding, body, content) = match String::from_utf8(output) {
        Ok(text) => (
            "text",
            text.clone(),
            json!({ "type": "text", "text": text }),
        ),
        Err(e) => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(e.as_bytes());
            (
                "base64",
                encoded.clone(),
                json!({
                    "type": "text",
                    "text": format!("{bytes} bytes of non-UTF-8 output; base64 in structuredContent.output"),
                }),
            )
        }
    };

    Ok(Outcome {
        content: vec![content],
        structured: Some(json!({
            "exit_code": exit_code,
            "status": status,
            "encoding": encoding,
            "output": body,
            "bytes": bytes,
            "truncated": truncated,
            "timed_out": timed_out,
        })),
    })
}

/// `synch_write`.
async fn write(ctx: &Context, args: &Value) -> Result<Outcome, ToolError> {
    let space = need_str(args, "space")?.to_string();
    ctx.scope(&space)?;
    let path = need_str(args, "path")?.to_string();
    if args.get("text").is_none() && args.get("base64").is_none() {
        return Err(ToolError::execution(
            "give the content as text or base64; to create an empty file, pass \
             text: \"\"",
        ));
    }
    let content = payload(args)?;

    let written = ctx
        .session
        .call(|mut client| {
            let (space, path, content) = (space.clone(), path.clone(), content.clone());
            async move {
                let mut put = client.put(&space, &path).await?;
                for chunk in content.chunks(CHUNK_SIZE) {
                    put.chunk(chunk.to_vec()).await?;
                }
                // Nothing is published without this: a handle dropped anywhere
                // above leaves the daemon with a payload it was never told to
                // keep (§9.4).
                put.finish().await
            }
        })
        .await?;

    Ok(Outcome::both(
        format!("wrote {} ({} bytes)", written.path, written.entry.size),
        entry_json(&written.entry),
    ))
}

/// `synch_delete`.
async fn delete(ctx: &Context, args: &Value) -> Result<Outcome, ToolError> {
    let space = need_str(args, "space")?.to_string();
    ctx.scope(&space)?;
    let path = need_str(args, "path")?.to_string();
    let deleted = ctx
        .session
        .call(|mut client| {
            let (space, path) = (space.clone(), path.clone());
            async move { client.delete(&space, &path).await }
        })
        .await?;
    let note = match deleted.still_published {
        true => "another origin still publishes this path, so it stays readable",
        false => "no origin publishes this path any more",
    };
    Ok(Outcome::both(
        format!("deleted {space}/{path}: {note}"),
        json!({
            "space": space,
            "path": path,
            "still_published": deleted.still_published,
        }),
    ))
}

/// `synch_adopt_path`.
async fn take(ctx: &Context, args: &Value, reporter: &Reporter) -> Result<Outcome, ToolError> {
    let space = need_str(args, "space")?;
    ctx.scope(space)?;
    let reference = reference(space, need_str(args, "path")?, None)?;
    rendered(
        ctx,
        Cmd::AdoptPath(pb::AdoptPath {
            reference,
            select: opt_str(args, "select")?.map(str::to_string),
        }),
        reporter,
    )
    .await
}

/// `synch_adopt_tree`.
async fn fill(ctx: &Context, args: &Value, reporter: &Reporter) -> Result<Outcome, ToolError> {
    let space = need_str(args, "space")?;
    ctx.scope(space)?;
    let reference = reference(space, opt_path(args, "dir")?, None)?;
    // Dry by default, unlike the CLI: a person typing `synch adopt tree` has the
    // directory in front of them, and a model calling it has not seen it.
    let dry_run = match args.get("dry_run") {
        None | Some(Value::Null) => true,
        _ => opt_bool(args, "dry_run")?,
    };
    rendered(
        ctx,
        Cmd::AdoptTree(pb::AdoptTree {
            reference,
            select: opt_str(args, "select")?.map(str::to_string),
            replace: opt_bool(args, "replace")?,
            dry_run,
        }),
        reporter,
    )
    .await
}

/// `synch_pin`.
async fn pin(ctx: &Context, args: &Value, reporter: &Reporter) -> Result<Outcome, ToolError> {
    let target = match opt_str(args, "root")? {
        Some(root) => root.to_string(),
        None => {
            let space = need_str(args, "space")?;
            ctx.scope(space)?;
            reference(space, need_str(args, "path")?, None)?
        }
    };
    let select = opt_str(args, "select")?.map(str::to_string);
    let command = match need_str(args, "action")? {
        "add" => Cmd::PinAdd(pb::PinAdd { target, select }),
        "rm" => Cmd::PinRm(pb::PinRm { target, select }),
        other => {
            return Err(ToolError::execution(format!(
                "{other:?} is not a pin action: use \"add\" or \"rm\""
            )))
        }
    };
    rendered(ctx, command, reporter).await
}

/// The `_meta`-free argument object a call carries, for handlers that reject
/// unknown properties.
pub(crate) fn arguments(params: &Value) -> Value {
    match params.get("arguments") {
        Some(Value::Object(map)) => {
            let mut map = map.clone();
            map.remove("_meta");
            Value::Object(map)
        }
        _ => Value::Object(Map::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(allow_write: bool, spaces: &[&str]) -> Options {
        Options {
            allow_write,
            spaces: spaces.iter().map(|s| s.to_string()).collect(),
            max_read_bytes: 64 * 1024,
        }
    }

    fn context(allow_write: bool, spaces: &[&str]) -> Context {
        Context {
            session: Session::new(Path::new("/nonexistent")),
            options: options(allow_write, spaces),
        }
    }

    use std::path::Path;

    #[test]
    fn the_catalogue_is_well_formed() {
        let tools = catalog();
        let mut names: Vec<&str> = tools.iter().map(|tool| tool.name).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "tool names must be unique");

        for tool in tools {
            // The character set legacy clients validate against. Dots are
            // allowed by the current revision and rejected by clients in the
            // field, so nothing here uses one.
            assert!(
                tool.name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "{}",
                tool.name
            );
            assert!(tool.name.len() <= 128, "{}", tool.name);
            assert_eq!(tool.input["type"], "object", "{}", tool.name);
            assert!(!tool.description.is_empty(), "{}", tool.name);
            let rendered = tool.to_json();
            assert_eq!(
                rendered["annotations"]["readOnlyHint"],
                Value::Bool(tool.tier == Tier::Read),
                "{}",
                tool.name
            );
            assert_eq!(
                rendered.get("outputSchema").is_some(),
                tool.output.is_some(),
                "{}",
                tool.name
            );
        }
    }

    #[test]
    fn every_listed_tool_is_dispatched() {
        // A tool in the catalogue with no arm in `call` would be advertised and
        // then answer "listed but not dispatched" at the worst moment.
        let dispatched = include_str!("tools.rs");
        for tool in catalog() {
            let arm = format!("\"{}\" =>", tool.name);
            assert!(
                dispatched.contains(&arm),
                "{} has no dispatch arm",
                tool.name
            );
        }
    }

    #[test]
    fn the_read_tier_is_what_a_default_server_serves() {
        let read_only = context(false, &[]);
        let names: Vec<&str> = read_only.catalog().iter().map(|t| t.name).collect();
        assert!(names.contains(&"synch_read"));
        assert!(names.contains(&"synch_socket_review"));
        assert!(names.contains(&"synch_connect"));
        assert!(!names.contains(&"synch_write"));
        assert!(!names.contains(&"synch_socket_arm"));

        let full = context(true, &[]);
        assert!(full.catalog().len() > read_only.catalog().len());
        assert!(full
            .catalog()
            .iter()
            .any(|tool| tool.name == "synch_socket_arm"));
    }

    #[tokio::test]
    async fn a_write_tool_is_refused_with_the_remedy_when_the_tier_is_off() {
        let ctx = context(false, &[]);
        let error = call(
            &ctx,
            "synch_write",
            &json!({"space": "media", "path": "a"}),
            &Reporter::silent(),
        )
        .await
        .unwrap_err();
        match error {
            ToolError::Execution { message, .. } => {
                assert!(message.contains("--allow-write"), "{message}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn an_unknown_tool_is_a_protocol_error() {
        let ctx = context(true, &[]);
        match call(&ctx, "synch_nope", &json!({}), &Reporter::silent())
            .await
            .unwrap_err()
        {
            ToolError::Protocol(e) => assert_eq!(e.code, rpc::INVALID_PARAMS),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_space_outside_the_filter_never_reaches_the_daemon() {
        // The session points at a datadir with no daemon, so anything that got
        // through would fail as Unavailable instead.
        let ctx = context(true, &["media"]);
        let error = call(
            &ctx,
            "synch_list",
            &json!({"space": "code"}),
            &Reporter::silent(),
        )
        .await
        .unwrap_err();
        match error {
            ToolError::Execution { message, .. } => {
                assert!(message.contains("out of scope"), "{message}");
                assert!(message.contains("--space media"), "{message}");
            }
            other => panic!("{other:?}"),
        }
        assert!(ctx.in_scope("media") && !ctx.in_scope("code"));
    }

    #[test]
    fn arguments_are_validated_before_anything_moves() {
        let args = json!({ "space": "media", "count": 3, "flag": "yes" });
        assert_eq!(need_str(&args, "space").unwrap(), "media");
        assert!(need_str(&args, "path").is_err());
        assert!(need_str(&args, "count").is_err());
        assert_eq!(opt_str(&args, "missing").unwrap(), None);
        assert_eq!(opt_u64(&args, "count").unwrap(), Some(3));
        assert!(opt_bool(&args, "flag").is_err());
        assert!(opt_u64(&json!({"n": -1}), "n").is_err());

        assert_eq!(
            opt_policy(&json!({"policy": "strict"})).unwrap().as_deref(),
            Some("strict")
        );
        assert_eq!(
            opt_policy(&json!({"policy": "origin=nas@x.example"}))
                .unwrap()
                .as_deref(),
            Some("origin=nas@x.example")
        );
        assert!(opt_policy(&json!({"policy": "latest"})).is_err());
    }

    #[test]
    fn a_payload_is_text_or_base64_and_never_both() {
        assert_eq!(payload(&json!({"text": "hi"})).unwrap(), b"hi");
        assert_eq!(payload(&json!({"base64": "aGk="})).unwrap(), b"hi");
        assert_eq!(payload(&json!({})).unwrap(), Vec::<u8>::new());
        assert!(payload(&json!({"text": "hi", "base64": "aGk="})).is_err());
        assert!(payload(&json!({"base64": "not base64!"})).is_err());
    }

    #[test]
    fn references_are_built_canonically_and_reject_nonsense() {
        assert_eq!(
            reference("media", "a/b.txt", None).unwrap(),
            "media/a/b.txt"
        );
        assert_eq!(reference("media", "", None).unwrap(), "media");
        assert_eq!(
            reference("media", "a.txt", Some("nas@cluster.example")).unwrap(),
            "nas@cluster.example:media/a.txt"
        );
        // A colon in the path is exactly what the text form is accused of not
        // carrying; it does, because the origin boundary is before the first
        // slash.
        assert_eq!(
            reference("media", "2024:07:01.bin", None).unwrap(),
            "media/2024:07:01.bin"
        );
        assert!(reference("", "a", None).is_err());
    }

    #[test]
    fn a_define_map_is_ordered_so_a_build_is_reproducible() {
        let args = json!({ "defines": { "PORT": "9418", "HOST": "git.internal" } });
        assert_eq!(
            string_map(&args, "defines").unwrap(),
            vec![
                ("HOST".to_string(), "git.internal".to_string()),
                ("PORT".to_string(), "9418".to_string()),
            ]
        );
        assert!(string_map(&json!({"defines": {"N": 1}}), "defines").is_err());
        assert!(string_map(&json!({"defines": []}), "defines").is_err());
    }

    #[test]
    fn control_failures_carry_their_code_and_a_next_step() {
        let divergent = ToolError::from(ControlError::new(
            ErrorCode::Divergent,
            "media/a.txt has 2 versions",
        ));
        match divergent {
            ToolError::Execution { message, data } => {
                assert!(message.contains("policy=\"origin=<id>\""), "{message}");
                assert_eq!(data.unwrap()["code"], "divergent");
            }
            other => panic!("{other:?}"),
        }

        match ToolError::from(ControlError::new(ErrorCode::NotFound, "no such path")) {
            ToolError::Execution { message, data } => {
                assert_eq!(message, "no such path");
                assert_eq!(data.unwrap()["code"], "not-found");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn arguments_drop_the_meta_a_client_puts_beside_them() {
        let params =
            json!({ "name": "synch_list", "arguments": { "space": "media", "_meta": {} } });
        let args = arguments(&params);
        assert_eq!(args["space"], "media");
        assert!(args.get("_meta").is_none());
        assert_eq!(arguments(&json!({ "name": "x" })), json!({}));
    }
}
